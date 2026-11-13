#!/usr/bin/env python3
"""Assert the census tells a DXE install from one that happened inside SMRAM.

Measured on the 138-target sweep 43454245046. `SmmInstallProtocolInterface:` CONTAINS the
string `InstallProtocolInterface:`, so the unanchored census pattern counted an interface
the SMM core installed as one a DXE harness can locate. It cannot: gBS->LocateProtocol
searches the DXE handle database and an MM protocol was never put there.

Fourteen GUIDs in that run's boot capture are installed only inside SMRAM, and ten of the
sweep's targets resolve to them -- EdkiiSmmCpuRendezvous, EdkiiSmmMemoryAttribute, EfiMmCpu,
EfiMmCpuIo among them. Each was scheduled as a DXE campaign. Each booted, generated a
harness, relinked the platform, ran thousands of inputs with every single one returning at
the LocateProtocol early exit, and was then reported as a boot failure. At the observed
cost that is about 11 hours of container-slot time spent fuzzing an early return.

The split must be exact in both directions: no GUID may be lost, and a protocol installed
in DXE **and** inside SMRAM is present, because the DXE handle really does have it. On the
real capture: 188 unanchored = 174 DXE + 14 SMRAM-only, union identical.
"""

import importlib.util
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FAILED = PASSED = 0


def check(what, ok, detail=''):
    global FAILED, PASSED
    if ok:
        PASSED += 1
        print(f'  [OK]   {what}')
    else:
        FAILED += 1
        print(f'  [FAIL] {what}' + (f'\n         {detail}' if detail else ''))


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, f'{name}.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def source(name):
    return io.open(os.path.join(HERE, f'{name}.py'), encoding='utf-8').read()


def code(text):
    """A region with its prose removed -- docstrings and comments both.

    Asserting on raw text whose comments explain the defect finds the defect's name in the
    explanation rather than in the statements. Both halves matter here, because the comment
    beside the pattern quotes the very spelling the pattern must not match.
    """
    found = re.search(r'"""', text)
    while found:
        try:
            closing = text.index('"""', found.end())
        except ValueError:
            break
        text = text[:found.start()] + text[closing + 3:]
        found = re.search(r'"""', text)
    kept = []
    for line in text.splitlines():
        if not line.strip().startswith('#'):
            kept.append(line.split('  #')[0])
    return '\n'.join(kept)


A = 'AAAAAAAA-1111-2222-3333-444444444444'
B = 'BBBBBBBB-1111-2222-3333-444444444444'
C = 'CCCCCCCC-1111-2222-3333-444444444444'
D = 'DDDDDDDD-1111-2222-3333-444444444444'

CAPTURE = (f'InstallProtocolInterface: {A} 7F9C1000\n'
           f'SmmInstallProtocolInterface: {B} 7FE00000\n'
           f'InstallProtocolInterface: {C} 7F9C2000\n'
           f'SmmInstallProtocolInterface: {C} 7FE01000\n'
           f'MmInstallProtocolInterface: {D} 7FE02000\n')

REAL = '/home/gl055/fuzzuer-eval1/43454245046/detect_capture/debug.log'


def main():
    import tempfile
    pp = load('protocol_presence')
    holder = tempfile.TemporaryDirectory()
    path = os.path.join(holder.name, 'capture.log')
    open(path, 'w').write(CAPTURE)
    dxe, smram = pp.installed_guids(path)

    print('the two spellings are counted apart')
    check('a DXE install is a DXE install', A in dxe, f'{sorted(dxe)}')
    check('an SMM install is NOT counted as a DXE install', B not in dxe,
          'SmmInstallProtocolInterface CONTAINS the DXE spelling, which is the whole bug')
    check('an SMM install is reported as inside SMRAM', B in smram, f'{sorted(smram)}')
    check('the MM spelling counts as SMRAM too', D in smram and D not in dxe)
    check('a protocol installed on BOTH sides belongs to DXE',
          C in dxe and C not in smram,
          'the DXE handle database really does have it, so a campaign can call it')

    print('\nnothing is lost or invented by the split')
    unanchored = {g.upper() for g in
                  re.findall(r'InstallProtocolInterface:\s*'
                             r'([0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12})',
                             CAPTURE)}
    check('every GUID the old pattern saw is on exactly one side',
          dxe | smram == unanchored and not (dxe & smram),
          f'dxe={len(dxe)} smram={len(smram)} old={len(unanchored)}')
    check('a capture with no SMM lines yields an empty SMRAM set',
          pp.installed_guids(_write(holder.name, 'd.log',
                                    f'InstallProtocolInterface: {A} 1\n'))[1] == set())
    check('a capture with only SMM lines still reports them',
          pp.installed_guids(_write(holder.name, 's.log',
                                    f'SmmInstallProtocolInterface: {B} 1\n'))[1] == {B})

    if os.path.isfile(REAL):
        print('\nand on the capture the sweep actually booted')
        real_dxe, real_smram = pp.installed_guids(REAL)
        text = open(REAL, errors='ignore').read().replace('\x00', '')
        old = {g.upper() for g in
               re.findall(r'InstallProtocolInterface:\s*'
                          r'([0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12})', text)}
        check('the real capture splits without loss',
              real_dxe | real_smram == old and not (real_dxe & real_smram),
              f'dxe={len(real_dxe)} smram={len(real_smram)} old={len(old)}')
        check('and it really does hold SMRAM-only interfaces',
              len(real_smram) > 0,
              'if this is zero the census was never wrong and this check proves nothing')
    else:
        print(f'\n  [skip] {REAL} is not on this host')

    print('\nthe census reports the new status')
    psrc = code(source('protocol_presence'))
    check('smm-only is a status the census can emit', "'smm-only'" in psrc)
    check('it is counted like the others', "'smm-only': 0" in psrc)
    # before(), not .index(). A mutation that DELETES the arm makes .index raise, and a
    # traceback is not a failed assertion: the harness sees a non-zero exit, credits a
    # catch, and the check never says which assertion it was. Two mutations landed exactly
    # there while this read `psrc.index(...) < psrc.index(...)`.
    check('it is decided before the service-binding arm',
          before(psrc, "status = 'smm-only'", 'bindings.append'),
          'a binding guess must not win over a protocol that was observed installed; '
          'absent entirely if the arm is gone')
    check('and it is not folded into absent or present',
          psrc.count("status = 'smm-only'") == 1,
          'zero occurrences means the arm was removed or renamed to another status')

    print('\nthe batch skips them, for a reason that is not the absent one')
    bsrc = code(source('fuzz_batch'))
    check('the batch reads the status', "'smm-only'" in bsrc)
    check('and drops them from the work list',
          "not in ('absent', 'smm-only')" in bsrc,
          'they would otherwise each cost a boot and a budget to fuzz an early return')
    # code(), not source(). The comment above the block quotes the reason it writes, so
    # reading the raw text passes with the statement commented out -- which is the one
    # mutation that got through the first time this check was written.
    check('the skip reason names SMRAM, not absence',
          'installed inside SMRAM only' in bsrc,
          '"not installed by this firmware" is false about a protocol that is installed')
    check('the reason points at the channel that does reach them', 'SMI harness' in bsrc)
    check('absent keeps its own, different reason',
          'protocol not installed by this firmware' in bsrc)
    check('both go to skipped.csv so the run says what it did not fuzz',
          bsrc.count('writer.writerow([name,') == 2, 'one row-writer per reason')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


def before(text, first, second):
    """True when both appear and `first` comes first. False, never an exception, if not."""
    at, then = text.find(first), text.find(second)
    return at >= 0 and then >= 0 and at < then


def _write(where, name, text):
    path = os.path.join(where, name)
    open(path, 'w').write(text)
    return path


if __name__ == '__main__':
    sys.exit(main())
