#!/usr/bin/env python3
"""Assert every presence verdict is backed by the capture, and says so when it is not.

Two verdicts in the census were not readings of the boot capture at all.

The first was 'unknown' for a protocol whose service binding exists in the tree and was
not installed. It was chosen to protect a measurement -- skipping the upper network stack
once cost the four most productive targets in a sweep -- and 'unknown' is never skipped,
so the whole stack ran. Sweep 43704163314 then measured the other side: this arm selects
exactly 23 protocols on each of its four refs, every one launched, and every one printed
"LocateProtocol never succeeded" -- 41262, 36173, 38208 and 38939 iterations per ref of
harness startup and nothing else, 23 of a launched 112. The protected case
holds on capture 43454245046, where PXE connected the NIC: the same four read present
there, three by their own child GUID and EfiHttp by its service binding, and EfiArp,
EfiIp6, EfiTcp4, EfiTcp6 and EfiUdp6 each recorded a fuzz-phase finding inside their own
driver. The discriminator is therefore the install line, not the arm, and the arm is
'absent'. Both halves are asserted here, because flipping either one back looks like a
tidy-up: the arm must skip, and a binding that IS installed must still read present.

The second was 'present' for a NULL interface. The DXE core's line is
`InstallProtocolInterface: %g %p`, so the capture records the pointer, and reading only
the GUID cannot tell VariableNotifySmmReady()'s readiness signal -- gEfiSmmVariableProtocolGuid
installed with EFI_NATIVE_INTERFACE and NULL -- from a working interface. A harness that
locates one checks EFI_ERROR(Status), gets EFI_SUCCESS, and dereferences NULL. Nothing
requests one today on either body of evidence, so this changes no launched count; what it
changes is that the census stops asserting presence it has not seen, and that
gEfiSmmVariableProtocolGuid reads smm-only, which is where its real interface is.

Known limit, asserted as the conservative verdict rather than the right one: edk2 also
prints `InstallProtocolInterface: %g %p failed with %r` for an install that FAILED, which
the census has always counted as presence. That line has no pointer at end-of-line, so it
now reads present-unverified instead of present. No capture in either body of evidence
contains one, so there is nothing to measure a skip on.

Run: python3 scripts/presence_evidence_check.py
"""

import importlib.util
import io
import os
import re
import sys
import tempfile

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
    explanation rather than in the statements. It matters more than usual here: the arm
    this guards carries the measurement that justifies it, in a comment that names every
    status the arm could have returned.
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


def before(text, first, second):
    """True when both appear and `first` comes first. False, never an exception, if not."""
    at, then = text.find(first), text.find(second)
    return at >= 0 and then >= 0 and at < then


DIRECT = 'AAAAAAAA-1111-2222-3344-5566778899AA'
NULLED = 'BBBBBBBB-1111-2222-3344-5566778899AA'
BOTH = 'CCCCCCCC-1111-2222-3344-5566778899AA'
UNSAID = 'DDDDDDDD-1111-2222-3344-5566778899AA'
SMMSIG = 'EEEEEEEE-1111-2222-3344-5566778899AA'
BOUND = '11111111-1111-2222-3344-5566778899AA'
BOUND_SB = '22222222-1111-2222-3344-5566778899AA'
UNBOUND = '33333333-1111-2222-3344-5566778899AA'
UNBOUND_SB = '44444444-1111-2222-3344-5566778899AA'
GONE = '55555555-1111-2222-3344-5566778899AA'

# One pair per question, differing in ONE attribute, because a pair that differs in two
# proves nothing about which one the code read. FakeDirect/FakeNull differ only in the
# pointer; FakeBound/FakeUnbound only in whether the service binding is on an install
# line -- both have a child GUID declared, both a binding declared, neither child
# installed. A fixture where the unbound one also lacked a declared binding would pass an
# implementation that never looked at the capture at all.
CAPTURE = (
    f'InstallProtocolInterface: {DIRECT} 7F9C1000\n'
    f'InstallProtocolInterface: {NULLED} 0\n'
    f'InstallProtocolInterface: {BOTH} 0\n'
    f'InstallProtocolInterface: {BOTH} 7F9C2000\n'
    f'InstallProtocolInterface: {UNSAID}\n'
    f'InstallProtocolInterface: {SMMSIG} 0\n'
    f'SmmInstallProtocolInterface: {SMMSIG} 7FE00000\n'
    f'InstallProtocolInterface: {BOUND_SB} 7F9C3000\n'
)

PROTOCOLS = ['FakeDirect', 'FakeNull', 'FakeBoth', 'FakeUnsaid', 'FakeSmmSignal',
             'FakeBound', 'FakeUnbound', 'FakeGone', 'FakeNoGuid']

DECLARED = [
    ('gFakeDirectProtocolGuid', DIRECT),
    ('gFakeNullProtocolGuid', NULLED),
    ('gFakeBothProtocolGuid', BOTH),
    ('gFakeUnsaidProtocolGuid', UNSAID),
    ('gFakeSmmSignalProtocolGuid', SMMSIG),
    ('gFakeBoundProtocolGuid', BOUND),
    ('gFakeBoundServiceBindingProtocolGuid', BOUND_SB),
    ('gFakeUnboundProtocolGuid', UNBOUND),
    ('gFakeUnboundServiceBindingProtocolGuid', UNBOUND_SB),
    ('gFakeGoneProtocolGuid', GONE),
]

SWEEP = '/home/gl055/fuzzuer-sweep/43704163314'
REFS = ['fuzz-edk2-stable202602', 'fuzz-edk2-stable202605', 'fuzz-edk2-stable202608',
        'fuzz-master']
EVAL1 = '/home/gl055/fuzzuer-eval1/43454245046/detect_capture/debug.log'
# The 23 the binding arm selects on every ref of 43704163314, and the per-ref iteration
# totals their campaigns spent reaching nothing.
UNBOUND_23 = """EfiArp EfiBluetoothAttribute EfiBluetoothIo EfiDhcp4 EfiDhcp6 EfiDns4
EfiDns6 EfiFtp4 EfiHash EfiHttp EfiIp4 EfiIp6 EfiIsaHc EfiManagedNetwork EfiMtftp4
EfiMtftp6 EfiRestEx EfiSupplicant EfiTcp4 EfiTcp6 EfiTls EfiUdp4 EfiUdp6""".split()
SMM_VARIABLE = 'ED32D533-99E6-4209-9CC0-2D72CDD998A7'
HTTP_SB = 'BDC8E6AF-D9BC-4379-A72A-E0C4E75DAE1C'
TCP4_CHILD = '65530BC7-A359-410F-B010-5AADC7EC2B62'


def dec_line(name, guid):
    """One edk2 .dec GUID declaration, in the syntax guid_map() actually parses."""
    head, b, c, group4, tail = guid.split('-')
    octets = [group4[0:2], group4[2:4]] + [tail[i:i + 2] for i in range(0, 12, 2)]
    return (f'  {name} = {{ 0x{head}, 0x{b}, 0x{c}, '
            f'{{ {", ".join("0x" + o for o in octets)} }} }}\n')


def fake_tree(work):
    """A tree guid_map() can read: the glob wants a top directory named edk2*."""
    package = os.path.join(work, 'edk2fake', 'FakePkg')
    os.makedirs(package)
    with open(os.path.join(package, 'FakePkg.dec'), 'w') as handle:
        handle.write('[Protocols]\n')
        for name, guid in DECLARED:
            handle.write(dec_line(name, guid))
    return work


def censused(work, capture):
    """Run the census as the sweep runs it and return {protocol: status}, plus stdout."""
    import contextlib
    pp = load('protocol_presence')
    evalset = os.path.join(work, 'evalset')
    os.makedirs(evalset, exist_ok=True)
    for name in PROTOCOLS:
        open(os.path.join(evalset, f'{name}.txt'), 'w').write('x')
    out = os.path.join(work, 'presence.csv')
    said = io.StringIO()
    argv = sys.argv
    sys.argv = ['protocol_presence.py', '--capture', capture, '--root', work,
                '--evalset', evalset, '--out', out]
    # Caught, not allowed out. A status the counts dict does not hold raises KeyError here,
    # and an uncaught one kills this check instead of failing it -- no "N passed, M failed"
    # line at all, which a harness reading the exit code scores as a catch. Measured: the
    # mutation that removed 'signal-only' from the dict did exactly that.
    try:
        with contextlib.redirect_stdout(said):
            rc = pp.main()
    except Exception as exc:
        rc = f'{type(exc).__name__}: {exc}'
    finally:
        sys.argv = argv
    import csv
    rows = {}
    if os.path.isfile(out):
        with open(out, newline='') as handle:
            rows = {r['protocol']: r['status'] for r in csv.DictReader(handle)}
    return rc, rows, said.getvalue()


def install_lines(path):
    """(real interfaces, NULL-only, no pointer recorded, every SMRAM install)."""
    pp = sys.modules['protocol_presence']
    null, unsaid, smram = pp.null_interfaces(path)
    dxe, _ = pp.installed_guids(path)
    return dxe - null - unsaid, null, unsaid, smram


def main():
    holder = tempfile.TemporaryDirectory()
    work = fake_tree(holder.name)
    capture = os.path.join(work, 'capture.log')
    open(capture, 'w').write(CAPTURE)
    rc, rows, said = censused(work, capture)

    print('the capture records the interface, so the census can read it')
    check('the census ran to completion over the new statuses', rc == 0,
          f'a KeyError in the counts dict exits here and no verdict below means anything; '
          f'rc={rc}')
    check('a real interface is present', rows.get('FakeDirect') == 'present',
          f'got {rows.get("FakeDirect")!r}')
    check('a NULL interface is NOT present', rows.get('FakeNull') == 'signal-only',
          f'got {rows.get("FakeNull")!r} -- LocateProtocol returns EFI_SUCCESS and hands '
          f'the harness NULL, which is not what present claims')
    check('a guid installed BOTH ways is present', rows.get('FakeBoth') == 'present',
          f'got {rows.get("FakeBoth")!r} -- one NULL signal does not unmake a real install')
    check('an install line with no pointer admits it cannot tell',
          rows.get('FakeUnsaid') == 'present-unverified',
          f'got {rows.get("FakeUnsaid")!r} -- present is the one answer the line does not '
          f'support, and absent is the other')
    check('a NULL signal whose real interface is in SMRAM reads smm-only',
          rows.get('FakeSmmSignal') == 'smm-only',
          f'got {rows.get("FakeSmmSignal")!r} -- this is gEfiSmmVariableProtocolGuid; '
          f'signal-only would lose the channel that does reach it, absent is false')

    print('\nthe service binding decides, and the install line decides the binding')
    check('a binding that IS installed is present, child protocol or not',
          rows.get('FakeBound') == 'present',
          f'got {rows.get("FakeBound")!r} -- this is the EfiHttp case the old arm existed '
          f'to protect; the harness supplies the CreateChild the boot never needed')
    check('a binding that is NOT installed is absent',
          rows.get('FakeUnbound') == 'absent',
          f'got {rows.get("FakeUnbound")!r} -- unknown is never skipped, which is the 23 '
          f'campaigns a ref of 43704163314 spent on harness startup')
    check('and the two differ only in that install line',
          rows.get('FakeBound') != rows.get('FakeUnbound'),
          'both have a child guid declared, both a service binding declared, neither '
          'child installed -- if these agree the capture was not read')
    check('a protocol with no binding and no install is still absent',
          rows.get('FakeGone') == 'absent', f'got {rows.get("FakeGone")!r}')
    check('an unresolvable name is still never skipped',
          rows.get('FakeNoGuid') == 'unknown', f'got {rows.get("FakeNoGuid")!r}')

    print('\na capture with no real interface in it is refused, not answered')
    all_null = os.path.join(work, 'all-null.log')
    open(all_null, 'w').write(f'InstallProtocolInterface: {DIRECT} 0\n'
                              f'InstallProtocolInterface: {BOUND_SB} 0\n')
    null_rc, null_rows, null_said = censused(work, all_null)
    check('it exits non-zero', null_rc == 1,
          f'rc={null_rc!r} -- the existing guard counts install LINES, which this capture '
          f'has, so it passes that one and empties present in the subtraction')
    check('and says why, rather than reporting a firmware that installs nothing',
          'no install line' in null_said and 'read absent' in null_said,
          f'every target absent is a sweep that skips everything and finishes green\n'
          f'         {null_said}')
    check('it does not write a census that says absent for everything',
          null_rows.get('FakeDirect') != 'absent', f'got {null_rows.get("FakeDirect")!r}')

    print('\nand the run says what it decided and why')
    check('the unbound ones are named, not just counted',
          'FakeUnbound' in said and 'nothing connected their controller' in said,
          'a fifth of a launched set disappearing with no reason printed is how this '
          f'arm went unexamined for a month\n         {said}')
    check('the NULL one is reported as a hazard, not as absence',
          'NULL interface' in said and 'not skipped' in said, said)

    print('\nthe arms are ordered so observed evidence outranks a guess')
    psrc = code(source('protocol_presence'))
    # before(), not .index(). A mutation that DELETES an arm makes .index raise, and a
    # traceback is not a failed assertion: a naive harness sees the non-zero exit and
    # credits itself a catch.
    check('an installed binding is decided before the uninstalled-binding arm',
          before(psrc, "bindings.append", "unbound.append"),
          'reversed, every service-binding protocol reads absent and the protected case '
          'is lost; absent entirely if an arm is gone')
    check('a NULL signal is decided before the binding arms',
          before(psrc, "status = 'signal-only'", "bindings.append"),
          'a binding guess must not win over a guid that was observed installed')
    check('smm-only is still decided first of all',
          before(psrc, "status = 'smm-only'", "status = 'signal-only'"))
    check('the uninstalled-binding arm resolves to absent exactly once',
          psrc.count('unbound.append') == 1 and
          before(psrc, "unbound.append", "print(f'  {len(unbound)}"),
          'zero means the arm was removed or renamed and the 23 are launched again')
    check('both new statuses are counted, so a verdict cannot KeyError',
          "'signal-only': 0" in psrc and "'present-unverified': 0" in psrc)
    check('the pointer pattern is anchored to end of line',
          '$' in psrc.split('WITH_INTERFACE')[1].split('\n\n')[0],
          'unanchored it captures the first hex run of whatever follows on a wrapped '
          'line, and every install reads as a real interface')

    print('\nthe measurements that justify the arm are still in the file')
    # Raw source, not code(): these are the comment that records WHY the arm is absent,
    # and an assertion that went through code() would pass with the whole justification
    # deleted. Each token below appears in exactly one sentence -- the one carrying the
    # number -- so editing that sentence away fails the check rather than moving it.
    raw = source('protocol_presence')
    check('the four refs that falsify "the harness connects the controller" are counted',
          all(n in raw for n in ('41262', '36173', '38208', '38939')),
          'the per-ref iteration totals the 23 spent on harness startup are the whole '
          'evidence for skipping, and they are the 23 alone -- a per-ref total that also '
          'counted EfiHash2 and EfiWatchdogTimerArch would be a different claim')
    check('the protected measurement is still recorded, so nobody re-flips it blind',
          all(n in raw for n in ('16972', '15566', '8802', '7643')),
          'without it the next reader sees only a skip and no reason it was ever unsafe')
    check('both bodies of evidence are named by run id',
          '43704163314' in raw and '43454245046' in raw)
    check('the NULL install names the function and the file that writes it',
          'VariableNotifySmmReady' in raw and 'VariableTraditionalMm.c' in raw)
    check('and the line the pointer comes from is named',
          'Handle.c:349' in raw,
          'a reader who cannot find the DEBUG line cannot check this at all')

    if os.path.isdir(SWEEP):
        print('\non the four captures the sweep actually booted')
        load('protocol_presence')
        for ref in REFS:
            path = os.path.join(SWEEP, ref, 'detect_capture', 'debug.log')
            if not os.path.isfile(path):
                check(f'{ref} has a capture', False, path)
                continue
            real, null, unsaid, smram = install_lines(path)
            check(f'{ref}: not one of the 23 bindings is on an install line',
                  not (real & {'00720665-67EB-4A99-BAF7-D3C33A1C7CC9'.upper()}),
                  'gEfiTcp4ServiceBindingProtocolGuid -- if this is installed the ref '
                  'bound TcpDxe and the 23 were not a wasted fifth of the run')
            check(f'{ref}: it does install NULL-only signals, so the rule has work',
                  len(null) == 15, f'{len(null)} NULL-only guids, expected 15')
            check(f'{ref}: and every install line records its pointer',
                  unsaid == set(),
                  f'{len(unsaid)} guid(s) with no pointer -- present-unverified is '
                  f'reported for exactly this and must stay rare')
    else:
        print(f'\n  [skip] {SWEEP} is not on this host')

    if os.path.isfile(EVAL1):
        print('\nand on the capture where PXE connected the NIC')
        load('protocol_presence')
        real, null, unsaid, smram = install_lines(EVAL1)
        check('the protected case is present there by its service binding',
              HTTP_SB in real,
              'gEfiHttpServiceBindingProtocolGuid -- EfiHttp reads present off this line, '
              'which is why the arm above can be absent')
        check('and EfiTcp4 by its own child guid', TCP4_CHILD in real)
        check('gEfiSmmVariableProtocolGuid is a NULL signal in the DXE database',
              SMM_VARIABLE in null,
              'if it is not, this capture cannot demonstrate the defect and the real '
              'interface question is untested')
        check('its real interface is inside SMRAM, so it is not absent',
              SMM_VARIABLE in smram,
              'smm-only is only the right answer while the SMM core installs it')
    else:
        print(f'\n  [skip] {EVAL1} is not on this host')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
