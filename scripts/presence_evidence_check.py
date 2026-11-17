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

A third verdict was not a reading of the install LINE. The pointer was separated from the
GUID by `\s+`, which matches a newline, so an install line that wrapped after its GUID had
the next line's leading hex captured as its interface pointer -- a bare `0` there made a
real interface read as a NULL readiness signal, and a pointer-shaped run made a line with
no pointer on it read as `present`, including for a protocol whose only real interface is
inside SMRAM. That one is the ten protocols and the eleven container-hours
presence_channel_check.py exists to prevent. It was latent on all 2060 distinct captures
on this host and it is not latent on firmware nobody here has booted yet. Both gaps in
that pattern are `[ \t]` now, and the assertions for it are behavioural -- on the wrapped
input, through the census, not on the pattern's text.

Where the evidence lives. Sixteen of these assertions used to be guarded on run
directories under /home/gl055, so CI ran none of the ones that bind the verdicts to a real
boot: the discriminator and the NULL rule were asserted only on the machine that wrote
them. The install lines of the same five captures are committed under
scripts/presence_fixtures/ -- 688 lines, 49 KB, one per distinct (spelling, GUID, pointer
shape), which is every distinction the census can draw -- and real_evidence() decides the
policy from those, through the same census code the sweep runs, in a fresh checkout.
fixture_provenance() is the half that stays host-only, and it is the right half: it
re-derives each fixture from its capture and requires byte equality and equal derived
sets, so a fixture edited to make an assertion pass fails here, where the captures are.
Regenerate with `python3 scripts/presence_evidence_check.py --distill`.

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


def region(text, opening, closing):
    """What lies between two markers, or '' if either is missing. Never raises.

    .index() would, and a traceback is not a failed assertion -- a harness reading the
    exit code scores it as a catch and names no assertion at all.
    """
    at = text.find(opening)
    if at < 0:
        return ''
    then = text.find(closing, at + len(opening))
    return text[at + len(opening):then] if then >= 0 else ''


def _write(where, name, text):
    path = os.path.join(where, name)
    open(path, 'w').write(text)
    return path


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

# Install records whose pointer landed on the FOLLOWING line, and the SAME records with
# the line break turned back into the space edk2 prints. One attribute apart -- the line
# break and nothing else, which is why UNWRAPPED is derived from WRAPPED by substitution
# rather than written out twice. FakeDirect's record is intact in both: the census refuses
# a capture in which no install line names a real interface, and that guard would
# otherwise answer for every verdict here.
#
# Unwrapped, all three of the others are claims the capture supports: FakeNull a NULL
# readiness signal, FakeBoth and FakeSmmSignal real interfaces in the DXE database.
# Wrapped, none of them is, and what the census said while the pattern joined the two
# lines with \s+ was the unwrapped answer to all three -- including `present` for
# FakeSmmSignal, whose only real interface is inside SMRAM. That is a DXE campaign
# scheduled on a protocol gBS->LocateProtocol cannot reach, which is the ten protocols and
# the eleven container-hours presence_channel_check.py exists to prevent.
WRAPPED = (f'InstallProtocolInterface: {DIRECT} 7F9C1000\n'
           f'InstallProtocolInterface: {NULLED}\n'
           f'0\n'
           f'InstallProtocolInterface: {BOTH}\n'
           f'7F9C2000\n'
           f'InstallProtocolInterface: {SMMSIG}\n'
           f'7FE00000\n'
           f'SmmInstallProtocolInterface: {SMMSIG} 7FE00000\n')
UNWRAPPED = re.sub(r'(InstallProtocolInterface: [0-9A-Fa-f-]{36})\n', r'\1 ', WRAPPED)

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
# The capture each committed fixture was distilled from. The captures are host paths and a
# fresh checkout has none of them; the fixtures are what the assertions below read, and
# fixture_provenance() re-derives them from the captures wherever the captures exist.
SOURCES = ([(f'43704163314-{ref}', os.path.join(SWEEP, ref, 'detect_capture', 'debug.log'))
            for ref in REFS]
           + [('43454245046-eval1', EVAL1)])
SWEEP_STEMS = [stem for stem, _ in SOURCES[:4]]
EVAL1_STEM = SOURCES[4][0]
FIXTURES = os.path.join(HERE, 'presence_fixtures')
# Not *.log: .gitignore ignores *.log repository-wide, so a fixture named that way is
# present in the working tree, absent from a fresh checkout, and the check that reads it
# passes here and fails in CI -- the exact failure mode this fixture exists to end.
INSTALLS = '.installs'
MANIFEST = os.path.join(FIXTURES, 'MANIFEST.csv')
GUIDS = os.path.join(FIXTURES, 'guids.csv')

# The 23 the binding arm selects on every ref of 43704163314, and the per-ref iteration
# totals their campaigns spent reaching nothing.
UNBOUND_23 = """EfiArp EfiBluetoothAttribute EfiBluetoothIo EfiDhcp4 EfiDhcp6 EfiDns4
EfiDns6 EfiFtp4 EfiHash EfiHttp EfiIp4 EfiIp6 EfiIsaHc EfiManagedNetwork EfiMtftp4
EfiMtftp6 EfiRestEx EfiSupplicant EfiTcp4 EfiTcp6 EfiTls EfiUdp4 EfiUdp6""".split()
# Of those 23, the ones whose service binding or child protocol IS on an install line of
# 43454245046, where PXE connected the NIC. This is the protected measurement, and it is
# fifteen protocols rather than the one (EfiTcp4's binding) the first version of this
# check asserted and the one (EfiHttp's) its report named.
BOUND_ON_EVAL1 = """EfiArp EfiDhcp4 EfiDhcp6 EfiDns4 EfiDns6 EfiHttp EfiIp4 EfiIp6
EfiManagedNetwork EfiMtftp4 EfiMtftp6 EfiTcp4 EfiTcp6 EfiUdp4 EfiUdp6""".split()
# A NULL DXE install line whose real interface is inside SMRAM: the census must answer
# smm-only. Both are on 43454245046 and on no ref of 43704163314.
SMM_SIGNALS = ['EfiSmmVariable', 'EfiSmmFaultTolerantWrite']
# A NULL DXE install line with nothing behind it anywhere: signal-only, on all five.
DXE_SIGNALS = ['EfiLockBox', 'EfiConsoleOutDevice', 'EfiVariableArch']
# Installed with a real interface on all five. EfiPciIo is the one that matters to the next
# run -- the only reachable planted defect on the tree about to be tested is in PciBusDxe's
# BAR parsing -- and EfiLoadedImage is installed on BOTH channels of 43454245046, which is
# the "installed both ways is present" rule on real evidence rather than a made-up pair.
REAL_INTERFACES = ['EfiPciIo', 'EfiLoadedImage']
REAL_PROTOCOLS = UNBOUND_23 + REAL_INTERFACES + SMM_SIGNALS + DXE_SIGNALS

SMM_VARIABLE = 'ED32D533-99E6-4209-9CC0-2D72CDD998A7'
HTTP_SB = 'BDC8E6AF-D9BC-4379-A72A-E0C4E75DAE1C'
TCP4_CHILD = '65530BC7-A359-410F-B010-5AADC7EC2B62'

MENTIONS = re.compile(rb'InstallProtocolInterface:')
ANY_GUID = re.compile(r'[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}')
IN_SMRAM_LINE = re.compile(r'(?:Smm|Mm)InstallProtocolInterface:')


def dec_line(name, guid):
    """One edk2 .dec GUID declaration, in the syntax guid_map() actually parses."""
    head, b, c, group4, tail = guid.split('-')
    octets = [group4[0:2], group4[2:4]] + [tail[i:i + 2] for i in range(0, 12, 2)]
    return (f'  {name} = {{ 0x{head}, 0x{b}, 0x{c}, '
            f'{{ {", ".join("0x" + o for o in octets)} }} }}\n')


def fake_tree(work, declared=DECLARED):
    """A tree guid_map() can read: the glob wants a top directory named edk2*."""
    package = os.path.join(work, 'edk2fake', 'FakePkg')
    os.makedirs(package, exist_ok=True)
    with open(os.path.join(package, 'FakePkg.dec'), 'w') as handle:
        handle.write('[Protocols]\n')
        for name, guid in declared:
            handle.write(dec_line(name, guid))
    return work


def distill(raw):
    """The install lines of a capture, one per distinct (spelling, guid, pointer shape).

    The census reads a capture through installed_guids() and null_interfaces() and nothing
    else. Both match one of the three install patterns line by line, and both return SETS
    keyed on the GUID plus -- for the pointer -- nothing finer than absent / zero /
    non-zero. So dropping every line that does not mention an install, and then every
    later line whose (spelling, GUIDs, pointer shape) key is already kept, is a reduction
    the census cannot observe. 2755 install lines over the five captures become 688, 49 KB
    instead of 196 KB.

    That argument is not taken on trust: fixture_provenance() re-derives all four sets
    from the capture AND from the fixture and requires them equal, wherever the captures
    are. Lines are kept byte for byte, CRLF and all, in the order the capture had them.

    The reduction may not go further than this. The assertions below include ABSENCES --
    not one of the 23 service bindings is on an install line of any ref of 43704163314 --
    and an absence is only evidence if every install line the capture had was considered.
    """
    kept, seen = [], set()
    for line in raw.replace(b'\x00', b'').splitlines(keepends=True):
        if not MENTIONS.search(line):
            continue
        text = line.decode('latin-1')
        spelling = 'smm' if IN_SMRAM_LINE.search(text) else 'dxe'
        pair = sys.modules['protocol_presence'].WITH_INTERFACE.findall(text)
        shape = 'none' if not pair else ('zero' if int(pair[0][1], 16) == 0 else 'nonzero')
        key = (spelling, tuple(g.upper() for g in ANY_GUID.findall(text)), shape)
        if key in seen:
            continue
        seen.add(key)
        kept.append(line)
    return kept


def fixture(stem):
    return os.path.join(FIXTURES, stem + INSTALLS)


def real_declared():
    """The GUID symbols the real-evidence assertions name, from the committed table.

    Resolved off the real edk2 tree by --distill, using the census's own guid_for() and
    binding_guid_for() candidate spellings, and re-derived from the tree by
    fixture_provenance() wherever the tree is checked out. Committed because the
    assertions must run in a fresh checkout whether or not a 24 GB submodule came with it.
    """
    import csv as _csv
    with open(GUIDS, newline='') as handle:
        return [(row['symbol'], row['guid']) for row in _csv.DictReader(handle)]


def censused(work, capture, protocols=PROTOCOLS):
    """Run the census as the sweep runs it and return {protocol: status}, plus stdout."""
    import contextlib
    pp = load('protocol_presence')
    evalset = os.path.join(work, 'evalset')
    os.makedirs(evalset, exist_ok=True)
    for name in protocols:
        open(os.path.join(evalset, f'{name}.txt'), 'w').write('x')
    out = os.path.join(work, 'presence.csv')
    # Removed first, because this function is called several times against one work
    # directory and a census that exits before writing would otherwise hand back the
    # PREVIOUS capture's verdicts -- a stale read that reports as a pass.
    if os.path.isfile(out):
        os.remove(out)
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


def candidate_symbols(protocol):
    """Every symbol spelling guid_for() and binding_guid_for() would try, in their order."""
    return [f'g{protocol}ProtocolGuid', f'g{protocol}Guid',
            f'g{protocol}ServiceBindingProtocolGuid', f'g{protocol}ServiceBindingGuid']


def resolve_from_tree(root):
    """{symbol: guid} for every spelling of REAL_PROTOCOLS the real tree declares."""
    pp = load('protocol_presence')
    names = pp.guid_map(os.path.abspath(root))
    return {symbol: names[symbol] for protocol in REAL_PROTOCOLS
            for symbol in candidate_symbols(protocol) if symbol in names}


def redistill(root):
    """Rebuild scripts/presence_fixtures/ from the real captures and the real tree.

    This is the whole derivation, and it is the only way the fixtures are ever written:

        python3 scripts/presence_evidence_check.py --distill [--root eval_source]

    It refuses to write anything unless every capture in SOURCES is present, so a partial
    rebuild cannot quietly replace four refs' evidence with one.
    """
    import csv as _csv
    import hashlib
    pp = load('protocol_presence')
    missing = [path for _, path in SOURCES if not os.path.isfile(path)]
    if missing:
        print('Error: --distill needs every capture it derives from; missing:')
        for path in missing:
            print(f'  {path}')
        return 1
    symbols = resolve_from_tree(root)
    unresolved = [symbol for protocol in REAL_PROTOCOLS
                  for symbol in candidate_symbols(protocol)[:2]
                  if not any(s in symbols for s in candidate_symbols(protocol))]
    if unresolved:
        print(f'Error: {root} declares no GUID for {sorted(set(unresolved))}')
        return 1
    os.makedirs(FIXTURES, exist_ok=True)
    with open(GUIDS, 'w', newline='') as handle:
        writer = _csv.writer(handle)
        writer.writerow(['symbol', 'guid'])
        for symbol in sorted(symbols):
            writer.writerow([symbol, symbols[symbol]])
    rows = [['fixture', 'source', 'source_sha256', 'source_bytes', 'install_lines',
             'kept_lines', 'real', 'null', 'unsaid', 'smram']]
    for stem, path in SOURCES:
        raw = open(path, 'rb').read()
        kept = distill(raw)
        with open(fixture(stem), 'wb') as handle:
            handle.write(b''.join(kept))
        real, null, unsaid, smram = install_lines(path)
        mine = install_lines(fixture(stem))
        if mine != (real, null, unsaid, smram):
            print(f'Error: the distillation of {path} is not equivalent to it; refusing')
            return 1
        rows.append([stem, path, hashlib.sha256(raw).hexdigest(), len(raw),
                     len(MENTIONS.findall(raw.replace(b'\x00', b''))), len(kept),
                     len(real), len(null), len(unsaid), len(smram)])
        print(f'  {stem}: {rows[-1][4]} install lines -> {len(kept)} '
              f'({os.path.getsize(fixture(stem))} bytes)')
    with open(MANIFEST, 'w', newline='') as handle:
        _csv.writer(handle).writerows(rows)
    print(f'  wrote {MANIFEST} and {GUIDS}')
    return 0


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

    print('\nthe pointer comes from the install line and from no other line')
    pp = sys.modules['protocol_presence']
    # Behavioural, on inputs, not a reading of the pattern's text. The pattern used to
    # read `\s+` between the GUID and the pointer and `\s*` after the spelling, and \s
    # MATCHES A NEWLINE, so an install line that wrapped after its GUID had the next
    # line's leading hex captured as its interface pointer -- while the comment beside it
    # claimed an anchoring the end-of-line `$` alone does not give.
    for text, what in [
            (f'InstallProtocolInterface: {DIRECT}\n7F9C1000\n',
             'a pointer-shaped run on the next line'),
            (f'InstallProtocolInterface: {DIRECT}\n0\n', 'a bare 0 on the next line'),
            (f'InstallProtocolInterface: {DIRECT}\n  DEADBEEF\n',
             'an indented hex run on the next line'),
            (f'InstallProtocolInterface: {DIRECT}\n\n7F9C1000\n',
             'a hex run two lines down'),
            (f'InstallProtocolInterface:\n{DIRECT} 7F9C1000\n',
             'a pointer on a line the GUID is not on either'),
            (f'InstallProtocolInterface: {DIRECT} 7F9C1000 failed with Invalid Parameter\n',
             'the pointer of an install edk2 reported as FAILED')]:
        got = pp.WITH_INTERFACE.findall(text)
        check(f'{what} is not this install line\'s pointer', got == [],
              f'captured {got} from {text!r} -- the whole record has to be on ONE line, '
              f'and end there')
    check('and a pointer on the same line is still read',
          pp.WITH_INTERFACE.findall(f'InstallProtocolInterface: {DIRECT} 7F9C1000\r\n')
          == [(DIRECT, '7F9C1000')],
          'the fix must not stop the census reading the line edk2 actually prints, CR '
          'and all')
    check('including a NULL one', pp.WITH_INTERFACE.findall(
        f'InstallProtocolInterface: {NULLED} 0\n') == [(NULLED, '0')])
    wrap_rc, wrap_rows, _ = censused(work, _write(work, 'wrapped.log', WRAPPED), PROTOCOLS)
    flat_rc, flat_rows, _ = censused(work, _write(work, 'unwrapped.log', UNWRAPPED),
                                     PROTOCOLS)
    check('both captures census to completion', wrap_rc == 0 and flat_rc == 0,
          f'wrapped rc={wrap_rc}, unwrapped rc={flat_rc}')
    check('the unwrapped records read as the claims they make',
          [flat_rows.get(p) for p in ('FakeDirect', 'FakeNull', 'FakeBoth',
                                      'FakeSmmSignal')]
          == ['present', 'signal-only', 'present', 'present'],
          f'{flat_rows} -- if this is wrong the pair below compares two broken readings')
    # The pair. One attribute apart, so a difference can only be the line break.
    check('wrapping an install line changes what the census may claim',
          wrap_rows != flat_rows,
          'identical verdicts mean the pointer was read across the line break, so a '
          'wrapped line is indistinguishable from the record it was wrapped out of')
    check('a wrapped install whose next line is 0 is not called a NULL install',
          wrap_rows.get('FakeNull') == 'present-unverified',
          f'got {wrap_rows.get("FakeNull")!r} -- signal-only here is a verdict about a '
          f'pointer that belongs to a different line')
    check('a wrapped install whose next line is a pointer is not called present',
          wrap_rows.get('FakeBoth') == 'present-unverified',
          f'got {wrap_rows.get("FakeBoth")!r} -- present is the one answer a line with no '
          f'pointer on it does not support')
    check('and a wrapped DXE line does not schedule an SMRAM-only protocol as DXE',
          wrap_rows.get('FakeSmmSignal') == 'smm-only',
          f'got {wrap_rows.get("FakeSmmSignal")!r} -- a borrowed pointer makes this read '
          f'present, which is the ten protocols and eleven container-hours that '
          f'presence_channel_check.py exists to prevent')

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
    # The pattern's TEXT, after the behavioural assertions above and not instead of them.
    # Each token pinned here occurs in exactly one place: the gap between the GUID and the
    # pointer. '$' alone was what this asserted before, and `\s+ ... $` passes that while
    # matching straight across a newline.
    pattern = region(psrc, 'WITH_INTERFACE = re.compile(', 're.M)')
    check('the pointer pattern is still there to read', pattern != '',
          'renamed or reflowed past the markers; the behavioural checks above are the '
          'ones that matter, but this one should be repaired, not deleted')
    check('the pointer pattern is anchored to end of line', '$' in pattern, pattern)
    check('and separated from the GUID by a gap that cannot be a newline',
          '[ \\t]+([0-9A-Fa-f]+)' in pattern,
          f'{pattern!r} -- \\s matches \\n, so the end anchor alone lets the pointer come '
          f'from the next line')
    check('with no \\s left anywhere in it', '\\s' not in pattern,
          f'{pattern!r} -- every gap in this one pattern has to exclude the line break')

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

    real_evidence()
    fixture_provenance()

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


def real_evidence():
    """The policy, decided on real install lines, in a fresh checkout.

    These were sixteen assertions guarded on run directories under /home/gl055, so CI ran
    none of them: the discriminator and the NULL-interface rule -- which together decide
    which protocols a sweep launches -- were asserted only on the machine that wrote them.
    They read the committed fixtures now, which are the install lines of the same five
    captures (see distill() and fixture_provenance()), so the evidence travels with the
    repository and the policy is decided by the same census code the sweep runs.
    """
    load('protocol_presence')
    missing = [stem for stem, _ in SOURCES if not os.path.isfile(fixture(stem))]
    if missing or not os.path.isfile(GUIDS):
        check('the committed fixtures are checked out', False,
              f'missing {missing or [GUIDS]} under {FIXTURES} -- run '
              f'`python3 scripts/presence_evidence_check.py --distill` on a host that has '
              f'the captures. Without them the policy is unasserted, which is the defect.')
        return
    declared = real_declared()
    holder = tempfile.TemporaryDirectory()
    work = fake_tree(holder.name, declared)

    print('\non the four refs of sweep 43704163314, where nothing connected the NIC')
    for stem in SWEEP_STEMS:
        path = fixture(stem)
        real, null, unsaid, smram = install_lines(path)
        rc, rows, said = censused(work, path, REAL_PROTOCOLS)
        ref = stem.split('-', 1)[1]
        check(f'{ref}: the census ran to completion', rc == 0, f'rc={rc}')
        # The 23-not-1 fix. This arm decides what a sweep launches, and it was asserted
        # against gEfiTcp4ServiceBindingProtocolGuid alone while the report said 23.
        installed = [p for p in UNBOUND_23
                     if any(guid in (real | null | unsaid | smram)
                            for guid in (binding_of(declared, p), child_of(declared, p))
                            if guid)]
        check(f'{ref}: not one of the 23 service bindings is on an install line',
              installed == [],
              f'{installed} -- if any is installed this ref bound its driver and those '
              f'campaigns were not a wasted fifth of the run')
        check(f'{ref}: nor is any of the 23 child protocols',
              not [p for p in UNBOUND_23
                   if (child_of(declared, p) or '') in (real | null | unsaid | smram)],
              'the arm is only absent because NEITHER guid was installed')
        wrong = {p: rows.get(p) for p in UNBOUND_23 if rows.get(p) != 'absent'}
        check(f'{ref}: so the census calls all 23 absent', not wrong,
              f'{wrong} -- unknown is never skipped, which is the 36173 to 41262 '
              f'iterations per ref each of them spent on harness startup')
        check(f'{ref}: it does install NULL-only signals, so the rule has work',
              len(null) == 15, f'{len(null)} NULL-only guids, expected 15')
        check(f'{ref}: and every install line records its pointer', unsaid == set(),
              f'{len(unsaid)} guid(s) with no pointer -- present-unverified is reported '
              f'for exactly this and must stay rare')
        bad = {p: rows.get(p) for p in DXE_SIGNALS if rows.get(p) != 'signal-only'}
        check(f'{ref}: a NULL interface reads signal-only, not present', not bad,
              f'{bad} -- these are real install lines carrying pointer 0')
        bad = {p: rows.get(p) for p in REAL_INTERFACES if rows.get(p) != 'present'}
        check(f'{ref}: and a real interface still reads present', not bad,
              f'{bad} -- EfiPciIo is the one the next run needs, and a rule that calls '
              f'it anything but present costs the only reachable planted defect there')
        check(f'{ref}: the run names the 23 rather than only counting them',
              'EfiTcp4' in said and 'nothing connected their controller' in said, said)

    print('\nand on 43454245046, where PXE connected the NIC')
    path = fixture(EVAL1_STEM)
    real, null, unsaid, smram = install_lines(path)
    rc, rows, said = censused(work, path, REAL_PROTOCOLS)
    check('the census ran to completion', rc == 0, f'rc={rc}')
    check('the protected case is present by its service binding', HTTP_SB in real,
          'gEfiHttpServiceBindingProtocolGuid -- EfiHttp reads present off this line, '
          'which is why the arm above can be absent')
    check('and EfiTcp4 by its own child guid', TCP4_CHILD in real)
    got = sorted(p for p in UNBOUND_23 if rows.get(p) == 'present')
    check('all fifteen of the 23 whose driver bound here read present',
          got == sorted(BOUND_ON_EVAL1),
          f'got {got}\n         want {sorted(BOUND_ON_EVAL1)} -- the discriminator is the '
          f'install line, so both directions have to hold on real evidence, and this '
          f'half was asserted against one binding guid while the report claimed 23')
    rest = sorted(set(UNBOUND_23) - set(BOUND_ON_EVAL1))
    wrong = {p: rows.get(p) for p in rest if rows.get(p) != 'absent'}
    check('and the other eight, whose driver did not bind even here, read absent',
          not wrong, f'{wrong} -- {rest}')
    check('gEfiSmmVariableProtocolGuid is a NULL signal in the DXE database',
          SMM_VARIABLE in null,
          'if it is not, this capture cannot demonstrate the defect and the real '
          'interface question is untested')
    check('its real interface is inside SMRAM, so it is not absent',
          SMM_VARIABLE in smram,
          'smm-only is only the right answer while the SMM core installs it')
    bad = {p: rows.get(p) for p in SMM_SIGNALS if rows.get(p) != 'smm-only'}
    check('so the census answers smm-only for both NULL signals backed by SMRAM', not bad,
          f'{bad} -- signal-only would lose the channel that does reach them, present is '
          f'the defect, absent is false')
    bad = {p: rows.get(p) for p in DXE_SIGNALS if rows.get(p) != 'signal-only'}
    check('and signal-only for the ones backed by nothing', not bad, f'{bad}')
    bad = {p: rows.get(p) for p in REAL_INTERFACES if rows.get(p) != 'present'}
    check('a real interface reads present, on both channels or one', not bad,
          f'{bad} -- gEfiLoadedImageProtocolGuid is installed in DXE AND inside SMRAM '
          f'here, which is the "one NULL signal does not unmake a real install" rule on '
          f'evidence rather than on a fixture somebody wrote')
    check('every install line here records its pointer too', unsaid == set(),
          f'{len(unsaid)} guid(s) with no pointer')


def binding_of(declared, protocol):
    table = dict(declared)
    for candidate in (f'g{protocol}ServiceBindingProtocolGuid',
                      f'g{protocol}ServiceBindingGuid'):
        if candidate in table:
            return table[candidate]
    return None


def child_of(declared, protocol):
    table = dict(declared)
    for candidate in (f'g{protocol}ProtocolGuid', f'g{protocol}Guid'):
        if candidate in table:
            return table[candidate]
    return None


def fixture_provenance():
    """The fixtures ARE the captures, re-derived -- asserted where the captures are.

    This is the half that cannot run in a fresh checkout, and it is the right half to
    guard: it asks whether the committed evidence is still the real evidence, which is a
    question only a host holding the captures can answer. What a fresh checkout runs is
    the policy, above. If a fixture were ever hand-edited to make an assertion pass, this
    is what fails, here, where the captures are.
    """
    import csv as _csv
    import hashlib
    if not os.path.isfile(MANIFEST):
        check('the fixture manifest is committed', False, MANIFEST)
        return
    print('\nthe fixtures are the captures, distilled (host-only: it needs the captures)')
    load('protocol_presence')
    manifest = {row['fixture']: row for row in _csv.DictReader(open(MANIFEST, newline=''))}
    check('the manifest names every fixture the assertions read',
          sorted(manifest) == sorted(stem for stem, _ in SOURCES),
          f'{sorted(manifest)}')
    for stem, path in SOURCES:
        if not os.path.isfile(path):
            print(f'  [skip] {path} is not on this host')
            continue
        raw = open(path, 'rb').read()
        row = manifest.get(stem, {})
        check(f'{stem}: the capture is the one it was derived from',
              row.get('source') == path
              and row.get('source_sha256') == hashlib.sha256(raw).hexdigest(),
              f'the manifest records {row.get("source_sha256")} for {row.get("source")}')
        check(f'{stem}: re-distilling the capture reproduces the fixture byte for byte',
              b''.join(distill(raw)) == open(fixture(stem), 'rb').read(),
              'a fixture nobody can regenerate is a hand-written one')
        check(f'{stem}: and the census reads the same four sets from either',
              install_lines(path) == install_lines(fixture(stem)),
              'the reduction keeps one line per (spelling, guid, pointer shape) because '
              'the census cannot see a finer distinction -- if it ever can, this fails')
    root = os.path.join(HERE, '..', 'eval_source')
    if os.path.isdir(os.path.join(root, 'edk2', 'MdePkg')):
        resolved = resolve_from_tree(root)
        check('the committed GUID table is what the real tree declares',
              resolved == dict(real_declared()),
              'guids.csv is resolved by --distill with the census\'s own candidate '
              'spellings; a GUID that drifted makes every verdict above meaningless')
    else:
        print(f'  [skip] {root}/edk2 is not checked out, so the GUID table is not '
              f're-resolved here')


if __name__ == '__main__':
    if '--distill' in sys.argv:
        where = sys.argv.index('--root') + 1 if '--root' in sys.argv else None
        sys.exit(redistill(sys.argv[where] if where else
                           os.path.join(HERE, '..', 'eval_source')))
    sys.exit(main())
