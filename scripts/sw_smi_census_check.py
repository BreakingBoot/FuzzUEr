#!/usr/bin/env python3
"""Assert the software SMI census counts registrations, and says so when it counts none.

Two separate failures, and the second one hid the first.

**The census was keyed by handler name.** A handler name is not unique across an edk2
tree: SecurityPkg registers `PhysicalPresenceCallback` from `Tcg/Tcg2Smm/Tcg2Smm.c` and
again from `Tcg/TcgSmm/TcgSmm.c`, and `MemoryClearCallback` from both as well. A dict
keyed by name keeps one of each pair, so `/home/gl055/eval-trees/eval1_edk2` reported five
registrations where it has seven and `edk2-master` reported four where it has five -- and
each kept entry was cited to whichever of the two files `os.walk` reached first, which is
how one census came back naming `MemoryClearCallback` in TcgSmm.c and
`PhysicalPresenceCallback` in Tcg2Smm.c off the same scan of the same tree. The number
this channel is judged by was wrong in the direction that flatters it.

**And an empty channel was invisible.** Upstream `OvmfPkgX64.dsc` builds no producer of
`EFI_SMM_SW_DISPATCH2_PROTOCOL` at all -- the only one in edk2 is
`UefiPayloadPkg/PchSmiDispatchSmm`, which that platform does not include -- so every tree
but EVAL-1 has nothing addressable here. Discovery wrote no request file for those, which
is right: the batch makes a campaign out of every `.txt` in the request directory, so an
empty list costs a container, an analysis and a build. But an absent file is also exactly
what a discovery that never ran leaves behind, so a run that fuzzed this channel and a run
that could not read the same. `DiscoveredSwSmi.txt` has never been written on any tree on
this machine, and no `presence.csv` of the 79 here mentions the channel at all; nothing in
any of those runs says why.

So: a verdict line goes out either way, counted in registrations and not in names, and the
empty case leaves a `DiscoveredSwSmi.absent` note carrying that line and a reason per
registration. Not a `.txt`, because that directory is a target list.

The last thing asserted here is the one that costs a guest. A name claimed by two
registrations at two DIFFERENT command bytes is dropped rather than resolved to either:
port 0xB2 is shared with the platform, command 0x04 is `ICH9_APM_CNT_CPU_HOTPLUG`, and a
byte aimed at the wrong handler buys no coverage to weigh against that.

Every verdict here is driven -- the real discovery pass over fixture trees, the real
`fuzz_batch.request_targets` over the note -- and the fixture pairs differ in one
attribute each, so an implementation that reads the file names or the handler names rather
than the registrations fails them.

Run: python3 scripts/sw_smi_census_check.py
"""
import importlib.util
import io
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

FAILED = PASSED = 0

# The fixture's registered bytes. Deliberately not 0xB4: a check written against the value
# the EVAL-1 tree uses passes just as well on a pass that hardcodes it.
ALPHA_VALUE = 0x70
BETA_VALUE = 0x55


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

    Not optional here. The docstring of the pass under test names the two files that
    register one handler name twice, writes out the count it has to produce, and spells
    `.absent` twice; the comments name the port and the reason. Reading the raw text finds
    the explanation rather than the statement, and passes with the statement deleted.
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


# One driver registering on the software dispatch protocol, in the shape every tree writes
# it in. `{init}` is the only hole a fixture pair needs to differ in.
DRIVER = '''/** @file
  A fixture driver. Nothing here is compiled; it is scanned.
**/
{defines}

EFI_STATUS
EFIAPI
{handler} (
  IN EFI_HANDLE  DispatchHandle,
  IN CONST VOID  *Context
  )
{{
  return EFI_SUCCESS;
}}

EFI_STATUS
EFIAPI
FixtureEntryPoint (
  IN EFI_HANDLE  ImageHandle
  )
{{
  EFI_STATUS                     Status;
  EFI_SMM_SW_DISPATCH2_PROTOCOL  *SwDispatch;
  EFI_SMM_SW_REGISTER_CONTEXT    SwContext;
  EFI_HANDLE                     SwHandle;

  SwContext.SwSmiInputValue = {init};
  Status                    = SwDispatch->Register (SwDispatch, {handler}, &SwContext, &SwHandle);
  return Status;
}}
'''

# Two registrations in ONE file, off one context variable, as Tcg2Smm writes them. The
# textual order is the order the scan finds them in, which is what makes the ordering
# assertion below deterministic rather than a property of the filesystem.
TWO_IN_ONE = '''/** @file
  A fixture driver registering twice, {first} before {second}.
**/

EFI_STATUS
EFIAPI
FixtureEntryPoint (
  IN EFI_HANDLE  ImageHandle
  )
{{
  EFI_STATUS                     Status;
  EFI_SMM_SW_DISPATCH2_PROTOCOL  *SwDispatch;
  EFI_SMM_SW_REGISTER_CONTEXT    SwContext;
  EFI_HANDLE                     SwHandle;

  SwContext.SwSmiInputValue = (UINTN)-1;
  Status                    = SwDispatch->Register (SwDispatch, {first}, &SwContext, &SwHandle);
  SwContext.SwSmiInputValue = (UINTN)-1;
  Status                    = SwDispatch->Register (SwDispatch, {second}, &SwContext, &SwHandle);
  return Status;
}}
'''


def tree(*drivers):
    """A fixture source tree: one package directory per driver, each with one .c file."""
    root = tempfile.mkdtemp(prefix='swsmi-census-')
    for package, name, text in drivers:
        where = os.path.join(root, package)
        os.makedirs(where, exist_ok=True)
        io.open(os.path.join(where, name), 'w', encoding='utf-8').write(text)
    return root


def driver(handler, init, defines=''):
    return DRIVER.format(handler=handler, init=init, defines=defines)


def run(discover, root, work):
    """write_sw_smi against a fresh output directory: (stdout, request text, note text)."""
    out = tempfile.mkdtemp(prefix='swsmi-out-', dir=work)
    request = os.path.join(out, 'DiscoveredSwSmi.txt')
    note = os.path.join(out, 'DiscoveredSwSmi.absent')
    said = io.StringIO()
    stdout, sys.stdout = sys.stdout, said
    try:
        discover.write_sw_smi(root, request)
    finally:
        sys.stdout = stdout
    return (said.getvalue(),
            io.open(request, encoding='utf-8').read() if os.path.isfile(request) else None,
            io.open(note, encoding='utf-8').read() if os.path.isfile(note) else None)


def verdict(said):
    """The one line a reader greps for, or '' if the pass printed none."""
    for line in said.splitlines():
        if line.startswith('software SMI channel:'):
            return line
    return ''


def counted(said):
    """(addressable, registrations) off the verdict line, or (None, None)."""
    found = re.search(r'software SMI channel: (\d+) of (\d+) registration', said)
    return (int(found.group(1)), int(found.group(2))) if found else (None, None)


def main():
    discover = load('discover_smi')
    batch = load('fuzz_batch')
    edk2 = load('fuzz_edk2')
    work = tempfile.mkdtemp(prefix='swsmi-census-work-')
    trees = []

    def fixture(*drivers):
        root = tree(*drivers)
        trees.append(root)
        return root

    # The pair differs in the initialiser and in nothing else: same package, same file
    # name, same handler name, same Register call.
    literal = fixture(('AlphaPkg', 'Alpha.c',
                       driver('AlphaCallback', 'ALPHA_SWSMI',
                              f'#define ALPHA_SWSMI  0x{ALPHA_VALUE:02X}')))
    runtime = fixture(('AlphaPkg', 'Alpha.c', driver('AlphaCallback', '(UINTN)-1')))

    print('a registration with a constant is a target, and is counted as one registration')
    said, request, note = run(discover, literal, work)
    check('the verdict line is printed', verdict(said) != '',
          f'{said!r} -- a run with no such line cannot be told from one that never '
          f'reached discovery')
    check('it counts one of one registration addressable', counted(said) == (1, 1),
          f'{verdict(said)}')
    check('the request file names the handler at the byte its #define carries',
          request is not None and request.split()[:2] == ['AlphaCallback',
                                                          f'0x{ALPHA_VALUE:02X}'],
          f'{request!r} -- nothing in the pipeline may assume the 0xB4 EVAL-1 happens '
          f'to use')
    check('and no absence note is left beside it', note is None,
          f'{note!r} -- a note carried over from a tree with no software SMI says the '
          f'channel is empty while the file beside it names a target')

    print('\nand the same registration asking the dispatcher for one is counted too')
    said, request, note = run(discover, runtime, work)
    check('the verdict counts zero of one, not nothing of nothing',
          counted(said) == (0, 1), f'{verdict(said)}')
    check('it says EMPTY in the line itself', 'EMPTY' in verdict(said),
          f'{verdict(said)} -- the count alone reads as a channel nobody looked at')
    check('no request file is written', request is None,
          'the batch makes a campaign out of every .txt in that directory')
    check('the absence note is written instead', note is not None,
          'an absent file is also what a discovery that never ran leaves behind')
    check('and the note carries the verdict and the reason',
          note is not None and 'EMPTY' in note.splitlines()[0]
          and discover.RUNTIME_REASON in note,
          f'{note!r}')
    check('the reason is the run-time assignment, named where the reader will look',
          discover.RUNTIME_REASON in said
          and 'assigns the command byte at run time' in discover.RUNTIME_REASON,
          f'{said!r} -- the empty case used to print the citation with no reason at all, '
          f'which is the one case where the reason is the whole answer')

    # This pair differs in the SECOND driver's handler name and in nothing else: same two
    # packages, same two file names, same (UINTN)-1 initialiser in both.
    one_name = fixture(('AlphaPkg', 'Alpha.c', driver('AlphaCallback', '(UINTN)-1')),
                       ('BetaPkg', 'Beta.c', driver('AlphaCallback', '(UINTN)-1')))
    two_names = fixture(('AlphaPkg', 'Alpha.c', driver('AlphaCallback', '(UINTN)-1')),
                        ('BetaPkg', 'Beta.c', driver('BetaCallback', '(UINTN)-1')))

    print('\ntwo registrations are two registrations, named alike or not')
    alike, _, alike_note = run(discover, one_name, work)
    apart, _, _ = run(discover, two_names, work)
    check('two drivers under one handler name count two',
          counted(alike) == (0, 2),
          f'{verdict(alike)} -- a census keyed by name reports one here, and that is '
          f'how eval1_edk2\'s seven registrations were reported as five')
    check('two drivers under two names count two as well',
          counted(apart) == (0, 2), f'{verdict(apart)}')
    check('the two are counted the same, which is the point',
          counted(alike) == counted(apart),
          f'{verdict(alike)} / {verdict(apart)} -- the pair differs only in the second '
          f'handler\'s name, so a count that differs is counting names')
    check('and the shared name says how many places claim it, so the lines add up',
          'other place(s)' in alike and 'other place(s)' not in apart,
          f'{alike!r} -- four lines under a count of five is arithmetic a reader cannot '
          f'check')
    check('the note carries the registration count too', alike_note is not None
          and counted(alike_note) == (0, 2), f'{alike_note!r}')

    print('\nthe registration list is ordered by what it found, not by what os.walk did')
    ordered = fixture(('AlphaPkg', 'Alpha.c',
                       TWO_IN_ONE.format(first='ZuluCallback', second='AlphaCallback')))
    sites = discover.sw_smi_registrations(ordered)
    check('both registrations in one file are found', len(sites) == 2, f'{sites}')
    check('and come back sorted, so two runs cite the same place',
          [site[:3] for site in sites] == sorted(site[:3] for site in sites),
          f'{[site[0] for site in sites]} -- the file registers ZuluCallback first, so an '
          f'unsorted pass returns them in that order and the citation a census prints '
          f'depends on which driver the walk reached first')

    # This pair differs in the second driver's constant and in nothing else.
    clash = fixture(('AlphaPkg', 'Alpha.c',
                     driver('AlphaCallback', f'0x{ALPHA_VALUE:02X}')),
                    ('BetaPkg', 'Beta.c',
                     driver('AlphaCallback', f'0x{BETA_VALUE:02X}')))
    agree = fixture(('AlphaPkg', 'Alpha.c',
                     driver('AlphaCallback', f'0x{ALPHA_VALUE:02X}')),
                    ('BetaPkg', 'Beta.c',
                     driver('AlphaCallback', f'0x{ALPHA_VALUE:02X}')))

    print('\none name at two different bytes is dropped, not resolved to either')
    said, request, note = run(discover, clash, work)
    check('it is not a target', request is None,
          f'{request!r} -- either byte would be written against the other '
          f'registration\'s handler, and on port 0xB2 command 0x04 reaches CpuHotplugSmm')
    check('it is reported unaddressable rather than dropped silently',
          'not addressable: AlphaCallback' in said, f'{said!r}')
    check('for the clash, not for the run-time assignment it does not have',
          discover.CLASH_REASON in said and discover.RUNTIME_REASON not in said,
          f'{said!r} -- "the dispatcher assigns it at run time" is false here and sends '
          f'the reader to the wrong file')
    check('and both registrations are still counted', counted(said) == (0, 2),
          f'{verdict(said)}')
    check('the channel is empty on that tree, and says so', note is not None,
          f'{note!r}')
    said, request, note = run(discover, agree, work)
    check('two registrations that agree on the byte are a target',
          request is not None and request.split()[:2] == ['AlphaCallback',
                                                          f'0x{ALPHA_VALUE:02X}'],
          f'{request!r} -- the pair differs only in the second constant, so refusing '
          f'this one refuses every duplicated name rather than the ambiguous ones')
    check('counted as the two registrations it is', counted(said) == (1, 2),
          f'{verdict(said)}')

    print('\na carried file or note from another tree does not survive this one')
    out = tempfile.mkdtemp(prefix='swsmi-stale-', dir=work)
    request = os.path.join(out, 'DiscoveredSwSmi.txt')
    note = os.path.join(out, 'DiscoveredSwSmi.absent')
    io.open(note, 'w', encoding='utf-8').write('software SMI channel: 0 of 4 -- EMPTY\n')
    said = io.StringIO()
    stdout, sys.stdout = sys.stdout, said
    try:
        discover.write_sw_smi(literal, request)
    finally:
        sys.stdout = stdout
    check('a note from a tree with no software SMI is removed when this one has a target',
          not os.path.exists(note) and os.path.isfile(request),
          f'note={os.path.exists(note)} request={os.path.isfile(request)} -- it would '
          f'otherwise say the channel is empty beside the file that names the target')
    check('and the removal is said out loud', 'removed' in said.getvalue(),
          f'{said.getvalue()!r}')
    io.open(request, 'w', encoding='utf-8').write('Carried  0xB4  // from another tree\n')
    said = io.StringIO()
    stdout, sys.stdout = sys.stdout, said
    try:
        discover.write_sw_smi(runtime, request)
    finally:
        sys.stdout = stdout
    check('and a carried request file is removed when this tree has nothing to aim at',
          not os.path.exists(request) and os.path.isfile(note),
          f'request={os.path.exists(request)} note={os.path.isfile(note)} -- a stale one '
          f'aims this tree\'s campaign at another tree\'s command bytes')

    print('\nthe note is a statement, and no part of the pipeline reads it as a target')
    only_note = tempfile.mkdtemp(prefix='swsmi-note-', dir=work)
    io.open(os.path.join(only_note, 'DiscoveredSwSmi.absent'), 'w',
            encoding='utf-8').write('software SMI channel: 0 of 4 -- EMPTY\n')
    io.open(os.path.join(only_note, 'EfiAcpiTable.txt'), 'w', encoding='utf-8').write('x\n')
    offered = batch.request_targets(only_note)
    check('fuzz_batch offers no handler channel target for it',
          offered[batch.HANDLER_CHANNEL] == [], f'{offered}')
    check('and still offers the protocol beside it',
          offered[batch.PROTOCOL_CHANNEL] == ['EfiAcpiTable'], f'{offered}')
    check('fuzz_edk2 does not pick it either',
          edk2.SW_SMI_TARGET not in edk2.pick_targets(only_note, 4, True),
          f'{edk2.pick_targets(only_note, 4, True)} -- naming a target whose request file '
          f'is missing costs a container and a full analysis to discover')
    check('because the suffix is not the one that directory is a target list of',
          discover.ABSENT_SUFFIX != '.txt' and not discover.ABSENT_SUFFIX.endswith('.txt'),
          f'{discover.ABSENT_SUFFIX}')

    print('\nand a run says which of the three it was, under --smi or not')
    stage = tempfile.mkdtemp(prefix='swsmi-stage-', dir=work)
    asked = os.path.join(stage, 'DiscoveredSwSmi.txt')
    silent = edk2.sw_smi_clause(asked, 0)
    check('neither a list nor a note is its own answer, not the empty one',
          'never looked at' in silent and 'EMPTY' not in silent,
          f'{silent!r} -- reporting that as an empty channel is the claim this cannot '
          f'support: it is also what a discovery that did not run leaves behind')
    said, _, note = run(discover, runtime, work)
    # `or ''` and a stand-in first line, not note.splitlines()[0]: the mutation that stops
    # the note being written is one of the most important here, and indexing into it made
    # the check die on exactly that one. A traceback is not a failed assertion -- nothing
    # reading the exit code can tell the two apart.
    io.open(os.path.join(stage, 'DiscoveredSwSmi.absent'), 'w',
            encoding='utf-8').write(note or '')
    empty = edk2.sw_smi_clause(asked, 0)
    first = note.splitlines()[0] if note else '(discovery wrote no note)'
    check('the note discovery wrote is what the stage reports, not a second wording',
          empty == first, f'{empty!r} vs {first!r} -- two sentences for one fact drift, '
          f'and the stage has no census of its own')
    check('and it carries the count and the verdict', counted(empty) == (0, 1)
          and 'EMPTY' in empty, f'{empty!r}')
    io.open(asked, 'w', encoding='utf-8').write('AlphaCallback  0x70  // x\n')
    full = edk2.sw_smi_clause(asked, 1)
    check('a tree with a target reports that instead',
          'DiscoveredSwSmi target' in full and 'EMPTY' not in full, f'{full!r}')
    check('the three answers are three different sentences',
          len({silent, empty, full}) == 3, f'{(silent, empty, full)}')
    esrc = code(source('fuzz_edk2'))
    check('the clause goes out on the run that does not pass --smi as well',
          esrc.count('sw_smi_clause(swsmi, sw_handlers)') == 2,
          f'{esrc.count("sw_smi_clause(swsmi, sw_handlers)")} call(s) -- it lived in the '
          f'--smi branch alone, and across the 86 pipeline.log files on this machine not '
          f'one printed a word about this channel')
    check('and the one without --smi still says the handlers are not fuzzed',
          "(not fuzzed; pass --smi). {sw_smi_clause" in esrc,
          'the count alone reads as though they were targets')

    print('\nand the code says why, where the next reader will be standing')
    dsrc = code(source('discover_smi'))
    check('the note path is derived from the request path, not spelled twice',
          'os.path.splitext(output)[0] + ABSENT_SUFFIX' in dsrc,
          'a second literal drifts from the first and the note lands beside nothing')
    check('the census counts the registration list, not the resolved names',
          'len(sites)' in dsrc and 'len(found)} of {len(sites)}' in dsrc,
          'len(unresolved) + len(found) is the name count, which is the defect')
    check('the sorted registration list is what the resolution reads',
          before(dsrc, 'def sw_smi_registrations', 'def _resolve')
          and '_resolve(sw_smi_registrations(root))' in dsrc,
          'a second, unsorted walk inside discover_sw_smi would disagree with the census '
          'printed beside it')
    bsrc = code(source('fuzz_batch'))
    check('and the batch really does take every .txt in that directory as a target',
          "if not name.endswith('.txt')" in bsrc,
          'which is the whole reason the note cannot be one')

    for path in trees + [work]:
        shutil.rmtree(path, ignore_errors=True)
    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
