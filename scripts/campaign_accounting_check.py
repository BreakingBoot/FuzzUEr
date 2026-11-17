#!/usr/bin/env python3
"""Assert a run counts the campaigns it launched, and does not credit the harness's own faults.

Three things measured on run 43454245046, a 138-campaign sweep, and all three of them
were a number or a sentence that read as a result and was not one.

  1. The fuzz stage reported

         [PASS] fuzz  66/263 campaign(s) fuzzed the harness (3922229 iteration(s)) ...

     and 138 campaigns ran. 263 is every protocol the discover stage found; 125 of them
     were skipped before launch, because this firmware does not install them or installs
     them inside SMRAM, and fuzz_batch.py recorded each one in campaigns/skipped.csv.
     125 + 138 = 263. So the headline halved a run that reached 66 of 138, and worse, it
     could not be compared with any other run either: the gap between the two numbers
     moves with the presence census rather than with the fuzzing, so two sweeps of the
     same tree differ in that ratio for reasons that have nothing to do with the fuzzer.

     The fix is the LAUNCHED count as the denominator, read out of fuzz_batch's own
     summary line rather than recomputed -- recomputing it means reproducing the presence
     filter, the already-done filter and the launch failures in a second place. Both
     other numbers stay in the line, because 66/138 alone cannot be told apart on a
     263-protocol tree and on a 138-protocol one, and that difference is the census.

  2. EfiCpuIo2 produced `CpuIo2Dxe+0x5296 cpu-exception (#DE)`, triaged as a severity 4
     candidate in firmware code. Nothing in CpuIo2Dxe divides. What the campaign was
     doing is in its own generated harness: it picks between ProtocolVariable->Mem.Write
     and ProtocolVariable->Io.Write at random, and bounds the Address argument with
     `Write_Arg_2 = Write_Arg_2 % (4096 + 1)` -- so half the iterations write fuzzer
     bytes into the low 4096 I/O ports, where this platform keeps the PIC (0x20/0xA0),
     the PIT (0x40-0x43), the keyboard controller (0x60/0x64) and the CMOS/RTC index and
     data ports (0x70/0x71).

     That campaign managed 111 iterations of a 1800s budget -- 0.065 exec/s -- its client
     stopped reporting executions at 1h39m and reported none for the remaining 27
     minutes. A campaign that bricks its own guest spends its budget and reports nothing,
     and then files an issue against a driver that did as it was asked.

     Two of that sweep's 138 harnesses name an I/O port accessor, EfiCpuIo2 and
     EfiMmCpuIo. The run reads that off the harness each campaign actually built and
     reports the cpu-exception in bugs.json's own `filtered.harness` bucket with its
     reason rather than among the candidates, which is where file_issues.py stops seeing
     it. Keeping the harness from driving those ports at all belongs to the generator;
     this is the half that stops the fault being reported as a finding.

     The classification itself is bug_report.py's, made where that report is written. It
     was done on the host afterwards for a while instead, which reopened a file a
     container had just written as root and cost run 43704163314 all four of its refs --
     scripts/container_write_check.py is that assertion's home. What is asserted here is
     this run's own verdict line: the count it prints, and the candidates left after the
     move.

  3. scripts/smi_coverage_check.py lifts a region of analyze_smi.py into an isolated
     namespace and execs it. The names that region needs were a hand-maintained list, so
     any new module-level helper in analyze_smi.py made a lifted body raise NameError at
     call time -- which arrives as a traceback with no verdict after it. Twice this week
     the battery went red for that, and a check that goes red for its own plumbing is one
     people learn to skip. What a region needs is now derived; what cannot be derived is
     named, with the instruction to add it.

Fixtures throughout, so this runs on a machine that has never fuzzed anything. Run
43454245046 is asserted against as well where it is still on disk, and skipped with a
note where it is not -- an evidence directory that was cleaned up is not a defect in the
driver, and failing over it is the mistake this file is partly about.

Run: python3 scripts/campaign_accounting_check.py
"""

import ast
import builtins
import io
import json
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# Lifted, not restated: fuzz_edk2's own readers of the two recorded facts, and its own
# detail line. A copy of either here would keep passing after the real one changed.
from fuzz_edk2 import launched_campaigns, skipped_before_launch   # noqa: E402
# The harness reader and the predicate moved to the file that writes the report, which is
# the only process that may write it. Imported from there so this cannot keep asserting
# against a copy fuzz_edk2 no longer has.
import bug_report as br                                           # noqa: E402
from bug_report import io_port_artefact, io_port_drivers, io_port_harness  # noqa: E402
# smi_coverage_check owns the lift under test. Importing it runs its module-level work
# (a sys.path insert and a vendor_types import), which is cheap and has no side effects
# on this check.
import smi_coverage_check                                          # noqa: E402
from smi_coverage_check import LiftError, needs                    # noqa: E402

# The sweep this is all measured on. Optional: see the docstring.
EVIDENCE = os.environ.get('FUZZUER_EVIDENCE_RUN',
                          '/home/gl055/fuzzuer-eval1/43454245046')

FAILED = PASSED = 0


def check(what, ok, detail=''):
    global FAILED, PASSED
    if ok:
        PASSED += 1
        print(f'  [OK]   {what}')
    else:
        FAILED += 1
        print(f'  [FAIL] {what}' + (f'\n         {detail}' if detail else ''))


def source(name):
    return io.open(os.path.join(HERE, f'{name}.py'), encoding='utf-8').read()


def code(text):
    """A region with its prose removed -- docstrings and comments both.

    Asserting on raw text whose comments explain the defect finds the defect's name in
    the explanation rather than in the statements. This project has been caught by that
    twice: own_code_check counted a comment quoting a section header, and an SMI check
    passed because a comment mentioned the shrink branch.
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


def region(name, opens, closes):
    """The source text between two anchors, or None if either has moved.

    None rather than an exception on purpose, and the reason is the subject of this file:
    a check that dies on a missing anchor reports a traceback and no verdict, and a naive
    mutation harness then credits the traceback as a catch.
    """
    text = source(name)
    start = text.find(opens)
    end = text.find(closes, start + 1) if start >= 0 else -1
    return None if start < 0 or end < 0 else text[start:end]


def bucket(found, kind='harness'):
    """bugs.json's filtered bucket, for a report that may not have one.

    Tolerant on purpose: a `found` that came back empty means the anchor moved, and every
    assertion below should then fail with a verdict rather than this file ending on a
    KeyError.
    """
    return ((found or {}).get('filtered') or {}).get(kind) or []


def assigned_from(name, function):
    """Every name read on the right of an assignment to `name`, inside `function`.

    By AST and not by substring, because the question is what the stage DIVIDES BY, and
    `planned = discovered` is a one-word edit that leaves every string in the file intact
    -- a mutation of exactly that shape went uncaught until this was written.
    """
    tree = ast.parse(source('fuzz_edk2'))
    for node in ast.walk(tree):
        if not (isinstance(node, ast.FunctionDef) and node.name == function):
            continue
        out = set()
        for inner in ast.walk(node):
            if (isinstance(inner, ast.Assign)
                    and any(getattr(t, 'id', None) == name for t in inner.targets)):
                out |= {n.id for n in ast.walk(inner.value)
                        if isinstance(n, ast.Name)}
                out |= {f'{n.value.id}.{n.attr}' for n in ast.walk(inner.value)
                        if isinstance(n, ast.Attribute)
                        and isinstance(n.value, ast.Name)}
        return out
    return None


def as_function(body, indent=8):
    """A lifted stage region, wrapped so its `return` and its locals work."""
    return ('def _run():\n'
            + '\n'.join('    ' + line[indent:] for line in body.splitlines()))


DETAIL_OPENS = "        detail = (f'{fuzzed}/{planned} campaign(s) fuzzed"
DETAIL_CLOSES = '        # Did the guest ever see its testcase?'

TRIAGE_OPENS = "        artefacts = [a for a in ((("
TRIAGE_CLOSES = '\n    def reuse():'

EMPTY = dict(fuzzed=0, planned=0, iterations=0, stability=[], absent=[], stuck=[],
             silent=[], unlocatable=[], unlocated_runs=0,
             discovered=0, skipped=0, launch_failed=0)


def detail_line(**state):
    """fuzz_edk2's headline line and its not-fuzzed verdict, lifted and evaluated."""
    found = region('fuzz_edk2', DETAIL_OPENS, DETAIL_CLOSES)
    if found is None:
        return None, '<fuzz_edk2 no longer builds its detail line here>'
    names = dict(EMPTY, **state)
    exec(as_function(found) + '\n    return None, detail\n', names)
    return names['_run']()


def triage_line(found, read=1, image_tag='img:latest'):
    """fuzz_edk2's triage verdict, lifted and run over a report bug_report has written.

    Over the report and not over a path: the stage reads this file and never opens it for
    writing, and handing the lift a filename would let a rewrite come back unnoticed.
    """
    body = region('fuzz_edk2', TRIAGE_OPENS, TRIAGE_CLOSES)
    if body is None:
        return None, '<fuzz_edk2 no longer builds its triage verdict here>'
    names = {'found': found, 'read': read, 'image_tag': image_tag}
    exec(as_function(body) + '\n', names)
    return names['_run']()


# ---------------------------------------------------------------- fixtures

LAUNCH_LOG = """  263 target(s) from /w/evalset
Skipping 125 protocol(s) this firmware does not install: AndroidBootImg, ArmScmiBase...
138 protocol(s) to fuzz, 8 at a time, 1800s each
  started AbsolutePointer (1 launched, 137 queued)
  started Pcd (138 launched, 0 queued)

launched 138, failed to launch 0
summarise with: python3 /w/scripts/coverage_matrix.py -r /out/campaigns
"""

# The member-choice switch the generator emits for a protocol whose accessors reach I/O
# port space, copied from run 43454245046's EfiCpuIo2 harness -- the bound on the Address
# argument included, because that is what puts the fuzzer inside the legacy I/O page.
IO_HARNESS = """
    Read_Arg_2 = Read_Arg_2 % (4096 + 1);
    EFI_CPU_IO_PROTOCOL_IO_MEM Read_Member = ProtocolVariable->Mem.Read;
    switch(Read_MemberChoice % 2) {
        case 0: Read_Member = ProtocolVariable->Mem.Read; break;
        case 1: Read_Member = ProtocolVariable->Io.Read; break;
    }
    Write_Arg_2 = Write_Arg_2 % (4096 + 1);
    EFI_CPU_IO_PROTOCOL_IO_MEM Write_Member = ProtocolVariable->Mem.Write;
    switch(Write_MemberChoice % 2) {
        case 0: Write_Member = ProtocolVariable->Mem.Write; break;
        case 1: Write_Member = ProtocolVariable->Io.Write; break;
    }
"""
# The SAME harness with the Io arm replaced by a second memory arm, and nothing else
# changed. A pair that differed in the protocol, the member names and the bound as well
# would prove nothing about which of those the test is reading.
MEM_HARNESS = IO_HARNESS.replace('->Io.', '->Mem.')


def campaign(root, name, harness=''):
    where = os.path.join(root, name)
    os.makedirs(os.path.join(where, 'Firness'), exist_ok=True)
    if harness:
        with open(os.path.join(where, 'Firness', 'FirnessHarnesses.c'), 'w') as handle:
            handle.write(harness)
    return where


def bugs(candidates, filtered=()):
    """A report in the shape bug_report.py writes one."""
    return {'rows': 9, 'clusters': 4, 'candidates': list(candidates),
            'ubiquitous': [],
            'filtered': {'harness': list(filtered), 'artefact': [], 'background': []}}


def artefact(ident, klass, protocols, module='CpuIo2Dxe.efi', site='+0x5296',
             members=('->Io.Read', '->Io.Write')):
    """A filtered.harness entry as bug_report writes one for an I/O port fault.

    The reason comes from bug_report's own template rather than being spelled out again,
    so the sentence this file reads is the sentence that file writes.
    """
    return {'id': ident, 'module': module, 'site': site, 'class': klass, 'hits': 1,
            'reason': br.IO_PORT_ARTEFACT.format(members=', '.join(members),
                                                 module=module),
            'io_ports': list(members), 'protocols': sorted(protocols)}


def held(candidate, drives):
    """A triaged candidate as a Cluster, so bug_report's own predicate can judge it."""
    cluster = br.Cluster((candidate['module'], candidate['class'], candidate['site']))
    cluster.protocols = set(candidate['protocols'])
    cluster.io_ports = drives
    return cluster


def candidate(ident, klass, protocols, module='CpuIo2Dxe.efi', site='+0x5296'):
    return {'id': ident, 'module': module, 'site': site, 'class': klass,
            'hits': 1, 'severity': 4, 'detail': f'1 fault(s) at {module}{site}',
            'protocols': list(protocols), 'source': 'IoWrite32 -- IoLibGcc.c:0:7'}


# A stand-in analyze_smi.py. The derivation cannot be asserted against the real one,
# because proving a new helper is picked up means ADDING one, and that file belongs to
# the generator.
FIXTURE = '''
import os
from fuzzywuzzy import fuzz

_ANCHOR = "handler"


def _depth_two(text):
    return text.upper()


def _helper(text):
    return _depth_two(text) + _ANCHOR


def wanted(text):
    return _helper(text)


def imports_only(text):
    return fuzz.ratio(text, _ANCHOR)


def shadows(os):
    """`os` is a parameter here, not the module: it must not be called free."""
    total = 0
    for os in range(3):
        total += os
    return [n for n in range(total)]
'''


def fixture(body=FIXTURE):
    holder = tempfile.mkdtemp(prefix='lift-fixture-')
    path = os.path.join(holder, 'analyze_smi.py')
    with open(path, 'w') as handle:
        handle.write(body)
    return path


# ---------------------------------------------------------------- the checks

def main():
    print('1. the two facts the denominator is read from, not recomputed')
    root = tempfile.mkdtemp(prefix='campaign-accounting-')
    log = os.path.join(root, 'fuzz.log')
    open(log, 'w').write(LAUNCH_LOG)
    check('the batch\'s own summary line gives the launch count',
          launched_campaigns(log) == (138, 0), f'{launched_campaigns(log)}')
    open(log, 'a').write('\nlaunched 4, failed to launch 1\n')
    check('a resumed stage takes the last launch loop, not the first',
          launched_campaigns(log) == (4, 1), f'{launched_campaigns(log)}')
    quiet = os.path.join(root, 'quiet.log')
    open(quiet, 'w').write('138 protocol(s) to fuzz\n  started A (1 launched, 0 queued)\n')
    check('a batch killed before its summary reads as unknown, not as zero',
          launched_campaigns(quiet) == (None, None),
          f'{launched_campaigns(quiet)} -- a zero here is a denominator of nothing')
    check('and so does a fuzz.log that was never written',
          launched_campaigns(os.path.join(root, 'nothing.log')) == (None, None))

    skipped = os.path.join(root, 'skipped.csv')
    with open(skipped, 'w') as handle:
        handle.write('protocol,reason\n')
        for n in range(125):
            handle.write(f'P{n},protocol not installed by this firmware\n')
    check('skipped.csv counts rows and not its header',
          skipped_before_launch(skipped) == 125, f'{skipped_before_launch(skipped)}')
    check('no skipped.csv is the same answer as nothing skipped',
          skipped_before_launch(os.path.join(root, 'none.csv')) == 0)

    print('\n   ...and the line divides by the one that was launched')
    _ok, said = detail_line(fuzzed=66, planned=138, iterations=3922229,
                            discovered=263, skipped=125)
    check('the denominator is the launched count', '66/138 campaign(s)' in said, said)
    check('not the discovered count', '66/263' not in said, said)
    check('the discovered count is still in the line', '263 discovered' in said, said)
    check('so is the number skipped before anything booted',
          '125 skipped before launch' in said, said)
    check('so the arithmetic a reader does is in front of them',
          125 + 138 == 263 and all(str(n) in said for n in (263, 125, 138)), said)
    check('a launch failure is reported when there was one',
          '2 failed to launch' in detail_line(fuzzed=1, planned=3, discovered=9,
                                              skipped=4, launch_failed=2)[1],
          detail_line(fuzzed=1, planned=3, discovered=9, skipped=4, launch_failed=2)[1])
    check('and not mentioned when there was none', 'failed to launch' not in said, said)

    print('\n   the counts survive the paths that report no campaign fuzzed at all')
    _ok, boot = detail_line(fuzzed=0, planned=138, discovered=263, skipped=125)
    check('a run where nothing fuzzed still says how many were dropped first',
          '263 discovered' in boot and '125 skipped before launch' in boot, boot)
    _ok, gone = detail_line(fuzzed=0, planned=138, discovered=263, skipped=125,
                            unlocatable=['A'], unlocated_runs=99)
    check('and so does the no-campaign-located-its-protocol path',
          '263 discovered' in gone and '125 skipped' in gone, gone)

    print('\n   the stage reads the recorded facts rather than guessing at them')
    # The prose comes off first, or the assertions below find the defect's name in the
    # paragraph that explains it. Asserted rather than assumed, because that is how it
    # was got wrong before: own_code_check counted a comment quoting a section header.
    check('a comment quoting the reverted form does not satisfy a source assertion',
          'planned = len(chosen)' not in
          code('# planned = len(chosen) if chosen else run.target_count\nx = 1'))
    check('nor does a docstring quoting it',
          'planned = len(chosen)' not in
          code('"""planned = len(chosen) if chosen else run.target_count"""\nx = 1'))
    body = code(source('fuzz_edk2'))
    check('the stage asks fuzz_batch what it launched',
          'launched, launch_failed = launched_campaigns(' in body)
    check('and the census how many it skipped',
          'skipped = skipped_before_launch(' in body)
    check('the discovered count is no longer the denominator',
          'planned = len(chosen) if chosen else run.target_count' not in body
          and 'discovered = len(chosen) if chosen else run.target_count' in body,
          'the pre-launch estimate must not be what the ratio divides by')
    from_ = assigned_from('planned', 'fuzz')
    check('the fuzz stage still assigns the thing it divides by', from_ is not None
          and bool(from_), f'{from_} -- nothing in fuzz() assigns planned')
    check('and assigns it from the launched count',
          from_ and 'launched' in from_, f'{sorted(from_ or ())}')
    check('and not from the discovered one',
          from_ is not None and 'discovered' not in from_
          and 'run.target_count' not in from_,
          f'{sorted(from_ or ())} -- planned = discovered is the whole defect, and it '
          f'changes no string in the file')
    check('the timeout is still sized off what might run, which is the discovered count',
          '-(-discovered // max(1, args.jobs))' in body,
          'sizing the timeout off the launched count is impossible: nothing has launched')
    # The fallback has to keep the denominator at or above the numerator. Deriving it as
    # discovered - skipped can undershoot -- a stale census, a protocol fuzz_batch
    # skipped as already done -- and a ratio of 9/4 is worse than an unknown.
    check('a derived denominator cannot come out below the campaigns that ran',
          'max(discovered - skipped, len(made))' in body,
          'discovered - skipped alone can be smaller than what produced a log')

    print('\n   and the check that lifts that same region is not left behind by it')
    found = region('fuzz_edk2', DETAIL_OPENS, DETAIL_CLOSES)
    check('the region this file lifts is still where it says it is', found is not None,
          f'{DETAIL_OPENS!r} is not in fuzz_edk2.py; every number above is vacuous')
    free = set()
    if found:
        tree = ast.parse(as_function(found) + '\n    return detail\n')
        bound = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)
                 and not isinstance(n.ctx, ast.Load)}
        bound |= {a.arg for a in ast.walk(tree) if isinstance(a, ast.arg)}
        free = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)
                and isinstance(n.ctx, ast.Load)} - bound
        free = {n for n in free if not hasattr(builtins, n)}
    supplied = set()
    for node in ast.walk(ast.parse(source('harness_outcome_check'))):
        if (isinstance(node, ast.Call) and getattr(node.func, 'id', '') == 'dict'
                and any(kw.arg == 'planned' for kw in node.keywords)):
            supplied = {kw.arg for kw in node.keywords}
    check('harness_outcome_check builds a state dict for that region',
          bool(supplied), 'nothing in it calls dict(planned=...)')
    check('and supplies every name the region reads',
          bool(free) and free <= supplied,
          f'short of {sorted(free - supplied)} -- the exec would raise NameError from '
          f'inside a lifted body, which is a traceback and no verdict')
    check('this file supplies them too', bool(free) and free <= set(EMPTY),
          f'short of {sorted(free - set(EMPTY))}')

    print('\n2. a fault the harness caused by driving live platform I/O ports')
    camps = os.path.join(root, 'campaigns')
    campaign(camps, 'EfiCpuIo2', IO_HARNESS)
    campaign(camps, 'EfiBlockIo', MEM_HARNESS)
    campaign(camps, 'EfiNoHarness')
    check('a harness that selects the I/O port accessor is recognised',
          io_port_harness(os.path.join(camps, 'EfiCpuIo2'))
          == ['->Io.Read', '->Io.Write'],
          f"{io_port_harness(os.path.join(camps, 'EfiCpuIo2'))}")
    check('one that drives only memory is not',
          io_port_harness(os.path.join(camps, 'EfiBlockIo')) == [],
          'the only difference between the two fixtures is the Io arm')
    check('a campaign whose generator left no harness answers [] rather than raising',
          io_port_harness(os.path.join(camps, 'EfiNoHarness')) == [])

    check('and the host no longer decides it after the fact',
          'harness_io_artefacts' not in code(source('fuzz_edk2')),
          'the host cannot write the report it would have to move the cluster in, which '
          'is why this moved into bug_report.py -- see container_write_check.py')

    # The report as bug_report.py now writes it: the cluster is already in the harness
    # bucket, and what the stage does with it is count it and name it.
    report = bugs([
        candidate('CpuIo2Dxe.efi|heap-buffer-overflow (write)|CpuIo2Dxe.c',
                  'heap-buffer-overflow (write)', ['EfiCpuIo2']),
        candidate('HiiDatabase.efi|cpu-exception (#GP)|String.c',
                  'cpu-exception (#GP)', ['EfiBlockIo'], module='HiiDatabase.efi'),
        candidate('DxeCore.efi|cpu-exception (#PF)|Timer.c',
                  'cpu-exception (#PF)', ['EfiCpuIo2', 'EfiBlockIo'],
                  module='DxeCore.efi'),
    ], [artefact('CpuIo2Dxe.efi|cpu-exception (#DE)|IoLibGcc.c',
                 'cpu-exception (#DE)', ['EfiCpuIo2'])])
    ok, said = triage_line(report, read=4)
    reason = (bucket(report)[0].get('reason', '') if bucket(report) else '')
    check('the reason beside it names the member and the ports',
          all(k in reason for k in ('->Io.Write', '0x40-0x43',
                                    'live platform registers')), f'{reason!r}')
    check('the stage still passes -- this is a reclassification, not a failure',
          ok is True, f'{ok}')
    check('the verdict says how many were moved and where they came from',
          '1 reported as a harness artefact rather than a finding' in said
          and 'CpuIo2Dxe.efi+0x5296' in said and 'EfiCpuIo2' in said, said)
    check('and the candidate count it prints is the one left after the move',
          said.startswith('3 candidate(s) from 4 cluster(s)'), said)
    check('a harness cluster filtered by NAME is not counted among them',
          'harness artefact' not in triage_line(
              bugs([], [{'id': 'Firness.efi|unknown-crash|FirnessHarnesses.c',
                         'module': 'Firness.efi', 'site': 'FirnessHarnesses.c:91',
                         'class': 'unknown-crash', 'hits': 2,
                         'reason': 'generated harness source'}]))[1],
          'the bucket holds both kinds and only one of them is the I/O ports')
    check('which is what stops it being filed, because that is the key filing reads',
          "json.load(open(args.bugs)).get('candidates')" in code(source('file_issues')),
          'if file_issues stops reading candidates this move stops having any effect')

    ok, said = triage_line(bugs([
        candidate('HiiDatabase.efi|cpu-exception (#GP)|String.c',
                  'cpu-exception (#GP)', ['EfiBlockIo'], module='HiiDatabase.efi')]))
    check('a run with nothing to move says nothing about it',
          'harness artefact' not in said, said)

    print('\n3. the lift derives what its region needs')
    path = fixture()
    space = lift_or_fail(['wanted'], path)
    check('a region that is asked for is lifted', callable(space.get('wanted')))
    check('a helper it calls comes with it without being named',
          callable(space.get('_helper')),
          'this is the list that was hand-maintained; a new helper raised NameError')
    check('and a helper of that helper, however deep the chain goes',
          callable(space.get('_depth_two')))
    check('a module-level constant the chain reads comes too',
          space.get('_ANCHOR') == 'handler')
    # In a try, because the failure this is looking for IS a NameError out of a lifted
    # body: letting it propagate would end this file on a traceback and whoever reads the
    # red would see a broken check rather than a lift that no longer carries its helpers.
    try:
        ran = space['wanted']('x') if callable(space.get('wanted')) else None
    except Exception as error:
        ran = f'{error.__class__.__name__}: {error}'
    check('the lifted code actually runs, which is the point of lifting it',
          ran == 'Xhandler', f'{ran!r}')
    check('nothing is pulled in that the region does not need',
          'imports_only' not in space,
          'lifting the whole module would import fuzzywuzzy, which is why this is a lift')

    print('\n   ...and names what it cannot derive instead of raising NameError')
    try:
        lift(['imports_only'], path)
        caught = None
    except LiftError as error:
        caught = str(error)
    except NameError as error:
        caught = f'NameError: {error}'
    check('a region reading an imported name fails with LiftError, not NameError',
          caught is not None and not caught.startswith('NameError'), f'{caught}')
    check('the message names the symbol that is missing',
          caught and 'fuzz' in caught, f'{caught}')
    check('and says where to add it, so the fix does not need a bisect',
          caught and "lift()'s namespace" in caught and 'smi_coverage_check' in caught,
          f'{caught}')
    check('and says what the alternative looks like, which is a traceback',
          caught and 'traceback instead of a verdict' in caught, f'{caught}')
    try:
        lift(['gone_from_the_module'], path)
        absent = None
    except LiftError as error:
        absent = str(error)
    check('a name the module no longer defines is named as well',
          absent and 'gone_from_the_module' in absent, f'{absent}')
    check('and reported as this check going blind, not as a defect in the generator',
          absent and 'gone blind' in absent, f'{absent}')

    print('\n   the free-name derivation does not invent work for itself')
    tree = ast.parse(FIXTURE)
    shadows = [n for n in tree.body
               if isinstance(n, ast.FunctionDef) and n.name == 'shadows']
    check('a parameter that shadows a module is not called free',
          shadows and 'os' not in needs(shadows[0]),
          f'{sorted(needs(shadows[0])) if shadows else None}')
    check('nor is a loop target or a comprehension variable',
          shadows and not (needs(shadows[0]) - {'range'}),
          f'{sorted(needs(shadows[0])) if shadows else None}')

    print('\n   and a lift that cannot be done is reported with a verdict under it')
    text = code(source('smi_coverage_check'))
    check('main catches LiftError rather than letting it out',
          'except LiftError as error:' in text)
    check('it records the failure through the same check() as everything else',
          re.search(r'except LiftError as error:\s*\n\s*check\(', text) is not None,
          'a print and a sys.exit would leave no count behind')
    check('and leaves through the summary, so the run still prints its verdict',
          'return summary()' in text and text.count('return summary()') >= 2,
          'main must not have an exit path that prints no summary')
    smi_coverage_check.FAILURES.append('planted')
    spoke = capture(smi_coverage_check.summary)
    smi_coverage_check.FAILURES.remove('planted')
    check('that summary really prints the failure count',
          'check(s) failed' in spoke and 'planted' in spoke, spoke)

    print('\nrun 43454245046, the sweep all of this is measured on')
    evidence(os.path.join(EVIDENCE, 'campaigns'), os.path.join(EVIDENCE, 'fuzz.log'),
             os.path.join(EVIDENCE, 'bugs.json'))

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


def lift(names, path):
    return smi_coverage_check.lift(names, path=path)


def lift_or_fail(names, path):
    """The lift, with a failure recorded rather than raised out of main()."""
    try:
        return lift(names, path)
    except LiftError as error:
        check('the fixture module lifts at all', False, str(error))
        return {}


def capture(fn):
    held, sys.stdout = sys.stdout, io.StringIO()
    try:
        fn()
        return sys.stdout.getvalue()
    finally:
        sys.stdout = held


def evidence(campaigns, log, report):
    """The real sweep, where it is still on disk.

    Skipped with a note otherwise. An evidence directory that was cleaned up is not a
    defect in the driver, and a check that reddens over one is the thing this file is
    partly about.
    """
    if not (os.path.isdir(campaigns) and os.path.isfile(log)
            and os.path.isfile(report)):
        print(f'  --     {EVIDENCE} is no longer on disk; the fixtures above stand '
              f'alone and nothing here is asserted')
        return
    launched, failed = launched_campaigns(log)
    skipped = skipped_before_launch(os.path.join(campaigns, 'skipped.csv'))
    ran = len([d for d in os.listdir(campaigns)
               if os.path.isfile(os.path.join(campaigns, d, 'run.log'))])
    check('the sweep says it launched 138 campaigns', (launched, failed) == (138, 0),
          f'{(launched, failed)}')
    check('its census says it skipped 125 before launch', skipped == 125, f'{skipped}')
    check('138 + 125 is the 263 the old line divided by', launched + skipped == 263,
          f'{launched + skipped}')
    check('and 138 is the number of campaigns that left a run.log', ran == launched,
          f'{ran} run.log(s) against {launched} launched')
    _ok, said = detail_line(fuzzed=66, planned=launched, iterations=3922229,
                            discovered=launched + skipped, skipped=skipped,
                            launch_failed=failed)
    check('so the line this run would now print is 66/138, not 66/263',
          said.startswith('66/138 campaign(s) fuzzed the harness (3922229 iteration(s)) '
                          '[263 discovered, 125 skipped before launch]'), said)
    drives = io_port_drivers(campaigns)
    check('two of its 138 harnesses drive platform I/O ports, and these two',
          sorted(drives) == ['EfiCpuIo2', 'EfiMmCpuIo'], f'{sorted(drives)}')
    found = json.load(open(report))
    faults = [c for c in found['candidates']
              if str(c.get('class') or '').startswith('cpu-exception')]
    moved = [c for c in faults if io_port_artefact(held(c, drives))]
    check('it triaged three cpu-exception candidates', len(faults) == 3,
          f'{[c["id"] for c in faults]}')
    check('and exactly one of them is the harness driving those ports',
          [c['id'] for c in moved] == ['CpuIo2Dxe.efi|cpu-exception (#DE)|IoLibGcc.c'],
          f'{[c["id"] for c in moved]}')
    serial = os.path.join(campaigns, 'EfiCpuIo2', 'fuzz.txt')
    if os.path.isfile(serial):
        text = io.open(serial, encoding='utf-8', errors='replace').read()
        check('which is the #DE its own serial capture recorded',
              'X64 Exception Type - 00(#DE - Divide Error)' in text,
              'the fault this moves is the one the guest actually took')


if __name__ == '__main__':
    sys.exit(main())
