#!/usr/bin/env python3
"""Assert that a firmware ASSERT is reported, and that it no longer ends the campaign.

An ASSERT was the one thing a campaign could hit that was both maximally destructive and
completely invisible. It is not a sanitizer report, so it never reaches crashes.csv; it is
not a CPU exception, so guest_faults() does not see it. What it does do, with
DEBUG_PROPERTY_ASSERT_DEADLOOP_ENABLED set, is CpuDeadLoop() with interrupts off -- and
inside SMM the snapshot restore does not recover the vCPU, so every later iteration times
out against a dead machine.

Measured on eval1 run 42154605158: the corpus grew 0 -> 20 over twenty fast iterations,
then input 21 handed VarCheckPolicyLibMmiHandler a 1-byte comm buffer, that handler
returned EFI_INVALID_PARAMETER, SmiManage hit its "Unexpected status code returned" ASSERT
and the machine stopped. Iterations 22, 23 and 24 produced no guest output at all. The
campaign reported four solutions, three of which were the same dead machine timing out.

Two changes have to hold together, and that is what this checks:
  - the fuzzing image clears the deadloop bit, so the campaign survives the ASSERT
  - the report reads the ASSERT back out of the capture, so clearing it loses nothing

Either one alone is a regression. Clearing the bit without reading the line back silently
drops findings; reading it back without clearing the bit still forfeits the budget.
"""

import os
import re
import sys
import tempfile
import textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import bug_report as br  # noqa: E402

FAILURES = []


def check(name, condition, detail=''):
    if condition:
        print(f'  ok    {name}')
    else:
        print(f'  FAIL  {name}' + (f' -- {detail}' if detail else ''))
        FAILURES.append(name)


def write(path, text):
    with open(path, 'w') as handle:
        handle.write(textwrap.dedent(text).lstrip('\n'))
    return path


# A capture shaped like a real one: drivers load, SMM dispatches, then the harness runs and
# an input breaks an invariant. The load lines are the boot/fuzz divider.
CAPTURE = '''
    Loading driver at 0x00018B00000 EntryPoint=0x00018B0F848 VariableSmm.efi
    ASSERT Early.c(42): (Thing != ((VOID *) 0))
    Loading driver at 0x00018BA1000 EntryPoint=0x00018BAF848 ShellPkg.efi
    SmmCore: dispatch 31CBC5E1-FEF6-43ED-BFBA-37DD487092AB len 24 -> Success
    VarCheckPolicyLibMmiHandler - Bad comm buffer size! 1 < 20
    ASSERT Smi.c(193): ((BOOLEAN)(0==1))
    SmmCore: dispatch 31CBC5E1-FEF6-43ED-BFBA-37DD487092AB len 24 -> Success
    ASSERT Smi.c(193): ((BOOLEAN)(0==1))
'''

QUIET = '''
    Loading driver at 0x00018B00000 EntryPoint=0x00018B0F848 VariableSmm.efi
    SmmCore: dispatch 31CBC5E1-FEF6-43ED-BFBA-37DD487092AB len 24 -> Success
    FIRNESS: fuzzing starts
'''


def main():
    print('ASSERT rows')
    work = tempfile.mkdtemp(prefix='assertchk-')
    capture = write(os.path.join(work, 'debugcon.log'), CAPTURE)
    quiet = write(os.path.join(work, 'quiet.log'), QUIET)

    rows = br.guest_asserts('T', [capture])
    by_site = {(r.path, r.line): r for r in rows}

    check('an ASSERT in the capture becomes a row', len(rows) == 2,
          f'{len(rows)} row(s) from a capture with two distinct sites')
    check('two sightings of one site are one row with a count',
          by_site.get(('Smi.c', '193')) is not None
          and by_site[('Smi.c', '193')].count == 2,
          'a site seen twice must not arrive as two candidates')
    check('an ASSERT after the last driver load is input driven',
          by_site.get(('Smi.c', '193')) is not None
          and by_site[('Smi.c', '193')].phase == 'fuzz')
    check('an ASSERT before the last driver load is boot noise',
          by_site.get(('Early.c', '42')) is not None
          and by_site[('Early.c', '42')].phase == 'boot',
          'a boot ASSERT reported as a fuzzing finding is a false candidate')
    check('a capture with no ASSERT yields no rows', br.guest_asserts('T', [quiet]) == [])
    check('a capture that does not exist yields no rows',
          br.guest_asserts('T', [os.path.join(work, 'nope.log')]) == [])

    # Severity and survival. A row the filters drop is the same as no row at all.
    row = by_site[('Smi.c', '193')]
    cluster = br.Cluster(row.group_key())
    cluster.add(row)
    check('the class is firmware-assert', cluster.klass == 'firmware-assert', cluster.klass)
    check('it ranks beside a CPU fault, not at the bottom', cluster.severity() == 4,
          f'severity {cluster.severity()}; 1 would sort it under the arithmetic rows')
    kind, why = br.verdict(cluster, set(), 8)
    check('it survives the filters as a candidate', kind == 'candidate', f'{kind}: {why}')

    print('attribution')
    # Three files of one name. Only one has an ASSERT on the line the message named.
    tree = os.path.join(work, 'Tree')
    for pkg, line_193 in (('MdeModulePkg/Core/PiSmmCore', 'ASSERT (FALSE);'),
                          ('UefiCpuPkg/Nowhere', 'Status = EFI_SUCCESS;'),
                          ('OvmfPkg/Other', '// nothing here'),):
        where = os.path.join(tree, pkg)
        os.makedirs(where)
        body = [f'// line {n}' for n in range(1, 193)] + [line_193, '// tail']
        write(os.path.join(where, 'Smi.c'), '\n'.join(body) + '\n')

    found = br.assert_source('Smi.c', '193', '((BOOLEAN)(0==1))', [tree])
    check('the named line picks the one file that really asserts there',
          found == 'MdeModulePkg/Core/PiSmmCore/Smi.c', found or '<none>')
    check('a line that is not an ASSERT is not a candidate',
          'UefiCpuPkg' not in found and 'OvmfPkg' not in found, found)
    check('a line past the end of a file is not a candidate',
          br.assert_source('Smi.c', '99999', 'x', [tree]) == '',
          'a short file of the right name must not match by name alone')

    # Two files that BOTH assert on that line, with different expressions. The expression
    # breaks the tie; without it the report says nothing rather than guessing.
    tie = os.path.join(work, 'Tie')
    for pkg, text in (('MdeModulePkg/A', 'ASSERT (FALSE);'),
                      ('MdeModulePkg/B', 'ASSERT (Buffer != NULL);')):
        where = os.path.join(tie, pkg)
        os.makedirs(where)
        body = [f'// line {n}' for n in range(1, 10)] + [text]
        write(os.path.join(where, 'Dup.c'), '\n'.join(body) + '\n')
    br._SOURCE_INDEX = None
    check('the expression breaks a tie between two asserting files',
          br.assert_source('Dup.c', '10', '((BOOLEAN)(0==1))', [tie])
          == 'MdeModulePkg/A/Dup.c',
          br.assert_source('Dup.c', '10', '((BOOLEAN)(0==1))', [tie]) or '<none>')
    br._SOURCE_INDEX = None
    check('an expression that fits neither file leaves the row on its basename',
          br.assert_source('Dup.c', '10', '(Other != NULL)', [tie]) == '',
          'naming one of two equally good candidates is a guess, not an answer')
    br._SOURCE_INDEX = None
    check('attribution with no build tree is inert',
          br.assert_source('Smi.c', '193', '((BOOLEAN)(0==1))', []) == '')

    print('the campaign survives it')
    # The report is only half of it. If the image still dead-loops, the ASSERT is read back
    # from a capture that ends at the first one and the budget is gone either way.
    source = open(os.path.join(HERE, 'fuzz_edk2.py')).read()
    mask = re.search(r"'gEfiMdePkgTokenSpaceGuid\.PcdDebugPropertyMask=(0x[0-9A-Fa-f]+)'",
                     source)
    check('the build pins PcdDebugPropertyMask', mask is not None,
          'without it OvmfPkgX64.dsc keeps 0x2F and every ASSERT is a dead loop')
    if mask:
        value = int(mask.group(1), 16)
        check('the deadloop bit is clear', not value & 0x20,
              f'{mask.group(1)} still has DEBUG_PROPERTY_ASSERT_DEADLOOP_ENABLED')
        check('the breakpoint bit is clear', not value & 0x10,
              f'{mask.group(1)} would CpuBreakpoint() instead, which halts just the same')
        check('the ASSERT message still prints', bool(value & 0x01),
              f'{mask.group(1)} clears DEBUG_PROPERTY_DEBUG_ASSERT_ENABLED, so there is '
              f'no line left to read back')
        check('freed memory is still poisoned', bool(value & 0x08),
              f'{mask.group(1)} clears DEBUG_PROPERTY_CLEAR_MEMORY_ENABLED, which the '
              f'platform had on; a use-after-free gets quieter')
    # Both command lines, from one list. They are maintained separately, and that is how
    # PcdResetOnMemoryTypeInformationChange came to be set on the build nobody boots.
    # Count the interpolations, not the name: "def shared_pcds():" contains the string
    # "shared_pcds()" too, so counting the name let a build line that had stopped reading
    # the list still pass this.
    check('both build command lines take the shared list',
          source.count('{shared_pcds()}') == 2,
          f"{source.count('{shared_pcds()}')} call site(s); the firmware build and the "
          f'image build in IMAGE_DOCKERFILE must read the same constant')
    check('the reset PCD is still in that list',
          'PcdResetOnMemoryTypeInformationChange=FALSE' in source)

    print(f'{len(FAILURES)} failure(s)')
    return 1 if FAILURES else 0


if __name__ == '__main__':
    sys.exit(main())
