#!/usr/bin/env python3
"""Assert the sanitizer's scope is the same scope in both configurations, and that every
module it does NOT check is named with a reason rather than hidden inside a ratio.

Two completed runs reported the detection benchmark differently and nobody had reconciled
them:

  /home/gl055/fuzzuer-eval1/43454245046   SMM_REQUIRE, --smi   16 of 16 scorable classes
  /home/gl055/fuzzuer-sweep/43704163314   four upstream refs   11 of 11 scorable classes

The 11 is a correct subset and not a silent failure: the board is 18 rows, two of them are
exempt in every configuration (boot-service-after-exit needs the runtime phase,
stale-interface is off unless built with -D ASAN_STALE_INTERFACE because it reports correct
firmware), and the five smm-* rows cannot run on an image with no SMM core -- that image
carries no SanBenchSmm to raise the SMI into, so they score NO SMM, which is an exemption
rather than a miss. 18 - 2 = 16 and 18 - 2 - 5 = 11. The first section below asserts that
arithmetic through bench_cases' own tally(), because the whole reason those two numbers
can be trusted is that an exemption leaves the denominator and a MISS does not.

The second thing nobody could see was the shortfall in the OTHER number the instrumented
stage prints. "314/327 modules have their own code instrumented" named thirteen modules
and the stage mentioned none of them unless they were SMM; on the upstream refs it was
300/311 and eleven. A ratio that reads as near-total coverage while something specific is
uncovered is the shape this project keeps getting burned by, so asan_scope.describe() now
groups the remainder and the stage prints it. Measured over the build logs committed in
this repository:

  results/fuzz-edk2-stable202608/build.log   11 dark, nothing unexplained
  results/smm-qualify/build.log              23 dark, NINE of them SMM modules

That second one is the gate's whole purpose, from the era before ASAN_SMM: PiSmmCore,
VariableSmm, PiSmmCpuDxeSmm and six more, every one of them a module whose own code
carried no checks while its image carried the symbols its libraries brought in. It is
kept here as a fixture because a classifier that cannot tell those two builds apart is
not worth printing.

Run: python3 scripts/asan_scope_check.py
"""

import io
import importlib.util
import os
import re
import sys

# Before any import of a sibling: a stale scripts/__pycache__ entry replays the module a
# mutation run has just edited, and the mutation then looks caught when nothing ran.
sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FORK = os.path.join(ROOT, 'eval_source', 'edk2')
DSC = os.path.join(FORK, 'OvmfPkg', 'OvmfPkgX64.dsc')
DSC_INC = os.path.join(FORK, 'MdeModulePkg', 'Include', 'Dsc', 'Asan.dsc.inc')
sys.path.insert(0, HERE)

FAILED = PASSED = 0


def check(what, ok, detail=''):
    global FAILED, PASSED
    if ok:
        PASSED += 1
        print(f'  [OK]   {what}')
    else:
        FAILED += 1
        print(f'  [FAIL] {what}' + (f'\n         {detail}' if detail else ''))


def read(path):
    try:
        return io.open(path, encoding='utf-8', errors='replace').read()
    except OSError:
        return ''


def source(name):
    return read(os.path.join(HERE, f'{name}.py'))


def code(text):
    """A region with its prose removed -- docstrings and comments both.

    Every reason in the code under test is written out in a comment beside it, so a
    source assertion made against the raw text finds the thing it is looking for in the
    paragraph that explains why it exists and passes with the statement deleted. That
    mutation is the one this project has let through before.
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
    """True when both appear and `first` comes first. False, never an exception, if not.

    A bare .index() on an anchor a mutation deleted raises, and a check that dies on its
    own traceback has not caught anything -- it has stopped reporting.
    """
    at, then = text.find(first), text.find(second)
    return at >= 0 and then >= 0 and at < then


def deduped_dsc():
    """OvmfPkgX64.dsc as the port ships it -- the fork holds its whole body twice.

    edk2 takes the last definition of everything, so what a build sees is what survives
    dedup_sections(), and an assertion against the raw file can be answered by a copy
    that never reaches a build.
    """
    spec = importlib.util.spec_from_file_location(
        'apply_asan', os.path.join(ROOT, 'uefi_asan', 'apply_asan.py'))
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except SystemExit:
        pass
    kept, _dropped = module.dedup_sections(open(DSC, 'rb').read().split(b'\n'))
    return b'\n'.join(kept).decode('utf-8', 'replace')


def sections(text, header):
    """[(offset, body), ...] for every occurrence of one [Section] header.

    Scoped rather than searched, because both of these files hold the same header more
    than once and a bare .find() answers about the wrong one. OvmfPkgX64.dsc opens
    "[BuildOptions.common.EDKII.DXE_SMM_DRIVER, ...SMM_CORE]" early to set DLINK_FLAGS,
    long before the !include, so "does the gate come after the include" asked of the
    FIRST occurrence says no about a block that sets no sanitizer flags at all.
    """
    found = []
    for match in re.finditer(re.escape(header), text):
        rest = text[match.end():]
        nxt = re.search(r'\n\[', rest)
        found.append((match.start(), rest[:nxt.start()] if nxt else rest))
    return found


def flag_setting(text, header):
    """(offset, body) for the one occurrence of `header` that sets SAN_FLAGS, or None."""
    owning = [pair for pair in sections(text, header)
              if '_CLANGSAN_X64_SAN_FLAGS' in pair[1]]
    return owning[0] if len(owning) == 1 else None


COMPONENT = re.compile(r'^([A-Za-z0-9]+Pkg/\S+)\.inf\s*\{')


def component_overrides(text):
    """{module path without .inf: [SAN_FLAGS values]} for each [Components] entry.

    Comment lines are dropped first. The comment above HiiDatabaseDxe's own override says
    '"==" replaces', which holds both SAN_FLAGS and '==' and was read as an override of
    its own when this was first written.
    """
    overrides = {}
    current = None
    for line in text.splitlines():
        bare = line.strip()
        if bare.startswith('#'):
            continue
        if bare.startswith('[') and bare.endswith(']'):
            current = None
            continue
        opened = COMPONENT.match(bare)
        if opened:
            current = opened.group(1)
            continue
        if current and bare.startswith('}'):
            current = None
            continue
        if current and 'SAN_FLAGS' in bare and '==' in bare:
            overrides.setdefault(current, []).append(bare.split('==', 1)[1].strip())
    return overrides


def instruments(value):
    """Does this SAN_FLAGS value switch the sanitizer ON for the module it is under."""
    return '$(ASAN_SAN_FLAGS)' in value or '-fsanitize=address' in value


def board(smm_verdict, others=None):
    """A whole scoreboard, as one configuration would produce it.

    Every row differs from the next board in exactly one attribute -- the verdict the
    five smm-* rows carry -- so a difference in the tally can only come from that.
    """
    import bench_cases as bench
    results = {}
    for case, _expect, _unreachable in bench.CASES:
        if case.startswith('smm-'):
            results[case] = dict(verdict=smm_verdict)
        elif case in EXEMPT_EVERYWHERE:
            results[case] = dict(verdict='N/A')
        else:
            results[case] = dict(verdict='PASS')
    results.update(others or {})
    return results


# The two classes the project records as unscorable in every configuration. Asserted
# against the code below rather than taken on trust: score_one has exactly two places
# that answer N/A, and nothing else may acquire a third.
EXEMPT_EVERYWHERE = ('boot-service-after-exit', 'stale-interface')


def main():
    import bench_cases as bench
    import asan_scope

    print('the board scores the same classes in both configurations')
    names = [case for case, _e, _u in bench.CASES]
    check('the benchmark names 18 classes', len(names) == 18, f'{len(names)}')
    check('each of them once', len(set(names)) == len(names),
          f'{sorted(n for n in set(names) if names.count(n) > 1)}')
    smm_rows = [row for row in bench.CASES if row[0].startswith('smm-')]
    check('five of them are SMM classes', len(smm_rows) == 5,
          f'{[r[0] for r in smm_rows]}')

    bench_src = code(source('bench_cases'))
    third = [case for case, _e, unreachable in bench.CASES if unreachable]
    check('exactly two rows carry a third column at all',
          third == ['control', 'boot-service-after-exit'], f'{third}')
    check('and the control rule runs before the one that reads it',
          before(bench_src, "case == 'control' or case.endswith('-control')",
                 'if unreachable:'),
          "the third column is overloaded: for 'control' it holds a description, and "
          'testing unreachable first reclassified the control row as N/A -- 12 of 12 '
          'became 11 of 11, still n of n, still green, no longer scoring the control')
    check('score_one answers N/A in exactly two places',
          bench_src.count("verdict='N/A'") == 2,
          f"{bench_src.count(chr(39) + 'N/A' + chr(39))} -- a third would shrink the "
          f'denominator without saying so')
    check('one of them is the stale-interface class, by name',
          before(bench_src, "case == 'stale-interface'", "verdict='N/A'"))
    check('and it is off unless the image was built for it',
          "getattr(args, 'stale_interface', False)" in bench_src,
          'the class reports correct firmware and cost the control row its verdict')

    dxe_detected, dxe_scored, dxe_exempt = bench.tally(board('NO SMM'), bench.CASES)
    smm_detected, smm_scored, smm_exempt = bench.tally(board('PASS'), bench.CASES)
    check('a DXE-only board scores 11 of 11',
          (dxe_detected, dxe_scored) == (11, 11), f'{dxe_detected} of {dxe_scored}')
    check('an SMM board scores 16 of 16',
          (smm_detected, smm_scored) == (16, 16), f'{smm_detected} of {smm_scored}')
    check('the two denominators differ by exactly the five SMM rows',
          smm_scored - dxe_scored == 5 == len(smm_rows),
          f'{smm_scored} - {dxe_scored}')
    check('and the names that leave are exactly those five',
          sorted(set(dxe_exempt) - set(smm_exempt)) == sorted(r[0] for r in smm_rows),
          f'{sorted(set(dxe_exempt) - set(smm_exempt))}')
    check('the classes exempt in BOTH are only the recorded two',
          sorted(smm_exempt) == sorted(EXEMPT_EVERYWHERE), f'{sorted(smm_exempt)}')
    silent_smm = board('PASS', {smm_rows[0][0]: dict(verdict='MISS')})
    check('an SMM row that ran and stayed silent keeps the denominator at 16',
          bench.tally(silent_smm, bench.CASES)[:2] == (15, 16),
          f'{bench.tally(silent_smm, bench.CASES)[:2]} -- exempting a MISS is how a '
          f'board hides the one result these rows exist to catch')
    check('NO SMM is an exemption and MISS is not',
          'NO SMM' in bench.EXEMPT and 'MISS' in bench.SCORED
          and 'NO SMM' not in bench.SCORED,
          f'{bench.EXEMPT} / {bench.SCORED}')
    check('no verdict is in both lists',
          not set(bench.SCORED) & set(bench.EXEMPT),
          f'{sorted(set(bench.SCORED) & set(bench.EXEMPT))} -- tally() tests SCORED '
          f'first, so an overlap means the branch order decides the verdict and '
          f'reordering those two lines would silently move a class out of the '
          f'denominator')
    check('the row that answers "is stack instrumentation on" is scored, not exempt',
          bench.tally(board('PASS'),
                      [r for r in bench.CASES
                       if r[0] == 'stack-buffer-overflow'])[:2] == (1, 1),
          'every other case passes with the stack off, so a green board without this '
          'row says nothing about the stack at all')

    print('\nevery module the sanitizer does not check is named, and grouped by why')
    # One attribute apart per row, so a wrong group can only be the module type.
    dark = [('OvmfPkg/PlatformPei/PlatformPei', 'PEIM'),
            ('OvmfPkg/Sec/SecMain', 'SEC'),
            ('MdePkg/Library/PeiCoreEntryPoint/PeiCoreEntryPoint', 'PEI_CORE'),
            ('OvmfPkg/Spi/DxeSpi', 'DXE_DRIVER'),
            ('OvmfPkg/Spi/SmmSpi', 'DXE_SMM_DRIVER'),
            ('MdeModulePkg/Core/PiSmmCore/PiSmmCore', 'SMM_CORE')]
    # Guarded, not subscripted. An emptied table made this IndexError before the first
    # assertion about it, and a check that dies on its own traceback has reported
    # nothing -- which a mutation run cannot tell from a catch.
    check('there is a table of exclusions to check against',
          bool(asan_scope.EXCLUDED),
          'an empty table makes every dark DXE module unexplained, which is louder '
          'than the truth rather than quieter, but it is still not the truth')
    declared = sorted(asan_scope.EXCLUDED)[0] if asan_scope.EXCLUDED \
        else 'MdeModulePkg/Nothing/IsExcluded'
    groups = asan_scope.classify(dark + [(declared, 'DXE_DRIVER')])
    where = {module: name for name, rows in groups.items() for module, _d in rows}
    check('a PEIM is put down to the phase it runs in',
          where.get('OvmfPkg/PlatformPei/PlatformPei') == 'phase')
    check('so is SEC', where.get('OvmfPkg/Sec/SecMain') == 'phase')
    check('so is the PEI core',
          where.get('MdePkg/Library/PeiCoreEntryPoint/PeiCoreEntryPoint') == 'phase')
    check('a dark DXE driver is unexplained',
          where.get('OvmfPkg/Spi/DxeSpi') == 'unexpected')
    check('a dark SMM driver is unexplained',
          where.get('OvmfPkg/Spi/SmmSpi') == 'unexpected')
    check('and so is the SMM core',
          where.get('MdeModulePkg/Core/PiSmmCore/PiSmmCore') == 'unexpected',
          'this is the one the whole stage exists to stop')
    check('a module excluded by name is declared, not unexplained',
          where.get(declared) == 'declared',
          f'{where.get(declared)} -- its own type can report, so only the table '
          f'distinguishes it')
    check('every row lands in exactly one group',
          sum(len(rows) for rows in groups.values()) == len(dark) + 1
          and len(where) == len(dark) + 1,
          f'{ {name: len(rows) for name, rows in groups.items()} }')

    guid = 'UefiCpuPkg/CpuMpPei/280251c4-1d09-4035-9062-839acb5f18c1'
    check('a FILE_GUID build directory points at its own directory\'s INF',
          asan_scope.sibling_inf(guid) == 'UefiCpuPkg/CpuMpPei/CpuMpPei',
          f'{asan_scope.sibling_inf(guid)}')
    check('and a name that is not a GUID points at nothing',
          asan_scope.sibling_inf('OvmfPkg/Spi/SmmSpi') == '',
          'a fallback that fires on every module would answer for the wrong INF')
    resolved = asan_scope.classify([(guid, '')],
                                   lambda m: 'PEIM' if m.endswith('CpuMpPei') else '')
    check('with a resolver it is the PEIM it really is',
          [m for m, _d in resolved['phase']] == [guid], f'{resolved}')
    blind = asan_scope.classify([(guid, '')])
    check('without one it is unknown, never unexplained',
          [m for m, _d in blind['unknown']] == [guid] and not blind['unexpected'],
          f'{blind} -- a type nothing could read is not evidence that a DXE driver '
          f'lost its checks')

    said = asan_scope.describe(dark + [(declared, 'DXE_DRIVER')])
    check('the sentence names every single dark module',
          all(module.split('/')[-1] in said for module, _k in dark),
          f'missing: {[m for m, _k in dark if m.split("/")[-1] not in said]} -- a '
          f'reader has to be able to see the list without re-deriving it')
    check('it counts them', said.startswith('7 carry none of their own'), said[:60])
    check('it shouts only about the ones that are unexplained', 'UNEXPLAINED' in said)
    check('and says nothing when nothing is dark', asan_scope.describe([]) == '')
    quiet = asan_scope.describe([('OvmfPkg/Sec/SecMain', 'SEC')])
    check('a board with only PEI/SEC left does not shout',
          'UNEXPLAINED' not in quiet and 'SecMain' in quiet, quiet)
    for mechanism in ('AsanLib declares no PEIM', 'AsanLibNull', 'gAsanInfoGuid'):
        check(f'the phase reason names {mechanism!r}',
              mechanism in asan_scope.PHASE_REASON,
              'a reason that does not say the mechanism is an excuse')

    print('\non the two build logs committed in this repository')
    from fuzz_edk2 import own_code_instrumented, module_type

    def classify_log(rel):
        text = read(os.path.join(ROOT, rel))
        if not text:
            return None
        _own, _total, rows = own_code_instrumented(text, FORK)
        return asan_scope.classify(rows, lambda m: module_type(FORK, m))

    healthy = classify_log('results/fuzz-edk2-stable202608/build.log')
    check('a healthy DXE build has nothing unexplained',
          healthy is not None and not healthy['unexpected'],
          f'{healthy and healthy["unexpected"]}')
    check('and the one module it excludes by name is the declared one',
          healthy is not None
          and [m for m, _d in healthy['declared']] == [declared],
          f'{healthy and healthy["declared"]}')
    check('everything else it leaves dark runs before the shadow exists',
          healthy is not None
          and all(kind.upper() in asan_scope.PHASE_TYPES
                  for _m, kind in healthy['phase'])
          and len(healthy['phase']) >= 8,
          f'{healthy and healthy["phase"]}')

    stale = classify_log('results/smm-qualify/build.log')
    check('the SMM build from before ASAN_SMM is called out',
          stale is not None and len(stale['unexpected']) == 9,
          f'{stale and len(stale["unexpected"])} unexplained -- this build is the '
          f'"0 of 17 SMM modules" era and a classifier that calls it clean is useless')
    check('and every one of the nine is an SMM module type',
          stale is not None
          and all('SMM' in kind.upper() for _m, kind in stale['unexpected']),
          f'{stale and stale["unexpected"]}')
    check('its SMM core is among them',
          stale is not None
          and any(m.endswith('/PiSmmCore') for m, _k in stale['unexpected']),
          f'{stale and [m for m, _k in stale["unexpected"]]}')

    print('\nthe reason PEI cannot report is in the integration, not only in this file')
    real = read(os.path.join(FORK, 'MdeModulePkg', 'Library', 'AsanLib', 'AsanLib.inf'))
    null = read(os.path.join(FORK, 'MdeModulePkg', 'Library', 'AsanLibNull',
                             'AsanLibNull.inf'))
    real_classes = re.search(r'LIBRARY_CLASS\s*=\s*(.+)', real)
    null_classes = re.search(r'LIBRARY_CLASS\s*=\s*(.+)', null)
    check('both runtimes were found', None not in (real_classes, null_classes))
    check('the reporting runtime offers no PEIM flavour',
          real_classes and 'PEIM' not in real_classes.group(1),
          f'{real_classes and real_classes.group(1)}')
    check('it does offer DXE_CORE and SMM_CORE',
          real_classes and 'DXE_CORE' in real_classes.group(1)
          and 'SMM_CORE' in real_classes.group(1),
          f'{real_classes and real_classes.group(1)}')
    check('the one that does offer PEIM is the Null one',
          null_classes and 'PEIM' in null_classes.group(1),
          f'{null_classes and null_classes.group(1)}')
    check('the reporting runtime has a DXE-shaped constructor',
          'CONSTRUCTOR' in real and 'CONSTRUCTOR' not in null,
          'AsanLibConstructor takes an ImageHandle and a SystemTable, which a PEIM has '
          'neither of')
    hooks = read(os.path.join(ROOT, 'uefi_asan', 'AsanLibNull', 'AsanNull.c'))
    bodies = re.findall(
        r'void __asan_(?:load|store)(?:##size)?[^(]*\([^)]*\)\s*(?:\\\s*)?\n?\{([^}]*)\}',
        hooks)
    check('every load/store hook the Null runtime defines has an empty body',
          bodies and all(not re.sub(r'[\s\\]', '', b) for b in bodies),
          f'{len(bodies)} found, non-empty: '
          f'{[b for b in bodies if re.sub(chr(92) + "s", "", b)][:2]}')
    check('so an instrumented PEIM emits calls that do nothing',
          len(bodies) >= 8, f'{len(bodies)} hooks -- too few to be the whole family')
    memdetect = read(os.path.join(FORK, 'OvmfPkg', 'PlatformPei', 'MemDetect.c'))
    check('the HOB that tells the runtime where the shadow is comes from a PEIM',
          'BuildGuidDataHob (&gAsanInfoGuid' in memdetect,
          'OvmfPkg/PlatformPei is itself a PEIM, so everything dispatched before it '
          'has no shadow to consult')
    inc = read(DSC_INC)
    pei_section = sections(inc, '[LibraryClasses.common.PEIM]')
    core_section = sections(inc, '[LibraryClasses.common.DXE_CORE]')
    check('the include gives PEI the Null instance and only that',
          len(pei_section) == 1
          and 'AsanLibNull/AsanLibNull.inf' in pei_section[0][1]
          and 'Library/AsanLib/AsanLib.inf' not in pei_section[0][1],
          f'{pei_section and pei_section[0][1].strip()[:120]}')
    check('and DXE_CORE the real one',
          len(core_section) == 1
          and 'AsanLib|MdeModulePkg/Library/AsanLib/AsanLib.inf' in core_section[0][1],
          f'{core_section and core_section[0][1].strip()[:120]}')

    print('\nthe exclusion is recorded in two places and they agree')
    plat = deduped_dsc()
    check('the platform DSC was read and deduped',
          bool(plat) and plat.count('[Defines]') >= 1 and len(plat) > 10000,
          f'{len(plat)} characters')
    overrides = component_overrides(plat)
    switched_off = sorted(module for module, values in overrides.items()
                          if values and not any(instruments(v) for v in values))
    check('every module this file excludes is excluded in the DSC too',
          all(module in switched_off for module in asan_scope.EXCLUDED),
          f'table={sorted(asan_scope.EXCLUDED)} dsc={switched_off}')
    check('and the DSC excludes nothing this file does not know about',
          switched_off == sorted(asan_scope.EXCLUDED),
          f'{switched_off} -- an exclusion in one place and not the other is how a '
          f'module goes dark with nobody able to say why')
    check('the DSC still records why that one is excluded',
          'Never instrumented' in plat and 'S3 boot script' in plat,
          'a named exclusion with no measurement behind it is a silent one with '
          'extra steps')

    print('\nstack instrumentation is per module, and both SMM gates agree')
    scope_flags = re.findall(r'\*_CLANGSAN_X64_SAN_FLAGS\s*==\s*\$\(ASAN_SAN_FLAGS\)'
                             r'\s*-mllvm\s*-asan-stack=0', plat)
    check('the platform restates the flags with -asan-stack=0',
          len(scope_flags) >= 1, f'{len(scope_flags)}')
    check('the full-scope default carries it',
          re.search(r'"\$\(ASAN_SCOPE\)" == "full"', inc)
          and '$(ASAN_SAN_FLAGS) -mllvm -asan-stack=0' in inc,
          'removing it faults the boot in CpuDxe: clang writes frame redzones inline '
          'and unconditionally, bypassing the MEM_TO_SHADOW guard')
    stack_on = sorted(module for module, values in overrides.items()
                      if any(instruments(v) and '-asan-stack=0' not in v
                             for v in values))
    check('at least one module opts into stack instrumentation',
          bool(stack_on), 'otherwise the stack-buffer-overflow row cannot score')
    check('the benchmark driver is one of them',
          any(m.endswith('/SanBenchDxe') for m in stack_on), f'{stack_on}')
    check('none of them is an SMM module',
          not any('SMM' in (module_type(FORK, m) or '').upper() for m in stack_on),
          f'{[(m, module_type(FORK, m)) for m in stack_on]} -- an SMM stack lives in '
          f'TSEG, and inline frame poisoning there writes shadow nothing maintains')
    smm_header = ('[BuildOptions.common.EDKII.DXE_SMM_DRIVER, '
                  'BuildOptions.common.EDKII.SMM_CORE]')
    gate = flag_setting(plat, smm_header)
    include_at = plat.find('!include MdeModulePkg/Include/Dsc/Asan.dsc.inc')
    check('exactly one block in the platform DSC sets the SMM sanitizer flags',
          gate is not None,
          f'{len(sections(plat, smm_header))} blocks with that header; two that set '
          f'SAN_FLAGS would win or lose by file order')
    check('and it comes after the include, which is why it wins',
          gate is not None and include_at >= 0 and include_at < gate[0],
          f'include at {include_at}, gate at {gate and gate[0]} -- editing only the '
          f'.inc instruments nothing and looks identical')
    arms = {'dsc': re.findall(r'\*_CLANGSAN_X64_SAN_FLAGS\s*==\s*(.+)',
                              gate[1] if gate else '')}
    # Two separate headers in the include, one per SMM module type, and both arms of the
    # knob live under each. Collected together because the question is about the strings,
    # not about which header carries them.
    arms['inc'] = [value
                   for header in ('[BuildOptions.common.EDKII.SMM_CORE]',
                                  '[BuildOptions.common.EDKII.DXE_SMM_DRIVER]')
                   for _at, body in sections(inc, header)
                   for value in re.findall(
                       r'\*_CLANGSAN_X64_SAN_FLAGS\s*==\s*(.+)', body)]
    check('both files state an enabled arm and a disabled arm',
          all(len(found) >= 2 for found in arms.values()),
          f'{ {k: len(v) for k, v in arms.items()} }')
    check('both enabled arms are the same flag string',
          all(any(v.strip() == '$(ASAN_SAN_FLAGS) -mllvm -asan-stack=0'
                  for v in found) for found in arms.values()),
          f'{arms} -- "==" replaces, so an arm listing a subset turns the rest off')
    check('both disabled arms are the same string too',
          all(any(v.strip() == '-Wno-frame-address' for v in found)
              for found in arms.values()), f'{arms}')
    check('and both are gated on the one knob',
          '!if "$(ASAN_SMM)" == "TRUE"' in inc
          and '!if "$(ASAN_SMM)" == "TRUE"' in plat,
          'two gates that do not read the same define are two gates')

    print('\nand the run says it, rather than leaving it to be re-derived')
    stage = code(source('fuzz_edk2'))
    check('the stage still reports both measurements',
          'images carry ASan symbols' in stage
          and 'modules have their own code instrumented' in stage,
          'the generous number and the honest one answer different questions')
    check('it names the remainder through this classifier',
          'asan_scope.describe(' in stage,
          'own_code_instrumented hands back the list and the stage used to drop it')
    check('and hands it a resolver, so a FILE_GUID module is not reported as dark '
          'for an unknown reason',
          re.search(r'asan_scope\.describe\(dark,\s*lambda\s+\w+:\s*module_type\(',
                    stage) is not None,
          'without it CpuMpPei\'s uniprocessor build has no INF and lands in unknown')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
