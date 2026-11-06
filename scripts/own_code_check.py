#!/usr/bin/env python3
"""Assert the instrumented stage says what the modules' OWN code carries.

The stage counted images whose .debug holds __asan_load/__asan_store and called that
"instrumented". For an SMM image that number is a fiction, and it is a fiction in the one
direction that matters.

A library instance is built once with the global flags, and BuildOptions cannot be scoped
to a library -- Asan.dsc.inc says so itself -- so every module links instrumented copies of
BaseLib and BaseMemoryLib whatever its own flags were. Asan.dsc.inc then switches ASan off
for SMM_CORE and DXE_SMM_DRIVER, because SMM needs its own shadow and runtime. The result:
an SMM driver's image carries the symbols while none of that driver's own code is checked.

Measured on eval1 run 42171026991: 288/290 images by symbols, against 0 of 17 SMM modules
by their own sources. Every injected bug in that tree sits in one of those 17, so a
campaign driving those handlers reports clean for a reason that has nothing to do with the
firmware being correct -- which is the exact outcome the gate's own comment says it exists
to prevent.

The measurement comes from the dependency file build(1) names on every compile line, so it
is per module rather than per directory: OvmfPkg/Spi builds DxeSpi, which is instrumented,
and SmmSpi, which is not, out of one directory.
"""

import os
import sys
import tempfile
import textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

FAILURES = []


def check(name, condition, detail=''):
    if condition:
        print(f'  ok    {name}')
    else:
        print(f'  FAIL  {name}' + (f' -- {detail}' if detail else ''))
        FAILURES.append(name)


def compile_line(module, obj, sanitized):
    """One clang command as build(1) logs it."""
    return ('"/workspace/llvm-15.0.7/build/bin/clang" -MMD -MF '
            f'/workspace/tmp/edk2/Build/OvmfX64/DEBUG_CLANGSAN/X64/{module}/OUTPUT/'
            f'{obj}.obj.deps -g -Os '
            + ('-fsanitize=address -mllvm -asan-stack=0 ' if sanitized else '')
            + f'-Wno-frame-address -c -o out.obj /workspace/tmp/edk2/{obj}.c')


def main():
    import fuzz_edk2 as fz

    work = tempfile.mkdtemp(prefix='ownchk-')
    # Two modules from ONE source directory, one instrumented and one not: the case a
    # per-directory measurement cannot express.
    plan = [
        ('OvmfPkg/Spi/DxeSpi', 'DxeSpi', True, 'DXE_DRIVER'),
        ('OvmfPkg/Spi/SmmSpi', 'SmmSpi', False, 'DXE_SMM_DRIVER'),
        ('OvmfPkg/RWVariable/RWVariable', 'RWVariable', False, 'DXE_SMM_DRIVER'),
        ('MdeModulePkg/Core/PiSmmCore/PiSmmCore', 'PiSmmCore', False, 'SMM_CORE'),
        ('OvmfPkg/PlatformPei/PlatformPei', 'PlatformPei', False, 'PEIM'),
        ('MdeModulePkg/Core/Dxe/DxeMain', 'DxeMain', True, 'DXE_CORE'),
    ]
    lines = []
    for module, obj, sanitized, kind in plan:
        lines.append(compile_line(module, obj, sanitized))
        # Every module also compiles AutoGen, and that one IS instrumented even where the
        # module is not. Without excluding it a dark module counts as covered.
        lines.append(compile_line(module, 'AutoGen', True))
        inf = os.path.join(work, f'{module}.inf')
        os.makedirs(os.path.dirname(inf), exist_ok=True)
        with open(inf, 'w') as handle:
            handle.write(textwrap.dedent(f'''
                [Defines]
                  INF_VERSION  = 0x00010005
                  BASE_NAME    = {obj}
                  MODULE_TYPE  = {kind}
                '''))
    text = '\n'.join(lines)

    own, total, dark = fz.own_code_instrumented(text, work)
    names = {m.split('/')[-1]: kind for m, kind in dark}

    print('what the measurement counts')
    check('every module in the log is counted once', total == 6, f'{total} of 6')
    check('a module whose own source was sanitized counts as instrumented', own == 2,
          f'{own} instrumented; DxeSpi and DxeMain are the only two')
    check('an instrumented AutoGen does not cover a dark module',
          'RWVariable' in names,
          'AutoGen is generated and nobody is looking for a bug in it')
    check('two modules from one directory are measured separately',
          'SmmSpi' in names and 'DxeSpi' not in names,
          f'{sorted(names)}: OvmfPkg/Spi builds both')

    print('what it says about them')
    check('an SMM driver is reported with its module type',
          names.get('RWVariable') == 'DXE_SMM_DRIVER', names.get('RWVariable'))
    check('the SMM core is too', names.get('PiSmmCore') == 'SMM_CORE',
          names.get('PiSmmCore'))
    check('a PEIM is named as a PEIM, not lumped in with SMM',
          names.get('PlatformPei') == 'PEIM', names.get('PlatformPei'))
    smm = [m for m, kind in dark if 'SMM' in (kind or '').upper()]
    check('the SMM ones can be picked out from the rest', len(smm) == 3,
          f'{len(smm)}: SmmSpi, RWVariable and PiSmmCore')
    check('a missing INF degrades to no type rather than a wrong one',
          fz.module_type(work, 'OvmfPkg/Nope/Nope') == '')
    check('no tree to read means no type', fz.module_type('', 'OvmfPkg/Spi/SmmSpi') == '')

    print('and that it reaches the stage detail')
    source = open(os.path.join(HERE, 'fuzz_edk2.py')).read()
    check('the stage reports own-code instrumentation',
          'own_code_instrumented(' in source.split('def own_code_instrumented')[-1],
          'the measurement exists but nothing calls it')
    check('and calls out the SMM modules by name',
          'NONE of the' in source and 'SMM module(s) are' in source,
          'the count alone reads as 99% healthy')

    print(f'{len(FAILURES)} failure(s)')
    return 1 if FAILURES else 0


if __name__ == '__main__':
    sys.exit(main())
