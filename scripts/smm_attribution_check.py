#!/usr/bin/env python3
"""Assert an SMM report is attributed from its OWN ip, not from a neighbour's.

Run 42943602615 was the first campaign with SMM code instrumented, and it filed

    SmmLockBox.efi | MdePkg/Library/UefiLib/UefiDriverModel.c:679 | 8824 hits

for three reports whose own messages carry ip 0x1F901170, 0x1F99AE2D and 0x1FF21688.
Those ips lie in SmmFaultTolerantWriteDxe, VariableSmm and SmmLockBox respectively, so two
of the three module names were wrong -- and the source line that travelled with the wrong
module was wrong with it: UefiDriverModel.c holds driver-binding helpers that never run
during an SMI.

The image map was NOT at fault. Both implementations -- firness.py's note_loads/module_for
and resolve_modules.py's ImageMap -- resolve all three correctly from the same
debugcon.log, which carries all seven "Loading SMM driver at 0x.. EntryPoint=0x.. Name.efi"
lines plus the SMM core's own line. What was wrong is that the streaming pass paired a
file-and-line with the NEXT ip line it saw and then applied that one module to every report
still queued. That was safe only while reports arrived strictly one at a time, and with SMM
instrumented they do not: AsanLib takes no lock and the SMI rendezvous runs instrumented
library code on every AP, so a header from one CPU is followed by an ip from another.

The bases below are the ones measured in that run, so the regression this guards against is
the one that happened.

Run: python3 scripts/smm_attribution_check.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import module_attribution_check as mac  # noqa: E402  (its lift() avoids importing firness)

FAILED = 0
PASSED = 0

# From run 42943602615's campaign debugcon.log, verbatim.
LOADS = """
SMM IPL loading SMM Core at SMRAM address 1FF89000
Loading SMM driver at 0x0001F8F2000 EntryPoint=0x0001F903A58 SmmFaultTolerantWriteDxe.efi
Loading SMM driver at 0x0001F902000 EntryPoint=0x0001F90CED8 CpuHotplugSmm.efi
Loading SMM driver at 0x0001F987000 EntryPoint=0x0001F9A47D8 VariableSmm.efi
Loading SMM driver at 0x0001F9E9000 EntryPoint=0x0001F9F5F51 FvbServicesSmm.efi
Loading SMM driver at 0x0001FE7C000 EntryPoint=0x0001FEB26C8 PiSmmCpuDxeSmm.efi
Loading SMM driver at 0x0001FF20000 EntryPoint=0x0001FF28268 SmmLockBox.efi
Loading SMM driver at 0x0001FF55000 EntryPoint=0x0001FF5D698 CpuIo2Smm.efi
"""

# ip -> the image that really owns it, as the bases above place it
OBSERVED = (
    (0x1F901170, 'SmmFaultTolerantWriteDxe.efi'),
    (0x1F99AE2D, 'VariableSmm.efi'),
    (0x1FF21688, 'SmmLockBox.efi'),
)


def check(what, ok, detail=''):
    global FAILED, PASSED
    if ok:
        PASSED += 1
        print(f'  [OK]   {what}')
    else:
        FAILED += 1
        print(f'  [FAIL] {what}' + (f'\n         {detail}' if detail else ''))


class Entry:
    """Enough of AsanError for the attribution pass."""

    def __init__(self, ip, module=''):
        self.message = (f'address 0x{0x1BF38018:016X}, size 0x0000000000000004, '
                        f'is_write 0x0000000000000000, ip 0x{ip:016X}')
        self.module = module


def main():
    ns = mac.lift('LOAD_LINE', 'SMM_CORE_LINE', 'SMM_CORE_NAME', 'MAX_IMAGE', 'REPORT_IP',
                  'note_loads', 'image_for', 'module_for', 'attribute_from_own_ip')

    print('the image map built from the real load lines')
    modules = []
    ns['note_loads'](LOADS, modules)
    check('all 7 SMM drivers plus the core are parsed', len(modules) == 8,
          f'{len(modules)}: the "Loading SMM driver at" spelling carries the base AND the '
          f'name, and the core announces itself separately with no 0x and no file name')
    names = {n for _, n in modules}
    check('the SMM core is named', 'PiSmmCore.efi' in names or 'PiSmmCore' in names,
          f'{sorted(names)}')

    print('\neach observed ip resolves to the image that owns it')
    for ip, want in OBSERVED:
        got = ns['module_for'](modules, ip)
        check(f'ip 0x{ip:08X} -> {want}', got == want, f'got {got!r}')

    print('\nattribution comes from the report, not from its neighbour')
    # The exact shape that misfiled: three reports queued, resolved off one ip.
    crashes = {i: Entry(ip) for i, (ip, _) in enumerate(OBSERVED)}
    fixed = ns['attribute_from_own_ip'](crashes, modules)
    check('the pass reports how many it corrected', fixed == 3, f'returned {fixed}')
    for i, (ip, want) in enumerate(OBSERVED):
        check(f'report {i} keeps its own module ({want})',
              crashes[i].module == want,
              f'got {crashes[i].module!r} for ip 0x{ip:08X}')
    check('the three do not collapse to one module',
          len({e.module for e in crashes.values()}) == 3,
          f'{sorted({e.module for e in crashes.values()})} -- one module across ips in '
          f'different images is the bug this guards')

    print('\na wrong module already set is corrected, not kept')
    wrong = {0: Entry(0x1F901170, module='SmmLockBox.efi')}
    ns['attribute_from_own_ip'](wrong, modules)
    check('a neighbour-attributed module is replaced',
          wrong[0].module == 'SmmFaultTolerantWriteDxe.efi',
          f'got {wrong[0].module!r}: the streaming pass sets module before this runs, so '
          f'the pass has to overwrite rather than only fill blanks')

    print('\na report with no ip of its own is left alone')
    class NoIp:
        message = 'double free detected'
        module = ''
    blank = {0: NoIp()}
    ns['attribute_from_own_ip'](blank, modules)
    check('no module is invented for it', blank[0].module == '',
          'a neighbour ip is not an approximation of an address this report never printed')

    print('\nan ip in no image is not forced into the nearest one')
    far = {0: Entry(0x0000FFFF)}
    ns['attribute_from_own_ip'](far, modules)
    check('an ip below every base stays unattributed', far[0].module == '',
          f'got {far[0].module!r}')
    # measured from the HIGHEST base, which is PiSmmCore at 0x1FF89000 and not the last
    # "Loading SMM driver" line -- the first version of this assertion used CpuIo2Smm and
    # landed inside PiSmmCore, which resolved correctly and read as a failure
    way = {0: Entry(max(b for b, _ in modules) + ns['MAX_IMAGE'] + 0x1000)}
    ns['attribute_from_own_ip'](way, modules)
    check(f'an ip more than MAX_IMAGE past a base stays unattributed',
          way[0].module == '',
          f'got {way[0].module!r}: without the bound the nearest base below always won, '
          f'which is how an SMRAM address once came back as PeiCore.efi')

    print('\nand the pipeline actually runs it')
    # The assertions above lift the function; none of them would notice if nothing called
    # it. collect_unique_crashes must, after the capture is read and before the rows are
    # written, or every row keeps whatever the streaming pass guessed.
    with open(os.path.join(HERE, 'firness.py'), encoding='utf-8') as handle:
        source = handle.read()
    check('collect_unique_crashes calls attribute_from_own_ip',
          'attribute_from_own_ip(crashes, modules)' in source)
    call = source.find('corrected = attribute_from_own_ip(crashes, modules)')
    write = source.find('crash_list = save_crashes_to_file(crashes, output_dir)')
    check('it runs before the rows are written', 0 <= call < write,
          f'call at {call}, write at {write}: after the write it changes nothing')
    check('the streaming pass attributes one report, not the whole queue',
          'if owner and not pending[-1].module:' in source
          and 'for entry in pending:' not in source,
          'applying one ip to every queued report is what collapsed three images into one')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
