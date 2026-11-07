#!/usr/bin/env python3
"""Assert an address in SMRAM is attributed to the module that actually contains it.

Every finding from an SMI campaign is raised by code in SMRAM, and until this was fixed
none of it could be attributed. Two things were wrong, and they compounded:

  * Each core words its dispatch line differently -- "Loading driver at", "Loading SMM
    driver at", "Loading PEIM at" -- and the SMM core has no dispatch line at all, because
    PiSmmIpl relocates it by hand and says so in its own words ("SMM IPL loading SMM Core
    at SMRAM address 1FFBC000"). Only the first form was read, so all 16 SMM images and
    the SMM core were missing from the map.
  * Attribution then took the nearest base BELOW the address, with no upper bound. A
    missing module does not produce "unattributed"; it produces the wrong answer.

On eval1 run 42154605158 that put eight findings from SmiManage -- PiSmmCore+0x11385 --
under PeiCore.efi, a PEIM whose base is 1082 MB below the address and whose image cannot
contain it. The same gap would have filed a finding in the injected RWVariable driver the
same way.

The parser exists twice, in firness.py (which writes Module into crashes.csv during the
campaign) and in resolve_modules.py (which resolves addresses afterwards). Both are
checked, against one capture, because one of them being right is how this survived.
"""

import os
import re
import sys
import tempfile
import textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import resolve_modules as rm  # noqa: E402

FAILURES = []


def check(name, condition, detail=''):
    if condition:
        print(f'  ok    {name}')
    else:
        print(f'  FAIL  {name}' + (f' -- {detail}' if detail else ''))
        FAILURES.append(name)


def lift(*names):
    """Pull names out of firness.py without importing it.

    firness.py imports matplotlib at module scope, which is not installed everywhere this
    check runs, and the parser under test has no use for it.
    """
    src = open(os.path.join(HERE, 'firness.py')).read()
    namespace = {'re': re}
    for name in names:
        if name[0].isupper():
            found = re.search(rf'^{name} = .*?(?=\n(?:[A-Z_]+ = |#|def |\n))',
                              src, re.S | re.M)
        else:
            found = re.search(rf'^def {name}\(.*?(?=\n(?:def |[A-Z_]+ = |@))',
                              src, re.S | re.M)
        if not found:
            raise SystemExit(f'{name} is not in firness.py any more; update this check')
        exec(found.group(0), namespace)
    return namespace


# One capture, all four spellings. The bases are the real ones from run 42154605158, so
# the gap this check is about is the real gap: PeiCore sits 1082 MB below the SMM core.
CAPTURE = '''
    Loading PEIM at 0x0001BFD3000 EntryPoint=0x0001BFE1FB4 PeiCore.efi
    Loading driver at 0x0001DBB5000 EntryPoint=0x0001DBC95D5 DevicePathDxe.efi
    SMM IPL loading SMM Core at SMRAM address 1FFBC000
    Loading SMM driver at 0x0001FC75000 EntryPoint=0x0001FC7C1D8 RWVariable.efi
    Loading SMM driver at 0x0001FF8D000 EntryPoint=0x0001FF94F48 CpuIo2Smm.efi
'''

# Addresses to resolve, and the image that really contains each.
WANTED = [
    (0x1FFCD385, 'PiSmmCore', 'SmiManage, 0x11385 into the SMM core'),
    (0x1FC7C1D8, 'RWVariable', "the injected driver's own entry point"),
    (0x1DBC95D5, 'DevicePathDxe', 'an ordinary DXE driver'),
    (0x1BFE1FB4, 'PeiCore', 'a PEIM'),
]


def main():
    work = tempfile.mkdtemp(prefix='attrchk-')
    capture = os.path.join(work, 'debugcon.log')
    with open(capture, 'w') as handle:
        handle.write(textwrap.dedent(CAPTURE).lstrip('\n'))

    print('resolve_modules.py')
    imap = rm.map_from_logs([capture])
    check('every dispatch spelling is indexed', len(imap) == 5,
          f'{len(imap)} image(s) from a capture naming five')
    for ip, want, why in WANTED:
        got = rm.describe(imap, ip).split('.efi')[0].split('+')[0]
        check(f'{ip:#x} is {want} ({why})', got == want, f'resolved to {got!r}')
    check('an address above every image is unattributed',
          rm.describe(imap, 0x7FFFFFFF) == 'unattributed',
          f'got {rm.describe(imap, 0x7FFFFFFF)!r}; the nearest base below must not win '
          f'at any distance')
    check('an address below every image is unattributed',
          rm.describe(imap, 0x1000) == 'unattributed',
          rm.describe(imap, 0x1000))
    # The SMM core's line carries no entry point, so it cannot calibrate itself. It must
    # drop out of the calibration rather than contribute a delta measured against zero --
    # which would be the whole load address, and every offset resolved through it would
    # land in the wrong function with full confidence.
    #
    # build_entries() is stubbed because the real one needs built PE images. Supplying the
    # entry points is the only way this check is not vacuous: with no build tree there is
    # nothing to calibrate against and the guard is never reached.
    real = rm.build_entries
    rm.build_entries = lambda dirs: {'PiSmmCore': 0x5000, 'DevicePathDxe': 0x145D5}
    try:
        deltas = rm.calibration([capture], ('/nonexistent',))
    finally:
        rm.build_entries = real
    check('a module that reported an entry point does calibrate',
          'DevicePathDxe' in deltas, f'{deltas}; the stub must actually be reached')
    check('the entry-less SMM core line calibrates to nothing',
          'PiSmmCore' not in deltas,
          f'{deltas}: a delta measured against entry 0 is the load address itself')

    print('firness.py')
    fn = lift('LOAD_LINE', 'SMM_CORE_LINE', 'SMM_CORE_NAME', 'MAX_IMAGE',
              'note_loads', 'image_for', 'module_for')
    modules = []
    fn['note_loads'](open(capture).read(), modules)
    check('every dispatch spelling is indexed', len(modules) == 5,
          f'{len(modules)} image(s) from a capture naming five')
    for ip, want, why in WANTED:
        got = fn['module_for'](modules, ip)
        check(f'{ip:#x} is {want} ({why})', got == f'{want}.efi',
              f'resolved to {got or "(unattributed)"!r}')
    check('an address above every image is unattributed',
          not fn['module_for'](modules, 0x7FFFFFFF),
          f'got {fn["module_for"](modules, 0x7FFFFFFF)!r}; this is the PeiCore.efi bug')
    check('an address below every image is unattributed',
          not fn['module_for'](modules, 0x1000))
    check('the map is kept sorted by base', modules == sorted(modules),
          'image_for walks it in order and stops at the first base above the address')

    print('the two parsers agree')
    # The whole reason this was broken in production: one of them was right.
    mine = sorted((base, name.replace('.efi', '')) for base, name in modules)
    theirs = sorted((base, name) for base, _entry, name in rm.loads_from_logs([capture]))
    check('both read the same images out of one capture', mine == theirs,
          f'firness.py {mine} vs resolve_modules.py {theirs}')
    for ip, want, _why in WANTED:
        a = (fn['module_for'](modules, ip) or '').replace('.efi', '')
        b = rm.describe(imap, ip).split('.efi')[0].split('+')[0]
        check(f'both place {ip:#x} in {want}', a == b == want, f'{a!r} vs {b!r}')

    print('what the right name then lets the report say')
    # The artefact rule below is only reachable once attribution works, which is why it is
    # checked here. SmiManage is handed a pointer into the caller's buffer and CompareGuid
    # re-reads it once per registered handler, so the dispatch GUID is reported as a double
    # fetch about as many times as there are handlers -- 8 sites, 20 hits each, on run
    # 42154605158. It is not a defect: the GUID is only compared, and the caller chooses
    # which handler it wants anyway.
    import bug_report as br

    def cluster_of(klass, path):
        row = br.Report({'Phase': 'fuzz', 'Module': 'PiSmmCore.efi', 'File': path,
                         'Line': '160', 'Asan Msg': '', 'ErrorType': klass,
                         'Message': 'read of 4 bytes at 0x000000001B568000',
                         'Count': '20'}, 'DiscoveredSmi')
        found = br.Cluster(row.group_key())
        found.add(row)
        return found

    guid_walk = cluster_of('fwsan-double-fetch (read)',
                           'MdeModulePkg/Core/PiSmmCore/Smi.c')
    kind, why = br.verdict(guid_walk, set(), 8)
    check('the dispatcher GUID walk is filtered as an artefact', kind == 'artefact',
          f'{kind}: filed as 8 separate issues on run 42154605158')
    check('and it says why', 'CompareGuid' in why, why[:80])

    # The same file with a different class is the finding an SMI campaign exists to find.
    # A path-only rule would have thrown it away.
    real = cluster_of('heap-buffer-overflow (write)',
                      'MdeModulePkg/Core/PiSmmCore/Smi.c')
    kind, _why = br.verdict(real, set(), 8)
    check('a real defect in the same file still reports', kind == 'candidate',
          f'{kind}: suppressing Smi.c by path would hide the dispatcher bugs')

    # And the same class elsewhere is not covered by this rule.
    elsewhere = cluster_of('fwsan-double-fetch (read)',
                           'OvmfPkg/RWVariable/RWVariable.c')
    kind, _why = br.verdict(elsewhere, set(), 8)
    check('a double fetch in a handler still reports', kind == 'candidate',
          f'{kind}: a handler re-reading its own comm buffer is the real class')

    print('and the narration does not manufacture its own findings')
    # The ten candidates run 42176147435 filed as issues #37-#46 were all one DEBUG
    # statement. The dispatch narration was handed &CommunicateHeader->HeaderGuid -- a
    # pointer into the caller's buffer -- and %g formats a GUID through BasePrintLib:
    # ReadUnaligned32 for Data1, ReadUnaligned16 twice, then Data4[0..7] one byte at a
    # time. This core's own code is not instrumented and BasePrintLib is, so those ten
    # reads were the ONLY instrumented reads of the dispatch GUID in the whole SMI and
    # every one came back as a double fetch: ten sites, 71662 hits each.
    core = os.path.join(os.path.dirname(HERE), 'eval_source', 'edk2', 'MdeModulePkg',
                        'Core', 'PiSmmCore', 'PiSmmCore.c')
    text = open(core).read() if os.path.isfile(core) else ''
    check('the port carries the dispatch narration', 'SmmCore: dispatch %g' in text, core)
    narration = text.split('SmmCore: dispatch %g')[-1][:200] if text else ''
    check('it prints a local, not a pointer into the comm buffer',
          '&DispatchGuid' in narration
          and '&CommunicateHeader->HeaderGuid' not in narration,
          narration.strip().splitlines()[1:3])
    copy = text.find('DispatchGuid = ')
    manage = text.find('Status = SmiManage (')
    check('the copy is taken before SmiManage runs',
          0 < copy < manage,
          'a handler may scribble the buffer, and then the narration names the wrong GUID')
    # CopyGuid and CopyMem are BaseMemoryLib and BaseLib, which ARE instrumented -- routing
    # the copy through either one puts the reads straight back where they were.
    check('the copy is a plain assignment, not a library call',
          'DispatchGuid = CommunicateHeader->HeaderGuid;' in text,
          'CopyGuid/CopyMem read through instrumented BaseLib and report the same ten '
          'sites from one line instead of ten')

    print('and a print that reads untrusted memory twice is not filed as a defect')
    printlib = cluster_of('fwsan-double-fetch (read)',
                          '/workspace/tmp/edk2/MdePkg/Library/BasePrintLib/'
                          'PrintLibInternal.c')
    kind, why = br.verdict(printlib, set(), 8)
    check('a double fetch inside BasePrintLib is an artefact', kind == 'artefact',
          f'{kind}: filed as issues #39-#46 on run 42176147435')
    check('and it says why a print cannot be the defect', 'decide' in why, why[:90])
    # Deliberately NOT filtered. BaseLib is linked into everything and ReadUnaligned is a
    # real way to re-read a validated field; blanket-filtering it to tidy up the same run's
    # report would hide the class in every module at once.
    baselib = cluster_of('fwsan-double-fetch (read)',
                         '/workspace/tmp/edk2/MdePkg/Library/BaseLib/Unaligned.c')
    kind, _why = br.verdict(baselib, set(), 8)
    check('a double fetch inside BaseLib still reports', kind == 'candidate',
          f'{kind}: ReadUnaligned32 on a re-read field is the real class')

    # ... but ReadUnaligned64 at the dispatcher is that same handler walk, attributed to
    # the library instead of the caller. CompareGuid compares two GUIDs as a pair of
    # UINT64s, so the re-read lands on BaseLib and the first artefact entry's
    # PiSmmCore/Smi.c never matches it.
    #
    # It only became visible once the firmware classes stopped sharing the outline
    # handlers' dedup table. Before that the boot reported this very IP as a
    # global-buffer-overflow -- run 42186976238 has it in the background bucket at
    # Unaligned.c:186:10 with 1 hit -- and every later double fetch at it was dropped as
    # already-seen, which is why 6403878 detections produced no report at all. Run
    # 42310220335, with the tables separated, filed it as one sev1 cluster of 165616 hits.
    # The values below are that cluster's, as bugs.json recorded them.
    guid64 = cluster_of('fwsan-double-fetch (read)',
                        'MdePkg/Library/BaseLib/Unaligned.c:186')
    kind, why = br.verdict(guid64, set(), 8)
    check('the dispatcher GUID compare through ReadUnaligned64 is an artefact',
          kind == 'artefact', f'{kind}: 165616 hits as a sev1 candidate on run 42310220335')
    check('and it says the GUID is only compared', 'compared' in why, why[:80])

    # The same site in another module is not the dispatcher's walk.
    elsewhere64 = br.Report({'Phase': 'fuzz', 'Module': 'VariableSmm.efi',
                             'File': 'MdePkg/Library/BaseLib/Unaligned.c:186',
                             'Line': '186', 'Asan Msg': '',
                             'ErrorType': 'fwsan-double-fetch (read)',
                             'Message': 'read of 8 bytes at 0x000000001B568000',
                             'Count': '20'}, 'DiscoveredSmi')
    other = br.Cluster(elsewhere64.group_key())
    other.add(elsewhere64)
    kind, _why = br.verdict(other, set(), 8)
    check('the same site in another module still reports', kind == 'candidate',
          f'{kind}: only the dispatcher compares a caller GUID against a handler list')

    print(f'{len(FAILURES)} failure(s)')
    return 1 if FAILURES else 0


if __name__ == '__main__':
    sys.exit(main())
