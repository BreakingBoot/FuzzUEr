#!/usr/bin/env python3
"""Assert a double fetch is reported as what it is, and once per routine.

Run 43452927684 produced 91 candidates and 82 of them were `fwsan-double-fetch (read)`.
Every one carried the same sentence -- "the OS can rewrite the buffer between the read that
validated the value and the read that uses it" -- and for ~75 of them that is not true. The
class needs a writer able to act between the two reads. An SMI has one: the OS keeps
running on the other cores and the comm buffer stays mapped and writable for the whole
dispatch. A DXE protocol call has none: no OS, nothing else executing, and a buffer the
calling firmware owns. The two were reported identically, which is what a reader meant by
"not helpful by themselves for a developer to understand what to patch".

The distinction was already known and thrown away. CommBufferJoin sets, in so many words,
"no smi-function-guid-map.json in the campaign, so the registered buffer is a protocol
argument rather than a comm buffer" -- and then the row rendered as though it were one.

Dropping every DXE one would lose a real class of finding, so the file decides it. A
library instance is compiled once and linked into both kinds of module: on that run
MdePkg/Library/BaseLib/Unaligned.c is in all 17 modules that run in SMRAM, so a re-read a
DXE campaign reached there is the same object code an SMI handler runs on the comm buffer.
That is read out of the firmware that was built -- each module's link map names the objects
it pulled in, each module's INF says whether it runs in SMRAM -- and not out of a list of
library names, because a list is wrong as soon as the tree moves. The same run resolves
DevicePathLib to UefiDevicePathLib for DXE and UefiDevicePathLibDevicePathProtocol for
DXE_SMM_DRIVER, so DevicePathUtilities.c is in two DXE images and no SMM one; nothing about
the library class name says so.

The second half is counting. LinkedList.c:596, :597 and :598 are three consecutive lines of
one list walk and were filed as issues #105, #106 and #109; HiiStringToImage raised ten
between Font.c:2913 and :2955, one issue each. One fix closes a routine's worth, so a
double fetch clusters on the routine and prints its lines in the detail.

The no-split rule below is here rather than in a check of its own because it is the same
rule: a key that names a routine is one site, and splitting it again by line proximity is
splitting on data the key was chosen because it could not trust. It is what made SmmSpi's
one overflow into issues #68 and #69 -- two rows at one faulting address whose Line column
held 533070167 and 533070366, which are two instruction pointers 199 apart.

Run: python3 scripts/double_fetch_check.py
"""

import importlib.util
import io
import json
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FAILED = PASSED = 0

# The field text AsanLib appends to a double-fetch report, which is what makes a row one.
FIELD = ('untrusted_field offset=0x8 base=0x16F58A28 extent=0x1000 '
         'first_ip=0x18D23CA3 first_addr=0x16F58A30 first_bytes=0x4')
ACCESS = 'address 0x16F58A30, size 0x4, is_write 0x0, ip 0x18D23F00, ' + FIELD

# Where the fixture's sources live, package-relative, as a report's File column spells it.
BASELIB = 'MdePkg/Library/BaseLib'
DXECORE = 'MdeModulePkg/Core/Dxe'
HIIFONT = 'MdeModulePkg/Universal/HiiDatabaseDxe'


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
    """A definition with its prose removed -- docstring and comments both.

    Every assertion on source text here would otherwise pass on the explanation: the
    comments in bug_report.py name UefiDevicePathLib, quote the TOCTOU sentence and say
    what a hardcoded list would look like, which is exactly what is being asserted absent.
    line_table_check.py carries the same helper for the same reason.
    """
    out = []
    for block in text.split('"""'):
        out.append(block)
    # Odd-indexed pieces are inside a docstring, so keep the even ones.
    text = ''.join(block for index, block in enumerate(out) if index % 2 == 0)
    return '\n'.join(line for line in text.splitlines()
                     if not line.strip().startswith('#'))


def region(src, start, end):
    """The text from one top-level marker up to the next, both given literally."""
    at = src.index(start)
    return src[at:src.index(end, at + len(start))]


def tree():
    """A build tree shaped like the one triage is given, with two modules in it.

    Three decisions are in the shape rather than in any file's contents, so the fixture has
    to have it: the INF sits beside the module's build directory, a library member in the
    map resolves to the directory that library's sources are in, and only the OUTPUT copy
    of a map is read (edk2 writes the same map into DEBUG as well).
    """
    root = tempfile.mkdtemp(prefix='doublefetch-')

    def write(path, text):
        full = os.path.join(root, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        io.open(full, 'w', encoding='utf-8').write(text)
        return full

    build = 'Build/OvmfX64/DEBUG_CLANGSAN/X64'
    lib = f'/workspace/{build}/MdePkg/Library/BaseLib/BaseLib/OUTPUT/BaseLib.lib'
    smm_own = (f'/workspace/{build}/MdeModulePkg/Universal/Variable/RuntimeDxe/'
               f'VariableSmm/OUTPUT/VariableSmm.lib')
    hii = f'/workspace/{build}/{HIIFONT}/HiiDatabaseDxe/OUTPUT/HiiDatabase.lib'

    write('MdeModulePkg/Universal/Variable/RuntimeDxe/VariableSmm.inf',
          '[Defines]\n  BASE_NAME = VariableSmm\n  MODULE_TYPE = DXE_SMM_DRIVER\n')
    write(f'{build}/MdeModulePkg/Universal/Variable/RuntimeDxe/VariableSmm/OUTPUT/'
          'VariableSmm.map',
          'Archive member included to satisfy reference by file (symbol)\n'
          '\n'
          f'{smm_own}(Variable.obj)\n'
          '                              (--whole-archive)\n'
          f'{lib}(Unaligned.obj)\n'
          '                              (--whole-archive)\n'
          f'{lib}(LinkedList.obj)\n'
          '                              (--whole-archive)\n'
          f'{lib}(X64Thunk.obj)\n'
          '\n'
          ' .text          0x0000000000000000        0x0 '
          f'{hii}(Font.obj)\n')
    # The DEBUG copy of the same map, which must not be read a second time.
    write(f'{build}/MdeModulePkg/Universal/Variable/RuntimeDxe/VariableSmm/DEBUG/'
          'VariableSmm.map', f'{lib}(Database.obj)\n')

    write('MdeModulePkg/Core/Dxe/DxeMain.inf',
          '[Defines]\n  BASE_NAME = DxeCore\n  MODULE_TYPE = DXE_CORE\n')
    write(f'{build}/MdeModulePkg/Core/Dxe/DxeMain/OUTPUT/DxeCore.map',
          f'/workspace/{build}/MdeModulePkg/Core/Dxe/DxeMain/OUTPUT/DxeCore.lib'
          '(Event.obj)\n'
          f'{lib}(Unaligned.obj)\n')

    write(f'{HIIFONT}/HiiDatabaseDxe.inf',
          '[Defines]\n  BASE_NAME = HiiDatabase\n  MODULE_TYPE = DXE_DRIVER\n')
    write(f'{build}/{HIIFONT}/HiiDatabaseDxe/OUTPUT/HiiDatabase.map',
          f'{hii}(Font.obj)\n')
    return root


def row(**kw):
    """One report, in the shape the grouping sees it.

    A double fetch reaches crashes.csv with "fwsan" where the file goes and locate()
    resolves it, and symbolise_offset answers "path:line:col" while locate() splits only
    the column off -- so by the time anything is grouped the PATH ends in ":2913" and the
    Line column holds a column number. That is not a detail: the file name carrying the
    line is why one routine's reads were one cluster per line, and a fixture that writes
    the tidy shape instead asserts nothing about the code that runs.
    """
    base = {'Phase': 'fuzz', 'AtBoot': '', 'Module': 'HiiDatabase.efi',
            'Function': 'HiiStringToImage', 'File': f'/build/edk2/{HIIFONT}/Font.c:2913',
            'Line': '23', 'Asan Msg': 'fwsan-double-fetch', 'ErrorType': 'asan',
            'Message': ACCESS, 'Count': '1'}
    base.update(kw)
    return base


def at(path, line, column='10'):
    """The File and Line columns for a resolved report at one source line."""
    return {'File': f'/build/edk2/{path}:{line}', 'Line': column}


def campaigns(rows_by_campaign, smi=()):
    """A campaign root, one directory per campaign, as load() walks it.

    A campaign carrying smi-function-guid-map.json drove SMI handlers and its registered
    buffer is a comm buffer; one without it drove a protocol member. That file is the
    whole of the distinction, and it is written here rather than asserted about, so the
    check drives the same decision load() takes rather than a restatement of it.
    """
    root = tempfile.mkdtemp(prefix='doublefetch-campaigns-')
    import csv
    for name, rows in rows_by_campaign.items():
        os.makedirs(os.path.join(root, name))
        with open(os.path.join(root, name, 'crashes.csv'), 'w', newline='') as handle:
            writer = csv.DictWriter(handle, fieldnames=list(row().keys()))
            writer.writeheader()
            for one in rows:
                writer.writerow(one)
        if name in smi:
            with open(os.path.join(root, name,
                                   'smi-function-guid-map.json'), 'w') as handle:
                json.dump({'SmmLockBoxHandler': {'Type': 'EFI_SMM_LOCK_BOX_PARAMETER'}},
                          handle)
    return root


def clustered(br, root, build_dirs=()):
    """{site: cluster} for one campaign root, through the real load()."""
    found, _rows = br.load(root, build_dirs)
    return {cluster.site: cluster for cluster in found.values()}, found


def main():
    br = load('bug_report')
    src = source('bug_report')

    print('the inventory is read out of the firmware, not out of a list of names')
    inventory = code(region(src, 'class SmmLinkage:', '\nMMIO_LOW'))
    check('the module type comes from the INF', 'MODULE_TYPE_RE' in inventory,
          'whether an image runs in SMRAM is a property of the module, and the INF is '
          'where the build read it from too')
    check('the objects come from the link map', 'MAP_MEMBER' in inventory,
          'the map is the only record of what the linker actually pulled in')
    check('no library is named in the decision',
          not any(name in inventory for name in
                  ('UefiDevicePathLib', 'BaseLib', 'DevicePathUtilities', 'Unaligned')),
          f'a hardcoded list is wrong as soon as the DSC resolves a class differently, '
          f'which this very tree does:\n         {inventory[:200]}')
    decision = code(br.verdict.__doc__ or '') + code(
        region(src, 'def verdict(', '\nVERDICT_NOTE'))
    check('the verdict asks the cluster, not a path list',
          'smm_modules' in decision and 'protocol_argument' in decision,
          decision[-300:])

    root = tree()
    try:
        print('\nand it answers for the firmware that was built')
        live = br.SmmLinkage([root])
        check('a tree with modules in it can be asked', live.known,
              f'typed {live.typed} of {live.images} map(s)')
        check('it found the module that runs in SMRAM', live.smm == ['VariableSmm'],
              f'{live.smm} -- DxeCore and HiiDatabase are DXE and must not be in here')
        check('a BaseLib file is linked into it',
              live.modules_for(f'/build/edk2/{BASELIB}/Unaligned.c') == ('VariableSmm',),
              str(live.modules_for(f'/build/edk2/{BASELIB}/Unaligned.c')))
        check('a file only DXE modules compile is not',
              live.modules_for(f'/build/edk2/{DXECORE}/Event/Event.c') == (),
              f'{live.modules_for(f"/build/edk2/{DXECORE}/Event/Event.c")} -- Event.c is '
              f'in DxeCore, which is DXE_CORE')
        check('a driver source no SMM module compiles is not',
              live.modules_for(f'/build/edk2/{HIIFONT}/Font.c') == (),
              f'{live.modules_for(f"/build/edk2/{HIIFONT}/Font.c")} -- Font.obj appears '
              f'in the SMM map only in a section that is not a member list')
        check('the SMM module\'s own source resolves to it',
              live.modules_for('/build/edk2/MdeModulePkg/Universal/Variable/RuntimeDxe/'
                               'Variable.c') == ('VariableSmm',),
              'the map names <module dir>/<inf stem>/OUTPUT, and the sources are one '
              'level above that')
        check('a source in a subdirectory of a library walks up',
              live.modules_for(f'/build/edk2/{BASELIB}/X64/X64Thunk.c')
              == ('VariableSmm',),
              'BaseLib keeps per-architecture sources below its own directory')
        check('a line that merely mentions a library is not linkage',
              live.modules_for(f'/build/edk2/{HIIFONT}/Font.c') == ()
              and live.modules_for(f'/build/edk2/{BASELIB}/Unaligned.c') != (),
              'a map names each member once in its member list and again in every '
              'section that places it, and matching anywhere in a line would make every '
              'module compile every file it links against')

        print('\na run with nothing to read says so rather than saying no')
        blind = br.SmmLinkage([])
        check('no build tree means the question cannot be asked', not blind.known,
              'an absence of evidence read as "no SMM module compiles it" would drop '
              'every double fetch in a run that simply did not carry the inventory')
        check('and it claims no modules either', blind.modules_for('x/MdePkg/a/b.c') == ())

        print('\nthe sentence under a finding describes the caller it happened in')
        smi_root = campaigns({'DiscoveredSmi': [row(Module='VariableSmm.efi',
                                                    Function='ReadUnaligned16', Count='16',
                                                    **at(f'{BASELIB}/Unaligned.c', 32))]},
                             smi=('DiscoveredSmi',))
        sites, _ = clustered(br, smi_root, [root])
        comm = sites.get('ReadUnaligned16')
        check('a comm-buffer double fetch is still reported', comm is not None,
              str(sorted(sites)))
        check('and keeps the TOCTOU sentence', comm and br.TOCTOU in comm.detail(),
              comm.detail() if comm else '')
        check('because the campaign carried a handler map',
              comm and not comm.protocol_argument(),
              'the map is what says the registered buffer is a comm buffer')
        # Guarded, because a cluster that went missing is already reported above and a
        # dereference here would replace the next assertions with a traceback.
        kind, _why = br.verdict(comm, set(), 8) if comm else ('(no cluster)', '')
        check('it is a candidate', kind == 'candidate', kind)
        shutil.rmtree(smi_root, ignore_errors=True)

        print('\nand a protocol argument gets what is true of a protocol argument')
        dxe_root = campaigns({'EfiHiiFont': [
            row(Module='DxeCore.efi', Function='ReadUnaligned16', Count='681',
                **at(f'{BASELIB}/Unaligned.c', 32)),
            row(Module='DxeCore.efi', Function='CoreCheckTimers', Count='169',
                **at(f'{DXECORE}/Event/Timer.c', 54)),
            # No source position at all, which is how firness.py writes a row whose line
            # it could not trust: the routine is known and the file is not. Its own ip,
            # because merge_by_ip pairs an unlocated row with the located one that shares
            # one -- they would be two rows for a single access, which this is not.
            row(Module='UsbBusDxe.efi', Function='UsbFindChild', File='fwsan',
                Line='389201906', Count='10',
                Message='address 0x1830BB28, size 0x8, is_write 0x0, ip 0x1830A000, '
                        + FIELD),
            # A second routine in the same file, two lines of it, so what keeps these
            # apart from the ten above is the routine and nothing else.
            row(Function='HiiGetFontInfo', Count='7',
                **at(f'{HIIFONT}/Font.c', 1106, '86')),
            row(Function='HiiGetFontInfo', Count='3',
                **at(f'{HIIFONT}/Font.c', 1112, '88')),
        ] + [row(Count='100', **at(f'{HIIFONT}/Font.c', line, column))
             for line, column in ((2913, '23'), (2915, '23'), (2917, '23'), (2919, '23'),
                                  (2921, '23'), (2933, '61'), (2943, '61'), (2947, '62'),
                                  (2951, '67'), (2955, '67'))]})
        sites, every = clustered(br, dxe_root, [root])

        linked = sites.get('ReadUnaligned16')
        check('a re-read in a file an SMM module compiles survives', linked is not None,
              str(sorted(sites)))
        kind, _why = br.verdict(linked, set(), 8) if linked else ('(no cluster)', '')
        check('as a candidate', kind == 'candidate', kind)
        check('it does not claim a TOCTOU that cannot happen in DXE',
              linked and br.TOCTOU not in linked.detail(),
              linked.detail() if linked else '')
        check('it says both reads are in a DXE caller',
              linked and br.DXE_REREAD in linked.detail(),
              linked.detail() if linked else '')
        check('and names the SMM module that makes it matter',
              linked and 'VariableSmm' in linked.detail(),
              f'{linked.detail() if linked else ""} -- "also linked into SMM" with no '
              f'module named is a claim a reader cannot check')

        dropped = sites.get('CoreCheckTimers')
        check('a re-read in a file no SMM module compiles is still clustered',
              dropped is not None, str(sorted(sites)))
        kind, why = br.verdict(dropped, set(), 8) if dropped else ('(no cluster)', '')
        check('but it is not a candidate', kind == 'artefact', f'{kind}: {why}')
        check('and the reason says why, naming the file',
              'DXE caller' in why and f'{DXECORE}/Event/Timer.c' in why
              and 'Timer.c:54' not in why, why)
        check('it is filtered, not deleted -- --show-filtered still prints it',
              kind in ('harness', 'artefact', 'background'),
              f'{kind} is not one of the buckets bugs.md counts and --show-filtered lists')

        unnamed = sites.get('UsbFindChild')
        check('a re-read whose file is unknown is still clustered', unnamed is not None,
              str(sorted(sites)))
        kind, _why = br.verdict(unnamed, set(), 8) if unnamed else ('(no cluster)', '')
        check('and is kept, because no file means no answer either way',
              kind == 'candidate',
              f'{kind} -- "this file is in no SMM module" and "nothing here can name the '
              f'file" are different answers and only one of them drops a finding')
        check('the row says which of the two it is',
              unnamed and br.SMM_UNCHECKED in unnamed.detail(),
              unnamed.detail() if unnamed else '')

        print('\none loop is one finding')
        loop = sites.get('HiiStringToImage')
        check('ten lines in one routine are one cluster', loop is not None,
              f'{sorted(sites)} -- Font.c:2913 to :2955 were ten issues')
        check('the cluster counts every report', loop and loop.hits == 1000,
              str(loop.hits if loop else None))
        check('the site is the routine, which is what gets fixed',
              loop and loop.site == 'HiiStringToImage', loop.site if loop else '')
        check('and the detail still names every line',
              loop and all(f'{n}' in loop.line_list() for n in
                           (2913, 2915, 2917, 2919, 2921, 2933, 2943, 2947, 2951, 2955)),
              loop.line_list() if loop else '')
        check('the list is lines, not the columns beside them',
              loop and loop.line_list().startswith('Font.c:2913,')
              and ':23' not in loop.line_list(),
              f'{loop.line_list() if loop else ""} -- the Line column holds a column '
              f'number for a resolved row, and listing those named one line of ten')
        check('the lines reach the row a developer reads',
              loop and '2913' in loop.detail() and '2955' in loop.detail(),
              loop.detail() if loop else '')
        other = sites.get('HiiGetFontInfo')
        check('two routines in one file stay two findings',
              other is not None and other is not loop and other.hits == 10,
              f'{sorted(sites)} -- Font.c holds both, so only the routine separates them')
        check('and each lists its own lines',
              other and other.line_list() == 'Font.c:1106, 1112',
              other.line_list() if other else '')
        check('every report is accounted for in some cluster',
              sum(c.hits for c in every.values()) == 681 + 169 + 10 + 10 + 1000,
              str(sum(c.hits for c in every.values())))
        shutil.rmtree(dxe_root, ignore_errors=True)

        print('\na group keyed on a routine is not split again by line number')
        # The SmmSpi rows, as the sanitizer wrote them: no source position, so the Line
        # column holds the instruction pointer. 533070366 - 533070167 = 199, over the
        # window, and the split filed issues #68 and #69 for one overflow.
        spi_root = campaigns({'DiscoveredSmi': [
            row(Module='SmmSpi.efi', Function='SmmSpiHandler',
                File='asan-outline-instrumentation', Line='533070167',
                **{'Asan Msg': 'heap-buffer-overflow'},
                Message='address 0x1FE616C8, size 0x8, is_write 0x1, ip 0x1FC60157',
                Count='8'),
            row(Module='SmmSpi.efi', Function='SmmSpiHandler',
                File='asan-outline-instrumentation', Line='533070366',
                **{'Asan Msg': 'heap-buffer-overflow'},
                Message='address 0x1FE616C8, size 0x8, is_write 0x1, ip 0x1FC6021E',
                Count='1')]}, smi=('DiscoveredSmi',))
        sites, every = clustered(br, spi_root, [root])
        check('two unlocated reports in one routine are one cluster', len(every) == 1,
              f'{len(every)} clusters: {sorted(sites)}')
        check('the hits are summed, not halved',
              sum(c.hits for c in every.values()) == 9,
              str(sum(c.hits for c in every.values())))
        check('and the key carries no positional suffix',
              all('~' not in str(c.key[2]) for c in every.values()),
              f'{[c.key for c in every.values()]} -- the ~N is what made two issues, and '
              f'it changes with the order the rows arrive in')
        shutil.rmtree(spi_root, ignore_errors=True)

        print('\nand a located group still splits where the lines are real')
        # A UBSan row arrives already located, so the file and the line are in their own
        # columns and the line really is a line -- which is where proximity means
        # something.
        far_root = campaigns({'EfiHiiFont': [
            row(Function='', **{'Asan Msg': ''}, ErrorType='PointerOverflow',
                File=f'/build/edk2/{HIIFONT}/Database.c',
                Message='pointer index expression overflowed', Line='100'),
            row(Function='', **{'Asan Msg': ''}, ErrorType='PointerOverflow',
                File=f'/build/edk2/{HIIFONT}/Database.c',
                Message='pointer index expression overflowed', Line='900')]})
        _sites, every = clustered(br, far_root, [root])
        check('800 lines apart in one file are still two findings', len(every) == 2,
              f'{len(every)} -- the proximity split is only wrong where the key already '
              f'names a routine')
        shutil.rmtree(far_root, ignore_errors=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)

    print('\na placeholder is not offered as a path')
    placeholder = br.Report(row(File='asan-outline-instrumentation', Line='533070167',
                                Function='SmmSpiHandler'), 'DiscoveredSmi')
    holder = br.Cluster(placeholder.group_key())
    holder.add(placeholder)
    check('the source column is empty rather than wrong',
          br.cluster_source(holder, ()) == '',
          f'{br.cluster_source(holder, ())!r} -- file_issues.py printed "the build '
          f'resolved this site to asan-outline-instrumentation, but that path is not in '
          f'this tree" about the instrumentation naming itself')
    real = br.Report(row(File=f'/src/edk2/{BASELIB}/Unaligned.c', Line='32',
                         Function='ReadUnaligned16'), 'EfiHiiFont')
    held = br.Cluster(real.group_key())
    held.add(real)
    check('and a real path is still made repo-relative',
          br.cluster_source(held, ()) == f'{BASELIB}/Unaligned.c',
          br.cluster_source(held, ()))

    print('\nnothing here touches another class')
    plain = br.Report({'Phase': 'fuzz', 'Module': 'DxeCore.efi', 'Function': 'CoreFoo',
                       'File': f'/build/edk2/{DXECORE}/Event/Timer.c', 'Line': '54',
                       'Asan Msg': 'heap-buffer-overflow', 'ErrorType': 'asan',
                       'Count': '4',
                       'Message': 'address 0x1000, size 0x4, is_write 0x1, ip 0x2000'},
                      'EfiHiiFont')
    plain.protocol_arg = True
    flat = br.Cluster(plain.group_key())
    flat.add(plain)
    flat.smm_checked = True
    kind, _why = br.verdict(flat, set(), 8)
    check('an overflow in the same file is unaffected', kind == 'candidate',
          f'{kind} -- the window argument is about reading a value twice, and says '
          f'nothing about writing past an allocation')
    check('and it renders as it always did', flat.detail() == 'write of 4 bytes at 0x1000',
          flat.detail())
    check('a cluster built by hand claims nothing about SMM',
          br.Cluster(('m', 'k', 's')).smm_modules == ()
          and not br.Cluster(('m', 'k', 's')).smm_checked,
          'the defaults have to read as "nothing was asked", or every check and every '
          'caller that builds one gets an answer nobody measured')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
