#!/usr/bin/env python3
"""Does the harness actually land in the DXE FV, unconditionally, without breaking the port?

The failure this guards against is silent. A module placed inside an !if block builds
cleanly, boots cleanly, and is simply absent from the firmware -- and the campaign then
reports "every boot spent its budget without reaching the harness", which reads as a
broken target. The first version of add_to_fdf did exactly that: OvmfPkgX64.fdf's DXEFV
ends inside

    !if $(CC_MEASUREMENT_ENABLE) == TRUE
    INF SecurityPkg/Tcg/TdTcg2Dxe/TdTcg2Dxe.inf
    !endif

so "after the last INF line" put the harness between that INF and the !endif. Several of
the checks below exist only because of that.
"""
import os
import re
import sys
import tempfile
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'firness', 'harness_generator'))

import fv_harness  # noqa: E402

FAILURES = []
CRLF = b'\r\n'


def check(name, condition, detail=''):
    if condition:
        print(f'  ok    {name}')
    else:
        FAILURES.append(name)
        print(f'  FAIL  {name}' + (f' -- {detail}' if detail else ''))


def depth_at(lines, section, target):
    """The !if nesting depth at `target`, counting from `section`'s header."""
    start = next((i for i, l in enumerate(lines) if l.strip() == section), None)
    if start is None:
        return -1
    depth = 0
    for i in range(start + 1, target):
        t = lines[i].strip()
        if re.match(rb'^!\s*(if|ifdef|ifndef)\b', t):
            depth += 1
        elif re.match(rb'^!\s*endif\b', t):
            depth = max(0, depth - 1)
    return depth


def staged(tmp):
    """A copy of the real port files, so the checks run against what ships."""
    os.makedirs(os.path.join(tmp, 'OvmfPkg'), exist_ok=True)
    for name in ('OvmfPkgX64.dsc', 'OvmfPkgX64.fdf'):
        src = os.path.join(ROOT, 'eval_source', 'edk2', 'OvmfPkg', name)
        if not os.path.isfile(src):
            return None
        with open(src, 'rb') as r, open(os.path.join(tmp, 'OvmfPkg', name), 'wb') as w:
            w.write(r.read())
    return tmp


def main():
    print('The harness reaches the DXE firmware volume')
    with tempfile.TemporaryDirectory() as tmp:
        tree = staged(tmp)
        if tree is None:
            check('the port DSC and FDF are present', False,
                  'eval_source/edk2/OvmfPkg is missing')
            print(f'{len(FAILURES)} failure(s)')
            return 1

        dsc_path = os.path.join(tree, 'OvmfPkg', 'OvmfPkgX64.dsc')
        fdf_path = os.path.join(tree, 'OvmfPkg', 'OvmfPkgX64.fdf')
        before_dsc = open(dsc_path, 'rb').read()
        before_fdf = open(fdf_path, 'rb').read()

        n_dsc, n_fdf = fv_harness.place(tree)

        check('the component goes into EVERY [Components] section',
              n_dsc == before_dsc.count(b'[Components]') and n_dsc >= 1,
              f'{n_dsc} added, {before_dsc.count(b"[Components]")} sections -- this file '
              f'holds its body twice and dedup_sections keeps one copy, so a component in '
              f'only one of them is a coin flip')
        check('the FDF gets exactly one entry', n_fdf == 1, str(n_fdf))

        after_dsc = open(dsc_path, 'rb').read()
        after_fdf = open(fdf_path, 'rb').read()

        print('line endings')
        # The hazard is READING in text mode -- that collapses CRLF to LF and a write-back
        # then rewrites every line in the file. Writing in text mode on Linux translates
        # nothing, so a mutation there is a no-op and proves nothing.
        check('the module reads the port files as bytes',
              open(os.path.join(HERE, 'fv_harness.py'), encoding='utf-8').read()
              .count("open(path, 'rb')") >= 2,
              "a text-mode read collapses CRLF and the write-back rewrites all 2502 lines")
        for label, data in (('DSC', after_dsc), ('FDF', after_fdf)):
            check(f'the {label} is still CRLF throughout',
                  data.count(b'\n') - data.count(CRLF) == 0,
                  'a bare LF means an edit went through Python text mode, and a whole-file '
                  'rewrite once cost a merge its anchor')

        print('the FDF placement')
        lines = after_fdf.split(CRLF)
        mark = next((i for i, l in enumerate(lines) if fv_harness._MARK in l), None)
        check('the harness is in the FDF', mark is not None)
        if mark is not None:
            check('it is inside [FV.DXEFV]',
                  depth_at(lines, b'[FV.DXEFV]', mark) >= 0,
                  'placed in some other FV, or outside one')
            check('it is NOT inside an !if block',
                  depth_at(lines, b'[FV.DXEFV]', mark) == 0,
                  'a conditional placement builds and boots and simply omits the harness; '
                  'this is the bug the first version of add_to_fdf had, inside '
                  '!if $(CC_MEASUREMENT_ENABLE)')
            check('the entry is an INF line',
                  re.match(rb'^INF\s+Firness/FirnessHarnesses\.inf$',
                           lines[mark + 1].strip()) is not None,
                  lines[mark + 1].decode('utf-8', 'replace'))
            check('it follows an existing INF rather than the FV attributes',
                  re.match(rb'^INF\b', lines[mark - 1].strip()) is not None,
                  'an INF among BlockSize/FvNameGuid is not valid FDF')

        print('the DSC component')
        text = after_dsc.decode('utf-8', 'replace')
        check('the component names the generated INF',
              'Firness/FirnessHarnesses.inf {' in text)
        #
        # Scoped to the harness's OWN component block, not the whole file. The DSC already
        # carries NULL|AsanLib in its SMM library sections, so a whole-file grep for it
        # passed with the harness override deleted -- mutation D5.
        #
        block = ''
        at = text.find('Firness/FirnessHarnesses.inf {')
        if at >= 0:
            end = text.find('\n  }', at)
            block = text[at:end if end > at else at + 600]
        check('the component block was found to scope the next checks', bool(block),
              'without this the overrides are checked against the whole file')
        check('it pins the one class OVMF does not resolve for a DXE_DRIVER',
              'RegisterFilterLib|MdePkg/Library/RegisterFilterLibNull' in block,
              'every other class the harness INF asks for is resolved in OvmfPkgX64.dsc; '
              'this one is not, and an unresolved class stops the build')
        check('it links AsanLib, in its own block',
              'NULL|MdeModulePkg/Library/AsanLib/AsanLib.inf' in block,
              'without it AsanSetFuzzingActive is the weak no-op, the window never opens, '
              'and a finding goes to the serial port and nowhere else')
        check('no new section header is added',
              sorted(re.findall(r'^\[[^\]]+\]', text, re.M))
              == sorted(re.findall(r'^\[[^\]]+\]',
                                   before_dsc.decode('utf-8', 'replace'), re.M)),
              'dedup_sections finds the duplicate body by the longest repeated run of '
              'section HEADERS, so a new header re-aligns that search and the wrong copy '
              'is dropped')

        print('the port still dedups the way it did')
        spec = importlib.util.spec_from_file_location(
            'apply_asan', os.path.join(ROOT, 'uefi_asan', 'apply_asan.py'))
        mod = importlib.util.module_from_spec(spec)
        sys.dont_write_bytecode = True
        try:
            spec.loader.exec_module(mod)
        except SystemExit:
            pass
        kept_before, _ = mod.dedup_sections(before_dsc.split(b'\n'))
        kept_after, _ = mod.dedup_sections(after_dsc.split(b'\n'))
        t_before = b'\n'.join(kept_before).decode('utf-8', 'replace')
        t_after = b'\n'.join(kept_after).decode('utf-8', 'replace')
        check('[Defines] still survives dedup', '[Defines]' in t_after)
        check('one [Components] survives, as before',
              t_after.count('[Components]') == t_before.count('[Components]') == 1,
              f'{t_after.count("[Components]")} after, {t_before.count("[Components]")} before')
        check('the harness component is in the copy that survives',
              'Firness/FirnessHarnesses.inf' in t_after,
              'it went into the copy dedup drops, so the firmware would not contain it')
        check('one SMM library section survives, as before',
              t_after.count('[LibraryClasses.common.DXE_SMM_DRIVER]')
              == t_before.count('[LibraryClasses.common.DXE_SMM_DRIVER]') == 1)
        check('the global BaseMemoryLib is untouched',
              'BaseMemoryLib|MdePkg/Library/BaseMemoryLibRepStr/BaseMemoryLibRepStr.inf'
              in t_after,
              'see fuzzuer-smm-memlib-mapping-closed: the instrumented instance in SMM '
              'cost a campaign its whole budget')

        print('running it twice is safe')
        check('a second place() changes nothing', fv_harness.place(tree) == (0, 0),
              'the port runs over trees that may already be ported')
        check('and the files are byte-identical after it',
              open(dsc_path, 'rb').read() == after_dsc
              and open(fdf_path, 'rb').read() == after_fdf)

    print('a tree with no DXEFV is reported, not silently skipped')
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, 'OvmfPkg'))
        for name, body in (('OvmfPkgX64.dsc', b'[Components]\r\n  A/A.inf\r\n'),
                           ('OvmfPkgX64.fdf', b'[FV.OTHER]\r\nINF  B/B.inf\r\n')):
            open(os.path.join(tmp, 'OvmfPkg', name), 'wb').write(body)
        got = fv_harness.place(tmp)
        check('no DXEFV means no FDF entry, and the caller can see it',
              got == (1, 0), str(got))

    print('a missing file raises rather than reporting success')
    with tempfile.TemporaryDirectory() as tmp:
        try:
            fv_harness.place(tmp)
            check('a missing DSC raises', False, 'it returned instead')
        except FileNotFoundError:
            check('a missing DSC raises', True)

    print('the INF flavour that goes with it')
    from uefi_harness.inf_template import gen_firness_inf, depex_for_smi  # noqa: E402
    from common.types import SmiInfo  # noqa: E402
    libs = {'UefiApplicationEntryPoint': 'x', 'BaseLib': 'y', 'NULL': 'z'}

    app = '\n'.join(gen_firness_inf('G', ['gA'], ['gB'], libs))
    dxe = '\n'.join(gen_firness_inf('G', ['gA'], ['gB'], libs, timing='dxe',
                                     depex_protocols=['gLightGuid', 'gAlarmGuid']))
    check('the default flavour is unchanged',
          'MODULE_TYPE                    = UEFI_APPLICATION' in app
          and '[Depex]' not in app
          and 'UefiApplicationEntryPoint' in app
          and 'UEFI_HII_RESOURCE_SECTION' in app,
          'every campaign to date has used this one; it must emit what it emitted before')
    check('the dxe flavour is a DXE_DRIVER',
          'MODULE_TYPE                    = DXE_DRIVER' in dxe, dxe[:200])
    check('and takes its entry point from UefiDriverEntryPoint',
          'UefiDriverEntryPoint' in dxe and 'UefiApplicationEntryPoint' not in dxe,
          'the application entry point does not fail the build, it fails the LINK with an '
          'unresolved _ModuleEntryPoint, which reads as a broken harness')
    check('it waits on SMM communication',
          '[Depex]' in dxe and 'gEfiSmmCommunicationProtocolGuid' in dxe,
          'without it there is no way to raise an SMI at all')
    check('and on the buffer protocols it was given',
          'gLightGuid' in dxe and 'gAlarmGuid' in dxe, dxe[dxe.find('[Depex]'):])
    check('the depex is an AND, not a list',
          dxe.count(' AND') == 2, dxe[dxe.find('[Depex]'):])
    check('an unknown timing is refused rather than silently defaulted',
          _raises(lambda: gen_firness_inf('G', [], [], libs, timing='later')),
          'a typo would otherwise produce the application flavour and the campaign would '
          'report a handler it could not reach')

    print('and the depex comes from the BufferProtocol field')
    data = {'A': SmiInfo('A', 'T *', 'gA', buffer_protocol='gLight'),
            'B': SmiInfo('B', 'T *', 'gB', buffer_protocol='gAlarm'),
            'C': SmiInfo('C', 'T *', 'gC'),
            'D': SmiInfo('D', 'T *', 'gD', buffer_protocol='gLight')}
    check('every distinct buffer protocol is waited on, once',
          depex_for_smi(data, {'gLight', 'gAlarm'}) == ['gAlarm', 'gLight'],
          str(depex_for_smi(data, {'gLight', 'gAlarm'})))
    check('a protocol the INF does not declare is dropped',
          depex_for_smi(data, {'gLight'}) == ['gLight'],
          'a depex naming a GUID the INF does not declare does not build')
    check('a handler with no buffer protocol contributes nothing',
          depex_for_smi({'C': data['C']}, {'gLight'}) == [])
    check('no handlers is not an error',
          depex_for_smi({}, {'gLight'}) == [] and depex_for_smi(None, {'gLight'}) == [])
    check('the order is stable',
          depex_for_smi(data, {'gLight', 'gAlarm'})
          == depex_for_smi(dict(reversed(list(data.items()))), {'gAlarm', 'gLight'}),
          'two runs of the generator must emit the same INF')

    print(f'{len(FAILURES)} failure(s)')
    return 1 if FAILURES else 0


def _raises(call):
    try:
        call()
        return False
    except Exception:
        return True


if __name__ == '__main__':
    sys.exit(main())
