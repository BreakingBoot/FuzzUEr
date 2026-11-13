#!/usr/bin/env python3
"""Assert a source line is not reported when the line table cannot be trusted.

Measured on run 43280109497. Four SMI findings, in four different images, resolved to
MdePkg/Library/UefiLib/UefiDriverModel.c -- lines 957, 897, 1338 and 1525, every one of
them at column 24. Those lines are gBS->InstallMultipleProtocolInterfaces inside the
driver-binding installers, which cannot run during an SMI, and UefiLib is in none of
those modules' [LibraryClasses]. One file and one column shared by four unrelated images
is a line table falling back, not attribution.

The offset was not the problem and was ruled out first: SmmSpi.efi loaded at 0x1FC5F000
with its entry point at 0x1FC677E8, so rva 0x87E8, and the ELF's own recorded entry is
0x87E8. The symbol table for the same four addresses gave SmmSpiHandler,
RWVariableHandler, SmmLockBoxHandler and a BaseLib routine -- the handlers themselves.

So the function is the answer and the line was the wrong one, and the three issues filed
from those rows -- the three most severe findings of the run -- sent a reader to a file
that cannot execute during an SMI. Two resolvers had to learn this, firness.py's
symbolise() during the campaign and bug_report.py's symbolise_offset() during triage,
and the halved counts below are what happens when only one of them does.
"""

import importlib.util
import io
import os
import re
import sys

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
    """A definition with its prose removed -- docstring and comments both.

    Asserting on the raw text of a function whose prose explains the defect finds the
    defect's name in the explanation. Both halves of that bit here: the first version of
    the --functions=none check below failed on symbolise()'s docstring, and the second on
    the comment beside the argument list that says what --functions=none used to print.
    Only the statements count.
    """
    found = re.search(r'"""', text)
    if found:
        closing = text.index('"""', found.end())
        text = text[:found.start()] + text[closing + 3:]
    kept = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith('#'):
            continue
        kept.append(line)
    return '\n'.join(kept)


def body(src, marker):
    """One definition's text, from its `def` to the next top-level one."""
    start = src.index(marker)
    rest = src[start + len(marker):]
    end = re.search(r'\n(?:def |[A-Z_]+ = |@)', rest)
    return src[start:start + len(marker) + (end.start() if end else len(rest))]


def firness_ns():
    """symbolise and its helpers, without importing firness.py.

    firness.py pulls matplotlib and networkx at module scope and neither is installed
    everywhere this runs; the resolver under test needs neither.
    """
    import subprocess
    src = source('firness')
    ns = {'os': os, 're': re, 'subprocess': subprocess,
          '_SYMBOL_CACHE': {}, '_DEFINES_CACHE': {}, '_DEBUG_INDEX': None}
    for marker in ('SYMBOL_BUILD = ', 'SYMBOLIZERS = '):
        found = re.search(rf'^{marker}.*$', src, re.M)
        exec(found.group(0), ns)
    for marker in ('def _debug_index(', 'def mentions(', 'def symbolise('):
        exec(body(src, marker), ns)
    return ns


def fake_symbolizer(tmp, func, where):
    """A stand-in llvm-symbolizer that answers with one function and one position."""
    path = os.path.join(tmp, 'llvm-symbolizer')
    io.open(path, 'w', encoding='utf-8').write(
        '#!/bin/sh\n'
        f'printf "%s\\n%s\\n" "{func}" "{where}"\n')
    os.chmod(path, 0o755)
    return path


def resolver():
    """firness.py's symbolise, answered by a scripted symbolizer over a real tree."""
    import shutil
    import tempfile
    tmp = tempfile.mkdtemp(prefix='linetable-')
    build = os.path.join(tmp, 'Build', 'X64')
    os.makedirs(build)
    io.open(os.path.join(build, 'SmmSpi.debug'), 'w').write('not really an elf')
    # The two files the measurement turned on: one defines the routine the symbol table
    # named, the other is the unrelated file the line table fell back to.
    io.open(os.path.join(tmp, 'SmmSpi.c'), 'w', encoding='utf-8').write(
        'EFI_STATUS\nSmmSpiHandler (\n  VOID *CommBuffer\n  )\n{\n  return 0;\n}\n')
    io.open(os.path.join(tmp, 'UefiDriverModel.c'), 'w', encoding='utf-8').write(
        'EFI_STATUS\nEfiLibInstallAllDriverProtocols2 (\n  VOID\n  )\n{\n'
        '  return gBS->InstallMultipleProtocolInterfaces (NULL);\n}\n')

    def ask(func, filename, line):
        ns = firness_ns()
        ns['SYMBOL_BUILD'] = os.path.join(tmp, 'Build')
        where = f'{os.path.join(tmp, filename)}:{line}:24'
        ns['SYMBOLIZERS'] = (fake_symbolizer(tmp, func, where),)
        return ns['symbolise']('SmmSpi.efi', 0x1157)

    return ask, tmp, shutil


class Row(dict):
    """A crashes.csv row, as csv.DictReader hands it over."""

    def __init__(self, **kw):
        super().__init__({'Phase': 'fuzz', 'AtBoot': '', 'Module': 'SmmSpi.efi',
                          'Function': '', 'File': 'asan-outline-instrumentation',
                          'Line': '0', 'Asan Msg': '__asan_store0x08',
                          'ErrorType': 'asan', 'Message': '', 'Count': '1'})
        self.update(kw)


def main():
    print('the resolver asks for the function, not only the position')
    fsrc = source('firness')
    sym = code(body(fsrc, 'def symbolise('))
    check('symbolise asks llvm-symbolizer for the function',
          '--functions=linkage' in sym and '--functions=none' not in sym,
          '--functions=none prints only the position, so the name the symbol table '
          'already knew was discarded before anything could use it')

    ask, tmp, shutil = resolver()
    try:
        print('\na position is kept only when its file holds the function')
        path, line, func = ask('SmmSpiHandler', 'SmmSpi.c', 97)
        check('a consistent file and line survive',
              path.endswith('SmmSpi.c') and line == '97' and func == 'SmmSpiHandler',
              f'{(path, line, func)}')

        path, line, func = ask('SmmSpiHandler', 'UefiDriverModel.c', 957)
        check('the routine is reported either way', func == 'SmmSpiHandler',
              f'got {func!r} -- the symbol table was right and is the whole answer here')
        check('a file that does not hold the routine is not reported',
              (path, line) == ('', ''),
              f'got {(path, line)} -- this is the exact shape of the defect: '
              f'UefiDriverModel.c:957 named against SmmSpiHandler')

        print('\nand the refusal is about this file, not about every file')
        path, _line, _func = ask('EfiLibInstallAllDriverProtocols2',
                                 'UefiDriverModel.c', 957)
        check('the same file is kept for a routine it does define',
              path.endswith('UefiDriverModel.c'),
              f'got {path!r} -- dropping it always would lose every real UefiLib line')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print('\ntriage applies the same test to its own resolver')
    bsrc = source('bug_report')
    offset = code(body(bsrc, 'def symbolise_offset('))
    check('symbolise_offset checks the file against the function',
          'mentions(' in offset,
          'this is the resolver that re-derived the same wrong path during triage, so '
          'fixing only the campaign-side one left the issue bodies unchanged')
    check('it checks before the path is made repo-relative',
          offset.index('mentions(') < offset.index("'/edk2/'"),
          'the stripped path cannot be opened, so the check has to happen first')
    check('an untrusted position returns the function alone',
          re.search(r'else\s+func', offset) is not None, offset[-400:])
    located = code(body(bsrc, 'def locate('))
    check('locate keeps the function when it refuses the path',
          'report.func' in located,
          'otherwise a refused path leaves the row with no location at all')

    print('\nthe function reaches the places that name a site')
    sys.path.insert(0, HERE)
    br = load('bug_report')
    check('a report reads the Function column',
          br.Report(Row(Function='SmmSpiHandler'), 'p').func == 'SmmSpiHandler')
    check('a row with a real path is located',
          br.Report(Row(File='MdePkg/Library/BaseLib/Unaligned.c', Line='32'),
                    'p').located)
    check('a row with a placeholder is not located',
          not br.Report(Row(), 'p').located)

    one = br.Report(Row(Function='SmmSpiHandler', Message='ip 0x1FC60157'), 'p')
    # Same module and same placeholder, different routine. The module has to be held
    # equal or the keys differ on that alone and the assertion proves nothing -- which is
    # what the first version of this check did.
    two = br.Report(Row(Function='SmmSpiGetAttributes', Message='ip 0x1FC609A0'), 'p')
    check('two unlocated rows in one module group apart by routine',
          one.group_key() != two.group_key(),
          f'{one.group_key()} == {two.group_key()} -- grouping on the placeholder put '
          f'every address-only finding in a module into one bucket')
    check('two unlocated rows in the same routine group together',
          one.group_key() == br.Report(
              Row(Function='SmmSpiHandler', Line='533070167',
                  Message='ip 0x1FC60157'), 'p').group_key(),
          'the twins of one access must land in one cluster')

    cluster = br.Cluster(one.group_key())
    cluster.add(one)
    check('an unlocated cluster names the routine', cluster.site == 'SmmSpiHandler',
          f'got {cluster.site!r}')
    nums = br.Report(Row(File='MdePkg/Library/BaseLib/Unaligned.c', Line='32',
                         Function='ReadUnaligned16'), 'p')
    resolved = br.Cluster(nums.group_key())
    resolved.add(nums)
    check('a located cluster keeps its file and line, not the routine',
          resolved.site.startswith('Unaligned.c:'),
          f'got {resolved.site!r} -- the offset resolver works for these rows and the '
          f'function must not override an answer that is already better')

    print('\ntwo unlocated twins for one access are one finding')
    # The sanitizer writes two rows per access: the check names a position, the typed
    # report names only the address. With the position refused, BOTH arrive unlocated.
    check_row = br.Report(Row(Function='SmmSpiHandler', File='', Line='0',
                              Message='ip 0x1FC60157', Count='42'), 'p')
    # 'Asan Msg' holds a space, so it goes in by key rather than as a keyword
    typed_row = Row(Function='SmmSpiHandler', Line='533070167',
                    Message='ip 0x1FC60157', Count='42')
    typed_row['Asan Msg'] = 'heap-buffer-overflow'
    typed = br.Report(typed_row, 'p')
    kept = br.merge_by_ip([check_row, typed])
    check('they merge to one row', len(kept) == 1, f'{len(kept)} kept')
    check('the counts add up', kept and kept[0].count == 84,
          f'{kept[0].count if kept else None} -- 42 is the halved count, and the other '
          f'42 came back as a second finding with an address for a site')

    print('\nthe artefact is carried where a reader will see it')
    check('crashes.csv has a Function column',
          "'Function', 'File'" in fsrc,
          'the column is what triage and the issue body both read it from')
    isrc = source('file_issues')
    check('the issue body prefers the recorded function',
          "first.get('Function')" in isrc,
          'the issue is the thing a developer reads, and it was naming the wrong file')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
