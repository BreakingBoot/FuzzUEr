#!/usr/bin/env python3
"""Assert a finding reported against the instrumentation still shows a reader the code.

Measured on run 43452927684. Three of the run's findings -- the SmmSpi heap overflow, the
RWVariable heap overread and the SmmLockBox double fetch, which are the most severe it
produced -- were caught by ASan's outline instrumentation, so crashes.csv recorded their
File column as `asan-outline-instrumentation` and their site as a routine rather than
file:line. Everything downstream is keyed on file:line:

  * rows_for matched the candidate's site against basename(File):Line, which can never
    equal a routine, so every one of those findings was built from ZERO raw rows. The
    issue lost its phase, its ErrorType, the sanitizer's own address-and-width message and
    the routine name, and reported the bug class as the triage class because the row that
    carries the real one was not there.
  * with no file, the body said "resolve the ip against the build's DEBUG directory",
    which is a correct instruction and not a code snippet.

Both are recoverable from the routine, because firness.py reads it out of the ELF symbol
table and edk2's coding style puts a function's name alone at column 0 above its parameter
list. 88 of the run's 91 candidate bodies carry a snippet with that in place, 6 of them
found through the routine; the 3 that do not are rows whose line table recorded line 0,
which is the table saying it does not know.
"""

import importlib.util
import io
import json
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

    Asserting on the raw text of a function whose prose explains what it handles finds the
    handled thing in the explanation. Only the statements count.
    """
    found = re.search(r'"""', text)
    if found:
        closing = text.index('"""', found.end())
        text = text[:found.start()] + text[closing + 3:]
    kept = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith('#'):
            kept.append(line.split('  #')[0])
    return '\n'.join(kept)


def tree(tmp):
    """A two-file edk2-shaped checkout, written once per run."""
    os.makedirs(os.path.join(tmp, 'OvmfPkg', 'Spi'), exist_ok=True)
    with open(os.path.join(tmp, 'OvmfPkg', 'Spi', 'SmmSpi.c'), 'w') as handle:
        handle.write('/**\n  A doc comment.\n**/\nEFI_STATUS\nEFIAPI\n'
                     'SmmSpiHandler (\n  IN VOID  *CommBuffer\n  )\n{\n  return 0;\n}\n')
    os.makedirs(os.path.join(tmp, 'MdePkg', 'Library'), exist_ok=True)
    with open(os.path.join(tmp, 'MdePkg', 'Library', 'Twice.c'), 'w') as handle:
        handle.write('VOID\nAmbiguous (\n  VOID\n  )\n{\n}\n')
    os.makedirs(os.path.join(tmp, 'MdeModulePkg', 'Core'), exist_ok=True)
    with open(os.path.join(tmp, 'MdeModulePkg', 'Core', 'Also.c'), 'w') as handle:
        handle.write('VOID\nAmbiguous (\n  VOID\n  )\n{\n}\n')
    with open(os.path.join(tmp, 'MdeModulePkg', 'Core', 'Head.h'), 'w') as handle:
        handle.write('VOID\nOnlyDeclared (\n  VOID\n  );\n')
    # A repository, because define_site reads the index first and walks the tree only
    # when there is none. A plain directory exercises the fallback and leaves the path
    # that actually runs in CI -- where the checkout is always a repository -- untested.
    import subprocess as sp
    for argv in (['git', 'init', '-q'], ['git', 'add', '-A'],
                 ['git', '-c', 'user.name=t', '-c', 'user.email=t@t',
                  'commit', '-qm', 'fixture']):
        sp.run(argv, cwd=tmp, capture_output=True)
    return tmp


def main():
    import tempfile
    ev = load('issue_evidence')
    fi = load('file_issues')
    holder = tempfile.TemporaryDirectory()
    checkout = tree(holder.name)

    print('a routine is found in the tree it was compiled from')
    check('an edk2-style definition resolves to its file and the name line',
          ev.define_site(checkout, 'SmmSpiHandler') == ('OvmfPkg/Spi/SmmSpi.c', '6'),
          f'got {ev.define_site(checkout, "SmmSpiHandler")}')
    check('a name nothing defines resolves to nothing',
          ev.define_site(checkout, 'NoSuchRoutine') == (None, None))
    check('a name two files define is left unresolved rather than guessed',
          ev.define_site(checkout, 'Ambiguous') == (None, None),
          'a static function of the same name in two drivers is ordinary in edk2, and '
          'quoting the wrong one is worse than quoting nothing')
    check('a header prototype is not mistaken for a definition',
          ev.define_site(checkout, 'OnlyDeclared') == (None, None),
          'a .h declaration is written exactly like a definition in this style')
    check('a name that is not an identifier is refused before any search',
          ev.define_site(checkout, 'Smm; rm -rf /') == (None, None))
    check('the identifier guard is what refuses it, not the search coming back empty',
          "re.fullmatch(r'[A-Za-z_]" in
          source('issue_evidence').split('def define_site')[1].split('\ndef ')[0],
          'nothing here builds a shell command, so the guard is what keeps a crafted '
          'name out of the regex rather than out of a shell')
    check('the index is read before the tree is walked',
          "'git', '-C', source, 'grep'" in
          source('issue_evidence').split('def define_site')[1].split('\ndef ')[0],
          'an edk2 checkout is large enough for the difference to be a stall')
    check('no source directory means no answer',
          ev.define_site('', 'SmmSpiHandler') == (None, None))

    print('\nthe raw rows of a routine-keyed finding are found')
    rows = [{'Module': 'SmmSpi.efi', 'Function': 'SmmSpiHandler',
             'File': 'asan-outline-instrumentation', 'Line': '533070167',
             'Asan Msg': '__asan_store0x08', 'ErrorType': 'asan',
             'Message': 'ip 0x1FC60157', 'Phase': 'fuzz', 'Count': '8'},
            {'Module': 'SmmSpi.efi', 'Function': 'SmmSpiHandler',
             'File': 'asan-outline-instrumentation', 'Line': '533070167',
             'Asan Msg': 'heap-buffer-overflow', 'ErrorType': 'asan',
             'Message': 'address 0x1FE616C8, size 0x08, is_write 0x01',
             'Phase': 'fuzz', 'Count': '8'},
            {'Module': 'Other.efi', 'Function': 'SmmSpiHandler', 'File': 'x.c',
             'Line': '12', 'Asan Msg': 'heap-buffer-overflow', 'Message': 'elsewhere'}]
    cand = {'module': 'SmmSpi.efi', 'site': 'SmmSpiHandler',
            'class': 'heap-buffer-overflow (write)'}
    got = ev.rows_for(cand, rows)
    check('a site that is a routine matches on the Function column', len(got) == 2,
          f'{len(got)} row(s) -- site_of builds file:line and can never equal a routine')
    check('the module still breaks the tie',
          all(r['Module'] == 'SmmSpi.efi' for r in got))
    check("the sanitizer's own report is read before the marker that fired it",
          got and got[0].get('Asan Msg') == 'heap-buffer-overflow',
          f'first row is {got[0].get("Asan Msg") if got else None} -- callers read the '
          f'FIRST row for the detail line, and the marker carries only an ip')
    check('a site that is file:line still matches on the site',
          len(ev.rows_for({'module': 'Other.efi', 'site': 'x.c:12',
                           'class': 'heap-buffer-overflow'}, rows)) == 1)
    check('a routine with no matching row stays empty',
          ev.rows_for({'module': 'SmmSpi.efi', 'site': 'Absent'}, rows) == [])

    print('\nthe issue body a reader opens')
    results = os.path.join(holder.name, 'results')
    os.makedirs(os.path.join(results, 'campaigns', 'DiscoveredSmi'), exist_ok=True)
    with open(os.path.join(results, 'campaigns', 'DiscoveredSmi', 'crashes.csv'),
              'w', newline='') as handle:
        handle.write('Phase,AtBoot,Module,Function,File,Line,Asan Msg,ErrorType,'
                     'Message,Count\n')
        for row in rows[:2]:
            handle.write(f"fuzz,,{row['Module']},{row['Function']},{row['File']},"
                         f"{row['Line']},{row['Asan Msg']},asan,\"{row['Message']}\",8\n")
    body = fi.body_for({'module': 'SmmSpi.efi', 'site': 'SmmSpiHandler',
                        'class': 'heap-buffer-overflow (write)', 'hits': 16,
                        'protocols': ['DiscoveredSmi'],
                        'source': 'asan-outline-instrumentation'},
                       'ref', '1', 'url', 'artifact', checkout, results, None)
    check('it names the file the routine is defined in',
          'OvmfPkg/Spi/SmmSpi.c' in body, body[:300])
    check('it says the line is the definition and not the access',
          'the definition; the report carries no line' in body,
          'a reader told a line number has to be told which line it is')
    check('it quotes the code', '```c' in body and 'SmmSpiHandler (' in body)
    check("it no longer sends the reader to the build's DEBUG directory",
          'resolve the ip against' not in body)
    check("it reports the sanitizer's bug class, not the marker",
          '| reported by | `heap-buffer-overflow` |' in body,
          'with no rows matched this fell back to the triage class')
    check('it carries the address and the width',
          '0x1FE616C8' in body and 'is_write' in body)
    check('it carries the phase', '| phase | fuzz |' in body)

    print('\na line of zero is treated as no line')
    with open(os.path.join(results, 'campaigns', 'DiscoveredSmi', 'crashes.csv'),
              'a', newline='') as handle:
        handle.write('fuzz,,DxeCore.efi,,MdeModulePkg/Core/Also.c,0,fwsan-double-fetch,'
                     'fwsan,"read twice",4\n')
    zero = fi.body_for({'module': 'DxeCore.efi', 'site': 'Also.c:0',
                        'class': 'fwsan-double-fetch (read)', 'hits': 4,
                        'protocols': ['DiscoveredSmi'],
                        'source': 'MdeModulePkg/Core/Also.c:0'},
                       'ref', '1', 'url', 'artifact', checkout, results, None)
    check('the file it did resolve is named as resolved',
          'MdeModulePkg/Core/Also.c' in zero)
    check('it is not called a path that is not in this tree',
          'not in this tree' not in zero,
          'the path plainly is in the tree; it is the LINE the table could not give')
    check('it says the line table is what gave nothing',
          'no usable line number' in zero, zero[zero.index('### '):][:300])
    with open(os.path.join(results, 'campaigns', 'DiscoveredSmi', 'crashes.csv'),
              'a', newline='') as handle:
        handle.write('fuzz,,SmmSpi.efi,SmmSpiHandler,OvmfPkg/Spi/SmmSpi.c,0,'
                     'heap-buffer-overflow,asan,"address 0x1FE616C8",4\n')
    named = fi.body_for({'module': 'SmmSpi.efi', 'site': 'SmmSpi.c:0',
                         'class': 'heap-buffer-overflow (write)', 'hits': 4,
                         'protocols': ['DiscoveredSmi'],
                         'source': 'OvmfPkg/Spi/SmmSpi.c:0'},
                        'ref', '1', 'url', 'artifact', checkout, results, None)
    check('a zero line with a routine falls through to the definition',
          'the definition; the report carries no line' in named,
          'a resolved file and an unusable line is still no line, and the routine is '
          'what is left to point at')
    check('and it quotes the routine rather than nothing',
          '```c' in named and 'SmmSpiHandler (' in named)

    print('\nthe behaviour is in the code and not only in this run')
    esrc = source('issue_evidence')
    check('rows_for falls back to the Function column',
          "r.get('Function')" in code(esrc.split('def rows_for')[1].split('\ndef ')[0]))
    check('the marker rows are ordered behind their report',
          "startswith('__asan')" in code(esrc.split('def rows_for')[1].split('\ndef ')[0]))
    check('define_site refuses a multi-file answer',
          'len(found) == 1' in code(esrc.split('def define_site')[1].split('\ndef ')[0]))
    fsrc = code(source('file_issues'))
    check('the body asks for the definition only when it has no located line',
          'ev.define_site(source, function)' in fsrc and 'not located' in fsrc)

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
