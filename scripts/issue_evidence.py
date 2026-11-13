#!/usr/bin/env python3
"""What a finding issue needs beyond the one-line triage row.

Triage reports a site as `module | class | source:line`, which is enough to count bugs and
nothing like enough to read one. Everything here answers a question a reader has in the
first ten seconds: what is the code at that line, how did a testcase get there, and where
are the bytes that did it.

All of it is derived, never hardcoded per bug class. A site with no real source file -- the
sanitizer's own outline instrumentation, or FWSAN, which report against themselves -- gets
told so rather than given a misleading snippet.
"""

import csv
import glob
import os
import re
import subprocess

# crashes.csv records the path as the BUILD saw it, inside the container
# (/workspace/tmp/edk2/MdeModulePkg/...). The tree on disk here is the caller's checkout at
# whatever path they chose, so the prefix is matched away rather than assumed: the longest
# suffix of the recorded path that exists in the tree is the file. That also survives a
# different build layout, which a fixed prefix would not.
def resolve(source, recorded):
    if not recorded or '/' not in recorded:
        return None                      # 'fwsan', 'asan-outline-instrumentation'
    parts = recorded.replace('\\', '/').split('/')
    for start in range(len(parts)):
        rel = '/'.join(parts[start:])
        if rel and os.path.isfile(os.path.join(source, rel)):
            return rel
    return None


# The site of a finding the sanitizer reported against itself. A heap overflow caught by
# the outline instrumentation records the File column as `asan-outline-instrumentation`,
# which resolve() correctly refuses -- so the highest-severity findings on this project,
# the SMI handler overflows, are exactly the ones with no file to quote. What they do have
# is a routine name, which firness.py reads out of the ELF symbol table and triage carries
# through as the site. edk2's coding style puts a function's name alone at column 0 of the
# line above its parameter list, so the definition is findable from the name alone.
#
# Only .c files, and only a match at column 0: a header's prototype is written the same way
# and would send the reader to a declaration instead of the body. A name that resolves to
# more than one definition is left unresolved rather than guessed at -- a static function
# of the same name in two drivers is ordinary in edk2, and quoting the wrong driver's copy
# is worse than quoting nothing.
DEFINITION = '^{name}[ \t]*\('


def define_site(source, function, _cache={}):
    """('path', 'line') of the .c file that defines `function`, else (None, None)."""
    if not source or not function or not re.fullmatch(r'[A-Za-z_]\w*', function):
        return None, None
    key = (source, function)
    if key in _cache:
        return _cache[key]
    pattern = DEFINITION.format(name=re.escape(function))
    found = []
    # git grep first because it reads the index rather than walking the tree, and an edk2
    # checkout is large enough for that to be the difference between a lookup and a stall.
    # It needs a work tree, so a source directory that is not a repository -- a copy, an
    # extracted tarball -- falls through to the walk.
    for argv in (['git', '-C', source, 'grep', '-nE', '--', pattern, '--', '*.c'],
                 ['grep', '-rnE', '--include=*.c', '--', pattern, '.']):
        try:
            done = subprocess.run(argv, cwd=source, capture_output=True, text=True,
                                  timeout=120)
        except (OSError, subprocess.SubprocessError):
            continue
        if done.returncode > 1:
            continue
        for row in done.stdout.splitlines():
            bits = row.split(':', 2)
            if len(bits) >= 2 and bits[1].isdigit():
                found.append((bits[0].lstrip('./'), bits[1]))
        break
    answer = found[0] if len(found) == 1 else (None, None)
    _cache[key] = answer
    return answer


def crash_rows(results):
    """Every row of every campaign's crashes.csv, tagged with its campaign."""
    rows = []
    for path in sorted(glob.glob(os.path.join(results, 'campaigns', '*', 'crashes.csv'))):
        campaign = os.path.basename(os.path.dirname(path))
        try:
            with open(path, newline='') as handle:
                for row in csv.DictReader(handle):
                    row['_campaign'] = campaign
                    rows.append(row)
        except (OSError, csv.Error):
            continue
    return rows


def site_of(row):
    """The key triage builds its site from: the file's basename and the line."""
    name = os.path.basename((row.get('File') or '').replace('\\', '/'))
    return f"{name}:{row.get('Line', '')}"


def rows_for(cand, rows):
    """The raw reports behind one candidate.

    Matched on site first -- which is how triage names it -- and on module only to break a
    tie, because a module column can come back empty on a report whose address no map
    covers, and dropping those loses the very rows that carry the source path.

    A candidate whose site is a ROUTINE rather than file:line is matched on the Function
    column instead. Triage names a site that way when the line table could not be believed
    and the symbol table could, so site_of -- which builds file:line out of the row -- can
    never equal it. Matching only on site drops every row of such a candidate, and an issue
    built from no rows silently loses its phase, its ErrorType, the sanitizer's own message
    and the routine name, which is the one fact those findings do carry. On run
    43452927684 that was the entire SMI handler class, the highest-severity findings there.
    """
    site = cand.get('site', '')
    hit = [r for r in rows if site_of(r) == site]
    if not hit and site and ':' not in site:
        hit = [r for r in rows if (r.get('Function') or '').strip() == site]
    exact = [r for r in hit if (r.get('Module') or '') == (cand.get('module') or '')]
    # Stable, so a site whose rows are all of one kind keeps the order the campaigns wrote.
    # One access produces two rows: the instrumentation callback that fired, whose Asan Msg
    # is `__asan_store0x08` and whose Message is only an ip, and the sanitizer's own report,
    # which names the bug class and the address and the width. Callers read the FIRST row
    # for the detail line and the reported-by line, so a marker row in front of its own
    # report turns `heap-buffer-overflow -- write of 8 bytes at 0x1FE616C8` into
    # `__asan_store0x08 -- ip 0x1FC60157`: true, and nothing a reader can act on.
    return sorted(exact or hit,
                  key=lambda r: (r.get('Asan Msg') or '').startswith('__asan'))


def snippet(source, rel, line, context=6):
    """The code around a line, with the line itself marked."""
    try:
        text = open(os.path.join(source, rel), errors='replace').read().splitlines()
    except OSError:
        return None
    try:
        line = int(line)
    except (TypeError, ValueError):
        return None
    if not 1 <= line <= len(text):
        return None
    lo, hi = max(1, line - context), min(len(text), line + context)
    out = []
    for n in range(lo, hi + 1):
        out.append(f'{">" if n == line else " "} {n:>5} | {text[n - 1]}')
    return '\n'.join(out)


def harness_entries(results, protocol):
    """The protocol members the generated harness drives.

    These are the entry points a testcase actually reaches: the fuzzer picks one and feeds
    it the input, so they are the first hop of the path to the crash site.
    """
    found = []
    for name in ('FirnessHarnesses.c', 'FirnessHarnesses.h'):
        path = os.path.join(results, 'campaigns', protocol, 'Firness', name)
        if not os.path.isfile(path):
            continue
        try:
            text = open(path, errors='replace').read()
        except OSError:
            continue
        for match in re.finditer(r'^\s*Fuzz([A-Za-z0-9_]+)\s*\(', text, re.M):
            if match.group(1) not in found:
                found.append(match.group(1))
        if found:
            break
    return found


def log_excerpt(results, protocol, rows, context=6, most=2):
    """The serial log around the report, which is the only first-hand record of it.

    Anchored on the instruction pointer out of the report message where there is one, and
    on the source basename otherwise: the address is what makes one report distinguishable
    from the thousand others a scanning loop leaves in the same file.
    """
    path = os.path.join(results, 'campaigns', protocol, 'fuzz.txt')
    if not os.path.isfile(path):
        return None
    try:
        lines = open(path, errors='replace').read().splitlines()
    except OSError:
        return None
    anchors = []
    for row in rows:
        for pattern in (r'ip (0x[0-9A-Fa-f]+)', r'address (0x[0-9A-Fa-f]+)'):
            found = re.search(pattern, row.get('Message') or '')
            if found:
                anchors.append(found.group(1))
        name = os.path.basename((row.get('File') or '').replace('\\', '/'))
        if '/' in (row.get('File') or ''):
            anchors.append(name)
    out, covered = [], set()
    for n, text in enumerate(lines):
        if len(out) >= most:
            break
        if not any(a in text for a in anchors):
            continue
        lo, hi = max(0, n - context), min(len(lines), n + context + 1)
        # Several rows anchor on the same address, so their windows overlap; emitting each
        # one gave the same excerpt twice over.
        if any(line in covered for line in range(lo, hi)):
            continue
        covered.update(range(lo, hi))
        out.append('\n'.join(lines[lo:hi]))
    return '\n\n...\n\n'.join(out) if out else None


def inputs_for(results, protocol, most=4):
    """The testcases the campaign kept for this protocol.

    Which byte string reached which site is not recorded -- the fuzzer keeps a crashing
    input, not a mapping from input to report -- so these are the inputs that crashed THIS
    protocol's harness, which is what can honestly be said about them.
    """
    found = []
    root = os.path.join(results, 'campaigns', protocol, 'qemu', 'crashes')
    for name in sorted(os.listdir(root)) if os.path.isdir(root) else []:
        if name.startswith('.'):          # libafl's own metadata sidecars
            continue
        path = os.path.join(root, name)
        if os.path.isfile(path) and os.path.getsize(path) > 0:
            found.append(path)
        if len(found) >= most:
            break
    return found


def hexdump(path, most=1024):
    """hexdump -C, including its '*' for runs of identical lines.

    A fuzzer input is mostly one byte repeated -- the testcases here are 1026 bytes of
    which 1020 are the same -- so rendering every line fills the issue with nothing. The
    collapse is what makes the interesting head and tail readable at a glance.
    """
    try:
        with open(path, 'rb') as handle:
            data = handle.read(most + 1)
    except OSError:
        return None
    clipped = len(data) > most
    data = data[:most]
    out, last, folding = [], None, False
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        if chunk == last and len(chunk) == 16:
            if not folding:
                out.append('*')
                folding = True
            continue
        folding = False
        last = chunk
        hexed = ' '.join(f'{b:02x}' for b in chunk)
        text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        out.append(f'{off:08x}  {hexed:<47}  |{text}|')
    size = os.path.getsize(path)
    out.append(f'{min(len(data), size):08x}'
               + (f'  (first {most} bytes of {size})' if clipped else ''))
    return '\n'.join(out)
