"""Apply the AddressSanitizer integration to an arbitrary edk2 checkout.

The integration is 81 added files and 30 modified ones. The added files are self contained
and carry across untouched; the modified ones are edits to upstream code that moves, so
they are applied with a three way merge against whatever the target tree has.

  python3 scripts/port_asan.py --from eval_source/edk2 --to <tree> [--base <sha>]

What it reports is what matters. "Applied" is not the same as "instrumented": a merge can
succeed and leave the sanitizer switched off, which is the failure this whole pipeline is
worst at noticing. The caller should build and count __asan_load/__asan_store symbols
afterwards -- scripts/workflow_local.sh does.
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile

# Upstream has deleted these since the fork's base. They are carried as additions rather
# than merges, because a three way merge against a file that no longer exists aborts the
# whole patch -- git apply is atomic -- and takes the other 29 files with it.
REVIVE = ('BaseTools/Scripts/ClangBase.lds',)


def dedup_sections(lines):
    """Drop a block that repeats the file's own section structure.

    The fork's OvmfPkg/OvmfPkgX64.dsc holds its whole body twice -- it was concatenated
    onto itself at some point and nobody noticed, because edk2 takes the last definition
    of everything and the fork therefore still builds. The port carries that second copy
    onto whichever edk2 it is applied to, and the copy is frozen at the fork's vintage: on
    edk2-stable202505 it reinstates "!include NetworkPkg/NetworkPcds.dsc.inc", a file
    upstream has since split in two and deleted, and the build stops at "File/directory
    not found in workspace" pointing at a line nobody wrote.

    The duplicate is found structurally rather than by name: the longest run of section
    headers that appears twice, the second occurrence not overlapping the first. Anything
    after that run -- here three [BuildOptions] sections that keep PEI and SMM out of the
    instrumentation -- is genuinely only in the second copy and is kept.

    Takes and returns a list of byte lines, plus how many were dropped.
    """
    heads = [(i, l.strip()) for i, l in enumerate(lines)
             if l.strip().startswith(b'[') and l.strip().endswith(b']')]
    names = [name for _, name in heads]
    best = (0, 0, 0)                                    # length, start of copy, source
    for j in range(len(names)):
        for start in range(j + 1, len(names)):
            limit = min(start - j, len(names) - start)  # never let the copies overlap
            run = 0
            while run < limit and names[j + run] == names[start + run]:
                run += 1
            if run > best[0]:
                best = (run, start, j)
    run, start, _ = best
    # A couple of repeated headers is ordinary -- [BuildOptions] legitimately appears more
    # than once. A run of them covering hundreds of lines is a file doubled on itself.
    if run < 5:
        return lines, 0
    first = heads[start][0]
    last = heads[start + run][0] if start + run < len(heads) else len(lines)
    if last - first < 50:
        return lines, 0
    return lines[:first] + lines[last:], last - first


def port_patch(src, base, path):
    """The port's delta for one file, with the fork's self-duplication taken out.

    When nothing is dropped this is plain "git diff base..HEAD". When something is, the
    trimmed content is written as a blob so git can diff against it: the patch then still
    carries the index line that "git apply --3way" needs to merge it into a tree whose
    version of the file is years newer.
    """
    plain = git_bytes(src, 'diff', f'{base}..HEAD', '--', path).stdout
    if not path.rsplit('.', 1)[-1].lower() in ('dsc', 'fdf', 'inc', 'dec', 'inf',
                                               'template'):
        return plain, 0
    head = git_bytes(src, 'show', f'HEAD:{path}').stdout
    kept, dropped = dedup_sections(head.split(b'\n'))
    if not dropped:
        return plain, 0
    old = git_bytes(src, 'rev-parse', f'{base}:{path}').stdout.decode().strip()
    made = subprocess.run(['git', '-C', src, 'hash-object', '-w', '--stdin'],
                          input=b'\n'.join(kept), capture_output=True)
    new = made.stdout.decode().strip()
    if made.returncode or not new:
        return plain, 0
    raw = git_bytes(src, 'diff', old, new).stdout
    # git names a blob-to-blob diff after the object ids. Point the header back at the
    # file so the patch applies to a worktree, and stop at the first hunk: a removed line
    # reading "-- x" is rendered "--- x" and would otherwise be rewritten as a header.
    out, header = [], True
    for line in raw.split(b'\n'):
        if header and line.startswith(b'diff --git '):
            out.append(f'diff --git a/{path} b/{path}'.encode())
        elif header and line.startswith(b'--- '):
            out.append(f'--- a/{path}'.encode())
        elif header and line.startswith(b'+++ '):
            out.append(f'+++ b/{path}'.encode())
            header = False
        else:
            out.append(line)
    return b'\n'.join(out), dropped



PIN_RE = re.compile(r'^(\s*)([A-Za-z_]\w*)(\s*\|\s*)(\S+\.inf)(\s*)$')


def enforce_library_pins(src, base, dst, path):
    """Apply the port's library-class choices to sections upstream added since.

    The port swaps BaseCryptLib for BaseCryptLibNull. It does that in every
    [LibraryClasses] section its own edk2 had, and edk2 resolves a class per module type,
    so a section added upstream afterwards keeps the real instance. edk2-stable202505 added
    one for PEIM, and PlatformPei therefore linked the 28 MB OpensslLibCrypto: PEIFV needed
    0x84c2e8 against the 0x2e0000 it is given and the build ended at "the required fv image
    size exceeds the set fv image size", which says nothing about a library.

    Only classes the port deliberately re-points are touched -- a class it merely carries
    unchanged is left to upstream, whose per-module-type choices are usually the reason the
    sections exist.
    """
    patch, _ = port_patch(src, base, path)
    adds, removes = {}, {}
    for line in patch.decode('utf-8', 'replace').split('\n'):
        body = line.rstrip('\r')
        if not body[:1] in ('+', '-'):
            continue
        found = PIN_RE.match(body[1:])
        if found:
            (adds if body[0] == '+' else removes)[found.group(2)] = found.group(4)
    pins = {k: v for k, v in adds.items() if k in removes and removes[k] != v}
    if not pins:
        return []
    full = os.path.join(dst, path)
    try:
        body = open(full, newline='', errors='ignore').read()
    except OSError:
        return []
    out, changed = [], []
    for line in body.split('\n'):
        found = PIN_RE.match(line.rstrip('\r'))
        if found and found.group(2) in pins and found.group(4) != pins[found.group(2)]:
            tail = '\r' if line.endswith('\r') else ''
            out.append(f'{found.group(1)}{found.group(2)}{found.group(3)}'
                       f'{pins[found.group(2)]}{found.group(5)}{tail}')
            changed.append(found.group(2))
        else:
            out.append(line)
    if changed:
        open(full, 'w', newline='').write('\n'.join(out))
    return changed


REGION_RE = re.compile(r'^(\s*)(0x[0-9A-Fa-f]+)\s*\|\s*(0x[0-9A-Fa-f]+)\s*$')


def _regions(lines):
    """Every "offset|size" line with the PCD pair or FV it binds on the next line."""
    found = []
    for i, line in enumerate(lines):
        hit = REGION_RE.match(line.rstrip('\r'))
        if hit:
            binding = lines[i + 1].strip() if i + 1 < len(lines) else ''
            found.append((i, int(hit.group(2), 16), int(hit.group(3), 16), binding))
    return found


def enlarge_memfd(dst, fdf_rel, pei_size, dxe_size):
    """Grow the PEI and DXE volumes in whichever file defines MEMFD.

    The port enlarges them because instrumented code is roughly three times the size and
    neither volume fits otherwise. It does that by carrying the fork's whole [FD.MEMFD]
    inline, which worked while upstream's was inline too. edk2-stable202511 moved it to
    OvmfPkg/Include/Fdf/MemFd.fdf.inc, so the ported FDF defines MEMFD twice and GenFds
    stops at "Unexpected the same FD name". Letting the port's copy win is not the answer
    either: that copy is the fork's 2023 layout, and upstream has added regions since --
    work areas and page tables that this version's modules read.

    So keep upstream's layout and change only what the port is actually asking for: the
    size of the two volumes, the offset of the one that follows, and the totals. Every
    region before them stays where upstream put it.

    Returns a description of what changed, or ''.
    """
    fdf = os.path.join(dst, fdf_rel)
    try:
        body = open(fdf, newline='', errors='ignore').read()
    except OSError:
        return ''
    lines = body.split('\n')
    # the include that defines MEMFD, if this file does not define it itself
    target, target_lines = None, None
    if not any(l.strip().upper().startswith('[FD.MEMFD]') for l in lines):
        return ''
    inline = [i for i, l in enumerate(lines) if l.strip().upper().startswith('[FD.MEMFD]')]
    included = []
    for line in lines:
        hit = re.match(r'^\s*!include\s+(\S+)', line)
        if not hit:
            continue
        path = os.path.join(dst, hit.group(1))
        try:
            text = open(path, newline='', errors='ignore').read()
        except OSError:
            continue
        if any(l.strip().upper().startswith('[FD.MEMFD]') for l in text.split('\n')):
            included.append((hit.group(1), path, text))
    if not included or not inline:
        return ''                                   # only one definition: nothing to fix

    # Drop the port's inline copy, back to the blank line before its leading comment.
    start = inline[0]
    while start > 0 and lines[start - 1].strip().startswith('#'):
        start -= 1
    end = start + 1
    for i in range(inline[0] + 1, len(lines)):
        stripped = lines[i].strip()
        if stripped.startswith('[') or stripped.startswith('!include'):
            end = i
            break
        end = i + 1
    del lines[start:end]
    open(fdf, 'w', newline='').write('\n'.join(lines))

    rel, path, text = included[0]
    target_lines = text.split('\n')
    block = os.path.getsize(path) and 0x10000
    for line in target_lines:
        hit = re.match(r'^\s*BlockSize\s*=\s*(0x[0-9A-Fa-f]+)', line)
        if hit:
            block = int(hit.group(1), 16)
            break
    regions = _regions(target_lines)
    pei = next((r for r in regions if 'PcdOvmfPeiMemFvBase' in r[3]), None)
    dxe = next((r for r in regions if 'PcdOvmfDxeMemFvBase' in r[3]), None)
    if not pei or not dxe:
        return f'{rel}: no PEI/DXE volume to enlarge'
    dxe_base = pei[1] + pei_size
    total = dxe_base + dxe_size
    pad = REGION_RE.match(target_lines[pei[0]].rstrip('\r')).group(1)
    eol = '\r' if target_lines[pei[0]].endswith('\r') else ''
    target_lines[pei[0]] = f'{pad}0x{pei[1]:06X}|0x{pei_size:06X}{eol}'
    target_lines[dxe[0]] = f'{pad}0x{dxe_base:06X}|0x{dxe_size:06X}{eol}'
    for i, line in enumerate(target_lines):
        if re.match(r'^\s*Size\s*=\s*0x', line):
            target_lines[i] = re.sub(r'0x[0-9A-Fa-f]+', f'0x{total:X}', line, count=1)
        elif re.match(r'^\s*NumBlocks\s*=\s*0x', line):
            target_lines[i] = re.sub(r'0x[0-9A-Fa-f]+',
                                     f'0x{total // block:X}', line, count=1)
    open(path, 'w', newline='').write('\n'.join(target_lines))
    return (f'{rel}: PEI 0x{pei_size:X}, DXE 0x{dxe_size:X} at 0x{dxe_base:X}, '
            f'MEMFD 0x{total:X}')


def port_memfd_sizes(src, base):
    """The volume sizes the port's own FDF asks for."""
    text = git_bytes(src, 'show', f'HEAD:OvmfPkg/OvmfPkgX64.fdf').stdout.decode(
        'utf-8', 'replace')
    lines = text.split('\n')
    regions = _regions(lines)
    pei = next((r for r in regions if 'PcdOvmfPeiMemFvBase' in r[3]), None)
    dxe = next((r for r in regions if 'PcdOvmfDxeMemFvBase' in r[3]), None)
    return (pei[2] if pei else 0), (dxe[2] if dxe else 0)


def _command_blocks(lines):
    """Map section header -> {command name: (index, indent, body lines)}."""
    out, section = {}, None
    for i, line in enumerate(lines):
        if line.strip().startswith('['):
            section = line.strip()
            out.setdefault(section, {})
            continue
        hit = re.match(r'^(\s*)<Command\.(\w+)>', line)
        if hit and section:
            body, j = [], i + 1
            while j < len(lines) and not re.match(r'^\s*<', lines[j]) \
                    and not lines[j].strip().startswith('['):
                body.append(lines[j])
                j += 1
            while body and not body[-1].strip():
                body.pop()
            out[section][hit.group(2)] = (i, hit.group(1), body)
    return out


def complete_sanitizer_rules(src, dst):
    """Put the port's SANITIZER build rules in the sections they belong to.

    CLANGSAN declares BUILDRULEFAMILY = SANITIZER, so a section with no
    <Command.SANITIZER> either runs its step without $(SAN_FLAGS) or skips it. The port
    adds those commands by patch, which places them wherever the surrounding context
    matched. On edk2-stable202511 upstream had added a [Cxx-Code-File] section just above
    [C-Code-File] and the C compile command landed in it: the build ran, produced a
    firmware, and instrumented nothing -- 1388 clang invocations, not one with
    -fsanitize, and a volume 20% full where an instrumented one is 56%.

    Which sections need one is not a guess: it is whichever the port's own build_rule
    gives one to. Anything else -- adding $(SAN_FLAGS) to every link command, say -- is
    inventing a configuration nobody has built.
    """
    path = os.path.join(dst, 'BaseTools/Conf/build_rule.template')
    try:
        here = open(path, newline='', errors='ignore').read().split('\n')
    except OSError:
        return []
    ours = git_bytes(src, 'show', 'HEAD:BaseTools/Conf/build_rule.template'
                     ).stdout.decode('utf-8', 'replace').split('\n')
    wanted = {head: cmds['SANITIZER']
              for head, cmds in _command_blocks(ours).items() if 'SANITIZER' in cmds}
    if not wanted:
        return []
    mine = _command_blocks(here)

    def same_section(head):
        if head in mine:
            return head
        name = head.strip('[]').split(',')[0].split('.')[0].strip()
        for other in mine:
            if other.strip('[]').split(',')[0].split('.')[0].strip() == name:
                return other
        return None

    added = []
    for head, (_, pad, body) in sorted(wanted.items(), reverse=True):
        target = same_section(head)
        if target is None or 'SANITIZER' in mine.get(target, {}):
            continue
        anchor = mine[target].get('GCC') or next(iter(mine[target].values()), None)
        if not anchor:
            continue
        at = anchor[0]
        stop = at + 1
        while stop < len(here) and not re.match(r'^\s*<', here[stop]) \
                and not here[stop].strip().startswith('['):
            stop += 1
        eol = '\r' if here[at].endswith('\r') else ''
        here[stop:stop] = [f'{pad}<Command.SANITIZER>{eol}'] + body + [eol]
        added.append(target)
        mine = _command_blocks(here)
    if added:
        open(path, 'w', newline='').write('\n'.join(here))
    return added


def drop_duplicate_modules(dst, path):
    """Remove an INF the port adds to a volume that this edk2 now adds itself.

    The port adds SmmCommunicationBufferDxe to DXEFV because PiSmmIpl has no
    communication region to advertise without it. edk2 master adds it too, so the ported
    FDF lists it twice and GenFv stops at "the 52th file and 61th file have the same file
    GUID" -- a message naming neither the module nor the file it is in.

    Three things decide whether a repeat is really a duplicate:

    The whole line, not the .inf path. edk2 lists a module twice on purpose where the
    second carries an overriding FILE_GUID -- master does that for CpuDxe and CpuMpPei --
    and those are two different files in the volume.

    Whether the two can be present together. Sibling arms of one conditional never are.
    A line inside an arm and a line outside it always are, which is exactly the case here:
    the port's copy sits in the !else of STANDALONE_MM_ENABLE and upstream's sits below
    the !endif.

    An APRIORI block lists dispatch order, not files, so an INF there is not a copy of
    anything.

    Where both are present, the one under a condition goes and the unconditional one
    stays, so the volume keeps the module however the condition evaluates.
    """
    full = os.path.join(dst, path)
    try:
        lines = open(full, newline='', errors='ignore').read().split('\n')
    except OSError:
        return []

    def coexist(one, other):
        arms = dict(one)
        return not any(where in arms and arms[where] != arm for where, arm in other)

    section, branch, counter, apriori = '', [], 0, 0
    ours_conditions = set()
    seen, drop = [], []
    for i, line in enumerate(lines):
        body = line.strip()
        if apriori:
            apriori -= body.count('}')
            continue
        if re.match(r'^APRIORI\b', body, re.I):
            apriori += body.count('{')
            continue
        if body.startswith('['):
            section, branch, seen = body, [], []
            continue
        if body.startswith('!if'):
            counter += 1
            branch.append((counter, 0))
            if re.search(r'ASAN_SCOPE|ASAN_FUZZER|FIRNESS_', body, re.I):
                ours_conditions.add(counter)
            continue
        if body.startswith('!else'):
            if branch:
                where, arm = branch[-1]
                branch[-1] = (where, arm + 1)
            continue
        if body.startswith('!endif'):
            if branch:
                branch.pop()
            continue
        if not re.match(r'^INF\s', body, re.I):
            continue
        whole = ' '.join(body.split()).lower()
        here = list(branch)

        clash = next((n for n, (sec, text, where, _) in enumerate(seen)
                      if sec == section and text == whole and coexist(where, here)), None)
        if clash is None:
            seen.append((section, whole, here, i))
            continue
        _, _, there, at = seen[clash]
        # A line the port puts under its own condition says when the module should be
        # there; an unconditional copy says always. The port's is the deliberate one, so
        # where exactly one of the two is under a port condition, that one stays --
        # otherwise BootScriptExecutorDxe is back in every build and the block excluding
        # it at full scope has nothing left to exclude.
        mine = any(w in ours_conditions for w, _ in here)
        theirs = any(w in ours_conditions for w, _ in there)
        if mine != theirs:
            if mine:
                drop.append((at, body.split()[-1]))
                seen[clash] = (section, whole, here, i)
            else:
                drop.append((i, body.split()[-1]))
        elif len(here) >= len(there):
            drop.append((i, body.split()[-1]))
        else:
            drop.append((at, body.split()[-1]))
            seen[clash] = (section, whole, here, i)
    if drop:
        for i, _ in sorted(drop, reverse=True):
            del lines[i]
        open(full, 'w', newline='').write('\n'.join(lines))
    return [name for _, name in drop]


def balance_conditionals(dst, path):
    """Give the port's own conditional its own !endif.

    The port wraps a driver it has to drop at full sanitizer scope in
    "!if "$(ASAN_SCOPE)" != "full" ... !else ... !endif". In the fork that block stands
    alone, so the patch adds the !if and the !else and treats the !endif below it as
    context. Upstream can have put that !endif to its own use since: edk2-stable202511
    wraps the same two drivers in "!if $(STANDALONE_MM_ENABLE) != TRUE", and after the
    patch the port's conditional closes with that !endif, leaving STANDALONE_MM_ENABLE
    open. The build stops at "Missing !endif near line 610" -- three hundred lines past
    the conditional that is actually unterminated.

    Only acts on a file that is genuinely unbalanced, and only on the port's own
    conditionals, which are the ones naming its defines.
    """
    full = os.path.join(dst, path)
    try:
        lines = open(full, newline='', errors='ignore').read().split('\n')
    except OSError:
        return 0

    def kind(line):
        body = line.strip()
        if body.startswith('!if'):              # !if, !ifdef, !ifndef
            return 'if'
        return 'endif' if body.startswith('!endif') else ''

    short = sum(1 for l in lines if kind(l) == 'if') - \
        sum(1 for l in lines if kind(l) == 'endif')
    if short <= 0:
        return 0
    ours = re.compile(r'ASAN_SCOPE|ASAN_FUZZER|FIRNESS_', re.I)
    added, i = 0, 0
    while i < len(lines) and added < short:
        if kind(lines[i]) == 'if' and ours.search(lines[i]):
            depth = 0
            for j in range(i + 1, len(lines)):
                step = kind(lines[j])
                if step == 'if':
                    depth += 1
                elif step == 'endif':
                    if depth == 0:              # the !endif this block would borrow
                        pad = re.match(r'\s*', lines[j]).group(0)
                        eol = '\r' if lines[j].endswith('\r') else ''
                        lines.insert(j, f'{pad}!endif{eol}')
                        added += 1
                        break
                    depth -= 1
        i += 1
    if added:
        open(full, 'w', newline='').write('\n'.join(lines))
    return added


def twin_clang_toolchain(dst):
    """Give CLANGSAN the build options edk2 already writes for CLANGDWARF.

    A package that needs something specific from clang writes it against the toolchain
    edk2 ships, and CLANGSAN is a name edk2 has never heard of, so it gets the generic GCC
    line and none of the clang workarounds. CryptoPkg is where this bites: OpensslLib.inf
    hands CLANGDWARF "-std=c99", which is the whole reason openssl does not take its C11
    atomics path, and without it the build stops inside clang's own stdatomic.h at
    "unknown type name 'uint_least16_t'" -- a message with nothing in it about toolchains,
    sanitizers or the port.

    Seventeen files in edk2-stable202505 carry such a line. Twinning them is mechanical
    and stays correct as packages add more, which naming the files would not.
    """
    changed = []
    for base, dirs, files in os.walk(dst):
        dirs[:] = [d for d in dirs if d not in ('.git', 'Build')]
        for name in files:
            if not name.endswith(('.inf', '.dsc', '.dec', '.inc')):
                continue
            path = os.path.join(base, name)
            try:
                body = open(path, newline='', errors='ignore').read()
            except OSError:
                continue
            # a file the port already speaks for is left alone
            if 'CLANGDWARF' not in body or 'CLANGSAN' in body:
                continue
            out, added = [], 0
            for line in body.split('\n'):
                out.append(line)
                bare = line.strip()
                if 'CLANGDWARF' in line and '=' in line and not bare.startswith('#'):
                    out.append(line.replace('CLANGDWARF', 'CLANGSAN'))
                    added += 1
            if added:
                open(path, 'w', newline='').write('\n'.join(out))
                changed.append(os.path.relpath(path, dst))
    return changed


def git(repo, *args, check=False):
    return subprocess.run(['git', '-C', repo, *args], capture_output=True, text=True,
                          check=check)


def git_bytes(repo, *args):
    """Run git and keep the output exactly as it came.

    text=True applies universal newline translation, which rewrites every CRLF in a diff
    to LF. edk2 has plenty of CRLF files, so the patch that comes back does not match the
    tree it was taken from and git apply reports a context mismatch on line 131 of a file
    that merges cleanly by hand. It never falls back to the three way merge either,
    because the corrupted patch no longer matches its own index blobs.
    """
    return subprocess.run(['git', '-C', repo, *args], capture_output=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--from', dest='src', required=True, help='tree holding the port')
    parser.add_argument('--to', dest='dst', required=True, help='tree to apply it to')
    parser.add_argument('--base', default='', help='the commit the port sits on top of')
    parser.add_argument('--force', action='store_true',
                        help='apply onto a tree that already has local changes')
    args = parser.parse_args()

    src, dst = os.path.abspath(args.src), os.path.abspath(args.dst)
    for tree in (src, dst):
        if not os.path.isdir(os.path.join(tree, '.git')) and \
                not os.path.isfile(os.path.join(tree, '.git')):
            print(f'not a git checkout: {tree}', file=sys.stderr)
            return 2

    # A dirty target makes every result a lie: a patch already applied comes back as
    # "patch failed", and a file left behind untracked by an earlier run makes the revive
    # step skip it so the merge then fails on a file missing from the index. Both happened
    # and both looked like the port not applying to this version.
    dirty = git(dst, 'status', '--porcelain').stdout.strip()
    if dirty and not args.force:
        print(f'  {dst} has uncommitted changes; port onto a clean tree or pass --force:',
              file=sys.stderr)
        for line in dirty.splitlines()[:6]:
            print(f'    {line}', file=sys.stderr)
        return 2

    base = args.base
    if not base:
        # the port's base is the last commit both trees share
        head = git(src, 'rev-parse', 'HEAD').stdout.strip()
        for tag in ('edk2-stable202302', 'origin/master', 'master'):
            found = git(src, 'merge-base', head, tag)
            if found.returncode == 0 and found.stdout.strip():
                base = found.stdout.strip()
                break
    if not base:
        print('cannot find the port base; pass --base', file=sys.stderr)
        return 2
    print(f'  port base {base[:12]}')

    added = [f for f in git(src, 'diff', '--name-only', '--diff-filter=A',
                            f'{base}..HEAD').stdout.split() if f]
    modified = [f for f in git(src, 'diff', '--name-only', '--diff-filter=M',
                               f'{base}..HEAD').stdout.split() if f]
    print(f'  {len(added)} added file(s), {len(modified)} modified file(s)')

    for path in added:
        blob = git_bytes(src, 'show', f'HEAD:{path}')
        if blob.returncode:
            continue
        target = os.path.join(dst, path)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, 'wb') as handle:
            handle.write(blob.stdout)
    print(f'  copied {len(added)} added file(s)')

    revived = []
    for path in REVIVE:
        tracked = git(dst, 'ls-files', '--error-unmatch', path).returncode == 0
        if path in modified and not tracked:
            blob = git_bytes(src, 'show', f'HEAD:{path}')
            if blob.returncode == 0:
                target = os.path.join(dst, path)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                open(target, 'wb').write(blob.stdout)
                revived.append(path)
    modified = [f for f in modified if f not in revived]
    if revived:
        print(f'  revived {len(revived)} file(s) upstream deleted: {", ".join(revived)}')

    # tools_def is appended to, not diffed. The port's delta there both adds the CLANGSAN
    # toolchain and rewrites unrelated GCC macros the fork had renamed; applying the second
    # half to a newer edk2 deletes definitions that version still references, and the build
    # ends at "Macro or Environment has not been defined" pointing at a generated file.
    # edk2 takes the last definition of a macro, so appending the port's own CLANGSAN lines
    # is the whole of what it needs and none of what it does not.
    TOOLS_DEF = 'BaseTools/Conf/tools_def.template'
    appended = []
    if TOOLS_DEF in modified:
        src_lines = git_bytes(src, 'show', f'HEAD:{TOOLS_DEF}').stdout.decode(
            'utf-8', 'replace').split('\n')
        base_lines = set(git_bytes(src, 'show', f'{base}:{TOOLS_DEF}').stdout.decode(
            'utf-8', 'replace').split('\n'))
        ours_only = [l for l in src_lines
                     if l not in base_lines and ('CLANGSAN' in l or 'SAN_FLAGS' in l)]

        # CLANGSAN is written in terms of the CLANG38 family, and edk2 has since deleted
        # that toolchain: on a current tree the appended lines reference DEF(CLANG38_IA32_
        # ASLCC) and the parse stops there. Carry the closure of what they reference and
        # the target does not define, so the toolchain stands on its own.
        target = os.path.join(dst, TOOLS_DEF)
        defined_here = set(re.findall(
            r'^DEFINE\s+([A-Za-z_0-9]+)\s*=',
            open(target).read() if os.path.isfile(target) else '', re.M))
        by_name = {}
        for line in src_lines:
            found = re.match(r'^DEFINE\s+([A-Za-z_0-9]+)\s*=', line)
            if found:
                by_name.setdefault(found.group(1), line)

        # A macro has to be defined above the line that uses it: the parser expands DEF()
        # as it reads, so carrying the closure in discovery order stops the build at
        # "Macro or Environment has not been defined" naming a line in the block just
        # written. Emit each definition after the ones it references -- depth first, post
        # order, marking in progress so a cycle stops rather than recursing.
        already = {m.group(1) for m in
                   (re.match(r'^DEFINE\s+([A-Za-z_0-9]+)\s*=', l) for l in ours_only) if m}
        carried, seen_def = [], set(already)

        def carry(name):
            if name in defined_here or name in seen_def or name not in by_name:
                return
            seen_def.add(name)
            for dep in re.findall(r'DEF\(([A-Za-z_0-9]+)\)', by_name[name]):
                carry(dep)
            carried.append(by_name[name])

        for line in ours_only:
            for name in re.findall(r'DEF\(([A-Za-z_0-9]+)\)', line):
                carry(name)
        if carried:
            print(f'  carrying {len(carried)} definition(s) this edk2 no longer has')
            ours_only = carried + ours_only
        if ours_only and os.path.isfile(target):
            with open(target, 'a') as handle:
                handle.write('\n\n#\n# AddressSanitizer toolchain, appended by '
                             'scripts/port_asan.py. edk2 takes the last definition of a\n'
                             '# macro, so these override anything above without editing it.\n#\n')
                handle.write('\n'.join(ours_only) + '\n')
            appended.append(TOOLS_DEF)
            modified = [f for f in modified if f != TOOLS_DEF]
            print(f'  appended {len(ours_only)} CLANGSAN line(s) to tools_def')

        # A flag edk2 has added since the fork exists for every toolchain it ships and
        # for none it does not. edk2 master added GENFWHII_FLAGS, which the Hii rule
        # passes to GenFw; CLANGSAN had none, GenFw was handed no option to act on, and
        # the build stopped at "GenFw: ERROR 1001: Missing option" while building
        # LogoDxehii.lib -- a message with nothing in it about toolchains. Take the value
        # from CLANGDWARF, which is the clang toolchain edk2 does ship, and only for flags
        # the CLANGSAN block does not set for itself.
        body = open(target, newline='', errors='ignore').read()
        setting = re.compile(r'^\*_(\w+)_([^_\s]+)_(\w+)\s*=(.*)$', re.M)
        have = {m.group(3) for m in setting.finditer(body) if m.group(1) == 'CLANGSAN'}
        borrowed = []
        for found in setting.finditer(body):
            tool, arch, flag, value = found.groups()
            if tool != 'CLANGDWARF' or flag in have:
                continue
            have.add(flag)
            borrowed.append(f'*_CLANGSAN_{arch}_{flag} ={value}')
        if borrowed:
            with open(target, 'a', newline='') as handle:
                handle.write('\n#\n# Flags this edk2 has and the port does not know '
                             'about, taken from CLANGDWARF.\n#\n')
                handle.write('\n'.join(borrowed) + '\n')
            print(f'  gave CLANGSAN {len(borrowed)} flag(s) it had none of: '
                  f'{", ".join(b.split("=")[0].split("_")[-2] + "_" + b.split("=")[0].split("_")[-1].strip() for b in borrowed[:4])}')

    # one file at a time: git apply is atomic, so a single unmergeable hunk would discard
    # the whole port and report nothing about which file caused it
    clean, conflicted, failed = [], [], []
    for path in modified:
        patch, dropped = port_patch(src, base, path)
        if dropped:
            print(f'  {path}: dropped {dropped} line(s) that repeat the file\'s own '
                  f'sections -- the fork has that block twice')
        if not patch.strip():
            continue
        # git apply rejects a patch whose last line has no newline with "corrupt patch",
        # and subprocess capture drops it. That failure is indistinguishable in the return
        # code from a patch that genuinely does not apply, which is how all 30 files came
        # back as unapplicable against a tree they merge into cleanly by hand.
        if not patch.endswith(b'\n'):
            patch += b'\n'
        with tempfile.NamedTemporaryFile('wb', suffix='.patch', delete=False) as handle:
            handle.write(patch)
            name = handle.name
        out = git(dst, 'apply', '--3way', '--whitespace=nowarn', name)
        os.unlink(name)
        if out.returncode == 0:
            clean.append(path)
        elif 'with conflicts' in (out.stdout + out.stderr):
            conflicted.append(path)
        else:
            why = (out.stderr or out.stdout).strip().splitlines()
            failed.append((path, why[0][:90] if why else 'no message'))

    # A conflict leaves markers in the file. git apply --3way reports that as a non-zero
    # exit the caller can shrug off, and the tree then looks ported: the build runs, reads
    # "=======" in Conf/tools_def.txt, and stops at "Macro or Environment has not been
    # defined" with no hint that a merge is the reason. Resolve what is safely resolvable
    # and fail on the rest, because a half-ported tree that builds is worse than one that
    # does not.
    # What the port legitimately changes in tools_def is the CLANGSAN toolchain. Its other
    # edits there are fork drift, and forcing them onto a newer edk2 breaks the build a long
    # way from the cause: the 2023 delta redefines GCC_IA32_X64_DLINK_COMMON in terms of
    # GCC_DLINK_FLAGS_COMMON, which upstream has since renamed, so the generated Conf ends
    # at "Macro or Environment has not been defined" naming a line in a file nobody wrote.
    def port_owns(line, path):
        if not path.endswith('tools_def.template'):
            return True
        body = line.strip()
        if not body or body.startswith('#'):
            return True
        return 'CLANGSAN' in body or 'SAN_FLAGS' in body

    resolved, unresolved = [], []
    for path in conflicted:
        full = os.path.join(dst, path)
        try:
            # newline='' or Python's universal newlines turn every CRLF into LF on the
            # way in and write LF on the way out. edk2 is CRLF throughout, so resolving
            # one conflict rewrote the whole file's line endings, and the port's actual
            # change was then invisible in a diff of 566 rewritten lines.
            body = open(full, newline='', errors='ignore').read()
        except OSError:
            unresolved.append(path)
            continue
        if '<<<<<<< ' not in body:
            resolved.append(path)                       # git resolved it after all
            continue
        if path.endswith(('.template', '.h', '.inf', '.dec')):
            # These are additive declaration lists. tools_def and build_rule take the last
            # definition of a macro, and a header, INF or DEC gains a declaration without
            # losing one, so keeping both sides with ours last is the merge rather than a
            # compromise. Deliberately NOT the linker script, whose sections have braces --
            # keeping both sides there put the init_array block outside its section and the
            # link failed with "syntax error" -- nor a DSC or FDF, where a conflict spanning
            # the tail of the file duplicates the entire platform definition.
            merged, keep = [], None
            for line in body.split('\n'):
                if line.startswith('<<<<<<< '):
                    keep = ('ours', [], [])
                elif line.startswith('=======') and keep:
                    keep = ('theirs', keep[1], [])
                elif line.startswith('>>>>>>> ') and keep:
                    merged.extend(keep[1])
                    merged.extend(l for l in keep[2] if port_owns(l, path))
                    keep = None
                elif keep:
                    (keep[1] if keep[0] == 'ours' else keep[2]).append(line)
                else:
                    merged.append(line)
            open(full, 'w', newline='').write('\n'.join(merged))
            resolved.append(path)
        elif path.endswith('.lds'):
            # The conflict is always the same shape: the port adds the sanitizer's
            # constructor and destructor arrays at the end of the section that collects
            # AutoGen's GUIDs, so its side ends with that section's closing brace, while
            # upstream's side is only the closing brace -- "} :text" once upstream started
            # assigning the section to a program header.
            #
            # Both sides therefore end the same section and neither is a superset. The
            # merge is the port's statements followed by upstream's closer: taking both
            # verbatim leaves the arrays after the brace, outside any section, and the
            # link stops at "GccBase.lds:51: syntax error" -- which names the linker
            # script rather than the merge that wrote it.
            def closes(line):
                return line.strip().startswith('}')

            merged, ours, theirs, keep, safe = [], [], [], None, True

            def flush_lds():
                nonlocal safe
                if not all(closes(l) or not l.strip() for l in ours):
                    safe = False                        # a shape we have not seen
                    return
                body_lines = list(theirs)
                while body_lines and (closes(body_lines[-1])
                                      or not body_lines[-1].strip()):
                    body_lines.pop()
                merged.extend(body_lines)
                merged.extend(ours)

            for line in body.split('\n'):
                if line.startswith('<<<<<<< '):
                    keep, ours, theirs = 'ours', [], []
                elif line.startswith('=======') and keep:
                    keep = 'theirs'
                elif line.startswith('>>>>>>> ') and keep:
                    flush_lds()
                    keep = None
                elif keep == 'ours':
                    ours.append(line)
                elif keep == 'theirs':
                    theirs.append(line)
                else:
                    merged.append(line)
            if safe:
                open(full, 'w', newline='').write('\n'.join(merged))
                resolved.append(path)
            else:
                unresolved.append(path)
        else:
            # Where both sides set the same thing, the port's value is the deliberate one:
            # BaseCryptLibNull instead of the real instance because the openssl submodule
            # is not built, MEMFD at 0x2700000 instead of 0xF80000 because instrumented
            # code does not fit in the stock volume. Where they set different things, both
            # belong -- upstream's new AmdSvsmLib line and the port's comment are not in
            # competition. Keying on the text before the first | or = separates the two
            # cases without knowing anything about DSC, FDF or C syntax.
            merged, ours, theirs, keep = [], [], [], None
            # An FDF region is "offset|size" followed by the PCD pair or FV it binds. The
            # offset is a position, not a name, so keying on it makes upstream's
            # 0x100000|0xE80000 and the port's 0x300000|0x2400000 look like two different
            # settings and both are kept. The result is two offset lines above one PCD
            # binding, which is not valid FDF: the build ends in a BaseTools traceback at
            # "PCD gUefiOvmfPkgTokenSpaceGuid.PcdOvmfDxeMemFvBase is not defined in DSC
            # file", naming neither the region nor the merge. When the port moves a region
            # it means to move it, so its offset replaces upstream's.
            is_fdf = path.endswith(('.fdf', '.fdf.inc'))
            region = re.compile(r'^\s*0x[0-9A-Fa-f]+\s*\|\s*0x[0-9A-Fa-f]+\s*$')
            def key_of(line):
                body = line.split('#')[0].strip()
                for sep in ('|', '='):
                    if sep in body:
                        return body.split(sep)[0].strip()
                return None
            def flush():
                drop_regions = is_fdf and any(region.match(l) for l in theirs)
                theirkeys = {key_of(l) for l in theirs if key_of(l)}
                merged.extend(l for l in ours
                              if key_of(l) not in theirkeys
                              and not (drop_regions and region.match(l)))
                merged.extend(theirs)
            for line in body.split('\n'):
                if line.startswith('<<<<<<< '):
                    keep, ours, theirs = 'ours', [], []
                elif line.startswith('=======') and keep:
                    keep = 'theirs'
                elif line.startswith('>>>>>>> ') and keep:
                    flush()
                    keep = None
                elif keep == 'ours':
                    ours.append(line)
                elif keep == 'theirs':
                    theirs.append(line)
                else:
                    merged.append(line)
            open(full, 'w', newline='').write('\n'.join(merged))
            resolved.append(path)

    # firness.py instruments a tree by applying uefi_asan/asan.patch unless the tree
    # carries this marker. That patch is from 2024 and installs the same CLANGSAN
    # toolchain this port has just merged properly: applied on top, it lands a second
    # copy of the toolchain block partway up tools_def.template, above the CLANG38
    # definitions the port appended at the end, and the harness build stops at
    # "tools_def.txt(1899): Macro or Environment has not been defined  CLANG38_IA32_ASLCC"
    # -- while leaving .rej files nobody reads. This tree is already instrumented, and by
    # a port that understands the version it is being applied to.
    open(os.path.join(dst, 'patch_applied'), 'w').close()

    doubled = []
    for path in modified:
        if path.endswith(('.fdf', '.fdf.inc')):
            doubled += drop_duplicate_modules(dst, path)
    if doubled:
        print(f'  dropped {len(doubled)} module(s) the port adds and this edk2 already '
              f'has: {", ".join(os.path.basename(d) for d in doubled)}')

    ruled = complete_sanitizer_rules(src, dst)
    if ruled:
        print(f'  the port\'s SANITIZER build rule was missing from '
              f'{len(ruled)} section(s); added: {", ".join(ruled)}')

    pei_size, dxe_size = port_memfd_sizes(src, base)
    if pei_size and dxe_size:
        grew = enlarge_memfd(dst, 'OvmfPkg/OvmfPkgX64.fdf', pei_size, dxe_size)
        if grew:
            print(f'  MEMFD is defined in an include here; enlarged that instead -- {grew}')

    closed = 0
    for path in modified:
        if path.endswith(('.fdf', '.fdf.inc', '.dsc', '.dsc.inc')):
            closed += balance_conditionals(dst, path)
    if closed:
        print(f'  closed {closed} conditional(s) the port opened and upstream no longer '
              f'had a spare !endif for')

    repinned = []
    for path in modified:
        if path.endswith('.dsc'):
            repinned += enforce_library_pins(src, base, dst, path)
    if repinned:
        print(f'  applied the port\'s choice of {", ".join(sorted(set(repinned)))} to '
              f'{len(repinned)} entr(ies) upstream had pointed elsewhere')

    twinned = twin_clang_toolchain(dst)
    if twinned:
        print(f'  gave CLANGSAN the CLANGDWARF build options in {len(twinned)} file(s)')

    print(f'  merged cleanly     {len(clean)}')
    print(f'  conflicts resolved {len(resolved)}')
    print(f'  conflicts REMAINING {len(unresolved)}')
    for path in unresolved:
        print(f'      {path}')
    print(f'  could not apply    {len(failed)}')
    for path, why in failed:
        print(f'      {path}: {why}')
    print('  applied is not instrumented: build and count __asan_load/__asan_store')
    return 1 if (failed or unresolved) else 0


if __name__ == '__main__':
    sys.exit(main())
