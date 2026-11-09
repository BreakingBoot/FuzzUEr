#!/usr/bin/env python3
"""Assert the port edits edk2 without rewriting it, and refuses what it cannot merge.

Run 42185742692 failed its build with "extraneous closing brace" at six places in
MdeModulePkg/Core/PiSmmCore/PiSmmCore.c, `break` outside any loop, and mSmmCoreSmiHandlers
undeclared -- in a file that had merged cleanly on every run before it. Two independent
defects had to line up, and the second one is the dangerous one:

  * A port edit was written back through Python's text mode, which reads CRLF as LF and
    writes LF. edk2 is CRLF throughout, so a 26-line change was recorded as 988 insertions
    and 972 deletions: every line in the file. git's three-way merge then had no anchor
    left and produced ONE conflict hunk spanning lines 1 to 1953.
  * That hunk reached apply_asan.py's generic resolver, which is a key-value merge for the
    platform description files -- its own comment says it knows nothing about C syntax --
    because it was the `else` arm and a .c file fell through to it. key_of() keys a line on
    the text before its first '=', so every C statement containing an assignment has a key,
    and flush() drops the port's lines whose key collides with upstream's. It deleted
    statements out of the middle of functions and called it resolved.

The first one is a mistake anybody editing the port can make again. The second turned it
into a corrupted firmware source that still built most of the way, and the build error
named PiSmmCore.c while nothing named the merge. A port that silently corrupts the
firmware it is about to fuzz is worse than one that stops.
"""

import os
import re
import subprocess
import sys

# Before apply_asan.py is imported. It lives in a submodule, and a __pycache__ left beside
# it shows up as an untracked file there -- which reads as a dirty tree, and the port stage
# refuses a dirty tree.
sys.dont_write_bytecode = True
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TREE = os.path.join(ROOT, 'eval_source', 'edk2')

FAILURES = []


def check(name, condition, detail=''):
    if condition:
        print(f'  ok    {name}')
    else:
        print(f'  FAIL  {name}' + (f' -- {detail}' if detail else ''))
        FAILURES.append(name)


_PORT = None


def port_module():
    """apply_asan.py as a module, loaded once."""
    global _PORT
    if _PORT is None:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            'apply_asan_under_test', os.path.join(ROOT, 'uefi_asan', 'apply_asan.py'))
        _PORT = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_PORT)
    return _PORT


def git(*args):
    return subprocess.run(('git', '-C', TREE) + args, capture_output=True).stdout


def endings(data):
    """('crlf', 'lf', 'mixed' or 'none') for a blob."""
    crlf = data.count(b'\r\n')
    lf = data.count(b'\n') - crlf
    if crlf and lf:
        return 'mixed'
    if crlf:
        return 'crlf'
    return 'lf' if lf else 'none'


def line_endings_preserved():
    """Every file the port modifies keeps the line endings the base blob had."""
    base = port_module().PORT_BASE

    if not git('cat-file', '-e', base + '^{commit}') and \
            subprocess.run(('git', '-C', TREE, 'cat-file', '-e', base + '^{commit}'),
                           capture_output=True).returncode:
        return None, base, []
    names = git('diff', '--name-only', base, 'HEAD').decode().split()
    # Both HEAD and the working tree. The run that failed was an edit sitting in the
    # working tree -- the port stage reads files off disk, not out of git, so a check that
    # only diffs HEAD against the base passes while the tree it is about to copy is
    # already broken. That is how this reached CI in the first place.
    wrong = []
    for name in sorted(set(names) | set(git('diff', '--name-only').decode().split())):
        if not name.endswith(('.c', '.h', '.inf', '.dec', '.dsc', '.fdf', '.nasm',
                              '.template', '.inc', '.uni', '.lds')):
            continue
        was = git('show', f'{base}:{name}')
        if not was:
            continue
        try:
            now = open(os.path.join(TREE, name), 'rb').read()
        except OSError:
            continue
        before, after = endings(was), endings(now)
        if before != after:
            wrong.append((name, before, after))
    return names, base, wrong


# A .c conflict, shaped like the one that broke the build: the port's side and upstream's
# side both contain assignments, and some of them share the text before the '='.
C_CONFLICT = '''\
VOID
SmmEntryPoint (
  VOID
  )
{
  UINTN  BufferSize;

<<<<<<< ours
  Status = SmiManage (&Guid, NULL, Data, &BufferSize);
  DEBUG ((DEBUG_INFO, "dispatch %r\\n", Status));
  gSmmCorePrivate->BufferSize = BufferSize + 8;
=======
  Status = SmiManage (&Guid, NULL, Data, &BufferSize);
  gSmmCorePrivate->BufferSize = BufferSize;
>>>>>>> theirs
  for (Index = 0; Index < Count; Index++) {
    break;
  }
}
'''

# Mind which side is which, because it reads backwards. The port applies its edits to the
# target tree with `git apply --3way`, so "ours" is the TARGET edk2 and "theirs" is the
# PORT's patch. Confirmed on the real conflict: the hunk ran `<<<<<<< ours` over eval1's
# 963-line PiSmmCore.c and `>>>>>>> theirs` over the port's 988-line one. flush() therefore
# drops OURS where the keys collide and keeps THEIRS, which is the port winning -- exactly
# what its comment says, and the opposite of what the labels suggest.
DSC_CONFLICT = '''\
[LibraryClasses]
<<<<<<< ours
  BaseCryptLib|CryptoPkg/Library/BaseCryptLib/BaseCryptLib.inf
  AmdSvsmLib|UefiCpuPkg/Library/AmdSvsmLibNull/AmdSvsmLibNull.inf
=======
  BaseCryptLib|CryptoPkg/Library/BaseCryptLibNull/BaseCryptLibNull.inf
  AsanLib|MdeModulePkg/Library/AsanLib/AsanLib.inf
>>>>>>> theirs
'''


def pristine(body):
    """The destination's side of a conflicted body -- what a clean checkout holds."""
    out, keep = [], None
    for line in body.split('\n'):
        if line.startswith('<<<<<<< '):
            keep = 'ours'
        elif line.startswith('=======') and keep:
            keep = 'theirs'
        elif line.startswith('>>>>>>> ') and keep:
            keep = None
        elif keep == 'theirs':
            continue
        else:
            out.append(line)
    return '\n'.join(out)


def resolve_one(name, body):
    """Run the port's resolver over one conflicted file and say what it did.

    A real git repository, not just a directory: the diagnostic-only arm restores its
    file with `git checkout HEAD --`, because the hunks that already applied cannot be
    undone by filtering conflict markers. A plain temp dir would silently exercise that
    arm's fallback instead of the path a campaign takes.

    HEAD holds the destination's side, which is what a clean checkout of the ref being
    ported to contains; the conflicted body is then written over it unstaged, exactly as
    `git apply -3` leaves things.
    """
    mod = port_module()
    work = tempfile.mkdtemp(prefix='portchk-')
    full = os.path.join(work, name)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    subprocess.run(['git', 'init', '-q', work], check=False)
    with open(full, 'w', newline='') as handle:
        handle.write(pristine(body))
    for argv in (['add', '--', name],
                 ['-c', 'user.email=check@example.invalid', '-c', 'user.name=check',
                  '-c', 'commit.gpgsign=false', 'commit', '-qm', 'pristine']):
        subprocess.run(['git', '-C', work] + argv, check=False,
                       capture_output=True)
    with open(full, 'w', newline='') as handle:
        handle.write(body)
    resolved, unresolved, dropped = mod.resolve_conflicts(work, [name])
    return resolved, unresolved, dropped, open(full, newline='').read()


def main():
    print('the port edits edk2 without rewriting it')
    names, base, wrong = line_endings_preserved()
    if names is None:
        check('the port base is reachable', False,
              f'{base[:12]} is not in {TREE}; a shallow checkout cannot run this check')
    else:
        check('the port modifies a plausible number of files', 20 <= len(names) <= 200,
              f'{len(names)} file(s) differ from {base[:12]}')
        check('no port edit changed a file\'s line endings', not wrong,
              '; '.join(f'{n}: {a} was {b}' for n, b, a in wrong)
              + ' -- Python text mode reads CRLF as LF and writes LF, which rewrites '
                'every line and leaves git\'s merge with no anchor')
        pismm = 'MdeModulePkg/Core/PiSmmCore/PiSmmCore.c'
        on_disk = endings(open(os.path.join(TREE, pismm), 'rb').read())
        check('the file that broke run 42185742692 is CRLF on disk',
              on_disk == 'crlf', on_disk)

    print('and refuses a conflict it has no model for')
    # A C source the port changes for real. Still refused: the key-value merge drops
    # statements out of the middle of functions, and there is no model for a C conflict.
    resolved, unresolved, dropped, after = resolve_one(
        'MdeModulePkg/Core/Dxe/DxeMain/DxeMain.c', C_CONFLICT)
    check('a conflicted C source is left unresolved',
          unresolved and not resolved and not dropped,
          f'resolved={resolved} unresolved={unresolved} dropped={dropped}')
    check('and it is not rewritten on the way out', '<<<<<<< ours' in after,
          'refusing means leaving the markers for a human, not writing a guess')

    print('while dropping one whose port content is only narration')
    # PiSmmCore.c is the exception, and it is not a softened standard: upstream deleted
    # the variable the port's DEBUG names, so keeping the port's side does not compile.
    # Dropping is the only correct resolution, and the alternative -- refusing -- fails
    # the port stage and stops a campaign that would otherwise have found defects.
    pismm = 'MdeModulePkg/Core/PiSmmCore/PiSmmCore.c'
    mod = port_module()
    check('it is declared diagnostic-only, with a reason',
          pismm in getattr(mod, 'DIAGNOSTIC_ONLY', {})
          and len(mod.DIAGNOSTIC_ONLY.get(pismm, '')) > 40,
          'a path dropped without a recorded reason is a capability lost silently')
    resolved, unresolved, dropped, after = resolve_one(pismm, C_CONFLICT)
    check('a conflict there is dropped, not refused',
          dropped == [pismm] and not unresolved and not resolved,
          f'resolved={resolved} unresolved={unresolved} dropped={dropped}')
    check('and the file it leaves has no markers',
          '<<<<<<<' not in after and '=======' not in after
          and '>>>>>>>' not in after,
          'the port stage passes on a dropped file, so what is left has to build')
    check('the whole file goes back to the destination\'s version',
          after == pristine(C_CONFLICT),
          'not just the conflicted hunks: a port diff is several hunks and they succeed '
          'independently, so resolving only the conflicts leaves half the narration -- '
          'untrustworthy to read, and a compile break as soon as the half that survives '
          'is the one naming a variable upstream deleted')
    check('and the port\'s side is gone, not merged in',
          after.count('SmiManage') == 1
          and 'gSmmCorePrivate->BufferSize = BufferSize;' not in after,
          'keeping both sides of a C conflict duplicates statements -- two SmiManage '
          'calls here -- which is the corruption this whole arm exists to prevent')

    print('while still merging what it does have a model for')
    resolved, unresolved, dropped, after = resolve_one('OvmfPkg/OvmfPkgX64.dsc',
                                                       DSC_CONFLICT)
    check('a conflicted DSC still resolves',
          resolved and not unresolved and not dropped,
          f'resolved={resolved} unresolved={unresolved} dropped={dropped}')
    check('the port\'s value wins where both sides set the same key',
          'BaseCryptLibNull' in after and 'BaseCryptLib/BaseCryptLib.inf' not in after,
          'the port picks BaseCryptLibNull because openssl is not built -- and "ours" is '
          'the target tree, not the port')
    check('upstream\'s key the port never had is kept', 'AmdSvsmLibNull' in after,
          'a line upstream added and the port never set is not in competition')
    check('the port\'s own addition survives', 'AsanLib' in after)
    check('no markers are left behind', '<<<<<<<' not in after)

    print(f'{len(FAILURES)} failure(s)')
    return 1 if FAILURES else 0


if __name__ == '__main__':
    sys.exit(main())
