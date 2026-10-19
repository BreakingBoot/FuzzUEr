"""Have the two copies of the sanitizer drifted?

The sanitizer exists twice. `uefi_asan/` is where it is developed and is what
`apply_asan.py` copies FROM; `eval_source/edk2/` is the fork it has already been applied
to, and that fork is what gets built. Both are real, neither is generated from the other,
and nothing has ever checked that they agree.

So the failure mode is this: you fix the copy that builds, verify the fix by booting it,
commit it, and the copy that ships to every other edk2 version still has the bug. Or the
reverse -- you fix `uefi_asan/`, see nothing change, and conclude the fix did not work.
Both have happened. The second is worse, because `apply_asan.py` reads
`git show HEAD:<path>`, so an UNCOMMITTED edit to the fork reaches no build at all and the
symptom is indistinguishable from a wrong fix.

    python3 scripts/asan_sync_check.py            # from the repository root
    python3 scripts/asan_sync_check.py --quiet    # only print what has drifted

Line endings are ignored, because the two trees disagree about them file by file and that
difference is not drift. Anything else is.
"""

import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

# reference path (under uefi_asan/) -> the path in the fork it corresponds to.
# A directory pair expands to every file the reference side holds, so a file ADDED to the
# reference and never applied to the fork is caught as well as one that was edited.
PAIRS = (
    ('Asan.h', 'MdeModulePkg/Include/Library/Asan.h'),
    ('AsanInfo.h', 'MdeModulePkg/Include/Guid/AsanInfo.h'),
    ('AsanLib', 'MdeModulePkg/Library/AsanLib'),
    ('AsanLibNull', 'MdeModulePkg/Library/AsanLibNull'),
    ('AsanRuntimeLib', 'MdeModulePkg/Library/AsanRuntimeLib'),
    ('AsanMemoryLib', 'MdePkg/Library/AsanMemoryLib'),
    ('AsanMemoryLibRepStr', 'MdePkg/Library/AsanMemoryLibRepStr'),
)


def read(path):
    """Contents with line endings normalised, or None when it is not there."""
    try:
        with open(path, 'rb') as handle:
            return handle.read().replace(b'\r\n', b'\n')
    except OSError:
        return None


def read_committed(repo, rel):
    """The file as HEAD has it, which is what apply_asan.py actually ships.

    Reading the worktree here was the hole this check was written to close and did not:
    apply_asan.py takes the port from `git show HEAD:<path>`, so a fix edited in both trees
    and committed to neither compares equal, reports "in sync", and reaches no build. The
    symptom is then indistinguishable from a wrong fix, which is the expensive case.
    """
    done = subprocess.run(['git', '-C', repo, 'show', f'HEAD:{rel}'],
                          capture_output=True)
    if done.returncode:
        return None
    return done.stdout.replace(b'\r\n', b'\n')


def dirty_paths(repo):
    """Tracked files with uncommitted changes, relative to that repository."""
    done = subprocess.run(['git', '-C', repo, 'status', '--porcelain', '--untracked-files=no'],
                          capture_output=True, text=True)
    if done.returncode:
        return set()
    found = set()
    for line in done.stdout.splitlines():
        name = line[3:].strip()
        # a rename prints "old -> new"; the new side is what would be shipped
        if ' -> ' in name:
            name = name.split(' -> ', 1)[1]
        if name:
            found.add(name.strip('"'))
    return found


def expand(reference_root, fork_root):
    """Every (reference, fork) file pair, for a file pair or a directory pair."""
    if os.path.isfile(reference_root):
        return [(reference_root, fork_root)]
    found = []
    for base, _dirs, files in os.walk(reference_root):
        for name in sorted(files):
            # build leftovers, not sources
            if name.endswith(('.pyc', '.obj', '.lib', '.efi', '.debug', '.map')):
                continue
            src = os.path.join(base, name)
            rel = os.path.relpath(src, reference_root)
            found.append((src, os.path.join(fork_root, rel)))
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--reference', default=os.path.join(REPO, 'uefi_asan'),
                        help='the tree the sanitizer is developed in')
    parser.add_argument('--fork', default=os.path.join(REPO, 'eval_source', 'edk2'),
                        help='the edk2 the port has already been applied to')
    parser.add_argument('--quiet', action='store_true', help='only print drift')
    args = parser.parse_args()

    drifted, missing, same = [], [], 0
    uncommitted, absent_pairs = [], []
    dirty = dirty_paths(args.fork)
    for reference_rel, fork_rel in PAIRS:
        reference_root = os.path.join(args.reference, reference_rel)
        fork_root = os.path.join(args.fork, fork_rel)
        if not os.path.exists(reference_root):
            # Silently skipping made a renamed or deleted reference directory drop out of
            # the comparison with no notice -- the script just printed a smaller "N in sync".
            absent_pairs.append(reference_rel)
            continue
        for src, dst in expand(reference_root, fork_root):
            rel = os.path.relpath(dst, args.fork)
            if rel in dirty:
                uncommitted.append(os.path.relpath(dst, REPO))
            a = read(src)
            # HEAD, not the worktree: that is what gets ported.
            b = read_committed(args.fork, rel)
            if b is None:
                b = read(dst)
            short_src = os.path.relpath(src, REPO)
            short_dst = os.path.relpath(dst, REPO)
            if b is None:
                # Only in the reference: never applied to the fork at all, which is the
                # shape that makes a fix look like it did nothing.
                missing.append((short_src, short_dst))
            elif a != b:
                drifted.append((short_src, short_dst))
            else:
                same += 1
                if not args.quiet:
                    print('  same     %s' % short_src)

    for short_src, short_dst in missing:
        print('  MISSING  %s\n           has no counterpart at %s' % (short_src, short_dst))
    for short_src, short_dst in drifted:
        print('  DRIFTED  %s\n           differs from %s' % (short_src, short_dst))
    for short in uncommitted:
        print('  UNCOMMITTED  %s\n               edited but not committed, so apply_asan.py '
              'ships the old one' % short)
    for name in absent_pairs:
        print('  ABSENT   %s is in PAIRS but not in the reference tree -- renamed or removed?'
              % name)

    print()
    print('%d in sync, %d drifted, %d missing from the fork, %d uncommitted'
          % (same, len(drifted), len(missing), len(uncommitted)))
    if uncommitted:
        print('An uncommitted edit to the fork reaches NO build: apply_asan.py reads '
              'git show HEAD:<path>. Commit it, or the next version ported gets the old '
              'sanitizer and the symptom looks like a wrong fix.')
    if drifted or missing or uncommitted or absent_pairs:
        print('Fix by copying whichever side is right -- and remember apply_asan.py reads '
              'git show HEAD:<path>, so an uncommitted edit to the fork reaches no build.')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
