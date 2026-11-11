#!/usr/bin/env python3
"""Assert the evidence branch is built and reported correctly.

The issues carry links to each finding's harness, crashing input and log, and those files
live on a branch of their own. When the push fails the issues still file -- so this step
degrades silently, and run 42703964006 lost the evidence for five issues while reporting
"the token needs Contents: write" at a repository that had already granted it.

Three defects, all covered here:
  * the branch exists and the fetch of it fails -> the old code committed with NO parent,
    which the remote rejects as a non-fast-forward. Losing the evidence is the SECOND
    cost; the first is that it looks like a permission problem.
  * git prints the same last line whatever went wrong, and the warning took only that
    line, then appended a cause it had not checked.
  * fuzz.txt went on the branch WHOLE. GitHub rejects a push holding any file over
    100 MB, so a 191 MB capture (run 42933720452) or a 214 MB one (42703964006) loses the
    evidence for every issue in the run -- and 42703964006 had already filed five, which
    are live with no harness, no input and no log. The sizes correlate exactly: 96 MB and
    0 MB pushed, 191 MB and 214 MB did not.

The size assertions pin 40 MiB and 80 MiB as LITERALS rather than reading
fi.MAX_EVIDENCE_FILE, so raising the constant past GitHub's warning fails the check
instead of moving the goalposts with it. They are all read back off the pushed commit --
a blob's size and its bytes, never the source text, because a constant can be defined and
never used.

Everything runs against a real local bare remote. Only the URL is substituted, because a
file path is the one thing the token URL cannot be.

Run: python3 scripts/evidence_push_check.py
"""
import io
import os
import subprocess
import sys
import tempfile
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import file_issues as fi

FAILED = 0
PASSED = 0


def check(what, ok, detail=''):
    global FAILED, PASSED
    if ok:
        PASSED += 1
        print(f'  [OK]   {what}')
    else:
        FAILED += 1
        print(f'  [FAIL] {what}' + (f'\n         {detail}' if detail else ''))


def sh(*args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, **kwargs)


# What GitHub actually enforces, written out here so the check does not inherit a bad
# edit to the implementation's own constants.
GITHUB_HARD_LIMIT = 100 * 1000 * 1000
CAP_PER_FILE = 40 * 1024 * 1024
CAP_TOTAL = 80 * 1024 * 1024

HEAD_MARK = b'MARK-first-line-of-the-capture'
EARLY_MARK = b'MARK-report-two-percent-in'
MIDDLE_MARK = b'MARK-halfway-through-the-filler'
TAIL_MARK = b'MARK-last-line-of-the-capture'

_BIG = {}


def big_capture(size, marks=True):
    """A capture of a given size with known markers at known offsets.

    Built once and reused: these run to tens of MiB and clip_evidence only reads them.
    The markers stand in for the real file's reports, which are NOT evenly spread -- on
    run 42933720452's 191 MB fuzz.txt all 28 distinct `bug_descr=` lines, every ASan
    finding among them, first appear inside the first 3.6%, and the last 96% is the same
    fwsan sites repeating. So a marker near the START is the one that matters most.
    """
    key = (size, marks)
    if key in _BIG:
        return _BIG[key]
    path = os.path.join(tempfile.mkdtemp(), f'fuzz{len(_BIG)}.txt')
    filler = (b'FIRNESS: iteration filler line, nothing to see here\n' * 512)
    with open(path, 'wb') as handle:
        written = 0
        if marks:
            written += handle.write(HEAD_MARK + b'\n')
        while written < size:
            at = written / size
            if marks and at < 0.02 <= (written + len(filler)) / size:
                written += handle.write(EARLY_MARK + b'\n')
            if marks and at < 0.5 <= (written + len(filler)) / size:
                written += handle.write(MIDDLE_MARK + b'\n')
            written += handle.write(filler[:max(1, min(len(filler), size - written))])
        if marks:
            handle.write(TAIL_MARK + b'\n')
    _BIG[key] = path
    return path


def setup(existing_branch, extra=None):
    """A bare remote, a work repo, and one evidence file to publish."""
    base = tempfile.mkdtemp()
    remote, work = os.path.join(base, 'remote'), os.path.join(base, 'work')
    os.makedirs(remote)
    os.makedirs(work)
    sh('git', 'init', '-q', '--bare', remote)
    sh('git', 'init', '-q', work)
    sh('git', '-C', work, 'config', 'user.email', 'check@example.invalid')
    sh('git', '-C', work, 'config', 'user.name', 'check')
    io.open(os.path.join(work, 'seed.txt'), 'w').write('seed\n')
    sh('git', '-C', work, 'add', '.')
    sh('git', '-C', work, '-c', 'commit.gpgsign=false', 'commit', '-qm', 'seed')
    if existing_branch:
        env = dict(os.environ, GIT_INDEX_FILE=os.path.join(base, 'index0'))
        blob = sh('git', '-C', work, 'hash-object', '-w', '--stdin',
                  input='earlier run\n', env=env).stdout.strip()
        sh('git', '-C', work, 'read-tree', '--empty', env=env)
        sh('git', '-C', work, 'update-index', '--add', '--cacheinfo',
           f'100644,{blob},run0/log.txt', env=env)
        tree = sh('git', '-C', work, 'write-tree', env=env).stdout.strip()
        commit = sh('git', '-C', work, '-c', 'commit.gpgsign=false', 'commit-tree',
                    tree, '-m', 'run 0', env=env).stdout.strip()
        sh('git', '-C', work, 'push', '-q', remote,
           f'{commit}:refs/heads/{fi.EVIDENCE_BRANCH}')
    path = os.path.join(base, 'crash.log')
    io.open(path, 'w').write('crash log\n')
    files = {'run1/crash.log': path}
    files.update(extra or {})
    return work, remote, files


def staged_blobs(work, remote):
    """published path -> (blob sha, size) as the pushed commit actually holds it."""
    listed = sh('git', 'ls-remote', remote,
                f'refs/heads/{fi.EVIDENCE_BRANCH}').stdout.split()
    if not listed:
        return {}
    out = {}
    for line in sh('git', '-C', work, 'ls-tree', '-r', '-l',
                   listed[0]).stdout.splitlines():
        meta, _, path = line.partition('\t')
        bits = meta.split()
        if len(bits) == 4:
            out[path] = (bits[2], int(bits[3]))
    return out


def blob_bytes(work, sha):
    return subprocess.run(['git', '-C', work, 'cat-file', 'blob', sha],
                          capture_output=True).stdout


def drive(existing_branch, break_fetch='', push_stderr='', extra=None):
    """push_evidence against the local remote.

    break_fetch is 'all' to fail every fetch or 'shallow' to fail only the --depth=1 one,
    which is what distinguishes "cannot reach the branch" from "cannot reach it CHEAPLY".
    Returns (result, remote commit count, the git subcommands it ran, what it printed).
    """
    work, remote, files = setup(existing_branch, extra)
    real = fi.git
    ran = []

    def patched(repo, *args, env=None):
        args = [remote if isinstance(a, str) and a.startswith('https://') else a
                for a in args]
        ran.append(' '.join(str(a) for a in args))
        if args and args[0] == 'fetch' and (
                break_fetch == 'all'
                or (break_fetch == 'shallow' and '--depth=1' in args)):
            return subprocess.CompletedProcess(args, 1, '', 'fatal: simulated failure\n')
        if push_stderr and args and args[0] == 'push':
            return subprocess.CompletedProcess(args, 1, '', push_stderr)
        return real(repo, *args, env=env)

    fi.git = patched
    held, sys.stdout = sys.stdout, StringIO()
    try:
        out = fi.push_evidence(work, 'BreakingBoot/eval1_edk2', 'token-not-used-locally',
                               '99', files, 'https://github.com')
    finally:
        fi.git = real
        said = sys.stdout.getvalue()
        sys.stdout = held
    listed = sh('git', 'ls-remote', remote,
                f'refs/heads/{fi.EVIDENCE_BRANCH}').stdout.split()
    count = int(sh('git', '-C', work, 'rev-list', '--count',
                   listed[0]).stdout.strip() or 0) if listed else 0
    drive.work, drive.remote, drive.files = work, remote, files
    return out, count, ran, said


def main():
    if sh('git', '--version').returncode:
        print('  [skip] git is not installed')
        return 0
    print('the evidence branch is built and reported correctly')

    out, count, ran, _ = drive(existing_branch=False)
    check('a first run publishes a root commit', bool(out) and count == 1,
          f'returned {out!r} and the branch has {count} commit(s)')

    out, count, ran, _ = drive(existing_branch=True)
    check('a later run ADDS to the branch instead of replacing it',
          bool(out) and count == 2,
          f'returned {out!r} and the branch has {count} commit(s); each run is supposed '
          f'to add a directory and rewrite nothing')

    # Not just "it did not publish": it must not have ATTEMPTED the push. Reaching the
    # push with no parent is the defect -- the remote rejects it, so the file count on
    # the branch looks identical either way, and only the attempt tells the two apart.
    out, count, ran, said = drive(existing_branch=True, break_fetch='all')
    pushed = [c for c in ran if c.startswith('push')]
    check('an unfetchable existing branch refuses WITHOUT attempting the push',
          out == '' and count == 1 and not pushed,
          f'returned {out!r}, branch has {count} commit(s), push attempts: {pushed}; '
          f'committing without the remote tip as the parent is a guaranteed '
          f'non-fast-forward, and that rejection reads exactly like a permission failure')
    check('and says the branch could not be fetched, not that a push was rejected',
          'evidence branch is at' in said and 'fetching it failed' in said,
          f'the warning was: {said.strip()[:200]!r}')

    # A shallow fetch of one ref can fail where a full fetch works. Giving up there
    # loses the evidence for a cost saving.
    out, count, ran, said = drive(existing_branch=True, break_fetch='shallow')
    check('a shallow fetch that fails falls back to a full one',
          bool(out) and count == 2,
          f'returned {out!r} and the branch has {count} commit(s); the --depth=1 fetch '
          f'is the cheap path, not the required one')

    # Static, because the tip guard now stops the one case where a force would make a
    # difference -- so a force added later would do nothing visible until the day the
    # guard is wrong, and then it would silently delete every earlier run's evidence.
    src = io.open(os.path.join(os.path.dirname(os.path.abspath(fi.__file__)),
                               'file_issues.py'), encoding='utf-8').read()
    push_line = [l for l in src.splitlines() if "git(source, 'push'" in l]
    check('the evidence push is never forced',
          len(push_line) == 1 and '--force' not in push_line[0] and '-f' not in
          push_line[0].split(','),
          f'the push line is {push_line}; the branch is append-only by design, one '
          f'directory per run, and a force-push deletes every earlier run\'s evidence')

    # The reason line, which is what the warning used to throw away. git prints the
    # per-ref rejection with a leading "!" and the server's refusal with "remote:";
    # "failed to push some refs" and the advice hints are the same text either way.
    cases = {
        'non-fast-forward': (
            "To <remote>\n"
            " ! [rejected]        abc123 -> fuzzuer-evidence (non-fast-forward)\n"
            "error: failed to push some refs to '<remote>'\n"
            "hint: Updates were rejected because a pushed branch tip is behind its "
            "remote\n"
            "hint: See the 'Note about fast-forwards' in 'git push --help' for details.\n",
            'non-fast-forward'),
        'a denied token': (
            "remote: Permission to BreakingBoot/eval1_edk2.git denied to "
            "github-actions[bot].\n"
            "fatal: unable to access '<remote>': The requested URL returned error: 403\n",
            'denied'),
    }
    for label, (stderr, wanted) in cases.items():
        out, _, _, said = drive(existing_branch=False, push_stderr=stderr)
        check(f'a push rejected for {label} is reported with the line that says so',
              out == '' and wanted in said and 'hint:' not in said,
              f'the warning was: {said.strip()[:200]!r}')

    print('\nan oversized capture is clipped, not dropped and not pushed whole')
    # 160 MiB, the order the real captures come in at (191 MB and 214 MB on the two runs
    # that lost their push), and four times the 40 MiB ceiling on purpose: whatever split
    # between head and tail the implementation picks, 40 MiB of a 160 MiB file cannot
    # reach the midpoint, so MIDDLE_MARK is in the elided region for any split and the
    # assertion below is not quietly reading the implementation's own share back.
    capture = big_capture(160 * 1024 * 1024)
    original = os.path.getsize(capture)
    out, _, _, said = drive(existing_branch=False,
                            extra={'run1/DiscoveredSmi/crash/fuzz.txt': capture})
    blobs = staged_blobs(drive.work, drive.remote)
    clipped = blobs.get('run1/DiscoveredSmi/crash/fuzz.txt')
    check('a capture over the cap still reaches the branch',
          bool(out) and clipped is not None,
          f'returned {out!r} and the branch holds {sorted(blobs)}; dropping it silently '
          f'is the other way to lose the evidence')
    check(f'and no pushed blob exceeds {CAP_PER_FILE} bytes',
          bool(blobs) and max(size for _, size in blobs.values()) <= CAP_PER_FILE,
          f'blob sizes are {sorted(s for _, s in blobs.values())}; GitHub warns at 50 MB '
          f'and rejects the WHOLE push at {GITHUB_HARD_LIMIT}, which loses the evidence '
          f'for every issue in the run')

    body = blob_bytes(drive.work, clipped[0]) if clipped else b''
    check('the clip keeps the start of the capture, where the reports are',
          HEAD_MARK in body and EARLY_MARK in body,
          f'head marker present: {HEAD_MARK in body}, 2%-in marker: {EARLY_MARK in body}. '
          f'On the real 191 MB file all 28 distinct bug_descr lines and all 464 "ASAN '
          f'MEMORY ACCESS check fail" lines are in the first 3.6%, so a tail-only clip '
          f'publishes 42 MB holding not one ASan finding')
    check('and the end of it, which is where whatever stopped the run is',
          TAIL_MARK in body,
          'the tail marker is missing; the head alone cannot show the last iteration')
    check('and really elides the middle rather than publishing the file whole',
          MIDDLE_MARK not in body and len(body) < original,
          f'the halfway marker is still there, or {len(body)} is not smaller than '
          f'{original}: the size assertion can also be satisfied by a smaller cap, so '
          f'this is the one that says the middle went')
    check('the published file says in its own content that it was truncated',
          b'TRUNCATED' in body[:4096],
          f'its first 4 KiB are {body[:200]!r}; a clipped capture that does not announce '
          f'itself reads as a complete one, and a reader counts reports off it')
    check('and names the original size, so a short count is explicable',
          str(original).encode() in body[:4096],
          f'{original} does not appear in the banner; "this was truncated" without the '
          f'original size tells a reader nothing about how much is missing')
    check('and marks the point the elision happened',
          b'elided here' in body,
          'nothing in the body says where the gap is, so the head and the tail read as '
          'one continuous capture')
    check('and the run log says it clipped the file and by how much',
          'clipped run1/DiscoveredSmi/crash/fuzz.txt' in said
          and str(original) in said,
          f'it printed {said.strip()[:200]!r}')

    small = drive.files['run1/crash.log']
    kept = blobs.get('run1/crash.log')
    check('a file under the cap is published byte for byte, with no banner',
          kept is not None
          and blob_bytes(drive.work, kept[0]) == io.open(small, 'rb').read(),
          f'crash.log went up as {kept} against {os.path.getsize(small)} bytes on disk; '
          f'clipping what already fits corrupts the evidence to no purpose')

    print(f'\nthe whole push is bounded, not just each file in it')
    # Three captures UNDER the per-file cap that together exceed the total. The per-file
    # ceiling cannot catch this one, and it is the shape a real run has: one directory per
    # campaign, three logs and up to eight inputs in each.
    # Four captures of 30 MiB, each UNDER the per-file cap and 120 MiB together. One file
    # on disk under four published paths -- same bytes, four campaigns, which is what a
    # run looks like. The budget runs out partway through the fourth, so this covers both
    # halves of the behaviour: clipped to what is left, then left off entirely.
    many = {f'run1/C{n}/crash/fuzz.txt': big_capture(30 * 1024 * 1024, marks=False)
            for n in range(4)}
    # And a harness source at the size the generator really emits -- 81337 bytes for
    # DiscoveredSmi on run 42933720452. It is the file an issue is useless without, and at
    # 79 KiB it is the one that gets evicted by anything that spends the budget biggest
    # first, because the leftovers are then too small to be worth publishing.
    harness = os.path.join(tempfile.mkdtemp(), 'FirnessHarnesses.c')
    io.open(harness, 'wb').write(b'// generated harness\n' * 3697)
    many['run1/C0/harness/FirnessHarnesses.c'] = harness
    out, _, _, said = drive(existing_branch=False, extra=many)
    blobs = staged_blobs(drive.work, drive.remote)
    total = sum(size for _, size in blobs.values())
    check(f'the pushed bytes stay at or under {CAP_TOTAL} in all',
          bool(out) and 0 < total <= CAP_TOTAL,
          f'the commit holds {total} bytes over {len(blobs)} blob(s): '
          f'{sorted((p, s) for p, (_, s) in blobs.items())}. Twenty campaigns at the '
          f'per-file ceiling is a branch nobody can clone, and the push fails for size '
          f'long before that')
    cheap = {'run1/crash.log': small, 'run1/C0/harness/FirnessHarnesses.c': harness}
    check('and the kilobyte-sized files survive the captures that spend the budget',
          all(path in blobs and blobs[path][1] == os.path.getsize(local)
              for path, local in cheap.items()),
          f'the branch holds {sorted((p, s) for p, (_, s) in blobs.items())} against '
          f'{ {p: os.path.getsize(l) for p, l in cheap.items()} } on disk; the budget is '
          f'spent smallest first exactly so an 80 KiB harness source -- the file an issue '
          f'is useless without -- is never evicted by a 30 MiB capture')
    check('and it says which files it left off',
          '::warning::' in said and 'left' in said and 'evidence file' in said,
          f'it printed {said.strip()[:300]!r}; a file silently absent from the branch is '
          f'a dead link in an issue')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
