#!/usr/bin/env python3
"""Assert the evidence branch is built and reported correctly.

The issues carry links to each finding's harness, crashing input and log, and those files
live on a branch of their own. When the push fails the issues still file -- so this step
degrades silently, and run 42703964006 lost the evidence for five issues while reporting
"the token needs Contents: write" at a repository that had already granted it.

Two defects, both covered here:
  * the branch exists and the fetch of it fails -> the old code committed with NO parent,
    which the remote rejects as a non-fast-forward. Losing the evidence is the SECOND
    cost; the first is that it looks like a permission problem.
  * git prints the same last line whatever went wrong, and the warning took only that
    line, then appended a cause it had not checked.

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


def setup(existing_branch):
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
    return work, remote, {'run1/crash.log': path}


def drive(existing_branch, break_fetch='', push_stderr=''):
    """push_evidence against the local remote.

    break_fetch is 'all' to fail every fetch or 'shallow' to fail only the --depth=1 one,
    which is what distinguishes "cannot reach the branch" from "cannot reach it CHEAPLY".
    Returns (result, remote commit count, the git subcommands it ran, what it printed).
    """
    work, remote, files = setup(existing_branch)
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

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
