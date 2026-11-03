#!/usr/bin/env python3
"""Does one unreachable submodule still poison the rest?

`git submodule update` clones every submodule first and checks each one out at the commit
the superproject records afterwards. When ONE cannot be cloned the operation aborts, and
the abort lands before that checkout pass -- so every submodule that cloned fine is left
at its default branch tip rather than the recorded commit, and the superproject reads as
MODIFIED.

That is not a hypothetical. An edk2 tree whose UnitTestFrameworkPkg/Library/SubhookLib/
subhook still points at https://github.com/Zeex/subhook (gone) produced exactly this:
`submodule update --init --depth=1` exited 1, 10 of the other 11 submodules were left off
their recorded commit, the stage reported `PASS submodules 10/11 populated` because the
exit code was discarded, and the port stage two steps later refused the tree with "has
uncommitted changes" -- naming neither submodules nor subhook.

Real git repositories here rather than mocks, because the whole behaviour under test is
what git does with a partly-failed submodule update. The dead remote is a local path that
does not exist, so this needs no network and cannot flake on someone else's outage.
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fuzz_edk2 import submodules_off_commit, repair_submodules  # noqa: E402


def allow_file_submodules():
    """Let git clone a submodule from a local path, for this process and its children.

    git refuses the `file` transport for submodules by default (CVE-2022-39253). Setting
    `protocol.file.allow` in the superproject's own config is not enough: the restriction
    is enforced in the child clone, which does not read it. GIT_CONFIG_* puts it in the
    ENVIRONMENT instead, so it reaches the plain `git` calls inside repair_submodules as
    well -- that function is the code under test and must not be special-cased here.
    """
    os.environ.update(GIT_TERMINAL_PROMPT='0', GIT_CONFIG_COUNT='1',
                      GIT_CONFIG_KEY_0='protocol.file.allow',
                      GIT_CONFIG_VALUE_0='always')


def git(*args, cwd=None, check=True):
    proc = subprocess.run(['git'] + list(args), cwd=cwd, capture_output=True, text=True,
                          env=dict(os.environ, GIT_TERMINAL_PROMPT='0'))
    if check and proc.returncode:
        raise RuntimeError(f'git {" ".join(args)} failed in {cwd}:\n{proc.stderr}')
    return proc


def out(*args, **kw):
    return git(*args, **kw).stdout.strip()


def dirty(tree):
    return out('status', '--porcelain', cwd=tree)


def make_sub(root, name, commits=2):
    """A submodule repo whose tip is NOT the commit the superproject will pin."""
    path = os.path.join(root, name)
    os.makedirs(path)
    git('init', '-q', '-b', 'main', cwd=path)
    git('config', 'user.email', 't@example.invalid', cwd=path)
    git('config', 'user.name', 'test', cwd=path)
    shas = []
    for n in range(commits):
        open(os.path.join(path, 'a.txt'), 'w').write(f'{n}\n')
        git('add', 'a.txt', cwd=path)
        git('commit', '-q', '-m', f'commit {n}', cwd=path)
        shas.append(out('rev-parse', 'HEAD', cwd=path))
    return path, shas


def fixture(root, with_dead=True):
    """A superproject pinning a live submodule at its FIRST commit, plus a dead one."""
    live, shas = make_sub(root, 'live')
    pinned, tip = shas[0], shas[-1]

    sup = os.path.join(root, 'super')
    os.makedirs(sup)
    git('init', '-q', '-b', 'main', cwd=sup)
    git('config', 'user.email', 't@example.invalid', cwd=sup)
    git('config', 'user.name', 'test', cwd=sup)
    git('config', 'protocol.file.allow', 'always', cwd=sup)
    git('submodule', 'add', '-q', f'file://{live}', 'vendor/live', cwd=sup)
    git('checkout', '-q', pinned, cwd=os.path.join(sup, 'vendor', 'live'))
    git('add', 'vendor/live', cwd=sup)
    if with_dead:
        # A remote that cannot resolve, the way subhook's URL cannot. Written straight
        # into .gitmodules and the index: `submodule add` would try to clone it.
        dead = os.path.join(root, 'no-such-repo.git')
        with open(os.path.join(sup, '.gitmodules'), 'a') as handle:
            handle.write(f'[submodule "vendor/dead"]\n\tpath = vendor/dead\n'
                         f'\turl = file://{dead}\n')
        git('add', '.gitmodules', cwd=sup)
        git('update-index', '--add', '--cacheinfo',
            f'160000,{tip},vendor/dead', cwd=sup)
    git('commit', '-q', '-m', 'pin the live submodule at its first commit', cwd=sup)
    return sup, pinned, tip


def clone(root, sup, name):
    work = os.path.join(root, name)
    git('-c', 'protocol.file.allow=always', 'clone', '-q', f'file://{sup}', work)
    # So that the plain `git` calls inside repair_submodules can reach a file:// submodule.
    git('config', 'protocol.file.allow', 'always', cwd=work)
    return work


def case_dead_submodule_poisons_the_rest(root):
    sup, pinned, tip = fixture(root, with_dead=True)
    work = clone(root, sup, 'work')
    live = os.path.join(work, 'vendor', 'live')

    upd = git('submodule', 'update', '--init', '--depth=1', cwd=work, check=False)
    ok = True
    if upd.returncode == 0:
        print('  [FAIL] the update succeeded; the fixture no longer reproduces an abort')
        return False
    print(f'  git submodule update exited {upd.returncode}, as it does on the real tree')

    off = submodules_off_commit(work)
    if off != ['vendor/live']:
        print(f'  [FAIL] expected vendor/live to be off its recorded commit, got {off}')
        return False
    if not dirty(work):
        print('  [FAIL] the superproject should read as dirty, which is what the port '
              'stage refuses')
        return False
    at = out('rev-parse', 'HEAD', cwd=live)
    print(f'  detected {off} left at the tip {at[:8]}, not the pinned {pinned[:8]}; '
          f'the tree is dirty')

    said = []
    still = repair_submodules(work, report=said.append)
    at = out('rev-parse', 'HEAD', cwd=live)
    if still:
        print(f'  [FAIL] repair left {still} wrong')
        ok = False
    elif at != pinned:
        print(f'  [FAIL] repaired to {at[:8]}, expected {pinned[:8]}')
        ok = False
    elif dirty(work):
        print(f'  [FAIL] still dirty after repair: {dirty(work)!r}')
        ok = False
    else:
        print(f'  [OK]   repaired to the pinned {pinned[:8]}, tree clean')
    # The repair must not pay for a full refetch: the objects are already local.
    shallow = out('rev-parse', '--is-shallow-repository', cwd=live)
    if shallow != 'true':
        print(f'  [FAIL] the submodule was deepened ({shallow}); the repair should not '
              f'refetch, which on a real tree means the whole of OpenSSL')
        ok = False
    else:
        print('  [OK]   the submodule is still shallow, so the repair cost no network')
    return ok


def case_already_correct(root):
    """Repair is a no-op on a tree that is already right."""
    sup, pinned, tip = fixture(root, with_dead=False)
    work = clone(root, sup, 'work2')
    git('submodule', 'update', '--init', '-q', cwd=work)
    off = submodules_off_commit(work)
    still = repair_submodules(work, report=lambda _m: None)
    ok = off == [] and still == [] and not dirty(work)
    print(f"  [{'OK' if ok else 'FAIL'}]   off={off}, repair={still}, "
          f"dirty={dirty(work)!r}")
    return ok


def case_uninitialised_is_not_wrong(root):
    """An uninitialised submodule is '-', not '+', and leaves the superproject clean.

    This is the subhook case stated as a property: a tree may pin a submodule whose URL
    has died, and a build that does not use it must not be blocked by it.
    """
    sup, pinned, tip = fixture(root, with_dead=True)
    work = clone(root, sup, 'work3')
    off = submodules_off_commit(work)
    status = out('submodule', 'status', cwd=work)
    marks = {line.split()[1]: line[:1] for line in status.splitlines() if line.split()}
    ok = (off == [] and not dirty(work)
          and marks.get('vendor/dead') == '-' and marks.get('vendor/live') == '-')
    print(f"  [{'OK' if ok else 'FAIL'}]   off={off}, marks={marks}, "
          f"dirty={dirty(work)!r}")
    return ok


CASES = (
    ('one dead submodule poisons the rest', case_dead_submodule_poisons_the_rest),
    ('a tree that is already correct', case_already_correct),
    ('an uninitialised submodule is not wrong', case_uninitialised_is_not_wrong),
)


def main():
    allow_file_submodules()
    bad = 0
    for name, fn in CASES:
        root = tempfile.mkdtemp(prefix='submodule-repair-')
        print(f'{name}:')
        try:
            if not fn(root):
                bad = 1
        except Exception as exc:
            print(f'  [FAIL] {type(exc).__name__}: {exc}')
            bad = 1
        finally:
            shutil.rmtree(root, ignore_errors=True)
    return bad


if __name__ == '__main__':
    sys.exit(main())
