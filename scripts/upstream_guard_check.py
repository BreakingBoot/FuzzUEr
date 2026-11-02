#!/usr/bin/env python3
"""Can a fuzzing finding reach upstream edk2?

The rule is absolute -- candidates are filed at forks and platform branches, never at
tianocore -- and for a long time the whole of the enforcement was one shell `case` in
action.yml, matching the raw output of `git remote get-url origin` against
`*tianocore/edk2*`. Three ordinary ways of writing that same remote walked past it:

    https://github.com/TianoCore/edk2.git     owner and repo names on GitHub are
    git@github.com:TIANOCORE/edk2.git         case-INSENSITIVE, so all three of these
    https://github.com/tianocore//edk2.git    resolve to upstream

and because it keyed on a repository NAME rather than on the org, every tianocore
repository whose name does not begin `edk2` went through untouched -- `containers`,
`tianocore.github.io`, and `full-disclosure`, which of everything in the org is the last
place a scheduled job should be opening issues. scripts/file_issues.py had no check of its
own: --slug went straight into POST /repos/{slug}/issues and into the force-push URL in
push_evidence.

So there are two checks now, and this exercises BOTH of them against the same table. That
is the point -- a rule with one enforcement point is one typo away from having none -- and
a test that only covered the Python half would have passed on the day the bypass existed.

    python3 scripts/upstream_guard_check.py             # from the repository root
    python3 scripts/upstream_guard_check.py --verbose   # print every case, not just failures

No network and no token: the shell half is sliced out of action.yml and run on a string,
and the Python half is asked about a slug and then run end to end with a --bugs path that
does not exist, so a slug that is NOT refused stops at "cannot read" rather than reaching
api.github.com.
"""

import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
ACTION = os.path.join(REPO, 'action.yml')
FILER = os.path.join(HERE, 'file_issues.py')

sys.path.insert(0, HERE)
import file_issues as fi                                  # noqa: E402

# remote as a caller might really have it, and what each half of the enforcement must say
# about it: (remote, the action must refuse it, the filer must refuse its slug).
#
# The two verdicts are the same everywhere but one row, and that row is worth the shape of
# this table. `git.tianocore.org/git/edk2` is upstream, and the action refuses it on the
# HOST -- but the slug the action derives is `git/edk2`, with no host left in it, and
# nothing downstream can reconstruct from `git/edk2` that it came from tianocore.org. That
# is not a hole so much as the boundary: file_issues.py speaks to api.github.com and
# force-pushes to github.com, so a tianocore.org remote is not somewhere it can reach. It
# IS refused when the whole URL is handed to --slug, which is what a person typing this by
# hand would do, and that row is below too.
#
# The first four rows are the case and duplicate-slash bypasses, and rows six to eight are
# the org hole -- real tianocore repositories whose names do not begin `edk2`, which is what
# the old pattern keyed on. The ALLOWED half matters every bit as much: a guard that refuses
# `my-tianocore-fork/edk2` has broken the only workflow this tool has.
CASES = (
    ('https://github.com/TianoCore/edk2.git', True, True),
    ('git@github.com:TIANOCORE/edk2.git', True, True),
    ('https://github.com/tianocore//edk2.git', True, True),
    ('HTTPS://GITHUB.COM/TianoCore/edk2.git/', True, True),
    ('https://github.com/tianocore/edk2', True, True),
    ('https://github.com/tianocore/edk2-platforms.git', True, True),
    ('https://github.com/tianocore/containers.git', True, True),
    ('https://github.com/tianocore/full-disclosure', True, True),
    ('git@github.com:tianocore/tianocore.github.io.git', True, True),
    ('ssh://git@github.com/TianoCore/EDK2.git', True, True),
    # A port after the host. The second is the remote GitHub documents for networks that
    # block 22, and normalising the port's colon as a path separator made `443` the owner.
    ('ssh://git@github.com:22/tianocore/edk2.git', True, True),
    ('ssh://git@ssh.github.com:443/tianocore/edk2.git', True, True),
    ('git://github.com/tianocore/edk2.git', True, True),
    ('https://user:tok@github.com/TianoCore/edk2.git', True, True),
    ('https://git.tianocore.org/git/edk2.git', True, False),
    # An ordinary consumer. Every one of these is what the action is pointed at in anger.
    ('https://github.com/acme/edk2.git', False, False),
    ('git@github.com:acme/edk2.git', False, False),
    ('https://github.com/acme/edk2-platform-bsp', False, False),
    ('https://github.com/my-tianocore-fork/edk2.git', False, False),
    ('https://github.com/acme/tianocore-edk2.git', False, False),
    ('https://github.com/acme/tianocore', False, False),
    ('https://tianocore@github.com/acme/edk2.git', False, False),
    ('https://gitlab.example.com/vendor/edk2.git', False, False),
    ('https://github.com/intel/edk2-platforms.git', False, False),
    ('ssh://git@ssh.github.com:443/acme/edk2.git', False, False),
)


def guard_from_action():
    """The upstream check as action.yml really holds it, wrapped so it can be run.

    Sliced out rather than copied: a copy here would pass while the file it is meant to be
    testing drifted, which is the failure this whole script exists to rule out. The slice
    is the normaliser through to the slug, which is everything between `canon_remote() {`
    and the assignment of `slug`.
    """
    try:
        import yaml
    except ImportError:
        return None
    action = yaml.safe_load(open(ACTION))
    body = ''
    for step in (action.get('runs', {}) or {}).get('steps', []) or []:
        if 'canon_remote()' in (step.get('run') or ''):
            body = step['run']
            break
    if not body:
        raise SystemExit('::error file=action.yml::no step holds canon_remote() any more -- '
                         'the upstream guard has been moved or removed, and this check '
                         'cannot assert what is no longer there')
    lines = body.splitlines()
    first = next(i for i, l in enumerate(lines) if 'canon_remote() {' in l)
    last = next(i for i, l in enumerate(lines) if l.strip().startswith('slug='))
    return ('set -uo pipefail\nremote="$1"\n'
            + '\n'.join(lines[first:last + 1])
            + '\n# Only reached when the guard let it through.\n'
              'echo "ALLOWED slug=$slug"\n')


def shell_refuses(script, remote):
    """True when action.yml's guard stops this remote. Raises if it neither passed nor refused."""
    done = subprocess.run(['bash', '-c', script, 'guard', remote],
                          capture_output=True, text=True)
    if 'ALLOWED slug=' in done.stdout:
        return False
    if 'not filing issues' in done.stdout:
        return True
    raise SystemExit(f'::error::the guard sliced out of action.yml neither allowed nor '
                     f'refused {remote!r} (exit {done.returncode}): '
                     f'{(done.stdout + done.stderr).strip()[:300]}')


def filer_refuses(slug):
    """True when file_issues.py refuses this slug before it does anything else.

    End to end, not just the predicate: what is being asserted is that the refusal happens
    ahead of the first request and ahead of reading --bugs, so the path with the POST and
    the force-push on it is never entered. A slug that is allowed falls over on the missing
    --bugs file with 2; a refused one never gets that far and exits 3.
    """
    done = subprocess.run([sys.executable, FILER, '--dry-run',
                           '--bugs', os.path.join(HERE, 'no-such-bugs.json'),
                           '--slug', slug],
                          capture_output=True, text=True,
                          env=dict(os.environ, GH_TOKEN=''))
    if done.returncode == 3 and 'refusing to file issues' in done.stdout:
        return True
    if done.returncode == 2 and 'no-such-bugs.json' in done.stderr:
        return False
    raise SystemExit(f'::error::file_issues.py did something unexpected for {slug!r} '
                     f'(exit {done.returncode}): '
                     f'{(done.stdout + done.stderr).strip()[:300]}')


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--verbose', action='store_true', help='print every case, not just failures')
    args = ap.parse_args()

    script = guard_from_action()
    if script is None:
        print('PyYAML absent, so action.yml cannot be parsed; checking only file_issues.py')

    bad = 0
    for remote, by_action, by_filer in CASES:
        # The slug as the action derives it, which is what the filer is handed in a real
        # run -- so the Python half is tested on its actual input and not only on URLs.
        slug = fi.canon_slug(remote)
        slug = slug.split('/', 1)[1] if '.' in slug.split('/', 1)[0] else slug
        got = {
            'action.yml': (shell_refuses(script, remote) if script else by_action, by_action),
            'upstream_reason(url)': (bool(fi.upstream_reason(remote)), by_action),
            'upstream_reason(slug)': (bool(fi.upstream_reason(slug)), by_filer),
            'file_issues.py(slug)': (filer_refuses(slug), by_filer),
            # Run by hand, --slug is as likely to be given the whole URL as the pair, and
            # then the host is still there to be judged on. This is the column that holds
            # the tianocore.org row to the same answer the action gives.
            'file_issues.py(url)': (filer_refuses(remote), by_action),
        }
        wrong = sorted(k for k, (v, want) in got.items() if v != want)
        if wrong:
            bad = 1
            print(f'  FAIL  {remote}')
            for key in wrong:
                v, want = got[key]
                print(f'        {key} {"refused" if v else "allowed"} it; '
                      f'it must be {"REFUSED" if want else "allowed"}')
        elif args.verbose:
            verdict = 'REFUSED' if by_action else 'allowed'
            note = '' if by_action == by_filer else '  (the action only: the slug has no host)'
            print(f'  ok    {verdict:8} {remote}  -> slug {slug}{note}')

    refused = sum(1 for _, by_action, _ in CASES if by_action)
    print(f'{len(CASES)} remote(s) checked against '
          f'{5 if script else 4} enforcement point(s): {refused} refused, '
          f'{len(CASES) - refused} allowed'
          + ('' if not bad else ' -- SOMETHING IS WRONG, see above'))
    return bad


if __name__ == '__main__':
    sys.exit(main())
