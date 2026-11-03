#!/usr/bin/env python3
"""Is the action's degraded branch REACHABLE?

degraded_report.py --selftest already asserts what the reporter prints. It cannot
assert that anything ever calls it, and for one release nothing did: GitHub runs a
composite `shell: bash` step as `bash -e -o pipefail {0}`, so errexit is on whether the
body asks for it or not. The driver exits 2 for a degraded run, errexit took that as a
failure and killed the step at the `tee` pipeline -- before `rc` was read, before the
degraded branch, and before the issue-filing step that comes after it. Every stage had
passed or warned; the job went red and filed nothing.

So this runs the step's own rc-handling under a real `bash -e -o pipefail`, with a stub
driver that exits whatever a case asks for, and checks the exit status and the
`degraded=` output the step publishes. The fragment is SLICED out of action.yml rather
than restated here, so it cannot keep passing while the file it checks drifts.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

# The region under test: from the driver invocation to the step's own exit. Anchored on
# literal text, and a missing anchor is a FAILURE rather than a skip -- an extraction that
# silently matches nothing is how a check goes blind.
# Matched as whole LINES, with re.MULTILINE, and each must occur exactly once. Plain
# substring search is not safe here and was not: the first version of this check used
# body.find('exit $rc'), which matched a COMMENT in the step that happens to mention
# `exit $rc` 76 lines before the statement. The slice then stopped early, the real exit
# never ran, and three cases that should have failed the step came back 0 -- a check that
# was wrong in the direction that passes.
START = re.compile(r'^mkdir -p "\$OUT"$', re.M)
END = re.compile(r'^exit \$rc$', re.M)


def fragment():
    import yaml
    action = yaml.safe_load(open(os.path.join(REPO, 'action.yml')))
    steps = [s for s in action['runs']['steps'] if s.get('name') == 'Fuzz']
    if len(steps) != 1:
        sys.exit(f'::error::expected exactly one step named Fuzz, found {len(steps)}')
    body = steps[0]['run']
    if steps[0].get('shell') != 'bash':
        sys.exit("::error::the Fuzz step no longer declares shell: bash, so this check's "
                 "whole premise -- that GitHub adds -e -- needs rechecking")
    starts = list(START.finditer(body))
    ends = list(END.finditer(body))
    if len(starts) != 1 or len(ends) != 1:
        sys.exit(f'::error::the Fuzz step has {len(starts)} start anchor(s) and '
                 f'{len(ends)} end anchor(s); this check needs exactly one of each and '
                 f'must be re-anchored rather than guessing which to use')
    if ends[0].start() < starts[0].start():
        sys.exit('::error::the end anchor precedes the start anchor in the Fuzz step')
    return body[starts[0].start():ends[0].end()] + '\n'


STUB = """import json, os, sys
out = os.environ['OUT']
os.makedirs(out, exist_ok=True)
warn = os.environ.get('STUB_WARN') == '1'
json.dump({'ref': 'stub', 'stages': [
    {'name': 'build', 'ok': True, 'detail': 'built'},
    {'name': 'fuzz', 'ok': 'warn' if warn else True,
     'detail': '3/4 campaign(s) fuzzed the harness'},
    {'name': 'triage', 'ok': True, 'detail': 'done'},
]}, open(os.path.join(out, 'run.json'), 'w'))
cands = int(os.environ.get('STUB_CANDIDATES', '0'))
json.dump({'candidates': [{'id': f'c{n}'} for n in range(cands)]},
          open(os.path.join(out, 'bugs.json'), 'w'))
print('stub driver: exiting', os.environ['STUB_RC'])
sys.exit(int(os.environ['STUB_RC']))
"""


def run_case(frag, rc, warn, fail_degraded, fail_findings, candidates):
    """Run the sliced fragment under the shell GitHub actually uses."""
    work = tempfile.mkdtemp(prefix='degraded-path-')
    try:
        os.makedirs(os.path.join(work, 'scripts'))
        open(os.path.join(work, 'scripts', 'fuzz_edk2.py'), 'w').write(STUB)
        # the real reporter, not a stand-in: the branch has to be able to call it
        shutil.copy(os.path.join(HERE, 'degraded_report.py'),
                    os.path.join(work, 'scripts', 'degraded_report.py'))
        out = os.path.join(work, 'results')
        gho = os.path.join(work, 'github_output')
        open(gho, 'w').close()
        script = os.path.join(work, 'step.sh')
        open(script, 'w').write(frag)
        env = dict(
            os.environ,
            OUT=out, GITHUB_OUTPUT=gho,
            STUB_RC=str(rc), STUB_WARN='1' if warn else '0',
            STUB_CANDIDATES=str(candidates),
            IN_FAIL_DEGRADED='true' if fail_degraded else '',
            IN_FAIL='true' if fail_findings else '',
        )
        # Exactly how GitHub invokes a composite step's `shell: bash`.
        proc = subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail',
                               script], cwd=work, env=env,
                              capture_output=True, text=True, timeout=300)
        outputs = {}
        for line in open(gho):
            if '=' in line:
                k, v = line.rstrip('\n').split('=', 1)
                outputs[k] = v
        return proc, outputs
    finally:
        shutil.rmtree(work, ignore_errors=True)


CASES = [
    # name,                       driver rc, warn, fail_degraded, fail_findings, cands,
    #                             want rc, want degraded
    ('a clean run',                       0, False, False, False, 0, 0, ''),
    ('DEGRADED stays green',              2, True,  False, False, 0, 0, 'true'),
    ('degraded + fail-on-degraded',       2, True,  True,  False, 0, 1, 'true'),
    ('a stage failed',                    1, False, False, False, 0, 1, ''),
    ('findings + fail-on-findings',       0, False, False, True,  2, 1, ''),
    ('findings, not failing by default',  0, False, False, False, 2, 0, ''),
]


def main():
    frag = fragment()
    print(f'sliced {len(frag.splitlines())} lines out of the Fuzz step')
    bad = 0
    for (name, rc, warn, faild, failf, cands, want_rc, want_deg) in CASES:
        proc, outputs = run_case(frag, rc, warn, faild, failf, cands)
        got_deg = outputs.get('degraded', '<unset>')
        ok = proc.returncode == want_rc and got_deg == want_deg
        bad |= not ok
        print(f"  [{'OK' if ok else 'FAIL'}] {name:<34} "
              f"driver={rc} -> step={proc.returncode} (want {want_rc}), "
              f"degraded={got_deg!r} (want {want_deg!r})")
        if not ok:
            tail = (proc.stdout + proc.stderr).strip().splitlines()[-6:]
            for line in tail:
                print(f'          | {line[:100]}')
            # The failure this check exists for names itself.
            if rc == 2 and proc.returncode != 0 and got_deg == '<unset>':
                print('          the step died before publishing `degraded`, which is what '
                      'errexit does')
                print('          to a driver that exits 2. The Fuzz step needs `set +e` '
                      'around the driver call.')
    if bad:
        print('the degraded path is not behaving as the action documents it')
    return bad


if __name__ == '__main__':
    sys.exit(main())
