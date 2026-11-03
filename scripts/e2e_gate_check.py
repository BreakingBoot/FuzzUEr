"""Assert the stable-release gate, by running the gate that is actually in the workflow.

    python3 scripts/e2e_gate_check.py

stable-e2e.yml decides whether a release is fit to tag. Its logic is heredoc'd Python, so
nothing in this repository could see it: the YAML parse takes a heredoc body as a string
and the Python parse only reads scripts/*.py. That gate has been wrong three times, and
every time in the same direction -- it passed a run it should have rejected:

  * it pattern-matched the `stages` OUTPUT, a count like "13/13", for the words "fuzz"
    and "triage". A count never contains a word, so no run could fail it.
  * it then used `not stages[n]['ok']`, which counts ok=None -- a stage deliberately
    skipped -- as a failure, so a correct qualify-only run failed its own gate.
  * and `ok is not True` rejected ok="warn": the stage ran, its triage is the report, and
    a single campaign of four losing its boot would have failed the gate.

So this EXTRACTS the live gate out of the workflow and runs it against fixtures, rather
than re-stating what it ought to do. A copy would drift; this cannot.
"""

import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
WORKFLOW = os.path.join(REPO, '.github', 'workflows', 'stable-e2e.yml')
STEP = 'Every stage ran'

BASE = [{'name': 'build', 'ok': True, 'detail': 'firmware built, FV 65% full'},
        {'name': 'detects', 'ok': True, 'detail': 'benchmark 12 of 12'}]

FUZZED = '4/4 campaign(s) fuzzed the harness (900 iteration(s))'

# (name, extra stages, write bugs.json, expected exit, why this shape matters)
CASES = [
    ('clean',
     [{'name': 'fuzz', 'ok': True, 'detail': FUZZED},
      {'name': 'triage', 'ok': True, 'detail': '0 candidate(s) from 0 cluster(s)'}],
     True, 0, 'an ordinary end-to-end run'),
    ('degraded',
     [{'name': 'fuzz', 'ok': 'warn',
       'detail': '3/4 campaign(s) fuzzed the harness (49334 iteration(s)) -- 1 produced '
                 'nothing'},
      {'name': 'triage', 'ok': True, 'detail': '9 candidate(s) from 10 cluster(s)'}],
     True, 0, 'a degraded fuzz stage still RAN; its triage is the report'),
    ('qualify-only',
     [{'name': 'fuzz', 'ok': None, 'detail': 'not run: --skip-fuzz'},
      {'name': 'triage', 'ok': None, 'detail': 'not run: --skip-fuzz'}],
     True, 1, 'the hole this gate exists for: every stage passes and nothing was fuzzed'),
    ('fuzz-failed',
     [{'name': 'fuzz', 'ok': False, 'detail': 'every boot spent its budget'},
      {'name': 'triage', 'ok': None, 'detail': 'not run'}],
     True, 1, 'a failed stage'),
    ('nothing-reached-the-harness',
     [{'name': 'fuzz', 'ok': True,
       'detail': '0/4 campaign(s) fuzzed the harness (0 iteration(s))'},
      {'name': 'triage', 'ok': True, 'detail': '0 candidate(s) from 0 cluster(s)'}],
     True, 1, 'the port applied, the firmware built, and no campaign got in'),
    ('no-report',
     [{'name': 'fuzz', 'ok': True, 'detail': FUZZED},
      {'name': 'triage', 'ok': True, 'detail': '0 candidate(s)'}],
     False, 1, 'triage claimed to run and wrote no bugs.json'),
    ('stages-absent', [], True, 1, 'fuzz and triage not in run.json at all'),
]


def extract():
    """The gate's own source, out of the workflow's heredoc."""
    text = open(WORKFLOW, encoding='utf-8').read()
    # The step first, so a heredoc belonging to another step cannot be picked up.
    start = text.find(f'- name: {STEP}')
    if start < 0:
        sys.exit(f'::error::no step named {STEP!r} in {WORKFLOW} -- it was renamed, and '
                 f'this check is now testing nothing')
    hit = re.search(r"python3 - \"\$RESULTS\" <<'PY'\n(.*?)\n\s*PY\s*$",
                    text[start:], re.S | re.M)
    if not hit:
        sys.exit('::error::that step no longer carries a PY heredoc taking $RESULTS')
    body = hit.group(1)
    # Strip the YAML block indentation, which is whatever the first line carries.
    pad = len(body) - len(body.lstrip(' '))
    return '\n'.join(l[pad:] if l.startswith(' ' * pad) else l for l in body.split('\n'))


def main():
    source = extract()
    bad = 0
    with tempfile.TemporaryDirectory() as tmp:
        gate = os.path.join(tmp, 'gate.py')
        open(gate, 'w', encoding='utf-8').write(source)
        for name, extra, bugs, want, why in CASES:
            root = os.path.join(tmp, name)
            os.makedirs(root)
            json.dump({'ref': 'edk2-stable202608', 'stages': BASE + extra},
                      open(os.path.join(root, 'run.json'), 'w'))
            if bugs:
                json.dump({'candidates': [], 'clusters': 0},
                          open(os.path.join(root, 'bugs.json'), 'w'))
            done = subprocess.run([sys.executable, '-I', gate, root],
                                  capture_output=True, text=True)
            got = done.returncode
            if got != want:
                print(f'  [FAIL] {name}: gate exited {got}, want {want} -- {why}')
                for line in (done.stdout + done.stderr).strip().split('\n')[-4:]:
                    print(f'         {line}')
                bad = 1
            else:
                verdict = 'accepts' if want == 0 else 'rejects'
                print(f'  [ok  ] {verdict:<7} {name:<28} {why}')
    # A gate that accepted everything would pass every case above only if none of them
    # expected a rejection. Assert the fixtures themselves still disagree.
    if not any(c[3] for c in CASES) or all(c[3] for c in CASES):
        print('::error::the fixtures no longer cover both outcomes')
        bad = 1
    print('  stable-release gate: ' + ('FAILED' if bad else 'OK'))
    return bad


if __name__ == '__main__':
    sys.exit(main())
