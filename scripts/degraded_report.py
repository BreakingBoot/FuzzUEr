"""Turn a degraded run into GitHub warning annotations.

    python3 scripts/degraded_report.py <results-dir>
    python3 scripts/degraded_report.py --selftest

The driver exits 2 when at least one stage came back WARN and none failed: it did its job,
but not for every target. action.yml reports that rather than failing the step, and this is
what it prints. A script rather than a heredoc inside the action, because a heredoc's
contents are a string to every check in this repository -- the YAML parse accepts anything,
and the Python parse only reads scripts/*.py -- so the one branch that decides whether a
consumer's weekly job goes red would have had no test at all.

Always exits 0. It reports; the caller decides what a degraded run means, via the action's
fail-on-degraded input.
"""

import json
import os
import sys

WARN = 'warn'


def annotations(run):
    """The warning lines for one parsed run.json. One per degraded stage, in order."""
    out = []
    for stage in run.get('stages', []):
        if stage.get('ok') == WARN:
            out.append(f"::warning::{stage.get('name', '?')} is degraded: "
                       f"{stage.get('detail', '')}")
    if not out:
        # Exit 2 and nothing marked WARN cannot both be true. Say so rather than printing
        # nothing, which would read as "degraded, cause unknown, nobody looked".
        out.append('::warning::this run reported degraded but no stage is marked WARN -- '
                   'run.json and the exit code disagree')
    return out


def selftest():
    cases = [
        ({'stages': [{'name': 'build', 'ok': True, 'detail': 'built'},
                     {'name': 'fuzz', 'ok': WARN, 'detail': '224/243 fuzzed'},
                     {'name': 'triage', 'ok': True, 'detail': '9 candidates'}]},
         ['::warning::fuzz is degraded: 224/243 fuzzed'],
         'the ordinary case: one degraded stage, named with its detail'),
        ({'stages': [{'name': 'detects', 'ok': WARN, 'detail': 'no verdict'},
                     {'name': 'fuzz', 'ok': WARN, 'detail': '2 produced nothing'}]},
         ['::warning::detects is degraded: no verdict',
          '::warning::fuzz is degraded: 2 produced nothing'],
         'two degraded stages, both reported, in order'),
        ({'stages': [{'name': 'fuzz', 'ok': True, 'detail': 'all fuzzed'}]},
         ['::warning::this run reported degraded but no stage is marked WARN -- '
          'run.json and the exit code disagree'],
         'exit 2 with nothing marked WARN is itself worth saying'),
        ({'stages': []}, None, 'no stages at all still produces the disagreement warning'),
        ({}, None, 'a run.json with no stages key does not raise'),
    ]
    bad = 0
    for run, want, why in cases:
        got = annotations(run)
        ok = got == want if want is not None else len(got) == 1
        if not ok:
            print(f'  [FAIL] {why}\n         got  {got}\n         want {want}')
            bad = 1
        else:
            print(f'  [ok  ] {why}')
    # The real file shape, read the way the action reads it. A COMMITTED fixture, not a
    # file under results/: results/ is gitignored, so pointing this at a recorded sweep
    # made the case pass on the machine that had one and silently not exist on the
    # runner -- five cases there, six here, and nothing saying so. A missing fixture is
    # now a failure, because a vanishing assertion reads as coverage and is not.
    here = os.path.dirname(os.path.abspath(__file__))
    probe = os.path.join(here, 'testdata', 'degraded-sweep-run.json')
    if not os.path.isfile(probe):
        print(f'  [FAIL] the fixture {probe} is missing, so this case cannot run')
        bad = 1
    else:
        lines = annotations(json.load(open(probe, encoding='utf-8')))
        if len(lines) == 1 and 'fuzz is degraded' in lines[0] and '224/243' in lines[0]:
            print('  [ok  ] a real recorded 243-target sweep reports exactly its one '
                  'degraded stage')
        else:
            print(f'  [FAIL] the recorded degraded sweep produced {lines}')
            bad = 1
    print('  degraded report: ' + ('FAILED' if bad else 'OK'))
    return bad


def main():
    if '--selftest' in sys.argv[1:]:
        return selftest()
    if len(sys.argv) != 2:
        print('usage: degraded_report.py <results-dir> | --selftest', file=sys.stderr)
        return 0                                  # never fail the step over this reporter
    path = os.path.join(sys.argv[1], 'run.json')
    try:
        run = json.load(open(path, encoding='utf-8'))
    except (OSError, ValueError) as exc:
        print(f'::warning::this run is degraded but {path} is unreadable ({exc}), so this '
              f'cannot say which stage')
        return 0
    for line in annotations(run):
        print(line)
    return 0


if __name__ == '__main__':
    sys.exit(main())
