"""Decide whether a multi-version sweep failed, and say why, per version.

    python3 scripts/sweep_verdict.py --ledger sweep.rc --results results
    python3 scripts/sweep_verdict.py --selftest

fuzz-edk2.yml fuzzes several edk2 refs in a loop and used to fail the job if ANY of them
exited non-zero. That turned the weekly sweep red for two reasons that are not failures
of this project:

  * a degraded run (exit 2) -- a handful of 243 campaigns timed out or produced nothing.
    No full-size sweep has ever come back without one, so this was every run.
  * a moving ref -- `master` is in the default set deliberately, as early warning. When
    upstream master breaks the port, that is worth a warning and is not a regression here.

So the policy lives here rather than in the workflow's shell, and it is asserted by
--selftest from checks.yml. A policy written inline in YAML is a policy nothing tests.

The sweep is RED when, and only when:

  * a stable release tag hard-failed (exit 1) -- the port is supposed to apply to those
  * every ref asked for failed, whatever kind they were -- there is then no result at all
  * no ref produced a verdict -- the loop never ran

and otherwise GREEN, with a ::warning:: for each degraded or moving-ref failure.
"""

import argparse
import contextlib
import io
import json
import os
import re
import sys

# A supported release: edk2-stable202608, and the occasional edk2-stable202508.01. Anything
# else -- master, a platform branch, a bare SHA -- is a moving target whose breakage is
# news rather than a regression in this repository.
RELEASE = re.compile(r'^edk2-stable\d{6}(\.\d+)?$')

OK, DEGRADED, FAILED = 'ok', 'degraded', 'failed'


def kind(ref):
    return 'release' if RELEASE.match(ref or '') else 'moving'


def state(rc):
    if rc == 0:
        return OK
    if rc == 2:
        return DEGRADED
    return FAILED


def verdict(entries):
    """entries: [(ref, rc)]. Returns (red, [(ref, state, level, note)])."""
    rows = []
    for ref, rc in entries:
        st = state(rc)
        if st is OK:
            rows.append((ref, st, 'notice', 'every stage passed'))
        elif st is DEGRADED:
            rows.append((ref, st, 'warning',
                         'a stage did its job but not for every target. The report '
                         'stands -- read it in the artifact'))
        elif kind(ref) == 'release':
            rows.append((ref, st, 'error',
                         f'a stage failed on release {ref}, which the port is expected '
                         f'to apply to'))
        else:
            rows.append((ref, st, 'warning',
                         f'a stage failed on moving ref {ref}. Tracked as early warning, '
                         f'so it does not fail this sweep'))

    if not rows:
        return True, rows
    # Every ref failed. Whatever they were, the sweep produced nothing, and a green job
    # for that is worse than a red one -- including the single-ref case, where a warning
    # would be the only output and nobody would see it.
    if all(r[1] is FAILED for r in rows):
        return True, rows
    return any(r[2] == 'error' for r in rows), rows


def read_ledger(path):
    entries = []
    with open(path, encoding='utf-8', errors='replace') as handle:
        for line in handle:
            parts = line.split()
            if len(parts) != 2:
                continue
            try:
                entries.append((parts[0], int(parts[1])))
            except ValueError:
                continue
    return entries


def slug(ref):
    return re.sub(r'[^A-Za-z0-9._-]', '-', ref)


def stage_table(results, ref):
    """The per-stage board for one ref, straight out of its run.json."""
    path = os.path.join(results, f'fuzz-{slug(ref)}', 'run.json')
    if not os.path.isfile(path):
        return ['    (no run.json -- this ref died before the first stage wrote one)']
    try:
        run = json.load(open(path, encoding='utf-8'))
    except (OSError, ValueError) as exc:
        return [f'    (run.json unreadable: {exc})']
    out = []
    for s in run.get('stages', []):
        ok = s.get('ok')
        mark = ('SKIP' if ok is None else
                'PASS' if ok is True else
                'WARN' if ok == 'warn' else 'FAIL')
        out.append(f"    [{mark}] {s.get('name', '?'):<13} {str(s.get('detail', ''))[:90]}")
    return out or ['    (run.json records no stages)']


def selftest():
    cases = [
        # (entries, expected red, why)
        ([], True, 'an empty sweep is not a pass'),
        ([('edk2-stable202608', 0)], False, 'one clean release'),
        ([('edk2-stable202608', 2)], False,
         'degraded release: the whole point of this change -- a few campaigns of 243 '
         'timed out and the report still stands'),
        ([('edk2-stable202608', 1)], True, 'a release the port no longer applies to'),
        ([('master', 1)], True,
         'master alone, failed: a warning would be the only output and nobody sees it'),
        ([('master', 2)], False, 'master alone, degraded'),
        ([('edk2-stable202602', 0), ('edk2-stable202605', 2),
          ('edk2-stable202608', 2), ('master', 1)], False,
         'the realistic weekly sweep: three releases fine or degraded, master broken '
         'upstream. This exact shape was red on every run before this policy existed'),
        ([('edk2-stable202602', 2), ('master', 1)], False, 'degraded release, broken master'),
        ([('edk2-stable202602', 1), ('master', 0)], True, 'a release failed; master fine'),
        ([('edk2-stable202602', 1), ('master', 1)], True, 'everything failed'),
        ([('edk2-stable202508.01', 1)], True, 'a dotted release tag is still a release'),
        ([('a2d6ba512a0587e1798093dc73775451a1aa7c55', 1)], True,
         'a bare SHA alone, failed -- moving, but it is the only ref'),
        ([('edk2-stable202608', 0), ('a2d6ba51', 1)], False,
         'a SHA is a moving ref: it warns beside a clean release'),
        ([('edk2-stable202608', 0), ('master', 137)], False,
         'any non-zero that is not 2 is a hard failure, including a signal'),
    ]
    bad = 0
    for entries, want, why in cases:
        got, rows = verdict(entries)
        mark = 'ok  ' if got == want else 'FAIL'
        if got != want:
            bad = 1
        shown = ', '.join(f'{r}:{c}' for r, c in entries) or '<none>'
        print(f'  [{mark}] red={str(got):<5} want={str(want):<5} {shown}')
        if got != want:
            print(f'         {why}')
    # The classifier itself, not just the aggregate.
    for ref, want in (('edk2-stable202608', 'release'), ('edk2-stable202508.01', 'release'),
                      ('master', 'moving'), ('edk2-stable202608-rc1', 'moving'),
                      ('my/platform-branch', 'moving'), ('', 'moving')):
        got = kind(ref)
        if got != want:
            print(f'  [FAIL] kind({ref!r}) = {got}, want {want}')
            bad = 1
    # The contract this whole policy rests on. state() maps the driver's exit code to a
    # meaning; if the driver ever changes what it returns, every classification above
    # silently becomes wrong while every case here still passes. So ask the driver.
    bad |= driver_contract()
    print('  sweep verdict policy: ' + ('FAILED' if bad else 'OK'))
    return bad


def driver_contract():
    """fuzz_edk2.py must still exit 0 clean, 2 degraded, 1 failed."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        import fuzz_edk2
    except Exception as exc:
        print(f'  [FAIL] cannot import the driver to check its exit codes: {exc}')
        return 1

    def code(states):
        run = fuzz_edk2.Run('ref', '/nonexistent')
        for i, st in enumerate(states):
            run.stage(f's{i}').ok = st
        with contextlib.redirect_stdout(io.StringIO()):
            return run.report()

    bad = 0
    for states, want, why in (
            ([True, True], 0, 'every stage passed'),
            ([True, None], 0, 'a skipped stage is not a failure'),
            ([True, fuzz_edk2.WARN], 2, 'degraded'),
            ([True, False], 1, 'failed'),
            ([fuzz_edk2.WARN, False], 1, 'a failure outranks a degraded stage')):
        got = code(states)
        if got != want:
            print(f'  [FAIL] driver exit for {why}: got {got}, want {want}')
            bad = 1
        else:
            print(f'  [ok  ] driver exits {got} when {why}')
    return bad


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--ledger', help='file of "<ref> <exit code>" lines, one per ref')
    ap.add_argument('--results', default='results',
                    help='where the per-ref fuzz-<ref>/run.json live')
    ap.add_argument('--selftest', action='store_true', help='assert the policy and exit')
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.ledger:
        ap.error('--ledger is required unless --selftest')

    entries = read_ledger(args.ledger) if os.path.isfile(args.ledger) else []
    red, rows = verdict(entries)

    for ref, st, level, note in rows:
        head = f'{ref} [{kind(ref)}] -- {st}'
        if level == 'notice':
            print(f'  {head}')
        else:
            # Printed before the annotation so the board reads in order in the job log;
            # the annotation is what shows up in the run's summary.
            print(f'  {head}: {note}')
            print(f'::{level}::{ref}: {note}')
        for line in stage_table(args.results, ref):
            print(line)

    if not entries:
        print('::error::no ref produced a verdict -- the sweep loop never ran')
    elif red:
        print('::error::this sweep is a failure: see the error annotations above')
    else:
        print('this sweep passed; any warnings above are reports to read, not regressions')
    return 1 if red else 0


if __name__ == '__main__':
    sys.exit(main())
