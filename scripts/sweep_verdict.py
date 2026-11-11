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
import subprocess
import sys

# A supported release: edk2-stable202608, and the occasional edk2-stable202508.01. Anything
# else -- master, a platform branch, a bare SHA -- is a moving target whose breakage is
# news rather than a regression in this repository.
RELEASE = re.compile(r'^edk2-stable\d{6}(\.\d+)?$')

OK, DEGRADED, FAILED = 'ok', 'degraded', 'failed'


def kind(ref):
    return 'release' if RELEASE.match(ref or '') else 'moving'


# ---------------------------------------------------------------------------
# Which refs a multi-version gate should qualify.
#
# Selection lives here rather than in the workflow's shell for the same reason the verdict
# does: a list written inline in YAML is a list nothing tests. The weekly sweep's used to
# be literal and went five releases stale -- it still named edk2-stable202502/202505/
# 202511 while its own description promised "the three newest", and it left out
# edk2-stable202608, the only release anything had ever gated on.
# ---------------------------------------------------------------------------

# A row of the README's "Which versions it works on" table, which is this project's claim
# about which releases the pipeline handles. The gate reads the claim rather than keeping a
# list beside it, so a version that is claimed can be chosen and a version that is not
# cannot. `master` is in that table too and is deliberately NOT matched here: it is a
# moving ref, the caller adds it, and kind() already decides what its failure means.
CLAIMED_ROW = re.compile(r'^\|\s*`?(edk2-stable\d{6}(?:\.\d+)?)`?\s*\|')


def version_key(ref):
    found = RELEASE.match(ref or '')
    if not found:
        return (0, 0)
    return (int(ref[len('edk2-stable'):len('edk2-stable') + 6]),
            int((found.group(1) or '.0')[1:]))


def claimed_versions(readme):
    """The releases the README claims the pipeline works on, in table order."""
    out = []
    with open(readme, encoding='utf-8', errors='replace') as handle:
        for line in handle:
            found = CLAIMED_ROW.match(line.strip())
            if found and found.group(1) not in out:
                out.append(found.group(1))
    return out


def pick(claimed, available, count):
    """Choose `count` releases to qualify, newest first, plus what is claimed and absent.

    The oldest claimed release, the newest, and an even spread between them -- because the
    two ends fail for opposite reasons and a gate that tests only one end cannot see both:

      * the NEWEST is where upstream churn lands. Upstream deleted OvmfPkg/OvmfPkgIa32.dsc
        at edk2-stable202511 and the port stage then hard-failed on every release from
        there on, while everything older was untouched.
      * the OLDEST is where a change to the resolver regresses. Every repair in
        apply_asan.py is keyed on something a NEW release needed, and nothing but an old
        release can show that the repair did not break the releases that were already
        working.

    Newest first, so a job cut short by its timeout has spent its minutes on the release
    that matters most rather than on the oldest one.

    `available` is what the checkout can actually resolve. A claimed release the tree
    cannot reach is returned separately rather than chosen: picking it would fail the gate
    for a fetch that did not happen, and dropping it silently would let the README go on
    claiming a release that does not exist.
    """
    order = sorted(set(claimed) & set(available), key=version_key)
    missing = [r for r in claimed if r not in available]
    if not order:
        return [], missing
    span = len(order)
    count = max(1, min(int(count), span))
    if count == 1:
        wanted = [span - 1]                                  # the newest
    else:
        wanted = sorted({round(i * (span - 1) / (count - 1)) for i in range(count)})
    return [order[i] for i in reversed(wanted)], missing


def resolvable(source, refs):
    """The subset of `refs` this checkout can resolve to a commit."""
    out = []
    for ref in refs:
        done = subprocess.run(
            ['git', '-C', source, 'rev-parse', '--verify', '--quiet',
             f'{ref}^{{commit}}'], capture_output=True, text=True)
        if done.returncode == 0 and done.stdout.strip():
            out.append(ref)
    return out


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
        # The cross-version gate's shapes. It qualifies several releases plus master in
        # one job, so its ledger is wider than the weekly sweep's and the same policy has
        # to hold across it.
        ([('edk2-stable202302', 0), ('edk2-stable202411', 0),
          ('edk2-stable202602', 0), ('edk2-stable202608', 0), ('master', 0)], False,
         'the cross-version gate, all green'),
        ([('edk2-stable202302', 0), ('edk2-stable202411', 0),
          ('edk2-stable202602', 0), ('edk2-stable202608', 0), ('master', 1)], False,
         'upstream master broke: early warning, not this project regressing'),
        ([('edk2-stable202302', 0), ('edk2-stable202411', 0),
          ('edk2-stable202602', 0), ('edk2-stable202608', 1), ('master', 0)], True,
         'the newest release failed -- exactly the OvmfPkgIa32.dsc shape, where every '
         'release from 202511 on hard-failed and everything older was fine'),
        ([('edk2-stable202302', 1), ('edk2-stable202411', 0),
          ('edk2-stable202602', 0), ('edk2-stable202608', 0), ('master', 0)], True,
         'the OLDEST release failed: a resolver repair for a new release regressed an '
         'old one, which is the half a newest-only gate cannot see'),
        ([('edk2-stable202302', 2), ('edk2-stable202411', 2),
          ('edk2-stable202602', 2), ('edk2-stable202608', 2), ('master', 2)], False,
         'every ref degraded and none failed: a report to read, not a red gate'),
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
    bad |= selection_selftest()
    # The contract this whole policy rests on. state() maps the driver's exit code to a
    # meaning; if the driver ever changes what it returns, every classification above
    # silently becomes wrong while every case here still passes. So ask the driver.
    bad |= driver_contract()
    print('  sweep verdict policy: ' + ('FAILED' if bad else 'OK'))
    return bad


def selection_selftest():
    """pick() spans the claimed versions, and the README still parses as a version table."""
    bad = 0
    # Eight releases, so a spread is visibly a spread rather than "all of them".
    span = ['edk2-stable202302', 'edk2-stable202305', 'edk2-stable202311',
            'edk2-stable202405', 'edk2-stable202411', 'edk2-stable202505',
            'edk2-stable202602', 'edk2-stable202608']
    cases = [
        (span, span, 4, ['edk2-stable202608', 'edk2-stable202505', 'edk2-stable202311',
                         'edk2-stable202302'],
         'four of eight: both ends and an even spread, newest first'),
        (span, span, 1, ['edk2-stable202608'], 'one means the newest'),
        (span, span, 2, ['edk2-stable202608', 'edk2-stable202302'],
         'two means the two ends -- never the newest twice'),
        (span, span, 99, list(reversed(span)), 'more than there are means all of them'),
        (span, span[:1], 4, ['edk2-stable202302'],
         'only one resolvable: no duplicates padding the list out'),
        # The table is claimed in whatever order it is written; the spread is by version.
        (list(reversed(span)), span, 3,
         ['edk2-stable202608', 'edk2-stable202411', 'edk2-stable202302'],
         'the table order does not decide the spread, the version does'),
        (span, [], 4, [], 'nothing resolvable is not a selection'),
    ]
    for claimed, available, count, want, why in cases:
        got, _ = pick(claimed, available, count)
        if got != want:
            print(f'  [FAIL] pick({count}) = {got}, want {want} -- {why}')
            bad = 1
        else:
            print(f'  [ok  ] pick {count:<3} {why}')
    # A claimed release the tree cannot reach is reported, not chosen. Silently dropping
    # it is how a table goes on naming a release that does not exist.
    chosen, missing = pick(span, span[:-1], 4)
    if 'edk2-stable202608' in chosen or missing != ['edk2-stable202608']:
        print(f'  [FAIL] an unresolvable claimed release was not reported: '
              f'chosen={chosen} missing={missing}')
        bad = 1
    else:
        print('  [ok  ] an unresolvable claimed release is reported, not chosen')
    # And against the real README, because the regex is the whole of the coupling: if the
    # table is reformatted this returns too few and the gate would quietly shrink.
    readme = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          'README.md')
    if os.path.isfile(readme):
        found = claimed_versions(readme)
        if len(found) < 4 or any(not RELEASE.match(r) for r in found):
            print(f'  [FAIL] the README version table parsed as {found}')
            bad = 1
        else:
            print(f'  [ok  ] the README claims {len(found)} release(s), '
                  f'{found[0]}..{found[-1]}')
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


def do_pick(args):
    """Print the refs a multi-version gate should qualify, one per line.

    Only the refs go to stdout, so a shell can take the whole of it; everything else is an
    annotation or a comment line. A gate that got no refs must not run an empty loop and
    call it a pass, so this exits non-zero instead -- see the "no ref produced a verdict"
    case below, which is the same failure one stage later.
    """
    readme = args.readme or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'README.md')
    if not os.path.isfile(readme):
        print(f'::error::no {readme} to read the claimed versions out of', file=sys.stderr)
        return 1
    claimed = claimed_versions(readme)
    # Four is arbitrary as a number and not as a floor: with fewer than that the table is
    # not a version table, and the likeliest reason is that its format changed under this
    # regex -- which would otherwise show up as a gate quietly testing one release.
    if len(claimed) < 4:
        print(f'::error::{readme} lists {len(claimed)} claimed release(s); the version '
              f'table is missing or its shape changed', file=sys.stderr)
        return 1
    chosen, missing = pick(claimed, resolvable(args.source, claimed), args.pick)
    for ref in missing:
        print(f'::warning::{ref} is in the README version table and {args.source} cannot '
              f'resolve it: either the tag fetch did not run or the table names a release '
              f'that does not exist', file=sys.stderr)
    if not chosen:
        print(f'::error::none of the {len(claimed)} claimed release(s) are resolvable in '
              f'{args.source}', file=sys.stderr)
        return 1
    print(f'# {len(chosen)} of {len(claimed)} claimed release(s), newest first',
          file=sys.stderr)
    for ref in chosen:
        print(ref)
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--ledger', help='file of "<ref> <exit code>" lines, one per ref')
    ap.add_argument('--results', default='results',
                    help='where the per-ref fuzz-<ref>/run.json live')
    ap.add_argument('--selftest', action='store_true', help='assert the policy and exit')
    ap.add_argument('--pick', type=int, metavar='N',
                    help='print N releases to qualify, newest first, instead of judging '
                         'a ledger. Chosen from the versions the README claims that '
                         '--source can resolve')
    ap.add_argument('--source', default='eval_source/edk2',
                    help='the edk2 checkout --pick resolves refs in')
    ap.add_argument('--readme', default='',
                    help='where the claimed-versions table lives (default: README.md '
                         'beside this repository)')
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if args.pick is not None:
        return do_pick(args)
    if not args.ledger:
        ap.error('--ledger is required unless --selftest or --pick')

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
