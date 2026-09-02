import os
import csv
import sys
import argparse


# Compare a coverage matrix against a recorded baseline and fail when a protocol goes
# backwards. Every regression this session -- a harness that stopped compiling, a firmware
# that stopped booting, an argument that stopped being fuzzed -- showed up first as
# coverage falling for protocols nobody was looking at, and nothing was watching for it.
def read_matrix(path):
    rows = {}
    with open(path, newline='') as handle:
        for row in csv.DictReader(handle):
            name = row.get('protocol')
            if not name:
                continue
            try:
                rows[name] = {
                    'edges': int(row.get('edges') or 0),
                    'executions': int(row.get('executions') or 0),
                    'reached': (row.get('reached_harness') or '').lower() in ('true', '1'),
                }
            except ValueError:
                continue
    return rows


def compare(baseline, current, tolerance):
    regressed, improved, appeared, vanished = [], [], [], []
    for name, base in sorted(baseline.items()):
        now = current.get(name)
        if now is None:
            vanished.append(name)
            continue
        # a protocol that used to reach the harness and no longer does is a regression
        # whatever its edge count says
        if base['reached'] and not now['reached']:
            regressed.append((name, base['edges'], now['edges'], 'no longer reaches the harness'))
            continue
        floor = base['edges'] * (1.0 - tolerance)
        if now['edges'] < floor:
            drop = 100.0 * (base['edges'] - now['edges']) / max(base['edges'], 1)
            regressed.append((name, base['edges'], now['edges'], f'-{drop:.0f}%'))
        elif now['edges'] > base['edges']:
            improved.append((name, base['edges'], now['edges']))
    for name in sorted(current):
        if name not in baseline:
            appeared.append(name)
    return regressed, improved, appeared, vanished


def main():
    parser = argparse.ArgumentParser(
        description='Fail when per-protocol coverage regresses against a baseline')
    parser.add_argument('-b', '--baseline', required=True, help='Baseline coverage_matrix.csv')
    parser.add_argument('-c', '--current', required=True, help='Current coverage_matrix.csv')
    parser.add_argument('-t', '--tolerance', type=float, default=0.10,
                        help='Fraction a protocol may drop before it counts as a '
                             'regression, to absorb run-to-run variance (default 0.10)')
    parser.add_argument('--update', action='store_true',
                        help='Rewrite the baseline from the current run instead of checking')
    args = parser.parse_args()

    if args.update:
        with open(args.current, newline='') as src, open(args.baseline, 'w', newline='') as dst:
            dst.write(src.read())
        print(f'Baseline updated from {args.current}')
        return 0

    for path in (args.baseline, args.current):
        if not os.path.isfile(path):
            print(f'Missing {path}')
            return 2

    baseline, current = read_matrix(args.baseline), read_matrix(args.current)
    regressed, improved, appeared, vanished = compare(baseline, current, args.tolerance)

    if regressed:
        print(f'REGRESSED ({len(regressed)}):')
        for name, was, now, why in regressed:
            print(f'  {name:32} {was:>6} -> {now:<6} {why}')
    if vanished:
        print(f'NO LONGER RUN ({len(vanished)}): {", ".join(vanished[:8])}'
              f'{" ..." if len(vanished) > 8 else ""}')
    if improved:
        best = sorted(improved, key=lambda r: r[2] - r[1], reverse=True)[:5]
        print(f'IMPROVED ({len(improved)}), largest gains:')
        for name, was, now in best:
            print(f'  {name:32} {was:>6} -> {now:<6} +{now - was}')
    if appeared:
        print(f'NEW ({len(appeared)}): {", ".join(appeared[:8])}'
              f'{" ..." if len(appeared) > 8 else ""}')
    if not (regressed or vanished):
        print(f'No regression across {len(current)} protocol(s) '
              f'(tolerance {args.tolerance * 100:.0f}%)')
    return 1 if (regressed or vanished) else 0


if __name__ == '__main__':
    sys.exit(main())
