import os
import re
import csv
import json
import argparse

from coverage_report import parse_coverage_into


# tsffs writes one "[Stats #N] run time: ..., executions: ..., exec speed: ..." line into
# log.json periodically, so the last one is the run's final tally
STATS = re.compile(r'run time:\s*([^,]+),.*?corpus:\s*(\d+).*?objectives:\s*(\d+)'
                   r'.*?executions:\s*(\d+).*?exec/sec:\s*([0-9.]+)')


def final_stats(log_path):
    runtime, corpus, objectives, executions, speed, solutions = '', 0, 0, 0, 0.0, 0
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as handle:
        for line in handle:
            if '"Solution"' in line:
                solutions += 1
            match = STATS.search(line)
            if match:
                runtime = match.group(1)
                corpus, objectives = int(match.group(2)), int(match.group(3))
                executions, speed = int(match.group(4)), float(match.group(5))
    return runtime, corpus, objectives, executions, speed, solutions


# a run that never reached the harness produces a log with no Interesting records at all,
# which is worth telling apart from a run that fuzzed and found nothing new
def summarize(log_path):
    coverage = parse_coverage_into(log_path)
    runtime, corpus, objectives, executions, speed, solutions = final_stats(log_path)
    edges = max(coverage.values()) if coverage else 0
    return {
        'edges': edges,
        'runtime': runtime,
        'corpus': corpus,
        'objectives': objectives,
        'executions': executions,
        'exec_per_sec': speed,
        'solutions': solutions,
        'samples': len(coverage),
        'reached_harness': bool(coverage) or executions > 0,
    }


def collect(root):
    rows = {}
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name)
        if not os.path.isdir(path):
            continue
        log_path = os.path.join(path, 'log.json')
        if not os.path.isfile(log_path):
            rows[name] = None
            continue
        try:
            rows[name] = summarize(log_path)
        except OSError:
            rows[name] = None
    return rows


def write_csv(rows, path):
    fields = ['protocol', 'edges', 'runtime', 'corpus', 'objectives', 'executions',
              'exec_per_sec', 'solutions', 'samples', 'reached_harness']
    with open(path, 'w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for protocol, stats in sorted(rows.items()):
            if stats is None:
                writer.writerow({'protocol': protocol, 'reached_harness': 'no run'})
            else:
                writer.writerow(dict(protocol=protocol, **stats))


def report(rows):
    ran = {k: v for k, v in rows.items() if v}
    print(f'{"protocol":34} {"edges":>7} {"execs":>9} {"exec/s":>8} {"sols":>5}  runtime')
    for protocol, stats in sorted(ran.items(), key=lambda kv: -kv[1]['edges']):
        print(f'{protocol:34} {stats["edges"]:>7} {stats["executions"]:>9} '
              f'{stats["exec_per_sec"]:>8.1f} {stats["solutions"]:>5}  {stats["runtime"]}')
    missing = [k for k, v in rows.items() if not v]
    print(f'\n  protocols with a run: {len(ran)}')
    print(f'  protocols with no run: {len(missing)}')
    if ran:
        # a sum, not a union: tsffs reports an edge count per run and the indices are not
        # comparable across runs, so this says how much each harness reached, not how much
        # of the firmware the campaign covered in total
        print(f'  best single protocol: {max(s["edges"] for s in ran.values())} edges')
        print(f'  median: {sorted(s["edges"] for s in ran.values())[len(ran) // 2]} edges')
        print(f'  protocols that never reached the harness: '
              f'{sum(1 for s in ran.values() if not s["reached_harness"])}')
    if missing:
        print(f'  missing: {", ".join(sorted(missing)[:8])}'
              f'{" ..." if len(missing) > 8 else ""}')


def main():
    parser = argparse.ArgumentParser(
        description='Summarise per-protocol fuzzing coverage from tsffs logs')
    parser.add_argument('-r', '--root', type=str, required=True,
                        help='Directory holding one subdirectory per protocol, each with log.json')
    parser.add_argument('-o', '--output', type=str, default='coverage_matrix.csv',
                        help='Combined csv to write')
    args = parser.parse_args()

    rows = collect(args.root)
    if not rows:
        print(f'No protocol directories under {args.root}')
        return 1
    write_csv(rows, args.output)
    report(rows)
    print(f'\nWrote {args.output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
