import json
from collections import defaultdict
import argparse


def parse_time_to_seconds(time_str):
    parts = time_str.split('-')
    hours = int(parts[0].replace('h', ''))
    minutes = int(parts[1].replace('m', ''))
    seconds = int(parts[2].replace('s', ''))
    total_seconds = hours * 3600 + minutes * 60 + seconds
    return total_seconds

# parse the JSONL tsffs writes to log_path (default %simics%/log.json). the log module
# serialises an externally-tagged enum, so every record is {"<Variant>": {...}} and the
# payload of Interesting/Solution/Timeout is nested under a "message" key:
#   {"Interesting": {"timestamp":.., "message": {"indices":[..], "input":[..],
#                                                "edges":[{"pc":..,"afl_idx":..}]}}}
#   {"Message":     {"timestamp":.., "message": "[Stats #0] run time: 0h-5m-23s, ..."}}
# this used to read data['Interesting']['edges'] and treat data['Message'] as a string,
# so it raised on the first real record
def parse_coverage_into(filename):
    coverage_per_time = {}
    covered = set()
    with open(filename, 'r') as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except ValueError:
                # a run killed mid-write leaves a partial final line
                continue
            if not isinstance(data, dict):
                continue

            for variant in ('Interesting', 'Solution', 'Timeout'):
                payload = data.get(variant)
                if isinstance(payload, dict):
                    message = payload.get('message')
                    if isinstance(message, dict):
                        covered |= set(message.get('indices') or [])
                        for edge in message.get('edges') or []:
                            if isinstance(edge, dict) and 'afl_idx' in edge:
                                covered.add(edge['afl_idx'])

            payload = data.get('Message')
            if isinstance(payload, dict):
                text = payload.get('message')
                if isinstance(text, str) and 'run time:' in text:
                    stamp = text.split(',')[0].split(' ')[-1]
                    try:
                        coverage_per_time[parse_time_to_seconds(stamp)] = len(covered)
                    except (ValueError, IndexError):
                        continue

    print(f'Maximum coverage: {len(covered)}')
    return dict(sorted(coverage_per_time.items()))


def plot_coverage(coverage_per_time, filename):
    # imported here rather than at module scope so the parser above can be reused by
    # tooling that has no plotting dependency
    import matplotlib.pyplot as plt

    plt.plot(coverage_per_time.keys(), coverage_per_time.values())
    plt.title('Coverage over time')
    plt.xlabel('Time (s)')
    plt.ylabel('Number of edges covered')
    plt.savefig(filename)  

# save to a csv file
def save_coverage_to_file(coverage_per_time, filename):
    with open(filename, 'w') as file:
        for timestamp, num_edges in coverage_per_time.items():
            file.write(f"{timestamp},{num_edges}\n")

def main():
    parser = argparse.ArgumentParser(description='Generate coverage report')
    parser.add_argument('-i','--log-file', type=str, default='log.json', help='Name of the log file')
    parser.add_argument('-o','--output-file', type=str, default='coverage.csv', help='Name of the output csv file')
    parser.add_argument('-p','--plot-file', type=str, default='coverage.png', help='Name of the output plot file')
    args = parser.parse_args()
    coverage_per_time = parse_coverage_into(args.log_file)
    save_coverage_to_file(coverage_per_time, args.output_file)
    plot_coverage(coverage_per_time, args.plot_file)

if __name__ == '__main__':
    main()
