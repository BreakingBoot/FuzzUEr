import json
from collections import defaultdict
import matplotlib.pyplot as plt
import argparse


def parse_time_to_seconds(time_str):
    parts = time_str.split('-')
    hours = int(parts[0].replace('h', ''))
    minutes = int(parts[1].replace('m', ''))
    seconds = int(parts[2].replace('s', ''))
    total_seconds = hours * 3600 + minutes * 60 + seconds
    return total_seconds

def parse_coverage_into(filename):
    coverage_per_time = defaultdict(list)
    map = set()
    with open(filename, 'r') as file:
        for line in file:
            data = json.loads(line)
            if 'Interesting' in data.keys():
                map |= set(data['Interesting']['indices'])
            elif 'Message' in data.keys():
                # Extract timestamp from the key (assuming it's the timestamp)
                timestamp = data['Message'].split(',')[0].split(' ')[-1]
                # Store coverage information for this timestamp
                coverage_per_time[parse_time_to_seconds(timestamp)] = len(map)
    return coverage_per_time


def plot_coverage(coverage_per_time, filename):
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
