import os
import sys
import json
import argparse


# Compare the edges two sets of runs reached.
#
# tsffs writes the indices it found into log.json as Interesting records, and those indices
# are stable for a given firmware: two independent runs of the same protocol overlap ~68%,
# and the difference is what one run explored and the other did not. That makes it possible
# to ask whether a harness reaches code another never does -- an edge count alone cannot,
# because two harnesses can report similar totals over quite different code.
def edge_set(path):
    edges = set()
    if not os.path.isfile(path):
        return edges
    with open(path, encoding='utf-8', errors='ignore') as handle:
        for line in handle:
            if '"Interesting"' not in line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            message = record.get('Interesting', {}).get('message') or {}
            edges |= set(message.get('indices') or [])
    return edges


def union_for(roots, protocols):
    edges = set()
    for root in roots:
        names = protocols or (os.listdir(root) if os.path.isdir(root) else [])
        for name in names:
            edges |= edge_set(os.path.join(root, name, 'log.json'))
    return edges


def main():
    parser = argparse.ArgumentParser(
        description='Which edges one set of runs reached and another did not')
    parser.add_argument('-a', '--left', nargs='+', required=True,
                        help='Run directories for the left side')
    parser.add_argument('-b', '--right', nargs='+', required=True,
                        help='Run directories for the right side')
    parser.add_argument('--left-protocols', nargs='*', default=None)
    parser.add_argument('--right-protocols', nargs='*', default=None)
    args = parser.parse_args()

    left = union_for(args.left, args.left_protocols)
    right = union_for(args.right, args.right_protocols)
    if not left and not right:
        print('No Interesting records found in either side')
        return 1
    print(f'  left:   {len(left)} edges')
    print(f'  right:  {len(right)} edges')
    print(f'  shared: {len(left & right)}')
    print(f'  only left:  {len(left - right)}')
    print(f'  only right: {len(right - left)}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
