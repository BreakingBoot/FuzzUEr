import os
import sys
import json
import argparse
import itertools


# Which protocols are worth driving from one harness.
#
# Sharing edges is not the test. EfiTcp4 and EfiTcp6 share 89% of their edges -- the same
# network stack underneath -- but their types are disjoint (EFI_TCP4_* against EFI_TCP6_*),
# so a combined harness threaded nothing between them and produced zero live tables. What
# makes a combination worth building is that one protocol produces an object the other
# consumes and cannot produce for itself: then a sequence can carry it across the seam.
GENERIC = {'UINT8', 'UINT16', 'UINT32', 'UINT64', 'UINTN', 'INT8', 'INT16', 'INT32',
           'INT64', 'INTN', 'BOOLEAN', 'CHAR8', 'CHAR16', 'VOID', 'EFI_STATUS'}


def io_types(cache, protocol):
    produced, consumed = set(), set()
    path = os.path.join(cache, protocol, 'call-database.json')
    try:
        with open(path) as handle:
            data = json.load(handle) or []
    except (OSError, ValueError):
        return produced, consumed
    for record in data:
        if not isinstance(record, dict):
            continue
        for argument in (record.get('Arguments') or {}).values():
            if not isinstance(argument, dict):
                continue
            arg_type = (argument.get('arg_type') or '').replace('const ', '').strip()
            base = arg_type.replace('*', '').strip().upper()
            if '*' not in arg_type or base in GENERIC:
                continue
            if (argument.get('variable') or '') in ('__PROTOCOL__', '__HANDLE__'):
                continue
            direction = argument.get('arg_dir') or ''
            if 'OUT' in direction:
                produced.add(arg_type)
            if 'IN' in direction:
                consumed.add(arg_type)
    return produced, consumed


def main():
    parser = argparse.ArgumentParser(
        description='Suggest protocols worth combining into one harness')
    parser.add_argument('-c', '--cache', default='eval_source/anacache')
    parser.add_argument('-n', '--top', type=int, default=10)
    parser.add_argument('--skip', nargs='*', default=[],
                        help='Targets to leave out, such as combinations already built')
    args = parser.parse_args()

    protocols = [p for p in sorted(os.listdir(args.cache))
                 if p not in args.skip
                 and os.path.isfile(os.path.join(args.cache, p, 'call-database.json'))]
    io = {p: io_types(args.cache, p) for p in protocols}
    io = {p: v for p, v in io.items() if v[0] or v[1]}
    print(f'{len(io)} protocol(s) with domain-specific pointer arguments')

    pairs = []
    for a, b in itertools.combinations(io, 2):
        flow = ((io[a][0] & io[b][1]) - io[b][0]) | ((io[b][0] & io[a][1]) - io[a][0])
        if flow:
            pairs.append((len(flow), a, b, sorted(flow)))
    pairs.sort(reverse=True)
    if not pairs:
        print('  no pair produces an object the other cannot make itself')
        return 0
    for count, a, b, flow in pairs[:args.top]:
        print(f'  {count:>2} type(s)  {a} + {b}')
        print(f'      {", ".join(flow[:3])}')
    print(f'\nBuild one with: python3 scripts/make_combo.py <Name> <ProtocolA> <ProtocolB>')
    return 0


if __name__ == '__main__':
    sys.exit(main())
