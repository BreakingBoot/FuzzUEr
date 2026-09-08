import os
import sys
import json
import argparse
import csv
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


def load_json(cache, protocol, name):
    try:
        with open(os.path.join(cache, protocol, name)) as handle:
            return json.load(handle) or {}
    except (OSError, ValueError):
        return {}


def is_handle_typedef(arg_type, aliases):
    """An opaque handle: a typedef to a pointer, spelled without a star.

    Mirrors the generator. EFI_HII_HANDLE is "void *" underneath and carries an object;
    TPM_HANDLE resolves to UINT32 and is a value, so the alias chain is what tells them
    apart. Threading these is what lets a sequence cross from one protocol to another.
    """
    name = arg_type.replace('*', '').strip()
    if '*' in arg_type or not name:
        return False
    for _ in range(8):
        resolved = aliases.get(name)
        if resolved is None:
            return False
        if '*' in resolved:
            return True
        name = resolved.replace('*', '').strip()
    return False


def io_types(cache, protocol):
    """Types this protocol hands out and types it takes in, as the generator sees them.

    The generator threads a value when one call declares it OUT and another declares it
    IN under the same declared type, so predicting a useful combination means applying the
    same rule: a two pointer argument is declared one level shallower, and an OUT handle
    arrives through a one element buffer whose contents are the object.
    """
    produced, consumed = set(), set()
    aliases = load_json(cache, protocol, 'aliases.json')
    # declarations as well as call sites: firness records a call site only where the tree
    # calls the member, but the generator harnesses every declared member, so a protocol
    # judged on call sites alone looks emptier than the harness it produces. EfiHiiFont
    # has one called member and six declared ones, and the handle flow is in the other five
    records = []
    for source, key in (('call-database.json', 'Arguments'),
                        ('functions.json', 'Parameters')):
        block = load_json(cache, protocol, source)
        if isinstance(block, list):
            records.extend((record, key) for record in block if isinstance(record, dict))
    for record, key in records:
        for argument in (record.get(key) or {}).values():
            if not isinstance(argument, dict):
                continue
            arg_type = (argument.get('arg_type') or '').replace('const ', '').strip()
            base = arg_type.replace('*', '').strip().upper()
            if base in GENERIC:
                continue
            if (argument.get('variable') or '') in ('__PROTOCOL__', '__HANDLE__'):
                continue
            direction = argument.get('arg_dir') or ''
            stars = arg_type.count('*')
            if stars:
                declared = arg_type[:arg_type.rfind('*')].strip() if stars == 2 else arg_type
                if 'OUT' in direction:
                    produced.add(declared)
                if 'IN' in direction:
                    consumed.add(declared)
            handle = arg_type[:arg_type.rfind('*')].strip() if stars == 1 else arg_type
            if not is_handle_typedef(handle, aliases):
                continue
            if 'OUT' in direction and stars == 1:
                produced.add(handle)
            if 'IN' in direction and stars == 0:
                consumed.add(handle)
    return produced, consumed


def main():
    parser = argparse.ArgumentParser(
        description='Suggest protocols worth combining into one harness')
    parser.add_argument('-c', '--cache', default='eval_source/anacache')
    parser.add_argument('-n', '--top', type=int, default=10)
    parser.add_argument('--skip', nargs='*', default=[],
                        help='Targets to leave out, such as combinations already built')
    parser.add_argument('--presence', help='presence csv, to only suggest protocols the '
                                           'firmware actually installs')
    args = parser.parse_args()

    protocols = [p for p in sorted(os.listdir(args.cache))
                 if p not in args.skip
                 and os.path.isfile(os.path.join(args.cache, p, 'call-database.json'))]
    # a combination of protocols the firmware never installs is a harness that only ever
    # reports "not found": 65 of the 142 are in that state, and pairing two of them is
    # two startup traces, not a sequence
    if args.presence:
        with open(args.presence) as handle:
            installed = {row['protocol'] for row in csv.DictReader(handle)
                         if row.get('status') == 'present'}
        protocols = [p for p in protocols if p in installed]
        print(f'{len(protocols)} installed protocol(s) from {args.presence}')
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
