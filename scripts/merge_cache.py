import os
import sys
import json
import argparse


# Build one analysis cache out of several, so a harness can drive more than one protocol.
#
# The static analysis runs per request file, so each cache under anacache/ describes one
# protocol. A sequence that crosses protocols -- open a package list with the HII database,
# then read a string out of it -- needs the functions and types of all of them in a single
# database. The records are lists of dicts keyed by function or type name, so merging is a
# concatenation that keeps the first definition of any repeated name.
FILES = ('call-database.json', 'generator-database.json', 'generators.json', 'types.json',
         'aliases.json', 'macros.json', 'enums.json', 'cast-map.json', 'includes.json',
         'functions.json', 'smi-function-guid-map.json', 'function-aliases.json')


def key_of(record):
    if not isinstance(record, dict):
        return json.dumps(record, sort_keys=True)
    for field in ('Function', 'function', 'Name', 'name', 'Type', 'type'):
        if field in record:
            return f'{field}:{record[field]}'
    return json.dumps(record, sort_keys=True)


def merge_one(sources, name, destination):
    merged, seen, is_dict = [], set(), False
    result = {}
    for source in sources:
        path = os.path.join(source, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path) as handle:
                data = json.load(handle)
        except ValueError:
            continue
        if data is None:
            continue
        if isinstance(data, dict):
            is_dict = True
            for k, v in data.items():
                result.setdefault(k, v)
        else:
            for record in data:
                k = key_of(record)
                if k not in seen:
                    seen.add(k)
                    merged.append(record)
    with open(os.path.join(destination, name), 'w') as handle:
        json.dump(result if is_dict else merged, handle)
    return len(result) if is_dict else len(merged)


def main():
    parser = argparse.ArgumentParser(
        description='Merge several per-protocol analysis caches into one')
    parser.add_argument('-c', '--cache', required=True, help='Directory holding the caches')
    parser.add_argument('-o', '--output', required=True, help='Where to write the merged cache')
    parser.add_argument('protocols', nargs='+', help='Protocols to merge')
    args = parser.parse_args()

    sources = [os.path.join(args.cache, p) for p in args.protocols]
    missing = [s for s in sources if not os.path.isdir(s)]
    if missing:
        print(f'No cache for: {", ".join(os.path.basename(m) for m in missing)}')
        return 1
    os.makedirs(args.output, exist_ok=True)
    for name in FILES:
        count = merge_one(sources, name, args.output)
        print(f'  {name:32} {count} record(s)')
    print(f'Merged {len(sources)} cache(s) into {args.output}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
