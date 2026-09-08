import os
import sys
import argparse
import subprocess


# Register a target that drives several protocols from one harness.
#
# Protocols that share most of their edges are the same subsystem, and a sequence that
# crosses them can reach the seams between them: the HII stack reached 1,961 edges that
# none of its three protocols reached alone. This writes the combined request file and the
# merged analysis cache into the usual places, so the new target runs through the normal
# campaign path with no special handling.
def main():
    parser = argparse.ArgumentParser(description='Build a multi-protocol fuzzing target')
    parser.add_argument('name', nargs='?', help='Name for the combined target, e.g. HiiStack')
    parser.add_argument('protocols', nargs='*', help='Protocols to combine')
    parser.add_argument('-f', '--from-file',
                        help='Build every combination recorded in a file, one per line, '
                             'as "name protocol protocol ..."')
    parser.add_argument('-r', '--repo', default=os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))))
    parser.add_argument('-c', '--cache', help='Analysis cache to merge from and write to')
    args = parser.parse_args()

    evalset = os.path.join(args.repo, 'eval_source', 'evalset')
    anacache = args.cache or os.path.join(args.repo, 'eval_source', 'anacache')

    # eval_source is generated, so scripts/combos.txt is where the combinations live
    if args.from_file:
        failures = 0
        with open(args.from_file) as handle:
            for line in handle:
                line = line.split('#', 1)[0].split()
                if not line:
                    continue
                print(line[0])
                failures += build(line[0], line[1:], evalset, anacache, args.repo)
        return 1 if failures else 0
    if not args.name or not args.protocols:
        parser.error('give a name and protocols, or --from-file')
    return build(args.name, args.protocols, evalset, anacache, args.repo)


def build(name, protocols, evalset, anacache, repo):

    missing = [p for p in protocols
               if not os.path.isfile(os.path.join(evalset, f'{p}.txt'))
               or not os.path.isdir(os.path.join(anacache, p))]
    if missing:
        print(f'No request or cache for: {", ".join(missing)}')
        return 1

    lines = ['[Protocols]']
    for protocol in protocols:
        with open(os.path.join(evalset, f'{protocol}.txt')) as handle:
            for line in handle:
                if line.strip().startswith('g'):
                    lines.append(line.rstrip('\n'))
    request = os.path.join(evalset, f'{name}.txt')
    with open(request, 'w') as handle:
        handle.write('\n'.join(lines) + '\n')
    print(f'  {request}: {len(lines) - 1} member(s)')

    destination = os.path.join(anacache, name)
    # A cache written by a container is owned by root, so rebuilding a combination that
    # already exists fails inside merge_cache.py with a bare PermissionError traceback.
    # Say which directory and why, and leave the existing cache alone: it is still valid,
    # because the merge is deterministic from the same component caches.
    if os.path.isdir(destination) and not os.access(destination, os.W_OK):
        print(f'  {destination}: not writable, keeping the cache already there')
        return 0
    merge = os.path.join(repo, 'scripts', 'merge_cache.py')
    result = subprocess.run([sys.executable, merge, '-c', anacache, '-o', destination]
                            + protocols, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stdout + result.stderr)
        return 1
    print(f'  {destination}: merged cache')
    print(f'  run it like any other protocol: fuzz_batch.py -p {name}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
