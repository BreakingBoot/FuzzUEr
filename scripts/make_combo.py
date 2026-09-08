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
    parser.add_argument('name', help='Name for the combined target, e.g. HiiStack')
    parser.add_argument('protocols', nargs='+', help='Protocols to combine')
    parser.add_argument('-r', '--repo', default=os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))))
    parser.add_argument('-c', '--cache', help='Analysis cache to merge from and write to')
    args = parser.parse_args()

    evalset = os.path.join(args.repo, 'eval_source', 'evalset')
    anacache = args.cache or os.path.join(args.repo, 'eval_source', 'anacache')

    missing = [p for p in args.protocols
               if not os.path.isfile(os.path.join(evalset, f'{p}.txt'))
               or not os.path.isdir(os.path.join(anacache, p))]
    if missing:
        print(f'No request or cache for: {", ".join(missing)}')
        return 1

    lines = ['[Protocols]']
    for protocol in args.protocols:
        with open(os.path.join(evalset, f'{protocol}.txt')) as handle:
            for line in handle:
                if line.strip().startswith('g'):
                    lines.append(line.rstrip('\n'))
    request = os.path.join(evalset, f'{args.name}.txt')
    with open(request, 'w') as handle:
        handle.write('\n'.join(lines) + '\n')
    print(f'  {request}: {len(lines) - 1} member(s)')

    destination = os.path.join(anacache, args.name)
    merge = os.path.join(args.repo, 'scripts', 'merge_cache.py')
    result = subprocess.run([sys.executable, merge, '-c', anacache, '-o', destination]
                            + args.protocols, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stdout + result.stderr)
        return 1
    print(f'  {destination}: merged cache')
    print(f'Run it like any other protocol: fuzz_batch.py -p {args.name}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
