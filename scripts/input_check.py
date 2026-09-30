"""Did the guest actually receive the testcase?

Every other check in this repo assumes it did. A campaign whose bytes never reach the
guest buffer is indistinguishable from a healthy one from the outside: the length still
arrives, the harness still runs, coverage still moves because the length drives how many
steps the sequence takes, and the findings that come out are whatever a constant input
reaches. Nothing fails.

What that looks like, from a real campaign: SanBenchMemory reported 474 heap overflows in
69120 executions, all of them byte-identical -- same faulting address, same return IP,
size 0x48 every time -- because 0x48 is KEY_KP8, a constant the generator planted in one
arm of the length argument and reachable with no input at all. Its corpus sat at 8, the
seed count, for the whole run. The paired SanBenchFirmware campaign reported nothing,
which read as a sanitizer blind to its own benchmark.

So FirnessMain now says what it got, once per iteration, on the serial wire:

    IN=<length, 4 hex digits>:<first 6 bytes, hex>

and this asserts those values vary. Six bytes is the span that decides which member is
called: the step count, the target selector, and the first argument's choice bytes.

  python3 scripts/input_check.py results/<run>/campaigns/<protocol>
  python3 scripts/input_check.py results/<run>            # every campaign under it

A campaign whose harness predates the marker is reported as UNINSTRUMENTED, not as a
pass: "no evidence" and "evidence of delivery" are different answers and only one of them
is worth having.
"""

import argparse
import glob
import os
import re
import sys

LINE = re.compile(rb'IN=([0-9a-f]{4}):([0-9a-f]{12})')

# Under this many iterations there is not enough signal to call it either way: a campaign
# that executed twice tells you about the boot, not about input delivery.
MIN_SAMPLES = 8


def scan(path):
    """Count the distinct lengths and distinct byte prefixes a campaign saw."""
    lengths, prefixes, total = set(), set(), 0
    for name in ('fuzz.txt', os.path.join('qemu', 'debugcon.log'), 'run.log'):
        full = os.path.join(path, name)
        if not os.path.isfile(full):
            continue
        with open(full, 'rb') as handle:
            for length, prefix in LINE.findall(handle.read()):
                lengths.add(length)
                prefixes.add(prefix)
                total += 1
    return lengths, prefixes, total


def verdict(lengths, prefixes, total):
    if total == 0:
        return 'UNINSTRUMENTED', 'no IN= marker; this harness predates the check'
    if total < MIN_SAMPLES:
        return 'TOO FEW', f'{total} sample(s), fewer than {MIN_SAMPLES}'
    if len(prefixes) == 1 and len(lengths) == 1:
        return 'DEAD', (f'{total} iterations, one input: length {lengths.pop().decode()}, '
                        f'bytes {prefixes.pop().decode()} -- nothing was delivered')
    if len(prefixes) == 1:
        return 'LENGTH ONLY', (f'{total} iterations, {len(lengths)} length(s) but one byte '
                               f'prefix {prefixes.pop().decode()} -- only the length crossed')
    return 'OK', f'{total} iterations, {len(prefixes)} distinct prefixes, {len(lengths)} length(s)'


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('path', help='a campaign directory, or a run directory holding '
                                     'campaigns/')
    parser.add_argument('--quiet', action='store_true', help='only print what is wrong')
    args = parser.parse_args()

    campaigns = []
    inner = os.path.join(args.path, 'campaigns')
    if os.path.isdir(inner):
        campaigns = sorted(d for d in glob.glob(os.path.join(inner, '*'))
                           if os.path.isdir(d))
    elif os.path.isdir(args.path):
        campaigns = [args.path]
    else:
        sys.exit(f'no such directory: {args.path}')

    counts = {}
    for campaign in campaigns:
        name = os.path.basename(campaign)
        state, detail = verdict(*scan(campaign))
        counts[state] = counts.get(state, 0) + 1
        if not args.quiet or state in ('DEAD', 'LENGTH ONLY'):
            print(f'  {name:<32} {state:<13} {detail}')

    print()
    print(' '.join(f'{state}={n}' for state, n in sorted(counts.items())))

    # DEAD and LENGTH ONLY are the failures. UNINSTRUMENTED is not a pass but it is not a
    # regression either -- it is an old artifact -- so it does not fail the exit status,
    # it just refuses to be counted as OK.
    broken = counts.get('DEAD', 0) + counts.get('LENGTH ONLY', 0)
    if broken:
        print(f'{broken} campaign(s) never saw their testcase. Coverage and findings from '
              f'those are functions of the input length alone.')
    return 1 if broken else 0


if __name__ == '__main__':
    sys.exit(main())
