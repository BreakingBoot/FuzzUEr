"""Did the guest actually receive the testcase?

Everything else in this pipeline counts iterations and edges, and all of that moves
whether or not the fuzzer's bytes arrived -- the delivered LENGTH alone decides how many
steps a harness sequence takes. So "the campaign ran" and "the campaign was fuzzed" are
different claims and only one of them was ever checked.

FirnessMain emits, once per iteration, before anything interprets the buffer:

    IN=<length, 4 hex digits>:<first 6 bytes, hex>

and this classifies a campaign from those lines: OK when the byte prefixes vary, LENGTH
ONLY when the length moves and the bytes never do, DEAD when neither moves.

  python3 scripts/input_check.py results/<run>/campaigns/<protocol>
  python3 scripts/input_check.py results/<run>            # every campaign under it

Read the FIRST SIX BYTES and not "the input page", which is the mistake this check exists
to make impossible. The buffer is one 4 KiB page and delivered lengths run 1..1025, so in
a perfectly healthy campaign 75% to 99.98% of that page is untouched and still holds
EDK2's 0xAF PcdDebugClearMemoryValue fill. Two separate investigations dumped the page,
truthfully reported 0xAF, and concluded the host never wrote anything. It does: in
libafl_qemu's LqemuInputSetter one call produces both the write and the byte count in RAX,

    let ret_value = input_location.write(&input.target_bytes());
    input_location.cpu().write_reg(*reg, ret_value as GuestReg)

so a correct length in RAX is itself evidence the copy ran, and "length right, page all
0xAF" is self-contradictory rather than damning. Six bytes at offset 0 sits inside the
delivered region whenever the length is at least 6, which is what makes this marker an
instrument instead of another way to measure the tail.

Its first real use found delivery WORKING and the corpus starving instead: a campaign that
had reported 0 firmware findings in 16234 executions with one imported seed reported 9041
distinct IN= prefixes and 3168 objectives once every seed was imported. The defect was
never delivery; see load_initial_inputs_forced and the byte-1 target selector.

A campaign whose harness predates the marker reports UNINSTRUMENTED, not OK: "no evidence"
and "evidence of delivery" are different answers and only one is worth having.
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
