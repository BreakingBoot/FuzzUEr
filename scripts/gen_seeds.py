import os
import re
import argparse


# FirnessMain reads TWO bytes before it dispatches, and which one is which has been got
# wrong twice now, so it is written out here in full:
#
#     UINT8 SequenceLength = 0;
#     ReadBytes(&Input, sizeof(SequenceLength), (VOID *)&SequenceLength);   <-- byte 0
#     Steps = (UINTN)(SequenceLength % 8) + 1;
#     for (Step = 0; Step < Steps; Step++) {
#         UINT8 DriverChoice = 0;
#         ReadBytes(&Input, sizeof(DriverChoice), (VOID *)&DriverChoice);   <-- byte 1
#         switch (DriverChoice % <N>)
#
# Byte 0 is the STEP COUNT. Byte 1 is the target. The first version of this script seeded
# nine DER certificates that all began with 0x30, so every one selected target 0; the
# replacement put the target index in byte 0 and filled the rest, so byte 1 was always
# 0x00 or 0xFF -- and 0 % N is 0 for every N while 255 % 5 is also 0. Across a 234
# protocol sweep the result was that every corpus reached at most 2 of a protocol's
# members and 87 of them reached exactly 1: EfiShell has 43 members and its seeds
# dispatched 2. Everything else was left to a mutation of one byte.
#
# So the count is printed at the end, from the same parse, and a caller that changes the
# layout will see the number fall.
def target_count_from_main(main_file):
    with open(main_file, 'r', encoding='utf-8', errors='ignore') as f:
        source = f.read()
    modulo = re.search(r'switch\s*\(\s*DriverChoice\s*%\s*(\d+)\s*\)', source)
    if modulo:
        return int(modulo.group(1))
    return len(re.findall(r'^\s*case\s+(\d+)\s*:', source, re.M))


# look for a generated harness if the count was not given
def find_target_count(main_file):
    candidates = [main_file] if main_file else []
    candidates += ['firness_output/Firness/FirnessMain.c',
                   '/workspace/firness_output/Firness/FirnessMain.c']
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return target_count_from_main(candidate)
    return 0


# How many steps a seed asks for. Steps = (byte0 % 8) + 1, and more than one matters: a
# heap error needs a buffer that one call allocates and a later call misuses, so a
# single-step seed can only ever find the faults that live in a function's first touch of
# its arguments. That is the shape the findings actually had -- null dereferences at entry
# and no heap errors at all.
SEQUENCE_STEPS = 4

# A short seed as well as a long one, for each target, because the two arguments about
# seed size are both correct and they pull opposite ways.
#
# Long is needed for sequences: the harness breaks out of its step loop the moment the
# buffer runs dry, so a short payload is spent inside the first call and every execution
# is one call -- which is why the findings were all null dereferences at a function's
# first touch of its arguments and never a heap error, since a heap error needs a buffer
# one call allocates and a later call misuses.
#
# Short is needed for steering: havoc picks byte positions, so in 1026 bytes the selector
# at byte 1 is one position in a thousand and the mutator almost never moves it, while in
# twenty bytes it is one in twenty. ReadBytes zero-fills a read past the end, so a short
# seed still reaches every member -- its arguments simply start at zero and grow.
#
# Emitting both costs a few files and lets the scheduler decide, which is better than this
# script guessing which of the two effects dominates for a protocol it cannot see.
SHORT_SIZE = 24


def _payload(variant, index, size):
    if variant == 'zero':
        return bytes(size)
    if variant == 'ones':
        return bytes([0xFF]) * size
    if variant == 'same':
        return bytes([index & 0xFF]) * size
    return bytes((i & 0xFF) for i in range(size))          # ramp


def generate_seeds(output_dir, count, size):
    """Three seeds per target, each of which actually dispatches that target.

    The tail fillers are the two extremes plus the index itself:

      zero  arguments all 0x00 -- zero lengths, NULL-shaped values
      ones  arguments all 0xFF -- maximum lengths, which the harness clamps with % (N+1)
      same  every byte is the target index, so every step of the sequence dispatches the
            SAME target: call it, then call it again with what the last call left behind.
            That is the arrangement a use-after-free or a double free needs, and neither
            of the extremes provides it -- under both of them steps 2..N dispatch
            whatever 0x00 or 0xFF happens to select.
      ramp  0x00,0x01,0x02,... A uniform filler makes every multi-byte field in the
            payload the same degenerate value: a length is 0 or 0xFFFFFFFF and nothing
            in between, and a member whose guard wants a moderate size with small
            contents -- SanBenchDoubleFetch wants SharedSize >= 36 with a first word
            <= 32 -- cannot be satisfied by any single byte value at all, because the
            size and the contents are fed from the same filler. A ramp gives each field
            a different value and costs one more seed.

    None of this claims to satisfy a particular member's guard: that needs the layout of
    that member's arguments, which the generator knows and this does not. What it does is
    put every target in the corpus with a non-degenerate payload, so the mutator starts
    inside the function instead of never entering it.

    Size is not a detail. The harness stops the moment the buffer runs dry:

        if (Step > 0 && Input.Length == 0) break;

    A 64 byte payload is spent inside the first call, so every execution was a single call
    however long the campaign ran -- 375246 executions of EfiShell reached a corpus of 14.
    The guest buffer is 0x1000, so there is room.
    """
    os.makedirs(output_dir, exist_ok=True)
    written = 0
    for index in range(count):
        for variant in ('zero', 'ones', 'same', 'ramp'):
            # byte 0: how many steps. byte 1: which target. then the arguments.
            body = bytes([SEQUENCE_STEPS - 1, index & 0xFF]) + _payload(variant, index, size)
            with open(os.path.join(output_dir, f'seed_{index:02d}_{variant}'), 'wb') as f:
                f.write(body)
            written += 1
        for variant in ('ramp', 'zero'):
            body = (bytes([SEQUENCE_STEPS - 1, index & 0xFF])
                    + _payload(variant, index, SHORT_SIZE))
            with open(os.path.join(output_dir, f'seed_{index:02d}_{variant}_short'),
                      'wb') as f:
                f.write(body)
            written += 1

    # Say which targets the corpus reaches, computed the way the harness computes it, so
    # a layout change shows up here as a number instead of as a quiet loss of coverage.
    reached = set()
    for index in range(count):
        for variant in ('zero', 'ones', 'same', 'ramp'):
            body = bytes([SEQUENCE_STEPS - 1, index & 0xFF]) + _payload(variant, index, size)
            reached.add(body[1] % count)
    print(f'Wrote {written} seeds for {count} target(s) into {output_dir} '
          f'({size + 2} bytes and {SHORT_SIZE + 2} bytes)')
    print(f'  seeds dispatch {len(reached)}/{count} target(s) on their first step, '
          f'{SEQUENCE_STEPS} step(s) each')
    if len(reached) < count:
        missing = sorted(set(range(count)) - reached)
        print(f'  WARNING: no seed reaches target(s) {missing} -- those are left to '
              f'mutation')
    return written


def main():
    parser = argparse.ArgumentParser(description='Generate a seed corpus covering every fuzz target')
    parser.add_argument('-o', '--output', type=str, required=True, help='Corpus directory to write')
    parser.add_argument('-n', '--targets', type=int, help='Number of fuzz targets')
    parser.add_argument('-m', '--main', type=str, help='Generated FirnessMain.c to infer the target count from')
    parser.add_argument('-s', '--size', type=int, default=64, help='Bytes of argument data after the two selectors')
    args = parser.parse_args()

    count = args.targets if args.targets else find_target_count(args.main)
    if not count:
        print('Error: could not determine the target count. Pass -n or -m.')
        return

    generate_seeds(args.output, count, args.size)


if __name__ == '__main__':
    main()
