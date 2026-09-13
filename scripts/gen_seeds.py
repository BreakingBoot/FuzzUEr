import os
import re
import argparse


# FirnessMain consumes the first input byte as a target selector:
#     ReadBytes(&Input, sizeof(DriverChoice), (VOID *)&DriverChoice);
#     switch (DriverChoice % <N>)
# so a seed's first byte decides which Fuzz<Func>() runs and the rest feeds its
# arguments. the corpus this repo shipped was nine DER certificates that all start
# with 0x30, so every one of them selected target 0 and the other targets were only
# ever reached by mutation
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


def generate_seeds(output_dir, count, size):
    """One seed per target per filler, long enough to reach a second call.

    Size is not a detail. FirnessMain reads a step count, then for each step a byte that
    picks the target and then that function's arguments, and it stops early the moment the
    buffer runs dry:

        if (Step > 0 && Input.Length == 0) break;

    A 64 byte payload is spent inside the first call, so every execution was a single call
    no matter how long the campaign ran -- 375246 executions of EfiShell reached a corpus
    of 14 and found nothing past the entry point. That also explains the shape of the
    findings: null dereferences where a function first touches an argument, and no heap
    errors at all, because reaching a heap bug means getting a buffer allocated by one call
    and misused by a later one. The guest buffer is 0x1000, so there is room.
    """
    os.makedirs(output_dir, exist_ok=True)
    for index in range(count):
        # byte 0 selects the target. the tail is all zeros in one seed and all ones in
        # the other so the first execution of each harness already sees both extremes,
        # which is where length and enum handling tends to break
        for variant, filler in (('zero', 0x00), ('ones', 0xFF)):
            body = bytes([index]) + bytes([filler]) * size
            with open(os.path.join(output_dir, f'seed_{index:02d}_{variant}'), 'wb') as f:
                f.write(body)
    print(f'Wrote {count * 2} seeds of {size + 1} bytes for {count} target(s) '
          f'into {output_dir}')


def main():
    parser = argparse.ArgumentParser(description='Generate a seed corpus covering every fuzz target')
    parser.add_argument('-o', '--output', type=str, required=True, help='Corpus directory to write')
    parser.add_argument('-n', '--targets', type=int, help='Number of fuzz targets')
    parser.add_argument('-m', '--main', type=str, help='Generated FirnessMain.c to infer the target count from')
    parser.add_argument('-s', '--size', type=int, default=64, help='Bytes of argument data after the selector')
    args = parser.parse_args()

    count = args.targets if args.targets else find_target_count(args.main)
    if not count:
        print('Error: could not determine the target count. Pass -n or -m.')
        return

    generate_seeds(args.output, count, args.size)


if __name__ == '__main__':
    main()
