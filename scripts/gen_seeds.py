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
    os.makedirs(output_dir, exist_ok=True)
    for index in range(count):
        # byte 0 selects the target. the tail is all zeros in one seed and all ones in
        # the other so the first execution of each harness already sees both extremes,
        # which is where length and enum handling tends to break
        for variant, filler in (('zero', 0x00), ('ones', 0xFF)):
            body = bytes([index]) + bytes([filler]) * size
            with open(os.path.join(output_dir, f'seed_{index:02d}_{variant}'), 'wb') as f:
                f.write(body)
    print(f'Wrote {count * 2} seeds for {count} target(s) into {output_dir}')


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
