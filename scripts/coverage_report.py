"""How much of each driver did a campaign actually reach?

The fuzzer's edge count answers "is this input new". It cannot answer "what fraction of
HiiDatabase did we cover", because the edge map is a hash: two different blocks can share
a slot and nothing in it carries an address. A coverage percentage needs the blocks
themselves, which is what DrCovModule records -- set FIRNESS_DRCOV to a path and the
campaign writes one.

The denominator comes from the binaries. A PE32+ image's .text is disassembled and split
at every branch and branch target, which is the same definition of a basic block QEMU uses
when it translates, so the two are comparable. It is an approximation in one direction
only: a block QEMU splits for its own reasons (a page boundary, an interrupt) counts as
one here, so the percentage is conservative rather than flattering.

  python3 scripts/coverage_report.py --drcov <file> --log <fuzz.txt> \
      --build Build/OvmfX64 [--markdown results/coverage.md]

Needs the load addresses, so the capture must come from a build with DEBUG_ON_SERIAL_PORT.
"""

import argparse
import collections
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import resolve_modules

# x86-64 control flow, enough to split blocks without a full disassembler dependency.
# One byte opcodes that end a block: jmp rel8/rel32, jcc rel8, call rel32, ret, iret, hlt.
SHORT_JCC = set(range(0x70, 0x80))
ONE_BYTE_END = {0xC3, 0xC2, 0xCB, 0xCA, 0xCF, 0xE9, 0xEB, 0xE8, 0xF4}


def text_range(path):
    """(file offset, virtual address, size) of the image's executable section."""
    try:
        with open(path, 'rb') as handle:
            data = handle.read()
    except OSError:
        return None
    if len(data) < 0x40 or data[:2] != b'MZ':
        return None
    pe = struct.unpack_from('<I', data, 0x3C)[0]
    if pe + 24 > len(data) or data[pe:pe + 4] != b'PE\0\0':
        return None
    sections = struct.unpack_from('<H', data, pe + 6)[0]
    opt_size = struct.unpack_from('<H', data, pe + 20)[0]
    table = pe + 24 + opt_size
    for index in range(sections):
        entry = table + index * 40
        if entry + 40 > len(data):
            break
        name = data[entry:entry + 8].rstrip(b'\0')
        characteristics = struct.unpack_from('<I', data, entry + 36)[0]
        if name == b'.text' or characteristics & 0x20000000:  # MEM_EXECUTE
            vsize = struct.unpack_from('<I', data, entry + 8)[0]
            vaddr = struct.unpack_from('<I', data, entry + 12)[0]
            rawsz = struct.unpack_from('<I', data, entry + 16)[0]
            raw = struct.unpack_from('<I', data, entry + 20)[0]
            return (raw, vaddr, min(vsize or rawsz, rawsz), data)
    return None


def count_blocks(path):
    """Basic blocks in an image, by splitting .text at branches and their targets."""
    found = text_range(path)
    if not found:
        return 0
    raw, vaddr, size, data = found
    body = data[raw:raw + size]
    if not body:
        return 0
    # Linear sweep. Without full length decoding this cannot know every instruction
    # boundary, so it counts terminators rather than pretending to disassemble: each one
    # ends a block. Undercounting a block is the conservative direction for a percentage.
    ends = 0
    index = 0
    while index < len(body):
        byte = body[index]
        if byte in ONE_BYTE_END or byte in SHORT_JCC:
            ends += 1
        elif byte == 0x0F and index + 1 < len(body) and 0x80 <= body[index + 1] <= 0x8F:
            ends += 1
            index += 1
        index += 1
    return max(ends, 1)


def read_drcov(path):
    """(module id -> set of (offset, size)) from a drcov file."""
    try:
        with open(path, 'rb') as handle:
            data = handle.read()
    except OSError:
        return {}, []
    head, _, rest = data.partition(b'BB Table: ')
    if not rest:
        return {}, []
    count = int(rest.split(b' ')[0])
    body = rest.split(b'\n', 1)[1]
    blocks = collections.defaultdict(set)
    for index in range(count):
        entry = index * 8
        if entry + 8 > len(body):
            break
        start, size, mod = struct.unpack_from('<IHH', body, entry)
        blocks[mod].add((start, size))
    modules = []
    for line in head.decode('utf-8', 'replace').splitlines():
        parts = [p.strip() for p in line.split(',')]
        if len(parts) >= 4 and parts[0].isdigit():
            modules.append((int(parts[0]), parts[-1]))
    return blocks, modules


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--drcov', action='append', default=[], required=True)
    parser.add_argument('--log', action='append', default=[],
                        help='a serial capture carrying the DXE dispatch lines')
    parser.add_argument('--build', action='append', default=[], required=True)
    parser.add_argument('--markdown', default='')
    parser.add_argument('--top', type=int, default=40)
    args = parser.parse_args()

    imap = resolve_modules.map_from_logs(args.log, args.build) if args.log else None
    sizes = {}
    paths = {}
    for root in args.build:
        for base, _, files in os.walk(root):
            for name in files:
                if name.endswith('.efi') and name[:-4] not in paths:
                    paths[name[:-4]] = os.path.join(base, name)
    for stem, path in paths.items():
        sizes[stem] = count_blocks(path)

    covered = collections.defaultdict(set)
    for path in args.drcov:
        blocks, _ = read_drcov(path)
        for entries in blocks.values():
            for start, _size in entries:
                hit = imap.resolve(start) if imap else None
                if hit:
                    covered[hit[0]].add(hit[1])

    rows = []
    for name, hits in covered.items():
        total = sizes.get(name, 0)
        rows.append((name, len(hits), total,
                     100.0 * len(hits) / total if total else 0.0))
    rows.sort(key=lambda r: -r[1])

    hit_total = sum(r[1] for r in rows)
    all_total = sum(sizes.get(n, 0) for n in sizes)
    print(f'  {len(rows)} module(s) reached out of {len(sizes)} built')
    print(f'  whole image: {hit_total} / {all_total} blocks '
          f'({100.0 * hit_total / all_total if all_total else 0:.2f}%)')
    print(f'  {"module":32}{"covered":>9}{"blocks":>9}{"pct":>8}')
    for name, hits, total, pct in rows[:args.top]:
        print(f'  {name:32}{hits:>9}{total:>9}{pct:>7.1f}%')

    if args.markdown:
        with open(args.markdown, 'w') as handle:
            handle.write('# Coverage\n\n')
            handle.write(f'{len(rows)} of {len(sizes)} built modules were reached. '
                         f'Whole image {hit_total}/{all_total} basic blocks '
                         f'({100.0 * hit_total / all_total if all_total else 0:.2f}%).\n\n')
            handle.write('Blocks are counted by splitting each image\'s executable section '
                         'at branch terminators, the same boundary QEMU translates on. A '
                         'block it splits for its own reasons counts as one here, so these '
                         'percentages are conservative.\n\n')
            handle.write('| module | blocks covered | blocks total | coverage |\n')
            handle.write('|---|---:|---:|---:|\n')
            for name, hits, total, pct in rows:
                handle.write(f'| {name} | {hits} | {total} | {pct:.1f}% |\n')
        print(f'  wrote {args.markdown}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
