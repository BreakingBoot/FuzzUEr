"""Turn a raw instruction pointer back into a module and an offset, after the run.

A sanitizer report names the source file of the *interceptor*, not of the caller, so the
one thing that says which driver actually did it is the `ip` in the message. Nothing in
the campaign resolves that: the firmware only prints `Find image based on IP` from the
exception handler, so a CPU fault gets a module name and every ASan finding does not.

The mapping exists in the log all the same. A DXE core built with `-D DEBUG_ON_SERIAL_PORT`
puts its dispatch narration on the same wire as the sanitizer:

    Loading driver at 0x0001DBB5000 EntryPoint=0x0001DBC95D5 DevicePathDxe.efi

That is a load address and a name for every image in the boot, which is all a resolver
needs -- provided it also knows how far each image extends. Two sources for that, in order
of preference:

  * the built PE32+ files, whose SizeOfImage is exact;
  * failing that, the distance to the next image loaded above it, which is right whenever
    the DXE allocator handed out adjacent blocks and conservative when it did not.

The second is a guess, so a resolution that rests on it is marked `~` and never silently
passed off as certain.

    python3 scripts/resolve_modules.py --log fuzz.txt --build Build/OvmfX64 --ip 0x1C2566D8
    python3 scripts/resolve_modules.py --log fuzz.txt --build Build/OvmfX64 --csv crashes.csv
"""

import argparse
import bisect
import os
import re
import struct
import sys

LOAD_RE = re.compile(r'Loading driver at (0x[0-9A-Fa-f]+) '
                     r'EntryPoint=(0x[0-9A-Fa-f]+) +([A-Za-z0-9_\-]+)\.efi')
IP_RE = re.compile(r'\bip (0x[0-9A-Fa-f]+)')

# No image is this big; a hit further than this past a base is not that image.
MAX_IMAGE = 0x400000


def size_of_image(path):
    """SizeOfImage out of a PE32/PE32+ optional header, or 0 if this is not one."""
    try:
        with open(path, 'rb') as handle:
            head = handle.read(0x400)
    except OSError:
        return 0
    if len(head) < 0x40 or head[:2] != b'MZ':
        return 0
    off = struct.unpack_from('<I', head, 0x3C)[0]
    if off + 0x60 > len(head) or head[off:off + 4] != b'PE\0\0':
        return 0
    # SizeOfImage sits at the same offset in both PE32 and PE32+
    return struct.unpack_from('<I', head, off + 24 + 56)[0]


def build_sizes(build_dirs):
    """Every <Name>.efi under the build trees, mapped to its SizeOfImage."""
    sizes = {}
    for root in build_dirs:
        for base, _, files in os.walk(root):
            for name in files:
                if not name.endswith('.efi'):
                    continue
                stem = name[:-4]
                if stem in sizes:
                    continue
                size = size_of_image(os.path.join(base, name))
                if size:
                    sizes[stem] = size
    return sizes


class ImageMap:
    """The images a boot loaded, ordered so an address can be looked up."""

    def __init__(self, loads, sizes=None):
        sizes = sizes or {}
        # A name can load more than once across the reboots in one campaign; each load is
        # its own range, and identical repeats collapse.
        seen = {}
        for base, entry, name in loads:
            seen[(base, name)] = entry
        ordered = sorted(seen, key=lambda item: item[0])
        self.bases = [base for base, _ in ordered]
        self.images = []
        for index, (base, name) in enumerate(ordered):
            exact = sizes.get(name, 0)
            if exact:
                end, sure = base + exact, True
            else:
                nxt = ordered[index + 1][0] if index + 1 < len(ordered) else 0
                span = nxt - base if nxt and nxt - base <= MAX_IMAGE else MAX_IMAGE
                end, sure = base + span, False
            self.images.append((base, end, name, sure))

    def __len__(self):
        return len(self.images)

    @property
    def exact(self):
        return sum(1 for image in self.images if image[3])

    def resolve(self, ip):
        """(name, offset, certain) for the image containing ip, or None."""
        index = bisect.bisect_right(self.bases, ip) - 1
        if index < 0:
            return None
        base, end, name, sure = self.images[index]
        if ip >= end:
            return None
        return name, ip - base, sure


def read_text(path):
    with open(path, 'rb') as handle:
        return handle.read().decode('utf-8', errors='replace').replace('\r', '')


def map_from_logs(paths, build_dirs=()):
    loads = []
    for path in paths:
        if not os.path.isfile(path):
            continue
        for base, entry, name in LOAD_RE.findall(read_text(path)):
            loads.append((int(base, 16), int(entry, 16), name))
    return ImageMap(loads, build_sizes(build_dirs) if build_dirs else {})


def describe(imap, ip):
    hit = imap.resolve(ip)
    if not hit:
        return 'unattributed'
    name, offset, sure = hit
    return f'{name}.efi+{offset:#x}{"" if sure else " ~"}'


def main():
    parser = argparse.ArgumentParser(description='Resolve firmware IPs to modules')
    parser.add_argument('--log', action='append', default=[],
                        help='a serial capture carrying the DXE dispatch lines')
    parser.add_argument('--build', action='append', default=[],
                        help='a build tree, for exact image sizes')
    parser.add_argument('--ip', action='append', default=[], help='an address to resolve')
    parser.add_argument('--csv', help='resolve every ip in this crashes.csv')
    parser.add_argument('--quiet', action='store_true')
    args = parser.parse_args()

    imap = map_from_logs(args.log, args.build)
    if not len(imap):
        print('no image loads in the log -- was it built with -D DEBUG_ON_SERIAL_PORT?',
              file=sys.stderr)
        return 2
    if not args.quiet:
        print(f'{len(imap)} images, {imap.exact} with an exact size from the build tree')

    for text in args.ip:
        print(f'  {text} -> {describe(imap, int(text, 0))}')

    if args.csv:
        counts = {}
        for match in IP_RE.finditer(read_text(args.csv)):
            key = describe(imap, int(match.group(1), 16))
            counts[key] = counts.get(key, 0) + 1
        for key, hits in sorted(counts.items(), key=lambda kv: -kv[1]):
            print(f'  {hits:5} {key}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
