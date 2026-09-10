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


def package_relative(path):
    """The part of a path from its edk2 package root onwards, or '' if there is none.

    A build tree and a report's source path share only the package relative part -- one is
    rooted at Build/<Plat>/<TARGET>_<TOOL>/<ARCH>, the other wherever the build ran. Every
    edk2 package directory ends in "Pkg", which is what makes the two comparable.
    """
    parts = path.replace(os.sep, '/').strip('/').split('/')
    for index, part in enumerate(parts):
        if part.endswith('Pkg'):
            return '/'.join(parts[index:])
    return ''


class SourceMap:
    """Which module owns a source file, from the shape of the build tree.

    An ASan report carries the address that faulted, so the image map resolves it. A UBSan
    report does not: it names a source file and a line and nothing else, which is why every
    row in the Simics corpus is unattributed even though its capture has the load addresses.

    edk2 builds each module into <arch>/<pkg>/<path>/<ModuleDir>/<Name>/OUTPUT/<Name>.efi,
    so three levels above the .efi is exactly the directory that module's sources live in.
    That maps a report's file back to the driver that compiled it.

    It only covers files the module owns. Code from a library instance is compiled into
    that library's own directory, so FrameBufferBltLib.c resolves to no module here and
    has to come from the faulting address instead -- the two are complementary, not
    alternatives.
    """

    def __init__(self, build_dirs):
        self.by_dir = {}
        for root in build_dirs:
            for base, _, files in os.walk(root):
                for name in files:
                    if not name.endswith('.efi'):
                        continue
                    stem = name[:-4]
                    # The build directory is named for the INF, the image for its
                    # BASE_NAME, and the two often differ -- HiiDatabaseDxe.inf produces
                    # HiiDatabase.efi and DxeMain.inf produces DxeCore.efi. Keying on the
                    # names matching drops exactly those modules, so key on the structure:
                    # <module dir>/<inf stem>/{OUTPUT,DEBUG}/<image>.
                    if os.path.basename(base) not in ('OUTPUT', 'DEBUG'):
                        continue
                    module_dir = os.path.dirname(os.path.dirname(base))
                    key = package_relative(module_dir)
                    if key:
                        self.by_dir.setdefault(key, stem)

    def __len__(self):
        return len(self.by_dir)

    def resolve(self, source_path):
        """The module owning this source file, or None."""
        if not source_path:
            return None
        wanted = package_relative(os.path.dirname(source_path.replace('\\', '/')))
        # A module keeps sources in subdirectories -- DxeCore's FwVol/FwVolRead.c belongs
        # to MdeModulePkg/Core/Dxe -- so walk up until a directory is one a module was
        # built from. The package root is the floor; above it a match would be a guess.
        while wanted:
            name = self.by_dir.get(wanted)
            if name:
                return name
            if '/' not in wanted:
                return None
            wanted = wanted.rsplit('/', 1)[0]
        return None


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


_SOURCE_MAPS = {}


def source_map(build_dirs):
    """One SourceMap per set of build trees; walking them is not cheap."""
    key = tuple(sorted(build_dirs))
    if key not in _SOURCE_MAPS:
        _SOURCE_MAPS[key] = SourceMap(build_dirs)
    return _SOURCE_MAPS[key]


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
