import os
import re
import bisect
import argparse


# DXE prints the runtime base of every image it dispatches:
#   Loading driver at 0x000DCA1A000 EntryPoint=0x000DCA34BC9 DevicePathDxe.efi
# and, when image protection is on, the size right after:
#   ProtectUefiImageCommon - 0xDCBDBA50
#     - 0x00000000DCA1A000 - 0x0000000000048E00
# together those give [base, base+size) per module, which is what turns a bare
# "Return IP address is 0x..." in a sanitizer report into module+symbol+offset
LOAD_RE = re.compile(
    r'Loading driver at 0x([0-9A-Fa-f]+)\s+EntryPoint=0x([0-9A-Fa-f]+)\s+(\S+\.efi)')
SIZE_RE = re.compile(r'^\s+-\s+0x([0-9A-Fa-f]+)\s+-\s+0x([0-9A-Fa-f]+)\s*$')


def parse_loaded_modules(serial_log):
    modules = []
    pending = {}
    with open(serial_log, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = LOAD_RE.search(line)
            if m:
                base = int(m.group(1), 16)
                pending[base] = {'name': m.group(3), 'base': base,
                                 'entry': int(m.group(2), 16), 'size': 0}
                modules.append(pending[base])
                continue
            m = SIZE_RE.match(line.rstrip('\r\n'))
            if m:
                base = int(m.group(1), 16)
                if base in pending:
                    pending[base]['size'] = int(m.group(2), 16)
    # a module with no ProtectUefiImageCommon line gets its extent from the next
    # image loaded above it, which is good enough to attribute an IP
    modules.sort(key=lambda x: x['base'])
    for i, mod in enumerate(modules):
        if mod['size'] == 0:
            nxt = modules[i + 1]['base'] if i + 1 < len(modules) else mod['base'] + 0x100000
            mod['size'] = max(0x1000, nxt - mod['base'])
    return modules


# the LLD map files under FV/Ffs/<GUID><Name>/<GUID>.map list
#             0x0000000000001453                DiskIoReadDisk
# with offsets relative to the image base, so they can be applied directly to
# (ip - runtime_base)
SYM_RE = re.compile(r'^\s+0x([0-9a-f]{16})\s{2,}([A-Za-z_][A-Za-z0-9_.$]*)\s*$')


def read_map(path):
    syms = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = SYM_RE.match(line.rstrip('\r\n'))
            if m:
                syms.append((int(m.group(1), 16), m.group(2)))
    syms.sort()
    return syms


def load_symbols_for(build_dir, module_name, extra_dirs=None):
    stem = module_name[:-4] if module_name.endswith('.efi') else module_name

    # platform modules live under FV/Ffs/<GUID><ModuleName>/<GUID>.map
    ffs = os.path.join(build_dir, 'FV', 'Ffs')
    if os.path.isdir(ffs):
        for entry in os.listdir(ffs):
            if not entry.endswith(stem):
                continue
            for name in os.listdir(os.path.join(ffs, entry)):
                if name.endswith('.map'):
                    return read_map(os.path.join(ffs, entry, name))

    # the generated harness is built in its own tree, not into the platform FV, so
    # Firness.efi has no FV/Ffs entry -- and it is exactly where fuzzing findings land.
    # several files share the name: the FV-level one is a different format and yields
    # nothing, so take whichever parses to the most symbols rather than the first hit
    best = []
    for root in (extra_dirs or []):
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                if name == stem + '.map':
                    syms = read_map(os.path.join(dirpath, name))
                    if len(syms) > len(best):
                        best = syms
    return best


class Symbolizer:
    def __init__(self, build_dir, serial_log, extra_dirs=None):
        self.build_dir = build_dir
        self.extra_dirs = extra_dirs or []
        self.modules = parse_loaded_modules(serial_log)
        self.bases = [m['base'] for m in self.modules]
        self.symbols = {}

    # find the loaded image containing this runtime address
    def module_for(self, ip):
        idx = bisect.bisect_right(self.bases, ip) - 1
        if idx < 0:
            return None
        mod = self.modules[idx]
        if ip < mod['base'] + mod['size']:
            return mod
        return None

    def resolve(self, ip):
        mod = self.module_for(ip)
        if mod is None:
            return {'ip': ip, 'module': None, 'symbol': None, 'offset': None}
        offset = ip - mod['base']
        if mod['name'] not in self.symbols:
            self.symbols[mod['name']] = load_symbols_for(
                self.build_dir, mod['name'], self.extra_dirs)
        syms = self.symbols[mod['name']]
        symbol = None
        delta = offset
        if syms:
            addrs = [s[0] for s in syms]
            i = bisect.bisect_right(addrs, offset) - 1
            if i >= 0:
                symbol = syms[i][1]
                delta = offset - syms[i][0]
        return {'ip': ip, 'module': mod['name'], 'symbol': symbol,
                'offset': offset, 'delta': delta}

    def format(self, ip):
        r = self.resolve(ip)
        if r['module'] is None:
            return f'0x{ip:016X}  <no loaded image covers this address>'
        if r['symbol'] is None:
            return f'0x{ip:016X}  {r["module"]}+0x{r["offset"]:X}'
        return f'0x{ip:016X}  {r["module"]}!{r["symbol"]}+0x{r["delta"]:X}'


IP_RE = re.compile(r'Return IP address is 0x([0-9A-Fa-f]+)')


# walk a serial capture and annotate every sanitizer report with the resolved frame
def annotate(serial_log, build_dir, out_file, extra_dirs=None):
    sym = Symbolizer(build_dir, serial_log, extra_dirs)
    resolved = 0
    total = 0
    with open(serial_log, 'r', encoding='utf-8', errors='ignore') as src, \
            open(out_file, 'w', encoding='utf-8') as dst:
        for line in src:
            dst.write(line)
            m = IP_RE.search(line)
            if m:
                total += 1
                ip = int(m.group(1), 16)
                text = sym.format(ip)
                if '!' in text:
                    resolved += 1
                dst.write(f'    -> {text}\n')
    print(f'Loaded {len(sym.modules)} module(s) from the serial log')
    print(f'Resolved {resolved}/{total} report address(es) to a symbol')
    return sym


def main():
    parser = argparse.ArgumentParser(
        description='Resolve sanitizer report addresses to module and symbol')
    parser.add_argument('-l', '--log', type=str, required=True,
                        help='Serial capture (fuzz.txt or reproduce.txt)')
    parser.add_argument('-b', '--build', type=str, required=True,
                        help='Build dir, e.g. Build/SimicsOpenBoardPkg/BoardX58Ich10/DEBUG_CLANGSAN')
    parser.add_argument('-o', '--output', type=str,
                        help='Annotated copy of the log (default: <log>.sym)')
    parser.add_argument('-a', '--address', type=str,
                        help='Resolve one address and exit')
    parser.add_argument('-x', '--extra', type=str, action='append', default=[],
                        help='Extra build tree to search for .map files (repeatable). '
                             'The generated harness needs this: it builds outside the platform FV.')
    args = parser.parse_args()

    if args.address:
        sym = Symbolizer(args.build, args.log, args.extra)
        print(sym.format(int(args.address, 16)))
        return

    annotate(args.log, args.build, args.output or args.log + '.sym', args.extra)


if __name__ == '__main__':
    main()
