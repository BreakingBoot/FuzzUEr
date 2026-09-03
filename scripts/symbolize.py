import os
import re
import sys
import argparse
import subprocess
from bisect import bisect_right


# Turn the raw addresses in a serial capture into module names.
#
# A sanitizer report gives a file and line for where the check failed, but the interesting
# part is who called it: StrLen(NULL) asserting inside BaseLib says nothing until you know
# which driver passed the NULL. Asan.c prints "Return IP address is 0x..." for the frames
# above the failure, and DXE prints "Loading driver at 0x... EntryPoint=0x... Name.efi" for
# every module, so an address can be attributed to the module whose image contains it.
#
# This is module-level attribution, not line-level: it says Shell.efi+0x3B1F9, which is
# enough to tell a finding in the firmware from one in a library everybody calls.
LOAD = re.compile(r'Loading driver at (0x[0-9A-Fa-f]+) EntryPoint=(0x[0-9A-Fa-f]+)\s+(\S+\.efi)')
RETURN_IP = re.compile(r'Return IP address is (0x[0-9A-Fa-f]+)')
ASAN_IP = re.compile(r'ip (0x[0-9A-Fa-f]+)')


def load_modules(path):
    modules = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as handle:
        for line in handle:
            found = LOAD.search(line)
            if found:
                modules.append((int(found.group(1), 16), found.group(3)))
    # a module can be loaded more than once; the last base wins for a given name, and the
    # list has to be sorted for the containing-module lookup below
    modules.sort()
    return modules


def attribute(modules, address):
    if not modules:
        return '', 0
    bases = [base for base, _ in modules]
    index = bisect_right(bases, address) - 1
    if index < 0:
        return '', 0
    base, name = modules[index]
    offset = address - base
    # an image is not usually larger than a few megabytes; past that the address is not
    # inside this module, it is simply above the last one loaded
    if offset > 0x400000:
        return '', 0
    return name, offset


def collect_addresses(path):
    seen = {}
    with open(path, 'r', encoding='utf-8', errors='ignore') as handle:
        for line in handle:
            for pattern in (RETURN_IP, ASAN_IP):
                for match in pattern.finditer(line):
                    value = int(match.group(1), 16)
                    seen[value] = seen.get(value, 0) + 1
    return seen


# With a module's .debug ELF the offset can be turned into a function name. The PE that DXE
# loads keeps the section layout of that ELF, so an offset from the load base is the ELF
# vaddr. Both the raw offset and the offset past .text are reported when they disagree,
# because GenFw's layout is close enough to make either plausible and a wrong guess here
# would name the wrong function with false confidence.
def resolve(debug_file, offset, text_base):
    names = []
    for candidate in dict.fromkeys((offset, offset + text_base)):
        result = subprocess.run(['addr2line', '-f', '-C', '-e', debug_file, hex(candidate)],
                                capture_output=True, text=True)
        name = (result.stdout or '').splitlines()
        if name and name[0] not in ('??', ''):
            names.append(name[0])
    return ' | '.join(dict.fromkeys(names))


def text_vaddr(debug_file):
    result = subprocess.run(['readelf', '-S', debug_file], capture_output=True, text=True)
    for line in (result.stdout or '').splitlines():
        if ' .text' in line:
            parts = line.split()
            for part in parts:
                if len(part) == 16 and all(c in '0123456789abcdef' for c in part):
                    return int(part, 16)
    return 0


# An address that shows up under many unrelated protocols is firmware the fuzzer did not
# provoke -- the boot baseline keeps running after the harness loads. Without this filter
# the busiest address in a capture is usually background: HiiDatabase.efi+0x22A57 appears
# under EdkiiVariablePolicy, EfiShell and EfiHiiString alike, and reading it as that
# protocol's finding attributes a fault to a function the harness never calls.
def common_addresses(root, threshold):
    seen = {}
    if not os.path.isdir(root):
        return set()
    for name in sorted(os.listdir(root)):
        capture = os.path.join(root, name, 'fuzz.txt')
        if not os.path.isfile(capture):
            continue
        for address in collect_addresses(capture):
            seen.setdefault(address, set()).add(name)
    return {a for a, who in seen.items() if len(who) >= threshold}


def main():
    parser = argparse.ArgumentParser(
        description='Attribute the addresses in a serial capture to the modules that own them')
    parser.add_argument('capture', help='fuzz.txt from a campaign')
    parser.add_argument('-n', '--top', type=int, default=15,
                        help='How many addresses to show (default 15)')
    parser.add_argument('--module', type=str, default='',
                        help='Only show addresses inside this module')
    parser.add_argument('--baseline', type=str, default='',
                        help='Run directory of other protocols: addresses common to several '
                             'of them are firmware background, not this run\'s finding')
    parser.add_argument('--shared-at', type=int, default=3,
                        help='Protocols an address must appear under to count as background')
    parser.add_argument('--debug-dir', type=str, default='',
                        help='Directory of <Module>.debug files, to name the functions')
    args = parser.parse_args()

    if not os.path.isfile(args.capture):
        print(f'No such capture: {args.capture}')
        return 1

    modules = load_modules(args.capture)
    addresses = collect_addresses(args.capture)
    if not modules:
        print('No "Loading driver at" lines in the capture, so nothing can be attributed.')
        return 1
    print(f'  {len(modules)} module load(s), {len(addresses)} distinct address(es)')

    background = common_addresses(args.baseline, args.shared_at) if args.baseline else set()
    if background:
        print(f'  {len(background)} background address(es) excluded')
    rows = []
    for address, count in addresses.items():
        if address in background:
            continue
        name, offset = attribute(modules, address)
        if not name or (args.module and args.module.lower() not in name.lower()):
            continue
        rows.append((count, name, offset, address))
    rows.sort(reverse=True)

    if not rows:
        print('  no address fell inside a loaded module')
        return 0
    print(f'  {"hits":>6}  {"module":26} {"offset":>10}  function')
    for count, name, offset, address in rows[:args.top]:
        symbol = ''
        if args.debug_dir:
            debug_file = os.path.join(args.debug_dir, name.replace('.efi', '.debug'))
            if os.path.isfile(debug_file):
                symbol = resolve(debug_file, offset, text_vaddr(debug_file))
        print(f'  {count:>6}  {name:26} +0x{offset:08X}  {symbol or f"0x{address:012X}"}')
    by_module = {}
    for count, name, _o, _a in rows:
        by_module[name] = by_module.get(name, 0) + count
    print('\n  by module:')
    for name, count in sorted(by_module.items(), key=lambda kv: -kv[1])[:8]:
        print(f'    {name:30} {count}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
