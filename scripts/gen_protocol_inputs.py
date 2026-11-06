import os
import re
import argparse


# a protocol header declares its GUID as
#     extern EFI_GUID  gEfiBlockIoProtocolGuid;
# and its callable surface as struct members whose type is a function-pointer typedef
# declared in the same header:
#     typedef EFI_STATUS (EFIAPI *EFI_BLOCK_READ)(...);
#     ...
#     EFI_BLOCK_READ  ReadBlocks;
# that pair is all firness needs to build a target list
GUID_RE = re.compile(r'extern\s+EFI_GUID\s+(g\w*ProtocolGuid)\s*;')
FPTYPE_RE = re.compile(r'\(\s*EFIAPI\s*\*\s*(\w+)\s*\)')
MEMBER_RE = re.compile(r'^\s*([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*;\s*$')
# a struct definition names itself either at the opening, "struct _EFI_X_PROTOCOL {",
# or at the closing, "} EFI_X_PROTOCOL;"
STRUCT_OPEN_RE = re.compile(r'^\s*(?:typedef\s+)?struct\s+([A-Za-z_]\w*)?\s*\{')
STRUCT_END_RE = re.compile(r'^\s*\}\s*([A-Za-z_]\w*)?\s*;')


# the struct the guid names: gEfiDhcp4ProtocolGuid -> EFIDHCP4PROTOCOL. separators are
# dropped because camel case does not say where an acronym ends (IoMmu vs IOMMU)
def guid_struct_key(guid):
    name = guid[1:] if guid.startswith('g') else guid
    if name.endswith('Guid'):
        name = name[:-4]
    return name.replace('_', '').upper()


def normalize(name):
    return (name or '').lstrip('_').replace('_', '').upper()


# members declared inside the protocol's own struct. a header also declares config and
# packet structs whose members are function pointers too, and those are not callable entry
# points -- EFI_DHCP4_CONFIG_DATA.Dhcp4Callback is a callback, not a protocol method
def struct_members(src, guid, fptypes):
    want = guid_struct_key(guid)
    depth = 0
    opened_as = None
    current = []
    for line in src.splitlines():
        opening = STRUCT_OPEN_RE.match(line)
        if opening and depth == 0:
            depth = 1
            opened_as = opening.group(1)
            current = []
            continue
        if depth:
            closing = STRUCT_END_RE.match(line)
            if closing:
                if normalize(opened_as) == want or normalize(closing.group(1)) == want:
                    return current
                depth = 0
                opened_as = None
                continue
            member = MEMBER_RE.match(line)
            if member and member.group(1) in fptypes and member.group(2) not in current:
                current.append(member.group(2))
    return []


def scan_header(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        src = f.read()
    guids = GUID_RE.findall(src)
    if not guids:
        return None
    fptypes = set(FPTYPE_RE.findall(src))
    if not fptypes:
        return None
    # a header often declares the service binding guid before the protocol's own, and the
    # callable methods belong to the protocol, not to the binding: Tls.h declares
    # gEfiTlsServiceBindingProtocolGuid then gEfiTlsProtocolGuid, and SetSessionData is a
    # member of _EFI_TLS_PROTOCOL. pick whichever guid actually owns a struct here
    # Every guid in the header that owns a struct, not the first one that does. A header
    # is allowed to declare more than one protocol and two upstream ones do -- Print2.h
    # carries gEfiPrint2ProtocolGuid and gEfiPrint2SProtocolGuid, SmmCpuService.h carries
    # gEfiSmmCpuServiceProtocolGuid and gEdkiiSmmCpuRendezvousProtocolGuid -- and
    # stopping at the first meant the second was never discovered and so never fuzzed.
    owned = []
    for guid in guids:
        found = struct_members(src, guid, fptypes)
        if found and guid not in [g for g, _ in owned]:
            owned.append((guid, found))
    if owned:
        return owned

    members = []
    if not members:
        # no block matched the guid name, so fall back to every function-pointer member in
        # the header rather than dropping the protocol entirely
        for line in src.splitlines():
            m = MEMBER_RE.match(line)
            if m and m.group(1) in fptypes and m.group(2) not in members:
                members.append(m.group(2))
    if not members:
        return None
    return [(guids[0], members)]


# ---------------------------------------------------------------------------------------
# Discovery from the installation site, for protocols whose headers do not follow the
# conventions the header scan relies on.
#
# The scan above needs three things to line up: the struct lives under an Include/Protocol
# directory, the header declares `extern EFI_GUID g<Name>ProtocolGuid;`, and the struct's
# name matches that GUID's name. Upstream edk2 holds to all three. A driver written for one
# platform frequently holds to none -- OvmfPkg/Spi declares DXE_SPI_PROTOCOL in
# OvmfPkg/Spi/SmmSpiCommon.h, never declares its GUID extern anywhere (the INF's
# [Protocols] section gets it from AutoGen), and names it gEfiDxeSmmSpiProtocolGuid, which
# does not resemble _DXE_SPI_PROTOCOL. Three independent misses, and the result is a
# protocol with two callable methods that no campaign has ever had a target file for.
#
# The install call has none of those problems. It names the GUID and the interface variable
# in one place, and the variable's declaration names the type:
#
#     DXE_SPI_PROTOCOL  mDxeSpiProtocol = { DxeSpiRead, DxeSpiWrite };
#     ...
#     gBS->InstallMultipleProtocolInterfaces (&Handle, &gEfiDxeSmmSpiProtocolGuid,
#                                             &mDxeSpiProtocol, NULL);
#
# which is evidence that the protocol is not only declared but actually installed -- a
# stronger statement than the header makes.

INSTALL_RE = re.compile(
    r'\bInstall(?:Multiple)?ProtocolInterfaces?\s*\(([^;]*?)\)\s*;', re.S)
TYPEDEF_CLOSE_RE = re.compile(r'^\s*\}\s*([A-Za-z_]\w*)\s*;')


def split_args(text):
    """Top-level comma split, so a nested call or cast does not break the pairing."""
    out, depth, current = [], 0, ''
    for char in text:
        if char in '([{':
            depth += 1
        elif char in ')]}':
            depth -= 1
        if char == ',' and depth == 0:
            out.append(current.strip())
            current = ''
        else:
            current += char
    if current.strip():
        out.append(current.strip())
    return out


def installed_pairs(src):
    """[(guid_symbol, interface_variable)] for every protocol this source installs."""
    pairs = []
    for match in INSTALL_RE.finditer(src):
        args = [a.lstrip('&').strip() for a in split_args(match.group(1))]
        if len(args) < 2:
            continue
        if 'Multiple' in src[match.start():match.start() + 40]:
            # (&Handle, &GuidA, &IfaceA, &GuidB, &IfaceB, NULL)
            rest = args[1:]
            for index in range(0, len(rest) - 1, 2):
                guid, iface = rest[index], rest[index + 1]
                if guid == 'NULL':
                    break
                pairs.append((guid, iface))
        elif len(args) >= 4:
            # (&Handle, &Guid, EFI_NATIVE_INTERFACE, Interface)
            pairs.append((args[1], args[3]))
    # NULL is not an interface. "Install NULL to DXE data base as notify" is a real edk2
    # idiom -- three of the EVAL-1 drivers use it to publish a readiness signal -- and
    # there is nothing on the other end to call, so it must not become a target.
    return [(g, i) for g, i in pairs
            if re.fullmatch(r'g\w*Guid', g) and re.fullmatch(r'[A-Za-z_]\w*', i)
            and i != 'NULL']


def interface_type(src, variable):
    """The declared type of an interface variable, or None."""
    match = re.search(
        rf'^\s*(?:STATIC\s+|static\s+|CONST\s+|GLOBAL_REMOVE_IF_UNREFERENCED\s+)*'
        rf'([A-Za-z_]\w*)\s+\*?\s*{re.escape(variable)}\s*(?:=|;|\[)',
        src, re.M)
    return match.group(1) if match else None


def structs_in(src):
    """{normalized struct name: [function-pointer members]} for one header."""
    fptypes = set(FPTYPE_RE.findall(src))
    if not fptypes:
        return {}
    found, depth, opened_as, current = {}, 0, None, []
    for line in src.splitlines():
        opening = STRUCT_OPEN_RE.match(line)
        if opening and depth == 0:
            depth, opened_as, current = 1, opening.group(1), []
            continue
        if not depth:
            continue
        closing = TYPEDEF_CLOSE_RE.match(line) or STRUCT_END_RE.match(line)
        if closing:
            for name in (opened_as, closing.group(1)):
                if name and current:
                    found.setdefault(normalize(name), list(current))
            depth, opened_as, current = 0, None, []
            continue
        member = MEMBER_RE.match(line)
        if member and member.group(1) in fptypes and member.group(2) not in current:
            current.append(member.group(2))
    return found


def struct_index(tree):
    """Every function-pointer struct in the tree, by normalized name. One walk."""
    index = {}
    for base, dirs, files in os.walk(tree):
        dirs[:] = [d for d in dirs if d not in ('.git', 'Build', 'BaseTools')]
        for name in sorted(files):
            if not name.endswith('.h') or name in NOT_TARGETS:
                continue
            try:
                with open(os.path.join(base, name), encoding='utf-8', errors='ignore') as f:
                    src = f.read()
            except OSError:
                continue
            for key, members in structs_in(src).items():
                if key not in index or len(members) > len(index[key][1]):
                    index[key] = (name, members)
    return index


def scan_installations(tree):
    """{guid: (header, members)} for protocols discovered at their install call."""
    index = struct_index(tree)
    found = {}
    for base, dirs, files in os.walk(tree):
        dirs[:] = [d for d in dirs if d not in ('.git', 'Build', 'BaseTools')]
        for name in sorted(files):
            if not name.endswith('.c'):
                continue
            path = os.path.join(base, name)
            try:
                with open(path, encoding='utf-8', errors='ignore') as f:
                    src = f.read()
            except OSError:
                continue
            if 'ProtocolInterface' not in src:
                continue
            for guid, variable in installed_pairs(src):
                kind = interface_type(src, variable)
                if not kind:
                    continue
                hit = index.get(normalize(kind))
                if not hit:
                    continue
                header, members = hit
                if guid not in found or len(members) > len(found[guid][1]):
                    found[guid] = (header, members)
    return found


# Protocols that exist in a header but are deliberately not in the firmware. Discovery
# reads headers, so a driver behind a build flag still looks like a target: AsanFaultDxe
# is the sanitizer's positive control and is built only under ASAN_FAULT_PROTOCOL, which
# no sweep defines. A request for it costs a container, a full analysis, a harness build
# and then the whole boot budget waiting for a protocol that was never installed -- once
# per version, every run, and it leaves the sweep reporting degraded forever for a
# protocol nobody wanted fuzzed.
NOT_TARGETS = {'AsanFault.h', 'SanBench.h'}

# SanBench.h is the exception to the exception. Its protocols ARE targets, but only when
# the firmware was built with -D SAN_BENCH -- otherwise the drivers are not in the image
# and a campaign spends a container, an analysis and a whole boot budget discovering that
# nothing installed them. --bench turns them back on, and fuzz_edk2.py passes it exactly
# when it passed the define.
BENCH_TARGETS = {'SanBench.h'}


def scan_roots(roots, skip=NOT_TARGETS):
    protocols = {}
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            for name in sorted(files):
                if not name.endswith('.h') or name in skip:
                    continue
                hit = scan_header(os.path.join(dirpath, name))
                for guid, members in (hit or []):
                    # a header can be scanned twice via different roots; keep the richest
                    if guid not in protocols or len(members) > len(protocols[guid][1]):
                        protocols[guid] = (name, members)
    return protocols


def write_inputs(protocols, output_dir, min_methods, limit):
    os.makedirs(output_dir, exist_ok=True)
    ordered = sorted(protocols.items(), key=lambda kv: (-len(kv[1][1]), kv[0]))
    written = 0
    for guid, (header, members) in ordered:
        if len(members) < min_methods:
            continue
        if limit and written >= limit:
            break
        # firness keys its input on the GUID variable name, so derive the file name
        # from it rather than from the header
        stem = guid[1:].replace('ProtocolGuid', '')
        path = os.path.join(output_dir, stem + '.txt')
        with open(path, 'w') as f:
            f.write('[Protocols]\n')
            f.write(f'  // from {header}\n')
            for member in members:
                f.write(f'  {guid}:{member}\n')
        written += 1
    print(f'Wrote {written} protocol input file(s) into {output_dir}')
    return written


# Firness learns a protocol's shape from its call sites, not from its header: a protocol
# nothing in the tree calls yields "Total Functions: 0" and the campaign spends a full
# analysis and build to produce nothing. Scanning every Include/Protocol directory rather
# than five named packages turns that from a rarity into a routine cost -- ArmPkg,
# EmbeddedPkg and EmulatorPkg headers all declare protocols an OVMF X64 build never
# installs -- so ask which ones the tree actually uses.
def consumed_guids(src):
    used = set()
    token = re.compile(rb'(g\w*ProtocolGuid)')
    for base, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d not in ('.git', 'Build')]
        for name in files:
            if not name.endswith('.c'):
                continue
            try:
                with open(os.path.join(base, name), 'rb') as handle:
                    used.update(m.decode() for m in token.findall(handle.read()))
            except OSError:
                continue
    return used


def main():
    parser = argparse.ArgumentParser(
        description='Generate one firness input file per UEFI protocol found in the source')
    parser.add_argument('-s', '--src', type=str, required=True,
                        help='edk2 source root')
    parser.add_argument('-o', '--output', type=str, required=True,
                        help='Directory to write the input files into')
    parser.add_argument('-m', '--min-methods', type=int, default=3,
                        help='Skip protocols with fewer callable methods than this')
    parser.add_argument('--packages', nargs='*', default=None,
                        help='restrict the scan to these packages (default: the whole '
                             'tree). A protocol declared by a package the platform does '
                             'not build cannot be installed by the firmware under test, '
                             'so a campaign against it spends its budget proving that.')
    parser.add_argument('--any-protocol', action='store_true',
                        help='keep protocols no source file in the tree calls; they have '
                             'no call sites for firness to learn a harness from')
    parser.add_argument('--bench', action='store_true',
                        help='also emit the SanBench benchmark protocols, which are '
                             'only installed when the firmware was built with '
                             '-D SAN_BENCH')
    parser.add_argument('-n', '--limit', type=int, default=0,
                        help='Stop after this many protocols (0 = no limit)')
    args = parser.parse_args()

    # Every Include/Protocol directory in the tree, not a list of five packages. A branch
    # that adds a package -- or a protocol under OvmfPkg, UefiCpuPkg or CryptoPkg, none of
    # which was named -- had it silently left out of the run, and the report then says
    # nothing was found there rather than that nothing was looked for.
    scan = ([os.path.join(args.src, p) for p in args.packages]
            if args.packages else [args.src])
    roots = []
    for top in scan:
        for base, dirs, _ in os.walk(top):
            dirs[:] = [d for d in dirs if d not in ('.git', 'Build', 'BaseTools')]
            if os.path.basename(base) == 'Protocol' and \
                    os.path.basename(os.path.dirname(base)) == 'Include':
                roots.append(base)
    roots = sorted(set(roots))
    print(f'Scanning {len(roots)} Include/Protocol director(ies)')
    protocols = scan_roots(roots, NOT_TARGETS - (BENCH_TARGETS if args.bench else set()))
    print(f'Found {len(protocols)} protocol(s) with callable methods')
    # Second pass, over install call sites, for the ones whose headers do not follow the
    # conventions the first pass needs. Header-derived entries win: they are the
    # conventional spelling and tend to carry the fuller member list.
    installed = scan_installations(args.src)
    added = {g: v for g, v in installed.items() if g not in protocols}
    if added:
        print(f'{len(added)} more from install call sites, whose headers the scan above '
              f'cannot match: ' + ', '.join(sorted(added)[:6])
              + (' ...' if len(added) > 6 else ''))
        protocols.update(added)
    if not args.any_protocol:
        used = consumed_guids(args.src)
        keep = {g: v for g, v in protocols.items() if g in used}
        dropped = len(protocols) - len(keep)
        if dropped:
            print(f'{dropped} of them are declared but never called in this tree; '
                  f'pass --any-protocol to generate inputs for those too')
        protocols = keep
    write_inputs(protocols, args.output, args.min_methods, args.limit)


if __name__ == '__main__':
    main()
