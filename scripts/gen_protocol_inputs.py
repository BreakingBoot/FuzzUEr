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
    members = []
    for guid in guids:
        members = struct_members(src, guid, fptypes)
        if members:
            guids = [guid] + [g for g in guids if g != guid]
            break
    if not members:
        # no block matched the guid name, so fall back to every function-pointer member in
        # the header rather than dropping the protocol entirely
        for line in src.splitlines():
            m = MEMBER_RE.match(line)
            if m and m.group(1) in fptypes and m.group(2) not in members:
                members.append(m.group(2))
    if not members:
        return None
    return guids[0], members


def scan_roots(roots):
    protocols = {}
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            for name in sorted(files):
                if not name.endswith('.h'):
                    continue
                hit = scan_header(os.path.join(dirpath, name))
                if hit:
                    guid, members = hit
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


def main():
    parser = argparse.ArgumentParser(
        description='Generate one firness input file per UEFI protocol found in the source')
    parser.add_argument('-s', '--src', type=str, required=True,
                        help='edk2 source root')
    parser.add_argument('-o', '--output', type=str, required=True,
                        help='Directory to write the input files into')
    parser.add_argument('-m', '--min-methods', type=int, default=3,
                        help='Skip protocols with fewer callable methods than this')
    parser.add_argument('-n', '--limit', type=int, default=0,
                        help='Stop after this many protocols (0 = no limit)')
    args = parser.parse_args()

    roots = [os.path.join(args.src, p, 'Include', 'Protocol')
             for p in ('MdePkg', 'MdeModulePkg', 'NetworkPkg', 'ShellPkg', 'SecurityPkg')]
    protocols = scan_roots(roots)
    print(f'Found {len(protocols)} protocol(s) with callable methods')
    write_inputs(protocols, args.output, args.min_methods, args.limit)


if __name__ == '__main__':
    main()
