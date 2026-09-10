"""Which protocols does this firmware actually install?

A campaign whose protocol is absent does nothing at all: the harness's opening
LocateProtocol fails, every Fuzz* function returns immediately, and the run still costs a
full boot plus its whole fuzzing budget. Measured on matrix v8, 65 of 142 protocols are
never installed, and the split is total -- absent protocols score 402-667 edges (median
448, all of it harness startup) while present ones score 1191-27241 (median 5918). No
overlap, so this is not a threshold judgement call.

Presence is a property of the firmware, not of a protocol, so the census is taken once from
any boot capture of that firmware and reused for every campaign against it.

  scripts/protocol_presence.py --capture <fuzz.txt> [--out presence.csv]

A protocol name maps to its GUID by edk2's own convention (EfiBlockIo ->
gEfiBlockIoProtocolGuid), resolved against every .dec in the tree: 138 of 142 resolve that
way. The four that do not -- ShellPaths, HiiConfig, HiiStack, TcpStack -- are multi-protocol
targets with no single GUID, and are reported "unknown" so they are never skipped.
"""
import argparse
import csv
import glob
import os
import re
import sys

GUID_DECL = re.compile(
    r'(g\w+Guid)\s*=\s*\{\s*(0x[0-9a-fA-F]+)\s*,\s*(0x[0-9a-fA-F]+)\s*,'
    r'\s*(0x[0-9a-fA-F]+)\s*,\s*\{([^}]*)\}')
INSTALLED = re.compile(r'InstallProtocolInterface:\s*([0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12})')
# the harness names the guid it locates, which beats the naming convention when available
LOCATED = re.compile(r'LocateProtocol\(&(g\w+Guid)')


def guid_map(root):
    """Every GUID the tree declares, by symbol name."""
    found = {}
    for dec in glob.glob(os.path.join(root, 'edk2*', '**', '*.dec'), recursive=True):
        try:
            text = open(dec, errors='ignore').read()
        except OSError:
            continue
        for match in GUID_DECL.finditer(text):
            name, a, b, c, rest = match.groups()
            tail = re.findall(r'0x[0-9a-fA-F]+', rest)
            if len(tail) != 8:
                continue
            found.setdefault(name, '{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{}'.format(
                int(a, 16), int(b, 16), int(c, 16), int(tail[0], 16), int(tail[1], 16),
                ''.join('{:02X}'.format(int(x, 16)) for x in tail[2:])))
    return found


def guid_for(protocol, names, harness_dir=None):
    """The GUID this protocol's harness would locate, or None if it cannot be resolved."""
    if harness_dir:
        source = os.path.join(harness_dir, protocol, 'Firness', 'FirnessHarnesses.c')
        if os.path.isfile(source):
            located = LOCATED.findall(open(source, errors='ignore').read())
            for name in located:
                if name in names:
                    return names[name]
    for candidate in (f'g{protocol}ProtocolGuid', f'g{protocol}Guid'):
        if candidate in names:
            return names[candidate]
    return None


def binding_guid_for(protocol, names):
    """The service binding GUID for a protocol that is reached by creating a child.

    EFI_TCP4_PROTOCOL is never installed by its driver: TcpDxe installs
    EFI_TCP4_SERVICE_BINDING_PROTOCOL, and the child protocol appears only when a consumer
    calls CreateChild. On OVMF nothing did, so a census looking for the child GUID called
    TCP4 absent on firmware that has a fully bound TcpDxe -- while UDP4 looked present
    only because PXE happened to create five children. The harness creates its own child,
    so the binding is what decides whether the protocol can be fuzzed.
    """
    for candidate in (f'g{protocol}ServiceBindingProtocolGuid',
                      f'g{protocol}ServiceBindingGuid'):
        if candidate in names:
            return names[candidate]
    return None


def installed_guids(capture):
    text = open(capture, errors='ignore').read().replace('\x00', '')
    return {g.upper() for g in INSTALLED.findall(text)}


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--capture', required=True,
                        help='a serial capture (fuzz.txt) from a boot of the firmware to census')
    parser.add_argument('--root', default=os.path.join(os.path.dirname(__file__), '..', 'eval_source'),
                        help='tree holding edk2/edk2-platforms (default: ../eval_source)')
    parser.add_argument('--evalset', default=None,
                        help='directory of <protocol>.txt request files (default: <root>/evalset)')
    parser.add_argument('--harness-dir', default=None,
                        help='a previous run directory, to read each harness for the guid it '
                             'locates instead of relying on the naming convention')
    parser.add_argument('--out', default=None, help='write the census here as csv')
    parser.add_argument('--against', default=None,
                        help='a census csv from the other backend; report what each '
                             'firmware has that the other does not')
    parser.add_argument('--matched', default=None,
                        help='with --against, write the protocols present on both, one '
                             'per line, to drive both matrices from the same set')
    args = parser.parse_args()

    root = os.path.abspath(args.root)
    evalset = args.evalset or os.path.join(root, 'evalset')
    if not os.path.isfile(args.capture):
        print(f'Error: no capture at {args.capture}')
        return 1

    names = guid_map(root)
    present = installed_guids(args.capture)
    if not present:
        print(f'Error: {args.capture} has no InstallProtocolInterface lines -- it is not a '
              f'boot capture, so every protocol would look absent.')
        return 1

    rows = [['protocol', 'guid', 'status']]
    counts = {'present': 0, 'absent': 0, 'unknown': 0}
    bindings = []
    for path in sorted(glob.glob(os.path.join(evalset, '*.txt'))):
        protocol = os.path.basename(path)[:-4]
        guid = guid_for(protocol, names, args.harness_dir)
        binding = binding_guid_for(protocol, names)
        if guid is None and binding is None:
            status = 'unknown'
        elif guid is not None and guid in present:
            status = 'present'
        elif binding is not None and binding in present:
            # the driver is bound and the harness supplies the CreateChild the boot never
            # needed, so this is reachable even though the child protocol is not installed
            status = 'present'
            guid = guid or binding
            bindings.append(protocol)
        elif guid is None:
            status = 'unknown'
        else:
            status = 'absent'
        counts[status] += 1
        rows.append([protocol, guid or '', status])

    print(f'{len(present)} protocols installed by this firmware')
    print(f'  present: {counts["present"]}   absent: {counts["absent"]}   '
          f'unresolved guid: {counts["unknown"]}')
    if bindings:
        print(f'  {len(bindings)} present via a service binding the harness creates a '
              f'child on: {", ".join(bindings)}')
    if counts['absent']:
        print('  absent campaigns cost a full boot and budget to produce only harness '
              'startup coverage')
    if args.out:
        with open(args.out, 'w', newline='') as handle:
            csv.writer(handle).writerows(rows)
        print(f'  wrote {args.out}')

    if args.against:
        compare(rows, args.against, args.matched)
    return 0


def compare(rows, other_path, matched_path=None):
    """What each firmware installs that the other does not.

    Two backends running different protocol sets are not two measurements of the same
    thing, and the difference does not announce itself: an absent protocol produces a
    campaign that boots, runs its whole budget and reports coverage, so a matrix compares
    as though both sides tested it. The intersection is the only set where a difference in
    findings is a difference in the backends.
    """
    mine = {row[0]: row[2] for row in rows[1:]}
    with open(other_path, newline='') as handle:
        theirs = {row['protocol']: row['status'] for row in csv.DictReader(handle)}
    names = sorted(set(mine) | set(theirs))
    both = [n for n in names if mine.get(n) == 'present' and theirs.get(n) == 'present']
    only_mine = [n for n in names if mine.get(n) == 'present' and theirs.get(n) != 'present']
    only_theirs = [n for n in names if theirs.get(n) == 'present' and mine.get(n) != 'present']
    label = os.path.basename(other_path)
    print(f'\n  present on both        : {len(both)}')
    print(f'  only this firmware     : {len(only_mine)}'
          + (f'  ({", ".join(only_mine)})' if only_mine else ''))
    print(f'  only {label:18}: {len(only_theirs)}'
          + (f'  ({", ".join(only_theirs)})' if only_theirs else ''))
    if matched_path:
        with open(matched_path, 'w') as handle:
            handle.write('\n'.join(both) + '\n')
        print(f'  wrote {matched_path} -- run both matrices from this set')


if __name__ == '__main__':
    sys.exit(main())
