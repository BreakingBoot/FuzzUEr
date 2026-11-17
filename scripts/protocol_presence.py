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

What each status claims, since only 'absent' and 'smm-only' are skipped and the rest cost a
campaign each:

  present             a real interface for it, or for the service binding the harness
                      creates a child on, is on an install line of this firmware's boot
  absent              neither is, so nothing in this firmware installs it -- including the
                      drivers nothing connected a controller for, which is measured in the
                      binding arm of main() rather than assumed
  smm-only            installed inside SMRAM, where gBS->LocateProtocol cannot reach it
  signal-only         in the DXE database with a NULL interface, which LocateProtocol
                      returns EFI_SUCCESS for; see null_interfaces()
  present-unverified  installed, and this capture does not say with what, so a NULL
                      install cannot be ruled out
  unknown             the GUID could not be resolved at all
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
# (?<!Smm) because the SMM core's line is `SmmInstallProtocolInterface:` and CONTAINS the
# DXE spelling, so an unanchored pattern counts an interface installed inside SMRAM as one
# a DXE harness can locate. It cannot: gBS->LocateProtocol searches the DXE handle database
# and an MM protocol was never put there. On the 138-target sweep 43454245046 that made ten
# protocols -- EdkiiSmmCpuRendezvous, EdkiiSmmMemoryAttribute, EfiMmCpu, EfiMmCpuIo and the
# rest -- read as `present`, so each was scheduled as a DXE campaign that booted, fuzzed
# thousands of inputs with every one of them returning at the LocateProtocol early exit,
# and then reported as a boot failure. The two spellings are counted apart here and the
# census says which side a protocol is on.
GUID_TAIL = r'([0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12})'
INSTALLED = re.compile(r'(?<!Smm)(?<!Mm)InstallProtocolInterface:\s*' + GUID_TAIL)
IN_SMRAM = re.compile(r'(?:Smm|Mm)InstallProtocolInterface:\s*' + GUID_TAIL)
# Anchored to end of line so the pointer it captures is the interface the DXE core
# installed and not the first hex run of whatever follows on a wrapped line. See
# null_interfaces() for what the second field decides.
WITH_INTERFACE = re.compile(r'(?<!Smm)(?<!Mm)InstallProtocolInterface:\s*' + GUID_TAIL
                            + r'\s+([0-9A-Fa-f]+)[ \t\r]*$', re.M)
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
    """(installed in DXE, installed only inside SMRAM) -- the two are different channels.

    A protocol on BOTH is reported present: the DXE handle has it and the harness can call
    it. One seen only in SMRAM is reachable through the SMI harness and through nothing a
    protocol campaign can do.
    """
    text = open(capture, errors='ignore').read().replace('\x00', '')
    dxe = {g.upper() for g in INSTALLED.findall(text)}
    return dxe, {g.upper() for g in IN_SMRAM.findall(text)} - dxe


def null_interfaces(capture):
    """(installed as NULL, installed with no pointer recorded, every SMRAM install).

    The DXE core's line is `DEBUG ((DEBUG_INFO, "InstallProtocolInterface: %g %p\\n",
    Protocol, Interface))` -- MdeModulePkg/Core/Dxe/Hand/Handle.c:349 -- so the capture
    records the interface POINTER as well as the GUID, and the census read only the GUID.
    A GUID whose every DXE install line carried pointer 0 is in the handle database
    without an interface behind it, which is a readiness signal rather than something a
    harness can call: gBS->LocateProtocol returns EFI_SUCCESS, the harness checks only
    EFI_ERROR(Status) and dereferences NULL on the next line.
    MdeModulePkg/Universal/Variable/RuntimeDxe/VariableTraditionalMm.c's
    VariableNotifySmmReady() installs gEfiSmmVariableProtocolGuid exactly this way, with
    EFI_NATIVE_INTERFACE and NULL, while the interface that works lives in SMRAM. On
    capture 43454245046 that GUID is on one DXE install line, pointer 0, and the SMM core
    installed the real one -- so this is what makes it read smm-only instead of present.
    22 GUIDs in that capture and 15 in each of sweep 43704163314's four are installed only
    as NULL; gEfiConsoleOutDeviceGuid, gEfiVariableArchProtocolGuid and gLockBox are the
    rest of the shape.

    The second set is the census admitting what it cannot see. All 2720 install lines over
    those five captures carry a pointer, but a capture taken with DEBUG_INFO suppressed or
    truncated mid-line carries the GUID alone, and there a NULL interface is
    indistinguishable from a working one -- which is the state every census this project
    has taken was in. Those are reported present-unverified rather than present, because
    asserting presence is the one answer the evidence does not support.
    """
    text = open(capture, errors='ignore').read().replace('\x00', '')
    real, null, said = set(), set(), set()
    for guid, pointer in WITH_INTERFACE.findall(text):
        guid = guid.upper()
        said.add(guid)
        (null if int(pointer, 16) == 0 else real).add(guid)
    unsaid = {g.upper() for g in INSTALLED.findall(text)} - said
    return null - real, unsaid, {g.upper() for g in IN_SMRAM.findall(text)}


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
    present, in_smram = installed_guids(args.capture)
    if not present:
        print(f'Error: {args.capture} has no InstallProtocolInterface lines -- it is not a '
              f'boot capture, so every protocol would look absent.')
        return 1
    signal, unsaid, smram_any = null_interfaces(args.capture)
    # installed_guids() took every DXE install line as a DXE install, so it subtracted the
    # NULL readiness signals from the SMRAM side as well. Putting them back is what lets
    # gEfiSmmVariableProtocolGuid reach the smm-only arm, which is the true answer for it:
    # the DXE line is a signal and the interface is in SMRAM.
    present = present - signal - unsaid
    in_smram = (in_smram | ((signal | unsaid) & smram_any)) - present

    rows = [['protocol', 'guid', 'status']]
    counts = {'present': 0, 'absent': 0, 'unknown': 0, 'smm-only': 0,
              'signal-only': 0, 'present-unverified': 0}
    bindings = []
    unbound = []
    for path in sorted(glob.glob(os.path.join(evalset, '*.txt'))):
        protocol = os.path.basename(path)[:-4]
        guid = guid_for(protocol, names, args.harness_dir)
        binding = binding_guid_for(protocol, names)
        if guid is None and binding is None:
            status = 'unknown'
        elif guid is not None and guid in present:
            status = 'present'
        elif guid is not None and guid in in_smram:
            # Installed, and not where a DXE campaign looks. Not 'absent', which would say
            # the firmware does not have it, and not 'present', which costs a full boot and
            # budget to discover otherwise.
            status = 'smm-only'
        elif guid is not None and guid in signal:
            # In the DXE database with nothing behind it. LocateProtocol SUCCEEDS here and
            # hands the harness NULL, so this is not the early exit an absent protocol
            # produces -- it is a #PF one line later, inside the harness, reported against
            # whatever module the fault lands in. Launched, not skipped: no campaign in
            # either body of evidence has ever requested one of these, so there is no
            # measurement to skip on, and the counterpart measurement does exist for the
            # binding arm below. What would justify skipping is one campaign on a
            # signal-only target showing the NULL dereference; until then the census
            # states the hazard and leaves the choice to whoever reads it.
            status = 'signal-only'
        elif guid is not None and guid in unsaid:
            # Installed, and this capture does not record what the interface was. Not
            # 'present': that is the assertion the evidence does not support.
            status = 'present-unverified'
        elif binding is not None and binding in present:
            # the driver is bound and the harness supplies the CreateChild the boot never
            # needed, so this is reachable even though the child protocol is not installed
            status = 'present'
            guid = guid or binding
            bindings.append(protocol)
        elif guid is None:
            status = 'unknown'
        elif binding is not None:
            # A service binding exists in the TREE and neither it nor the child protocol
            # was seen installed in this capture. The discriminator is the arm above:
            # whether that binding is on an install line of this firmware's own boot. A
            # UEFI_DRIVER binds when something connects its controller, and the install
            # line is how the capture reports that it did.
            #
            # This arm reported 'unknown' -- never skipped -- to protect a real
            # measurement: skipping the upper network stack once cost the four most
            # productive targets in a sweep, EfiHttp, EfiManagedNetwork, EfiTcp6 and
            # EfiTcp4 at 16972, 15566, 8802 and 7643 executions. That case is now caught
            # by the binding arm and does not need this one. On capture 43454245046, where
            # PXE connected the NIC, those four are present there: EfiManagedNetwork,
            # EfiTcp6 and EfiTcp4 by their own child GUID and EfiHttp by
            # gEfiHttpServiceBindingProtocolGuid, and EfiArp, EfiIp6, EfiTcp4, EfiTcp6 and
            # EfiUdp6 each recorded a fuzz-phase finding inside ArpDxe, Ip6Dxe, TcpDxe,
            # TcpDxe and Udp6Dxe -- the call was reached, not just the harness.
            #
            # What is NOT true is the claim that the campaign's own harness connects the
            # controller. Sweep 43704163314 falsifies it on all four refs: this arm
            # selects exactly 23 protocols there, every one of them launched, and every
            # one of the 23 printed "LocateProtocol never succeeded" -- 41778, 36593,
            # 41446 and 40371 iterations per ref of harness startup and nothing else,
            # about a fifth of the launched set. Not one member of the arm was productive
            # on any ref. So this is 'absent' on the firmware's own evidence, and the
            # protected case keeps its answer because the evidence for it is also the
            # firmware's own.
            status = 'absent'
            unbound.append(protocol)
        else:
            status = 'absent'
        counts[status] += 1
        rows.append([protocol, guid or '', status])

    print(f'{len(present)} protocols installed by this firmware'
          + (f', and {len(in_smram)} more only inside SMRAM' if in_smram else '')
          + (f'; {len(signal)} more are in the DXE database as a NULL readiness signal'
             if signal else '')
          + (f'; {len(unsaid)} more with no interface recorded' if unsaid else ''))
    print(f'  present: {counts["present"]}   absent: {counts["absent"]}   '
          f'unresolved guid: {counts["unknown"]}'
          + (f'   smm-only: {counts["smm-only"]}' if counts['smm-only'] else '')
          + (f'   signal-only: {counts["signal-only"]}' if counts['signal-only'] else '')
          + (f'   present-unverified: {counts["present-unverified"]}'
             if counts['present-unverified'] else ''))
    if counts['smm-only']:
        print(f'  {counts["smm-only"]} protocol(s) are installed inside SMRAM only, so '
              f'gBS->LocateProtocol cannot find them and a protocol campaign on one fuzzes '
              f'its own early exit. They are reachable through the SMI harness (--smi).')
    if counts['signal-only']:
        print(f'  {counts["signal-only"]} protocol(s) are installed with a NULL interface, '
              f'so LocateProtocol SUCCEEDS and hands the harness nothing to call. These '
              f'are not skipped; no campaign has ever requested one.')
    if counts['present-unverified']:
        print(f'  {counts["present-unverified"]} protocol(s) are installed and this '
              f'capture does not record the interface, so a NULL install cannot be ruled '
              f'out. Take a capture with DEBUG_INFO on the DXE core to decide them.')
    if bindings:
        print(f'  {len(bindings)} present via a service binding the harness creates a '
              f'child on: {", ".join(bindings)}')
    if unbound:
        print(f'  {len(unbound)} absent because nothing connected their controller in this '
              f'boot, so neither the child protocol nor its service binding was installed: '
              f'{", ".join(unbound)}')
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
