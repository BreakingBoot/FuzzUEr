import os
import re
import argparse


# a protocol header declares its GUID as
#     extern EFI_GUID  gEfiBlockIoProtocolGuid;
# and its callable surface as struct members whose type is a function-pointer typedef:
#     typedef EFI_STATUS (EFIAPI *EFI_BLOCK_READ)(...);
#     ...
#     EFI_BLOCK_READ  ReadBlocks;
# that pair is all firness needs to build a target list. the typedef is not always in the
# same file as the member -- see INCLUDE_DEPTH below
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


def struct_blocks(src):
    """{normalized struct name: [(member type, member name)]} for one header.

    Every member MEMBER_RE matches, not only the function-pointer ones, because a member
    whose type is another struct is the way into the nested surface below. A struct is
    registered under the name at its opening and the name at its closing, first
    registration winning, which is how a header that spells the protocol
    `struct _EFI_X_PROTOCOL {` and one that spells it `} EFI_X_PROTOCOL;` both resolve.
    """
    found, depth, opened_as, current = {}, 0, None, []
    for line in src.splitlines():
        opening = STRUCT_OPEN_RE.match(line)
        if opening and depth == 0:
            depth, opened_as, current = 1, opening.group(1), []
            continue
        if not depth:
            continue
        closing = STRUCT_END_RE.match(line)
        if closing:
            for name in (opened_as, closing.group(1)):
                if name and current:
                    found.setdefault(normalize(name), list(current))
            depth, opened_as, current = 0, None, []
            continue
        member = MEMBER_RE.match(line)
        if member:
            current.append((member.group(1), member.group(2)))
    return found


# A protocol's callable surface is not always flat, and when it is not, every member below
# the top level used to be dropped without a word. EFI_PCI_IO_PROTOCOL has no Read and no
# Write: it has Mem, Io and Pci, each a by-value struct holding a Read and a Write, so the
# member is reached as ProtocolVariable->Mem.Read. Measured over the request files the
# script emits for the EVAL-1 tree: 8 members across 4 protocols -- EFI_PCI_IO_PROTOCOL,
# EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL, EFI_DEVICE_IO_PROTOCOL and EFI_ISA_IO_PROTOCOL -- and
# 22 distinct (Width, Address, Count, Buffer) access paths, never requested, so never
# harnessed and never fuzzed. That is the shape memory-safety findings have already come
# out of on EFI_CPU_IO2_PROTOCOL, which only escaped because its struct has no direct
# function-pointer member at all and so fell through to the whole-header fallback below.
#
# The spelling is the LEAF name, `gEfiPciIoProtocolGuid:Read`, not `Mem.Read`. That is not
# a choice: it is the one convention already in use end to end. firness's load_functions()
# splits a request line on the colon and compares the right-hand side to the callee name
# the analysis recorded, and a call site writes mCpuIo->Mem.Read(...), which the analysis
# records as the leaf "Read" (call-database.json for the EfiCpuIo2 campaign of run
# 43454245046: "Function": "Read"). The access path is then recovered by the generator's
# own protocol_member_paths(), which walks the struct and emits every path to that leaf --
# `case 0: ProtocolVariable->Mem.Read; case 1: ProtocolVariable->Io.Read;` in that
# campaign's FirnessHarnesses.c. A dotted request line would reach harness_match() as the
# function name "Mem.Read", match no callee, and silently drop the member instead.
#
# Three things bound the walk, and all three have to be there:
#   * NEST_DEPTH, set to the same 3 the generator's protocol_member_paths() uses. A member
#     deeper than the generator can resolve is a member the harness cannot call, so
#     requesting it only buys a dropped target.
#   * the `seen` set of structs already on the path, so a struct that reaches itself --
#     directly or through a cycle of two -- terminates inside the depth budget rather than
#     spending it.
#   * MEMBER_RE, which matches `TYPE NAME;` and nothing else. A pointer member is written
#     `TYPE *NAME;` and never matches, so an opaque or self-referential pointer is never
#     walked into; and struct_blocks() indexes `struct` bodies only, so a union member
#     resolves to nothing and is skipped. This is the same rule the generator applies --
#     it descends only into members held by value, because a pointer member is a separate
#     object the protocol is entitled to leave NULL.
NEST_DEPTH = 3


def expand_members(members, blocks, fptypes, depth=NEST_DEPTH, seen=()):
    """Leaf function-pointer member names, in declaration order, deduped."""
    out = []
    for kind, name in members:
        if kind in fptypes:
            if name not in out:
                out.append(name)
            continue
        key = normalize(kind)
        if depth <= 0 or key in seen or key not in blocks:
            continue
        for leaf in expand_members(blocks[key], blocks, fptypes,
                                   depth - 1, tuple(seen) + (key,)):
            if leaf not in out:
                out.append(leaf)
    return out


# members declared inside the protocol's own struct, at any depth. a header also declares
# config and packet structs whose members are function pointers too, and those are not
# callable entry points -- EFI_DHCP4_CONFIG_DATA.Dhcp4Callback is a callback, not a
# protocol method -- so the walk starts at the struct the guid names and goes no wider
def struct_members(src, guid, fptypes):
    blocks = struct_blocks(src)
    want = guid_struct_key(guid)
    # the protocol's own struct goes into `seen` before the walk starts, so a struct that
    # reaches itself is refused at the first step rather than one level in
    return expand_members(blocks.get(want, []), blocks, fptypes, seen=(want,))


# ---------------------------------------------------------------------------------------
# The function-pointer typedefs a protocol's members name are not always declared in the
# protocol's own header. scan_header() built its fptypes set from the one file it had open,
# so a member typed from an #include was not recognised as callable, and was therefore not
# requested, not harnessed and not fuzzed, with nothing in any log saying so.
#
# Measured over the request files this script emits, before vs after, on three trees
# (eval1_edk2 271 files / 1315 member lines, edk2-master 274, eval_source/edk2 268): the
# same 11 members across the same 2 protocols on all three.
#
#   EFI_EAP_MANAGEMENT2_PROTOCOL asked for GetKey and nothing else, 1 of 9. The other 8 --
#   GetSystemConfiguration, SetSystemConfiguration, InitializePort, UserLogon, UserLogoff,
#   GetSupplicantStatus, SetSupplicantConfiguration, GetSupplicantStatistics -- are typed
#   by EFI_EAP_* typedefs that EapManagement2.h takes from <Protocol/EapManagement.h>.
#   EDKII_FORM_BROWSER_EXTENSION2_PROTOCOL asked for 3 of 6; SetScope, RegisterHotKey and
#   RegiserExitHandler are typed from <Protocol/FormBrowserEx.h>.
#
# Both are one edk2 idiom -- the second revision of a protocol includes the first and
# re-uses its typedefs -- so this is a shape, not two odd headers.
#
# INCLUDE_DEPTH bounds the walk, and the bound is chosen from the measurement: every
# member the hole hid on all three trees resolves at depth 1, because the typedef sits in
# the header the protocol header includes DIRECTLY. Depth 2 is that plus one hop, for a
# header that reaches a shared typedef through an intermediate. It is a cap and not the
# full closure because the closure keeps growing without buying anything -- SmmVarCheck.h
# reaches 2 headers at depth 1, 11 at depth 3 and 23 unbounded, and the gain past depth 1
# is measured at zero on all three trees, while every extra name is one the member walk
# might reclassify. Cost over the 353 protocol headers of eval1_edk2: 539 header reads at
# depth 1, 668 at depth 2, 1220 unbounded, each file parsed once (header_facts memoises).
# Measured, five runs each: scan_roots -- the only pass this touches -- goes from 149 ms
# to 341 ms, of which 81 ms is building the include index; the whole generator goes from
# 3.15 s to 3.11 s, which is to say the difference does not show against the full-tree
# walks struct_index() and consumed_guids() already do.
#
# Two things are deliberately NOT widened.
#
#   * Which GUIDs scan_header reports. Every branch below is still decided by the typedefs
#     declared IN the header: a header with none of its own is still not a protocol
#     header, a GUID that owned no struct under the local set still owns none, and the
#     whole-header fallback still runs exactly when it ran before. Only the member lists
#     are resolved wider. That is not caution for its own sake -- with the decision
#     widened too, gEdkiiSmmVarCheckProtocolGuid becomes a request file on every tree,
#     because SmmVarCheck.h declares a GUID and a three-member struct and not one typedef
#     of its own. Discovering a protocol is a separate question from which members an
#     existing target asks for, and a protocol nobody chose costs a container, an
#     analysis, a build and a whole boot budget. This is the second question, as the
#     nested-member fix was.
#   * structs_in() and the install-site pass it feeds, for that same reason one level
#     down: that index is what scan_installations() recognises a struct by, so widening it
#     adds protocols. It is untouched, and so is every member list it produces.
#
# One caveat, measured rather than argued. --min-methods counts members, and a member list
# that grows can cross it: at -m 1, which fuzz_edk2.py, fuzz_batch.py and
# workflow_local.sh all pass, the set of request FILES is identical before and after on
# all three trees; at -m 2 or the argparse default of 3, EfiEapManagement2.txt appears,
# because 1 member was under the floor and 9 is over it. Nothing calls the generator that
# way, and a protocol with nine methods is not one -m 3 meant to exclude, but it is a
# change to the set under a flag and is written down here rather than left to be found.
#
# Finally, a resolved name that collides with a struct defined in this header is dropped,
# so a typedef declared elsewhere cannot reclassify a by-value sub-struct as a function
# pointer and undo the nested walk above -- the two fixes have to compose.
INCLUDE_DEPTH = 2

INCLUDE_RE = re.compile(r'^[ \t]*#[ \t]*include[ \t]*[<"]([^>"]+)[>"]', re.M)

# ---------------------------------------------------------------------------------------
# The third hole in the same family, and the first one that changes WHICH protocols get a
# request rather than which members an existing request asks for.
#
# scan_header's opening gate -- `fptypes = set(FPTYPE_RE.findall(src))`, then
# `if not fptypes: return None` -- reads "a header that declares no function-pointer
# typedef of its own is not a protocol header". For a protocol whose members are ENTIRELY
# typed from an included header that is simply false, and the consequence is total: no
# request file, no campaign, and nothing anywhere saying the protocol was skipped. The
# worked example is gEdkiiSmmVarCheckProtocolGuid. MdeModulePkg/Include/Protocol/
# SmmVarCheck.h declares the GUID, declares `struct _EDKII_SMM_VAR_CHECK_PROTOCOL` with
# three members, and declares not one typedef: all three are EDKII_VAR_CHECK_* taken from
# <Protocol/VarCheck.h>. It is installed at MdeModulePkg/Universal/Variable/RuntimeDxe/
# VariableSmm.c:1180.
#
# Measured, rather than assumed. Every protocol GUID the tree declares extern or installs
# at an Install*ProtocolInterface call, against the request files the generator emits
# (-m 1), on three trees -- eval1_edk2 390 GUIDs / 271 files / 119 with none, edk2-master
# 395 / 274 / 121, eval_source/edk2 388 / 268 / 120. Six reasons, and this gate is the
# largest single one at 69 on all three. But 69 is not the size of the hole: of those 69,
# exactly THREE have any callable member at all, even when the typedef set is widened to
# every function-pointer typedef in the tree -- gEdkiiSmmVarCheckProtocolGuid (3 members),
# gEfiSmmVariableProtocolGuid (4) and gEfiLoadedImageProtocolGuid (1). The other 66 split
# 56 that name no struct in their header at all and 10 whose struct is data only, and are
# GUID-only signal protocols (gEfiSmmReadyToLockProtocolGuid, gEdkiiSmmLegacyBootProtocol-
# Guid), architectural protocols installed with a NULL interface (gEfiResetArchProtocol-
# Guid, gEfiRuntimeArchProtocolGuid), data-only structs (gEfiEdidActiveProtocolGuid,
# gEfiPartitionInfoProtocolGuid, gXenIoProtocolGuid) and typedef aliases whose struct
# lives in another header (gEfiSmmCpuIo2ProtocolGuid is EFI_MM_CPU_IO_PROTOCOL from
# <Protocol/MmCpuIo.h>). None of them is hidden by the typedef scope, so none of them is
# this fix's business.
#
# Of the three, only one is admitted, and the other two are refused on measured grounds
# rather than on the depth bound:
#
#   * gEfiSmmVariableProtocolGuid is typed by EFI_GET_VARIABLE, EFI_SET_VARIABLE,
#     EFI_GET_NEXT_VARIABLE_NAME and EFI_QUERY_VARIABLE_INFO from Uefi/UefiSpec.h, which
#     SmmVariable.h does not include -- it includes nothing at all, because every edk2
#     source file has UefiSpec.h in scope through Uefi.h. So no include closure reaches it
#     at any depth and only a tree-wide typedef set does. That is a good thing, because a
#     DXE request for it is a trap: VariableTraditionalMm.c's VariableNotifySmmReady()
#     installs the GUID into the DXE handle database with a NULL interface as a readiness
#     signal, and the real interface goes in by gMmst->MmInstallProtocolInterface, inside
#     SMRAM. The harness does LocateProtocol, gets EFI_SUCCESS and a NULL pointer, and the
#     next line is ProtocolVariable->SmmGetVariable(...). The presence census cannot save
#     it either: it reads the DXE InstallProtocolInterface line and reports `present`.
#   * gEfiLoadedImageProtocolGuid has one callable member, Unload, typed EFI_IMAGE_UNLOAD
#     from the same UefiSpec.h and equally unreachable by include. It is also optional by
#     spec and NULL on the image DxeCore installs first, so the same NULL call follows.
#
# So the gate change is the narrowest shape available: it runs ONLY for a header whose
# local typedef set is empty -- the one case the old code refused outright -- and it
# admits ONLY a GUID that owns a struct in that header by guid_struct_key. Everything
# else stays exactly as it was:
#
#   * A header with no `extern EFI_GUID g<Name>ProtocolGuid;` is still not a protocol
#     header; that gate is above this one and untouched.
#   * A header with ANY local typedef takes the old path, decided on the local set, so
#     e6dd94c6's "gate narrow, list wide" rule still holds everywhere it ever applied and
#     every existing request file is unchanged by construction, not by measurement.
#   * A GUID that owns no struct in the header is still refused. That is what keeps the 66
#     out, and it is load-bearing: the whole-header fallback is NOT reachable from the new
#     path, so a callback inside a config struct is still never requested.
#     gEfiRuntimeArchProtocolGuid is the proof. Runtime.h has no local typedef, so it
#     takes the new path; EFI_RUNTIME_EVENT_ENTRY.NotifyFunction is EFI_EVENT_NOTIFY and
#     IS a function-pointer typedef under a wide set; and the protocol still gets no
#     request, because the GUID owns no struct and the fallback never runs.
#   * consumed_guids() still drops a protocol no .c in the tree mentions (12 on eval1, 17
#     on edk2-master), and scan_installations() still excludes a NULL interface.
#
# Measured effect on the request-file set, -m 1, all three trees: exactly one file added,
# EdkiiSmmVarCheck.txt, with its three members; no file removed and every other file byte
# identical. With ADMIT_RESOLVED_ONLY False the output is `diff -r` identical to before on
# all three trees.
#
# Unlike the previous two fixes, the set DOES change under every --min-methods: the new
# file has 3 members, so it appears at -m 1, -m 2 and the argparse default of 3. That is
# the point of the change rather than a side effect of it, and is written down here
# because de728582 recorded the opposite property for the member-list widening.
#
# What the request file buys today, and what it does not. firness builds a target either
# from a call site or, failing that, from the protocol's own header -- and
# data_analysis/analyze.py's protocol_member_params() reads only the member's own header,
# so an include-typed member returns None and is dropped. Run offline against the
# EdkiiVarCheck campaign of sweep 43454245046 (same tree, same databases, same command,
# only the request file swapped): the DXE sibling EdkiiVarCheck.txt gives "Total
# Functions: 3" and rc 0, while EdkiiSmmVarCheck.txt gives three "was not able to be
# harnessed" warnings, "Total Functions: 0" and the ValueError fuzz_edk2.py already
# classifies as NO_CALL_SITES -- named, and explicitly not a failure. With
# protocol_member_params() resolving the include in a scratch copy, the same command emits
# FuzzSmmRegisterSetVariableCheckHandler, FuzzSmmVariablePropertySet and
# FuzzSmmVariablePropertyGet: 3 of 3. The request file is the prerequisite and the only
# part of it that lives here; that fix is firness's. Landing this first costs nothing,
# because the protocol is installed only by gMmst->MmInstallProtocolInterface and the
# presence census marks it smm-only, which fuzz_batch skips by name into skipped.csv --
# which is the whole complaint being answered, a protocol that says it was skipped instead
# of one nobody can see.
ADMIT_RESOLVED_ONLY = True

# path -> (the function-pointer typedefs declared there, the paths it includes)
_HEADER_FACTS = {}


def include_index(roots):
    """{the path an #include spells: the file on disk} for the Include trees in scope.

    Keyed the way a header spells it -- `Protocol/EapManagement.h` -- which is the path
    relative to the package's Include directory, so the index is built from the Include
    ancestors of the Protocol directories the scan was already given rather than from
    another walk of the tree. A root that is not under an Include directory contributes
    nothing, and resolution then falls back to the including header's own directory, which
    is also what a quoted include means.
    """
    index = {}
    for root in sorted({os.path.dirname(r) for r in roots}):
        if os.path.basename(root) != 'Include':
            continue
        for base, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in ('.git', 'Build')]
            for name in files:
                if not name.endswith('.h'):
                    continue
                rel = os.path.relpath(os.path.join(base, name), root)
                index.setdefault(rel.replace(os.sep, '/'), os.path.join(base, name))
    return index


def header_facts(path):
    """(typedefs declared in `path`, the paths it includes), read and parsed once.

    A header on the closure of two hundred protocol headers would otherwise be re-read
    two hundred times. The typedef set is a frozenset so that a caller unioning it into
    its own set cannot mutate the cached one -- which it does, and which silently made
    every header after the first report the union of all of them.
    """
    if path not in _HEADER_FACTS:
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                src = f.read()
        except OSError:
            src = ''
        _HEADER_FACTS[path] = (frozenset(FPTYPE_RE.findall(src)),
                               tuple(INCLUDE_RE.findall(src)))
    return _HEADER_FACTS[path]


def resolved_fptypes(path, src, includes=None, depth=INCLUDE_DEPTH):
    """The function-pointer typedefs this header declares plus those it includes.

    `seen` carries the headers already resolved, so a pair of headers that include each
    other -- which the include guards make legal and common -- terminates inside the depth
    budget instead of spending it.
    """
    local = set(FPTYPE_RE.findall(src))
    found, seen = set(local), {path}
    frontier = list(INCLUDE_RE.findall(src))
    for _ in range(depth):
        following = []
        for spelled in frontier:
            target = (includes or {}).get(spelled.replace('\\', '/'))
            if not target:
                beside = os.path.join(os.path.dirname(path), spelled)
                target = beside if os.path.isfile(beside) else None
            if not target or target in seen:
                continue
            seen.add(target)
            more, deeper = header_facts(target)
            found |= more
            following += deeper
        frontier = following
        if not frontier:
            break
    # a struct this header defines is a struct, whatever a typedef elsewhere calls that
    # name; otherwise expand_members would take the sub-struct for a function pointer and
    # drop the leaves below it. the local set is never filtered, so with depth 0 this
    # returns exactly what the pre-change scan used
    here = set(struct_blocks(src))
    return local | {name for name in found - local if normalize(name) not in here}


def scan_header(path, includes=None):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        src = f.read()
    guids = GUID_RE.findall(src)
    if not guids:
        return None
    fptypes = set(FPTYPE_RE.findall(src))
    if not fptypes:
        # The header declares no typedef of its own, which used to end the matter. Ask the
        # resolved set instead -- and only this one question, "does a guid here own a
        # struct with callable members": no whole-header fallback, so the admission rule
        # is the narrowest one that takes SmmVarCheck.h and leaves the other 66 out.
        if not ADMIT_RESOLVED_ONLY:
            return None
        admitted, wider = [], resolved_fptypes(path, src, includes)
        for guid in guids:
            members = struct_members(src, guid, wider)
            if not members or guid in [g for g, _ in admitted]:
                continue
            admitted.append((guid, members))
        return admitted or None
    resolved = resolved_fptypes(path, src, includes)
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
        # the gate is the LOCAL typedef set and the list reported is the resolved one, so
        # that widening resolution cannot add a GUID to the result -- only members to one
        # already in it
        if not struct_members(src, guid, fptypes):
            continue
        if guid in [g for g, _ in owned]:
            continue
        owned.append((guid, struct_members(src, guid, resolved)))
    if owned:
        return owned

    # no block matched the guid name, so fall back to every function-pointer member in the
    # header rather than dropping the protocol entirely. same split: whether this header
    # yields a protocol at all is decided by its own typedefs, while the member list is
    # resolved. EDKII_FORM_BROWSER_EXTENSION2_PROTOCOL arrives here -- its struct is named
    # _EDKII_FORM_BROWSER_EXTENSION2_PROTOCOL and its GUID gEdkiiFormBrowserEx2ProtocolGuid,
    # which guid_struct_key cannot match -- and it is 3 of the 11 members measured
    members, local = [], []
    for line in src.splitlines():
        m = MEMBER_RE.match(line)
        if not m:
            continue
        if m.group(1) in resolved and m.group(2) not in members:
            members.append(m.group(2))
        if m.group(1) in fptypes and m.group(2) not in local:
            local.append(m.group(2))
    if not local:
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
# there used to be a TYPEDEF_CLOSE_RE here, matching a closing brace that names the
# struct. STRUCT_END_RE is the same pattern with the name optional, so it matches
# everything that did and reports the same group, and both struct walks now share
# struct_blocks()


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
    """{normalized struct name: [function-pointer members, nested ones included]}."""
    fptypes = set(FPTYPE_RE.findall(src))
    if not fptypes:
        return {}
    blocks = struct_blocks(src)
    found = {}
    for name, members in blocks.items():
        # the gate is the DIRECT members, deliberately, while the list reported is the
        # expanded one. this index is what scan_installations() recognises a struct by at
        # an install call, so a struct whose whole callable surface is nested would become
        # a protocol the header scan never matched and this pass never used to report --
        # an addition to the target set, which is a different question from which members
        # an existing target asks for. the hole being closed here is the second.
        if any(kind in fptypes for kind, _ in members):
            found[name] = expand_members(members, blocks, fptypes)
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
    # built once for the whole scan, from the Include ancestors of these roots, so that a
    # typedef a protocol header includes is resolvable without a second walk of the tree
    includes = include_index(roots)
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            for name in sorted(files):
                if not name.endswith('.h') or name in skip:
                    continue
                hit = scan_header(os.path.join(dirpath, name), includes)
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
