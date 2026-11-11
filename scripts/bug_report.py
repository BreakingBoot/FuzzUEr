"""Turn a campaign's sanitizer reports into a list of bugs.

A matrix produces thousands of report rows and a handful of actual defects. The 2026-09-09
run was 2328 rows, 58 sites and, after triage, zero new firmware bugs -- everything was
either a known site, firmware background, or the harness tripping over an input it had
constructed itself. Doing that triage by hand takes an afternoon and is the step most
likely to be skipped, which is how a solution count gets quoted as a bug count.

This is that step, written down. It does what afl-cmin and the crash-exploration triage do
for a native target, adapted to what a UEFI campaign actually records:

  cluster   reports that differ only by line, or by which protocol provoked them, are one
            bug. Nine adjacent pointer-overflow sites in ExportPackageList are one defect,
            not nine.
  filter    a report attributed to the harness image, to a library linked into the harness
            and never called, or to a known scanner is not a firmware bug.
  rank      what is left is ordered by how much it looks like a memory-safety defect
            rather than a contract violation.

Nothing is dropped silently. Every filtered cluster is printed with the reason, because a
filter that hides a real bug is worse than no filter, and the reasons are the part that
needs review when the firmware changes.

  python3 scripts/bug_report.py -r <matrix dir> [--json out.json] [--show-filtered]
"""

import argparse
import csv
import glob
import json
import os
import re
import subprocess
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import resolve_modules

IP_RE = re.compile(r'ip (0x[0-9A-Fa-f]+)')
ADDR_RE = re.compile(r'address (0x[0-9A-Fa-f]+)')
SIZE_RE = re.compile(r'size (0x[0-9A-Fa-f]+)')
WRITE_RE = re.compile(r'is_write (0x[0-9A-Fa-f]+)')

# Lines within this many of each other, in the same file and the same class, are one bug.
# ExportPackageList raises the identical construct at 3277, 3290, 3303 ... 13 lines apart,
# once per Export*Packages call; they are one defect with one fix.
CLUSTER_WINDOW = 32

# Reports that are the harness, not the firmware. Each entry is (match, reason).
HARNESS_SOURCES = [
    ('FirnessHarnesses', 'generated harness source'),
    ('FirnessHelpers', 'generated harness source'),
    ('FirnessMain', 'generated harness source'),
    ('BootScriptSave', 'S3BootScriptLib is linked into the harness, never called, and '
                       'PcdAcpiS3Enable is FALSE, so its state is never initialised'),
    ('UefiHandleParsingLib', 'shell library linked into the harness'),
]

# Firmware code whose reports are an artefact of how it works, not a defect.
KNOWN_ARTEFACTS = [
    ('PeCoffGetEntryPoint', 'PeCoffSearchImageBase scans memory backwards for the PE '
                            'signature, so reading past an allocation is what it does'),
    ('Mem/Page.c', 'the DXE page allocator walking its own poisoned free lists'),
    ('Mem/Pool.c', 'the DXE pool allocator walking its own poisoned free lists'),
    ('VbeShim', 'QemuVideoDxe writes its int10h shim into reserved low memory on purpose'),
]

# Artefacts that only a class and a site together identify. KNOWN_ARTEFACTS matches a path
# alone, which is too blunt here: a genuine defect in the SMM dispatcher is exactly what an
# SMI campaign is looking for, so "Smi.c is noise" would throw away the finding this is
# meant to surface. Each entry is (class substring, path substring, reason).
CLASS_ARTEFACTS = [
    ('double-fetch', 'PiSmmCore/Smi.c',
     'SmiManage is handed &CommunicateHeader->HeaderGuid, a pointer into the caller\'s '
     'buffer, and CompareGuid re-reads it once per registered handler -- so a boot with '
     '22 handlers registered reports 21 double fetches of the dispatch GUID. The GUID is '
     'only ever compared, and the caller controls which handler it wants anyway, so '
     'nothing is bypassed by changing it mid-walk', None),
    ('double-fetch', 'MdePkg/Library/BasePrintLib/',
     'the second read is inside BasePrintLib, which means a DEBUG statement is printing '
     'untrusted memory that something else already read -- %g formats a GUID as '
     'ReadUnaligned32, ReadUnaligned16 twice and then Data4[0..7] one byte at a time, so '
     'one print of a caller-supplied GUID reports ten double fetches at ten sites. A '
     'print does not decide anything with the value it reads, so re-reading it bypasses '
     'no check; the defect class needs the second read to feed a decision', None),
    # The same SmiManage walk as the first entry, attributed to the library instead of the
    # caller. CompareGuid compares two GUIDs as a pair of UINT64s, so the re-read lands on
    # BaseLib's ReadUnaligned64 and the path is Unaligned.c -- the first entry's
    # PiSmmCore/Smi.c never matches it. It only became visible once the firmware classes
    # stopped sharing the outline handlers' dedup table: before that, the boot reported
    # this very IP as a global-buffer-overflow and every later double fetch at it was
    # dropped as already-seen. Measured on run 42310220335: one cluster, 165616 hits, an
    # 8-byte read at the comm buffer's base, which is the HeaderGuid.
    #
    # Pinned three ways on purpose, because each one alone would hide real findings.
    # BaseLib is linked into everything, so the file is not noise. ReadUnaligned32 and
    # ReadUnaligned16 in the same file are the shape of a caller re-reading a field it
    # validated, which is the real class -- hence the line, which is ReadUnaligned64. And
    # the same site in any other module is that module re-reading untrusted memory for its
    # own reasons, not the dispatcher's handler walk -- hence PiSmmCore.efi.
    #
    # The line number is the brittle part: it moves when MdePkg does. It fails safe. A
    # moved line stops matching, the finding comes back as a candidate, and someone reads
    # it again -- which is the right direction to fail in.
    ('double-fetch', 'MdePkg/Library/BaseLib/Unaligned.c:186',
     'the dispatcher comparing the caller-supplied HeaderGuid against each registered '
     'handler. CompareGuid reads both GUIDs as two UINT64s, so the re-read is reported '
     'against BaseLib ReadUnaligned64 rather than against SmiManage, and the hit count '
     'tracks the number of dispatches. The GUID is only ever compared -- the caller '
     'already chooses which handler it wants -- so changing it mid-walk bypasses no '
     'check', 'PiSmmCore.efi'),
]

# The sanitizer names the handler it entered, not the defect. `__ubsan_handle_type_mismatch_v1`
# covers a null dereference, a misaligned access and an undersized object; grouping all
# three under "ubsan" throws away the distinction that decides whether a finding matters.
# These are the clang runtime's own categories, spelled the way its diagnostics do.
UBSAN_HANDLERS = {
    'type_mismatch': 'invalid-pointer-use',
    'pointer_overflow': 'pointer-arithmetic',
    'add_overflow': 'signed-integer-overflow',
    'sub_overflow': 'signed-integer-overflow',
    'mul_overflow': 'signed-integer-overflow',
    'negate_overflow': 'negation-overflow',
    'divrem_overflow': 'division-overflow',
    'shift_out_of_bounds': 'invalid-shift',
    'out_of_bounds': 'array-index-out-of-bounds',
    'load_invalid_value': 'invalid-enum-or-bool-value',
    'nonnull_arg': 'null-passed-to-nonnull-parameter',
    'nonnull_return': 'null-returned-from-nonnull-function',
    'builtin_unreachable': 'reached-unreachable-code',
    'missing_return': 'missing-return',
    'vla_bound_not_positive': 'invalid-vla-bound',
    'alignment_assumption': 'alignment-assumption-violated',
    'function_type_mismatch': 'indirect-call-type-mismatch',
    'float_cast_overflow': 'float-cast-overflow',
    'implicit_conversion': 'lossy-implicit-conversion',
    'invalid_builtin': 'invalid-builtin-argument',
}

# What the firmware writes into ErrorType, refined by the sentence that follows it.
UBSAN_DETAIL = [
    ('member access within null pointer', 'null-pointer-member-access'),
    ('load of null pointer', 'null-pointer-read'),
    ('store to null pointer', 'null-pointer-write'),
    ('misaligned address', 'misaligned-pointer-use'),
    ('insufficient space', 'object-too-small-for-type'),
    ('offset applied to a null pointer', 'null-pointer-arithmetic'),
    ('pointer index expression overflowed', 'pointer-arithmetic-overflow'),
]

TYPE_NAME = re.compile(r"of type '([^']+)'")


# ---------------------------------------------------------------------------------------
# The untrusted field a double-fetch report now carries, and what it is called.
#
# A fwsan-double-fetch row used to read, in full:
#
#     sev1 x2759  VariableSmm.efi  Unaligned.c:32:10  fwsan-double-fetch (read)
#             read of 2 bytes at 0x000000001B56802C
#
# MdePkg/Library/BaseLib/Unaligned.c:32 is ReadUnaligned16, a leaf utility called from
# everywhere, and nobody can patch that. What a developer needs is which field of which
# comm-buffer struct was read twice, from which two call sites, inside which handler --
# and every piece of that was available: AsanLib knows the offset from the registered
# buffer and both ips, and the static SMI analysis knows the layout of each handler's
# parameter block. The two were never joined.
# ---------------------------------------------------------------------------------------

# AsanLib appends "untrusted_field offset=0x.. base=0x.. extent=0x.. first_ip=0x..
# first_addr=0x.. first_bytes=0x.." to the ERROR line, so it arrives in the Message
# column. key=0xVALUE with no space after the '=' on purpose: IP_RE, SIZE_RE and ADDR_RE
# above are leftmost-first searches for "ip 0x..", "size 0x.." and "address 0x..", and a
# field spelled with a space would be a second thing each of them can match.
FIELD_KV = re.compile(r'\b(offset|base|extent|first_ip|first_addr|first_bytes)='
                      r'(0x[0-9A-Fa-f]+)')


def untrusted_field(message):
    """The untrusted-field facts in a report message, or {} for a report without them."""
    marker = 'untrusted_field '
    if marker not in (message or ''):
        return {}
    found = {k: int(v, 16) for k, v in FIELD_KV.findall(message.split(marker, 1)[1])}
    return found if 'offset' in found else {}


# X64 is the only ABI any of this is built for, and edk2 packs nothing: a member sits at
# the next multiple of its own alignment. UINTN is 8 here, which aliases.json agrees with
# (UINTN -> UINT64 in every campaign's map).
#
# A type that is not in here, not a typedef that reaches something that is, and not a
# struct in types.json has NO entry and no guess. That is the point: one member of unknown
# size makes every offset after it unknown, and a field named out of a layout that guessed
# is worse than no field at all.
SCALAR_BYTES = {
    'UINT8': 1, 'INT8': 1, 'CHAR8': 1, 'BOOLEAN': 1, 'char': 1, 'signed char': 1,
    'unsigned char': 1,
    'UINT16': 2, 'INT16': 2, 'CHAR16': 2, 'short': 2, 'unsigned short': 2,
    'UINT32': 4, 'INT32': 4, 'int': 4, 'unsigned int': 4, 'unsigned': 4, 'float': 4,
    'UINT64': 8, 'INT64': 8, 'UINTN': 8, 'INTN': 8, 'double': 8,
    'long': 8, 'unsigned long': 8, 'long long': 8, 'unsigned long long': 8,
}

ARRAY_DECL = re.compile(r'^(.*?)\s*\[\s*(\d*)\s*\]$')

# How deep a typedef chain or a nest of structs is followed before the answer is "unknown".
# A cyclic alias map is a real shape -- scalar_choice_check.py carries the case -- and an
# unbounded walk on one does not come back.
TYPE_DEPTH = 24


def type_extent(decl, types, aliases, depth=0):
    """(size, alignment) in bytes for a member declaration, or None when unknowable.

    Spellings come from the analyzer's types.json, which writes an array as `UINT8[1024]`
    and a pointer as `RW_VARIABLE_INFO *`.
    """
    if depth > TYPE_DEPTH:
        return None
    name = (decl or '').strip()
    if not name:
        return None

    found = ARRAY_DECL.match(name)
    if found:
        element = type_extent(found.group(1), types, aliases, depth + 1)
        if element is None:
            return None
        # A trailing [] or [0] is a flexible member: it has an alignment and no extent,
        # which is exactly how the payload region of a comm buffer is usually declared.
        count = int(found.group(2)) if found.group(2) else 0
        return (element[0] * count, element[1])

    if name.endswith('*'):
        return (8, 8)

    if name in SCALAR_BYTES:
        size = SCALAR_BYTES[name]
        return (size, size)

    info = types.get(name)
    if info is not None and getattr(info, 'fields', None):
        return aggregate_extent(name, types, aliases, depth + 1)

    target = aliases.get(name)
    if target and target != name:
        return type_extent(target, types, aliases, depth + 1)
    return None


def aggregate_extent(name, types, aliases, depth=0):
    """(size, alignment) for a struct in types.json, or None when a member is unknowable."""
    laid = struct_layout(name, types, aliases, depth)
    if laid['size'] is None:
        return None
    return (laid['size'], laid['align'])


def struct_layout(name, types, aliases, depth=0):
    """Where every field of a struct sits.

    Returns {'type', 'size', 'align', 'fields', 'stopped'}. `fields` is
    [(path, offset, size)] for each member AND, for a nested struct, for each of its
    members under a dotted path -- so a two-byte read at the fifth byte of an EFI_GUID
    comes back as `VarGuid.Data2` rather than as `VarGuid`.

    `size` is None and `stopped` names the member when one of them cannot be sized. The
    fields BEFORE it are still returned, because their offsets are certain; nothing after
    it is, so nothing after it is offered.
    """
    answer = {'type': name, 'size': None, 'align': 1, 'fields': [], 'stopped': ''}
    info = types.get(name)
    if info is None or not getattr(info, 'fields', None) or depth > TYPE_DEPTH:
        answer['stopped'] = f'{name} is not a struct this campaign recorded'
        return answer

    at, align = 0, 1
    for field in info.fields:
        member = (getattr(field, 'name', '') or '').strip()
        decl = (getattr(field, 'type', '') or '').strip()
        extent = type_extent(decl, types, aliases, depth + 1)
        if extent is None or not member:
            answer['stopped'] = f'{member or "an unnamed member"} ({decl or "no type"})'
            return answer
        size, want = extent
        at = ((at + want - 1) // want) * want if want else at
        align = max(align, want)
        answer['fields'].append((member, at, size))
        # Descend, so the answer can be a field of a field. Only into something that laid
        # out completely: a partial nested layout would place its tail members wrongly.
        base = ARRAY_DECL.match(decl)
        inner = (base.group(1) if base else decl).strip()
        inner = inner if inner in types else (aliases.get(inner) or inner)
        if not base and not decl.endswith('*') and inner in types:
            nested = struct_layout(inner, types, aliases, depth + 1)
            if nested['size'] is not None:
                for path, offset, bytes_ in nested['fields']:
                    answer['fields'].append((f'{member}.{path}', at + offset, bytes_))
        at += size

    answer['align'] = align
    answer['size'] = ((at + align - 1) // align) * align if align else at
    return answer


def field_at(fields, offset, size):
    """The most specific recorded field the access lands in, or None.

    Exact first: a two-byte read at the two-byte field that starts there is the answer
    even though the enclosing struct also contains it. Then the smallest field that holds
    the whole access. An access that starts inside one field and ends in the next matches
    nothing here, which is itself worth saying.
    """
    exact = [f for f in fields if f[1] == offset and f[2] == size]
    if exact:
        return exact[0]
    holds = [f for f in fields
             if f[1] <= offset and (offset + max(size, 1)) <= (f[1] + f[2])]
    if holds:
        return min(holds, key=lambda f: (f[2], f[1]))
    return None


# EFI_SMM_COMMUNICATE_HEADER, which the PI spec fixes: EFI_GUID HeaderGuid, UINTN
# MessageLength, UINT8 Data[1]. The SMI harness registers the WHOLE message --
# FirnessUntrusted(CommBuffer, CommSize) -- so a reported offset is measured from
# HeaderGuid and the handler's own parameter block starts after MessageLength, at
# OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data).
#
# Written out rather than read from types.json because it decides where the payload
# begins: a campaign whose types.json happens not to carry the header would otherwise
# join every offset against the wrong base, which names the wrong field with full
# confidence.
COMM_HEADER_FIELDS = (
    ('HeaderGuid', 0, 16),
    ('HeaderGuid.Data1', 0, 4),
    ('HeaderGuid.Data2', 4, 2),
    ('HeaderGuid.Data3', 6, 2),
    ('HeaderGuid.Data4', 8, 8),
    ('MessageLength', 16, 8),
)
COMM_PAYLOAD_AT = 24


# A cast of the comm-buffer parameter to a pointer: `(RW_VARIABLE_INFO *)CommBuffer`.
#
# A nested cast does not match, which is what makes this usable on a recorded expression
# rather than on source. In
#
#     (VOID *)((CHAR16 *)((RW_VARIABLE_INFO *)CommBuffer)->Data + CommData->Offset)
#
# the outer two casts are followed by '(' where this requires an identifier, so the only
# match is the one whose target is the parameter itself -- and `(CHAR16 *)CommData->Data`
# is rejected because CommData is not the comm buffer.
CAST_OF_BUFFER = re.compile(r'\(\s*([A-Za-z_]\w*)\s*\*\s*\)\s*\(?\s*([A-Za-z_]\w*)\b')


def is_comm_buffer(name):
    """Whether an identifier is the handler's comm-buffer parameter.

    EFI_MM_HANDLER_ENTRY_POINT fixes the signature, so the name is CommBuffer in every
    handler in the tree -- matched loosely anyway, and with the size parameter next to it
    excluded, because the two differ by a suffix and taking CommBufferSize for the buffer
    would read a cast of the size as the type of the block.
    """
    lowered = (name or '').lower()
    return 'commbuffer' in lowered and 'size' not in lowered


def comm_buffer_casts(edges):
    """handler -> the type names its own body casts CommBuffer to, first seen first.

    The analyser records a handler's declared parameter block, and for a handler that
    takes CommBuffer as VOID * and casts it inside the body there is nothing to record:
    RWVariableHandler comes back as `void *`, which has no fields, no size and no field
    names -- so the one handler EVAL-1's injected bugs live in was the one the join could
    say nothing about.

    The cast is the handler's own statement of what the block is, and it is already in
    smi-call-edges.json: the expression that reaches a callee carries it verbatim, which
    is where bugs.md's "derived from" column gets
    `(VOID *)((CHAR16 *)((RW_VARIABLE_INFO *)CommBuffer)->Data + CommData->Offset)`.

    Not cast-map.json. That file is keyed by type rather than by function -- 1448 entries
    for this campaign and no RW_VARIABLE entry at all -- so it cannot say which recorded
    type belongs to this buffer. Not the handler source either: triage runs against a
    campaign directory, which holds the analysis and not the tree.

    Nothing is filtered by name here. A `(UINT8 *)CommBuffer` is a byte-pointer cast and
    not a parameter block, and it drops out by having no fields in types.json rather than
    by being on a list of spellings someone has to keep.
    """
    found = {}
    for edge in edges or []:
        if not isinstance(edge, dict):
            continue
        handler = (edge.get('EnclosingFunction') or '').strip()
        if not handler:
            continue
        for arg in (edge.get('Arguments') or {}).values():
            if not isinstance(arg, dict):
                continue
            for text in (arg.get('assignment'), arg.get('usage')):
                for cast in CAST_OF_BUFFER.finditer(text or ''):
                    if not is_comm_buffer(cast.group(2)):
                        continue
                    names = found.setdefault(handler, [])
                    if cast.group(1) not in names:
                        names.append(cast.group(1))
    return found


class CommBufferJoin:
    """What offset N of one campaign's untrusted buffer is called.

    Built from the files the analyzer already copies into every campaign directory:
    smi-function-guid-map.json gives handler -> parameter block, types.json gives each
    block's members, aliases.json resolves EFI_STATUS -> RETURN_STATUS -> UINTN, and
    smi-call-edges.json recovers the block for a handler that declares its buffer VOID *
    and casts it inside the body. A campaign with none of them -- a DXE protocol campaign,
    where the registered buffer is an argument the harness built and not a comm buffer --
    joins nothing and says so.
    """

    def __init__(self, campaign_dir):
        # handler -> [layout, ...]. A list because a handler can cast its buffer to more
        # than one type, and picking one of those would be a guess; one entry is the
        # ordinary case.
        self.handlers = {}
        self.why = ''
        smi = self._read(campaign_dir, 'smi-function-guid-map.json')
        if not isinstance(smi, dict) or not smi:
            self.why = ('no smi-function-guid-map.json in the campaign, so the registered '
                        'buffer is a protocol argument rather than a comm buffer and has '
                        'no handler layout')
            return
        raw_types = self._read(campaign_dir, 'types.json')
        aliases = self._read(campaign_dir, 'aliases.json')
        if not isinstance(raw_types, list) or not raw_types:
            self.why = 'the campaign kept no types.json, so no struct can be laid out'
            return
        types = _types_from_json(raw_types)
        aliases = {k: v for k, v in (aliases or {}).items() if isinstance(v, str)}
        casts = comm_buffer_casts(self._read(campaign_dir, 'smi-call-edges.json'))
        for handler, data in sorted(smi.items()):
            if not isinstance(data, dict):
                continue
            found = []
            # The declared type first and on its own terms. A handler that names a real
            # block keeps it even when its body also casts the buffer somewhere: the
            # declaration is what the analyser resolved and what the harness sends.
            block = (data.get('Type') or '').replace('*', '').strip()
            if block:
                laid = self._lay(block, types, aliases, 'declared')
                if laid:
                    found.append(laid)
            # Only then the cast, and only because the declaration gave no fields -- which
            # is what `void *`, an empty Type, and a type nothing recorded all look like.
            if not found:
                for name in casts.get(handler, ()):
                    laid = self._lay(name, types, aliases, 'cast')
                    if laid:
                        found.append(laid)
            if found:
                self.handlers[handler] = found
        if not self.handlers:
            self.why = 'no handler in the campaign named a parameter block'

    @staticmethod
    def _lay(name, types, aliases, via):
        """The layout of a candidate block, or None when it has no fields to offer."""
        resolved = name if name in types else (aliases.get(name) or name)
        laid = struct_layout(resolved, types, aliases)
        if not laid['fields']:
            return None
        laid['via'] = via
        return laid

    @staticmethod
    def _read(campaign_dir, name):
        try:
            with open(os.path.join(campaign_dir, name)) as handle:
                return json.load(handle)
        except (OSError, ValueError):
            return None

    def matches(self, offset, size):
        """[(handler, type, path, field offset, field size, how)] for a buffer offset.

        One campaign drives every handler it found, so several parameter blocks can have
        something at one offset and nothing here knows which handler was running. The
        ambiguity is narrowed rather than hidden: a field that starts exactly there and is
        exactly that wide is what a two-byte read of a two-byte field looks like, while a
        256-byte payload array merely CONTAINS the offset and would match almost any read.
        So when any block fits exactly, only the exact fits are offered.
        """
        inner = offset - COMM_PAYLOAD_AT
        found = []
        for handler, blocks in sorted(self.handlers.items()):
            for laid in blocks:
                hit = field_at(laid['fields'], inner, size)
                if hit:
                    exact = hit[1] == inner and hit[2] == size
                    found.append((exact, handler, laid['type'], hit[0], hit[1], hit[2],
                                  laid.get('via', 'declared')))
        if any(entry[0] for entry in found):
            found = [entry for entry in found if entry[0]]
        return [entry[1:] for entry in found]

    def describe(self, offset, size):
        """One clause naming the field, or saying exactly why it could not be named."""
        # Before the header arithmetic, not after. With no handler map the buffer is not
        # known to be a comm buffer at all -- in a DXE protocol campaign it is an argument
        # the harness built -- so subtracting a message header it may not have, and naming
        # a field of EFI_SMM_COMMUNICATE_HEADER, would be a claim about a layout nothing
        # here has seen.
        if not self.handlers:
            return (f'offset 0x{offset:X} of the registered buffer; '
                    f'{self.why or "no comm-buffer layout for this campaign"}, so which '
                    f'field it is cannot be said from here')
        if offset < COMM_PAYLOAD_AT:
            hit = field_at(COMM_HEADER_FIELDS, offset, size)
            where = f'EFI_SMM_COMMUNICATE_HEADER.{hit[0]}' if hit else \
                'inside EFI_SMM_COMMUNICATE_HEADER'
            return (f'{where} at offset 0x{offset:X} -- the message header the SMM core '
                    f'reads, not a field of any handler\'s parameter block')
        found = self.matches(offset, size)
        if not found:
            unsized = sorted({laid['stopped'] for blocks in self.handlers.values()
                              for laid in blocks if laid['stopped']})
            inner = offset - COMM_PAYLOAD_AT
            said = (f'no field at payload offset 0x{inner:X} in any of the '
                    f'{len(self.handlers)} parameter block(s) this campaign drove '
                    f'({", ".join(sorted(self.handlers))})')
            if unsized:
                said += f' -- {len(unsized)} of those layouts stop at {"; ".join(unsized)}'
            else:
                said += ' -- the read is past the end of every one of them'
            return said
        # "via the cast" is said rather than left out. A block recovered from
        # `(TYPE *)CommBuffer` is the handler's own statement of what it believes the
        # buffer is, not a declaration the analyser resolved, and a reader deciding
        # whether to trust the field name should be told which of the two it is.
        shown = [f'{handler} comm buffer: {block}.{path} at payload offset 0x{at:X}, '
                 f'{bytes_} byte(s)'
                 + (' (block recovered from the cast the handler performs on CommBuffer, '
                    'which declares it VOID *)' if how == 'cast' else '')
                 for handler, block, path, at, bytes_, how in found[:3]]
        if len(found) > 3:
            shown.append(f'and {len(found) - 3} other handler(s) with a field there')
        return '; '.join(shown)

    def handler_names(self, offset, size):
        """Just the handlers whose block has a field there, for narrowing a caller list."""
        if offset < COMM_PAYLOAD_AT:
            return ()
        seen = []
        for entry in self.matches(offset, size):
            if entry[0] not in seen:
                seen.append(entry[0])
        return tuple(seen)


def _types_from_json(raw):
    """types.json as the generator's TypeInfo, without importing the generator.

    bug_report.py runs on a host that may not have the generator's dependencies -- it
    imports fuzzywuzzy at module scope -- and this needs two attributes off each record.
    """
    class _Field:
        __slots__ = ('name', 'type')

        def __init__(self, name, type_):
            self.name, self.type = name, type_

    class _Type:
        __slots__ = ('name', 'fields')

        def __init__(self, name, fields):
            self.name, self.fields = name, fields

    built = {}
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        name = entry.get('TypeName')
        if not name:
            continue
        built[name] = _Type(name, [_Field(f.get('Name') or '', f.get('Type') or '')
                                   for f in (entry.get('Fields') or [])
                                   if isinstance(f, dict)])
    return built


# Said once per double-fetch row, because it is the reason the row is a finding at all and
# a reader who has not met the class cannot act on a field name without it.
TOCTOU = ('a caller-controlled field read twice is a TOCTOU risk: the OS can rewrite the '
          'buffer between the read that validated the value and the read that uses it, so '
          'what passed the check is not what acts')


def untrusted_payload(cluster):
    """The untrusted-field facts of a cluster, for bugs.json, or {}."""
    for report in cluster.reports:
        field = getattr(report, 'field', None) or {}
        if not field:
            continue
        return {'untrusted': {
            'offset': field['offset'],
            'base': field.get('base', 0),
            'extent': field.get('extent', 0),
            'first_ip': field.get('first_ip', 0),
            'first_addr': field.get('first_addr', 0),
            'first_bytes': field.get('first_bytes', 0),
            'first_source': getattr(report, 'first_site', ''),
            'field': getattr(report, 'field_note', ''),
            'handlers': list(getattr(report, 'field_handlers', ()) or ()),
        }}
    return {}


# The interceptor reports at its own source line, so the file says CopyMemWrapper.c for
# every out-of-bounds copy in the image. Cluster those by caller instead.
INTERCEPTOR_SOURCES = ('CopyMemWrapper', 'SetMemWrapper', 'ScanMem', 'CompareMemWrapper',
                       'ZeroMemWrapper', 'MemLibGuid')


def match_reason(text, table):
    for needle, reason in table:
        if needle in text:
            return reason
    return ''


class Report:
    # field/field_note/field_handlers/first_site are filled in by load(), which is the
    # only place that knows which campaign directory the row came from and therefore which
    # handler layout to join its offset against. A Report built by hand -- the checks do
    # that -- carries the defaults and renders as it always did.
    __slots__ = ('protocol', 'phase', 'module', 'path', 'line', 'asan', 'kind',
                 'message', 'count', 'field', 'field_note', 'field_handlers',
                 'first_site')

    def __init__(self, row, protocol):
        self.protocol = protocol
        self.phase = (row.get('Phase') or '').strip().lower()
        self.module = (row.get('Module') or '').strip()
        self.path = (row.get('File') or '').strip()
        self.line = (row.get('Line') or '').strip()
        self.asan = (row.get('Asan Msg') or '').strip()
        self.kind = (row.get('ErrorType') or '').strip() or 'ubsan'
        self.message = (row.get('Message') or '').strip()
        try:
            self.count = int(row.get('Count') or 0)
        except ValueError:
            self.count = 0
        self.field = untrusted_field(self.message)
        self.field_note = ''
        self.field_handlers = ()
        self.first_site = ''

    @property
    def basename(self):
        return os.path.basename(self.path)

    @property
    def ip(self):
        found = IP_RE.search(self.message)
        return found.group(1) if found else ''

    def line_number(self):
        try:
            return int(self.line, 0)
        except (TypeError, ValueError):
            return -1

    def bug_type(self):
        """The defect, not the handler that reported it.

        Falls back to the handler's category when the firmware did not record a detail,
        and says so rather than inventing one -- an older capture has no ErrorType on a
        pointer_overflow at all.
        """
        haystack = f'{self.kind} {self.message}'.lower()
        for needle, name in UBSAN_DETAIL:
            if needle in haystack:
                return name
        if self.asan.startswith('__ubsan_handle_'):
            stem = self.asan[len('__ubsan_handle_'):].replace('_abort', '')
            stem = stem[:-3] if stem.endswith('_v1') else stem
            base = UBSAN_HANDLERS.get(stem, stem.replace('_', '-'))
            return f'{base} (undetailed)' if not self.message else base
        if self.asan:
            # an ASan class is already specific; the direction is the part that decides
            # how bad it is, and it is in the message rather than the class
            write = WRITE_RE.search(self.message)
            if write:
                return f'{self.asan} ({"write" if int(write.group(1), 16) else "read"})'
            return self.asan
        return self.kind or 'unknown'

    def type_name(self):
        found = TYPE_NAME.search(self.message)
        return found.group(1) if found else ''

    def group_key(self):
        """Reports that could be the same bug, before proximity is considered.

        An interceptor reports at its own source line, so the file is always the wrapper
        and the caller is the only thing that separates two different overflows.
        """
        klass = self.bug_type()
        if any(name in self.basename for name in INTERCEPTOR_SOURCES):
            return (self.module, klass, 'via:' + (self.ip or self.basename))
        return (self.module, klass, self.basename)


class Cluster:
    def __init__(self, key):
        self.key = key
        self.reports = []
        self.protocols = set()
        self.lines = set()
        self.phases = set()
        self.hits = 0

    def add(self, report):
        self.reports.append(report)
        self.protocols.add(report.protocol)
        if report.line:
            self.lines.add(report.line)
        self.phases.add(report.phase)
        self.hits += report.count

    @property
    def module(self):
        return self.key[0]

    @property
    def klass(self):
        return self.key[1]

    @property
    def site(self):
        first = self.reports[0]
        nums = sorted(r.line_number() for r in self.reports if r.line_number() >= 0)
        if not nums:
            return first.basename
        if len(set(nums)) == 1:
            return f'{first.basename}:{nums[0]}'
        return f'{first.basename}:{nums[0]}-{nums[-1]} ({len(set(nums))} sites)'

    def severity(self):
        """Higher is more likely to be a memory-safety defect worth chasing.

        Ordered by what an attacker gets, not by how loud the report is. A write past an
        allocation is the top of the list; arithmetic on a null pointer that is never
        dereferenced is near the bottom, and the two used to sort together because both
        strings contain the word "overflow".
        """
        klass = self.klass.lower()
        if klass.startswith('cpu-exception'):
            # the guest actually faulted. Whether the harness or the firmware is at fault
            # is a triage question; it is never noise.
            return 4
        if klass.startswith('firmware-assert'):
            # Beside the fault, not at the bottom with the arithmetic rows: the firmware
            # stated its own invariant and an input broke it, and on a build with the
            # deadloop bit set the machine stops there. An SMM one stops it for good --
            # CpuDeadLoop() with interrupts off, in a context the OS cannot preempt, so
            # the recovery is a power cycle. It also arrives pre-located, naming its file,
            # its line and the expression, which is more than a sanitizer row carries.
            return 4
        if 'heap-buffer-overflow' in klass or 'unknown-crash' in klass:
            return 5 if '(write)' in klass else 4
        if any(k in klass for k in ('use-after-free', 'double-free', 'use-after-poison',
                                    'use-after-return', 'use-after-scope')):
            return 4
        if 'buffer-overflow' in klass or 'buffer-underflow' in klass or \
                'array-index-out-of-bounds' in klass or 'intra-object' in klass:
            return 4
        if 'pointer-arithmetic-overflow' in klass or 'null-pointer-write' in klass or \
                'object-too-small' in klass or 'indirect-call-type-mismatch' in klass:
            return 3
        if 'null-pointer' in klass or 'misaligned' in klass or \
                'nonnull' in klass or 'pointer-arithmetic' in klass:
            return 2
        return 1

    def detail(self):
        # the type the firmware was reading through says a lot about a null dereference:
        # a member access on SCRIPT_TABLE_PRIVATE_DATA is a different bug from one on CHAR16
        # Only when it adds something. The message already names the type for a single
        # one, so repeating it is noise; spanning several is the part worth saying.
        names = {r.type_name() for r in self.reports if r.type_name()}
        suffix = f' across {len(names)} types' if len(names) > 1 else ''
        for report in self.reports:
            if report.message:
                size = SIZE_RE.search(report.message)
                write = WRITE_RE.search(report.message)
                addr = ADDR_RE.search(report.message)
                if size and write:
                    direction = 'write' if int(write.group(1), 16) else 'read'
                    said = (f'{direction} of {int(size.group(1), 16)} bytes'
                            f'{" at " + addr.group(1) if addr else ""}')
                    return said + self.untrusted_detail(report)
                return report.message[:90] + suffix
        return suffix.strip() or ''

    def field_handlers(self):
        """Handlers whose parameter block has a field where this cluster's reports read.

        Empty when nothing in the cluster carried an untrusted offset, which is every
        class but this one -- and the caller treats empty as "do not narrow", so a
        non-double-fetch row keeps the behaviour it had.
        """
        picked = set()
        for report in self.reports:
            picked.update(getattr(report, 'field_handlers', ()) or ())
        return tuple(sorted(picked))

    def untrusted_detail(self, report):
        """What a double fetch adds to the access: the field, both reads, and why.

        Everything here comes off the report itself. The row's own location is the SECOND
        read -- the one that used the value -- and until the detector started recording the
        first fetch's ip the read that validated it was simply not in the output, so the
        finding named the line that cannot be fixed without naming the check it got past.

        One line, because this lands in a markdown table cell and on one console line.
        """
        field = getattr(report, 'field', None) or {}
        if not field:
            return ''
        said = [f'untrusted offset 0x{field["offset"]:X} of the '
                f'0x{field.get("extent", 0):X}-byte buffer at '
                f'0x{field.get("base", 0):016X}']
        if getattr(report, 'field_note', ''):
            said.append(report.field_note)
        first = field.get('first_ip', 0)
        where = getattr(report, 'first_site', '') or ''
        read = f'first read at ip 0x{first:016X}'
        if where:
            read += f' ({where})'
        if field.get('first_bytes') and field.get('first_bytes') != int(
                SIZE_RE.search(report.message).group(1), 16):
            # The granule match earning its keep: four bytes to check a length and eight
            # to use it is the same word read twice, and the two sizes are what say so.
            read += f', {field["first_bytes"]} byte(s) there'
        said.append(f'{read}; re-read at {self.site}')
        said.append(TOCTOU)
        return ' -- ' + ' -- '.join(said)


EXC_RE = re.compile(r'X64 Exception Type - ([0-9A-Fa-f]{2})\(([^)]*)\)')
IMG_RE = re.compile(r'Find image based on IP\((0x[0-9A-Fa-f]+)\)[^\n]*?/([A-Za-z0-9_]+)\.dll '
                    r'\(ImageBase=([0-9A-Fa-f]+)')


def guest_faults(protocol, path):
    """CPU exceptions the guest took, from the serial capture.

    A sanitizer report is not the only way a campaign finds something. Under the QEMU
    backend most findings are a fault: the harness drives the firmware into a #GP and the
    iteration ends. Those never reach crashes.csv, which only carries sanitizer output, so
    a report built from that alone says a QEMU campaign found nothing.

    The location is the module and the offset into it, because symbolising needs the build
    tree. Resolve one with:

        llvm-symbolizer --obj=<Build>/.../<Module>.debug --functions=linkage <rva>
    """
    if not os.path.isfile(path):
        return []
    try:
        with open(path, 'rb') as handle:
            text = handle.read().decode('utf-8', errors='replace').replace('\r', '')
    except OSError:
        return []
    kinds = EXC_RE.findall(text)
    if not kinds:
        return []
    images = IMG_RE.findall(text)
    _, name = kinds[0]
    module, where, message = '', '', f'{len(kinds)} fault(s)'
    if images:
        ip, module, base = images[0]
        offset = int(ip, 16) - int(base, 16)
        where = f'+{offset:#x}'
        message = f'{len(kinds)} fault(s) at {module}{where}'
    rows = []
    for _ in range(len(kinds)):
        rows.append(Report({'Phase': 'fuzz', 'Module': f'{module}.efi' if module else '',
                            'File': where or 'unattributed',
                            'Line': '', 'Asan Msg': '',
                            'ErrorType': f'cpu-exception ({name.split("-")[0].strip()})',
                            'Message': message, 'Count': '1'}, protocol))
    return rows


ASSERT_RE = re.compile(r'^ASSERT (?P<file>[^\s(]+)\((?P<line>\d+)\): (?P<expr>.*)$',
                       re.MULTILINE)
# Boot loads drivers; the harness loads nothing. The last load line is therefore the last
# moment that is certainly still boot, which is the only divider these two captures share
# -- the harness markers firness.py splits on go to the serial capture, and ASSERTs go to
# the debug console. Measured on run 42154605158: last load at line 556, the ASSERT at
# 3287. A capture with no load lines at all leaves every ASSERT in the boot bucket, where
# the report tells a reader to confirm it against the source, rather than claiming an
# input provoked something that may fire on every boot.
LOAD_RE = re.compile(r'^Loading driver at ', re.MULTILINE)


_SOURCE_INDEX = None


def _source_index(build_dirs):
    """source basename -> every path under the build dirs with that name."""
    global _SOURCE_INDEX
    if _SOURCE_INDEX is None:
        _SOURCE_INDEX = defaultdict(list)
        for root in build_dirs:
            for base, dirs, files in os.walk(root):
                # Build/ holds generated copies and the AutoGen files; the sources an
                # ASSERT names are the ones that were compiled, not their build artefacts.
                dirs[:] = [d for d in dirs if d not in ('Build', '.git')]
                for name in files:
                    if name.endswith(('.c', '.h')):
                        _SOURCE_INDEX[name].append(os.path.join(base, name))
    return _SOURCE_INDEX


def assert_source(name, line, expr, build_dirs):
    """The package-relative path of the file an ASSERT named, or ''.

    DebugAssert is handed __FILE__, and edk2 compiles each module from its own directory,
    so what arrives is a bare basename: "Smi.c", and edk2 has more than one of those. The
    line number settles most of it -- a file of the same name whose line 193 is not an
    ASSERT at all did not raise this one.

    The expression is only a tie-breaker, and deliberately so. It reaches the message
    macro-expanded, so for anything but a bare ASSERT (FALSE) it will not appear in the
    source verbatim; requiring it to match would have thrown away every attribution it
    cannot confirm, including ones the line number had already settled on its own.

    Returns a path only when exactly one candidate survives. Two that both fit is not a
    tie to break -- naming one would be a guess presented as an answer, and a bare
    basename is the more honest row.
    """
    if not build_dirs or not name or not line.isdigit():
        return ''
    wanted = int(line)
    hits = []
    for path in _source_index(build_dirs).get(name, ()):
        try:
            with open(path, 'rb') as handle:
                lines = handle.read().decode('utf-8', errors='replace').splitlines()
        except OSError:
            continue
        if len(lines) >= wanted and 'ASSERT' in lines[wanted - 1]:
            hits.append((path, lines[wanted - 1]))
    if len(hits) > 1:
        # FALSE is how DebugLib's own expansion of ASSERT (FALSE) comes back.
        spellings = [expr.strip(), expr.strip().replace(' ', '')]
        if expr.replace(' ', '') == '((BOOLEAN)(0==1))':
            spellings.append('FALSE')
        narrowed = [hit for hit in hits
                    if any(s and s in hit[1].replace(' ', '') for s in spellings)]
        if len(narrowed) == 1:
            hits = narrowed
    if len(hits) != 1:
        return ''
    found = resolve_modules.package_relative(hits[0][0])
    return found or hits[0][0]


def guest_asserts(protocol, paths, build_dirs=()):
    """ASSERTs the firmware raised, from the captures.

    An ASSERT is a finding the other two sources cannot see. It is not a sanitizer report,
    so it never reaches crashes.csv, and it is not a CPU exception, so guest_faults misses
    it -- yet DEBUG_PROPERTY_ASSERT_DEADLOOP_ENABLED makes it the most destructive thing a
    campaign can hit: CpuDeadLoop() with interrupts off, and inside SMM the snapshot
    restore does not recover the vCPU. Run 42154605158 spent its last four iterations
    timing out against a machine killed that way by its 21st input.

    SHARED_PCDS in fuzz_edk2.py now clears that bit so the campaign survives, which is
    only safe because the finding is read back here. The ASSERT names its own file, line
    and expression, so these rows arrive better located than a sanitizer row does -- no
    symbolisation, no image map, no build tree.
    """
    rows = []
    for path in paths:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, 'rb') as handle:
                text = handle.read().decode('utf-8', errors='replace').replace('\r', '')
        except OSError:
            continue
        loads = [m.start() for m in LOAD_RE.finditer(text)]
        boot_ends = loads[-1] if loads else len(text)
        # Count repeats, and keep the phase of the first sighting: one site asserting in
        # both phases is a boot defect the harness also reaches, not two defects.
        seen = {}
        for found in ASSERT_RE.finditer(text):
            name, line = found.group('file'), found.group('line')
            key = (name, line, found.group('expr'))
            if key in seen:
                seen[key][0] += 1
            else:
                seen[key] = [1, 'fuzz' if found.start() > boot_ends else 'boot']
        for (name, line, expr), (count, phase) in seen.items():
            where = assert_source(name, line, expr, build_dirs) or name
            rows.append(Report({'Phase': phase, 'Module': '',
                                'File': where, 'Line': line, 'Asan Msg': '',
                                'ErrorType': 'firmware-assert',
                                'Message': f'assertion failed: {expr} -- a deadloop '
                                           f'build stops here, in SMM for good',
                                'Count': str(count)}, protocol))
    return rows


# Which of two rows for ONE access keeps its label. A named sanitizer class beats the bare
# access helper, which beats a crash the firmware could not classify at all. This is not a
# severity order -- Report.severity above is -- it only breaks the tie in merge_by_ip.
def class_rank(asan):
    name = (asan or '').lower()
    if not name or 'unknown-crash' in name:
        return 0
    if name.startswith('__asan_load') or name.startswith('__asan_store'):
        return 1
    return 2


def merge_by_ip(reports):
    """One access, one report.

    The sanitizer writes two rows for the same access: the access check names the source
    file and line, while the typed report names "asan-outline-instrumentation" and puts the
    ip where a line number would go. They carry the same ip, so they are the same
    instruction and the same defect.

    Filing both is what put eight unattributable issues beside eight real ones on run
    40332735518 -- half of everything open, each saying "No source line to show" -- and no
    fingerprint could catch it, because module, class and file all differ between twins.

    The row that knows the source is the one kept. It adopts the other's class when that
    class is the more specific of the two, so a stack-buffer-overflow still reads as one
    and arrives with a file and a line instead of an address.
    """
    located = {}
    for report in reports:
        if report.ip and '/' in report.path:
            located.setdefault(report.ip, report)
    kept = []
    for report in reports:
        twin = located.get(report.ip) if report.ip and '/' not in report.path else None
        if twin is None or twin is report:
            kept.append(report)
            continue
        if class_rank(report.asan) > class_rank(twin.asan):
            # the message comes too: it carries address, size and is_write, which is where
            # bug_type() reads the (read)/(write) direction from, and the ip is in both
            twin.asan, twin.message = report.asan, report.message
        twin.count += report.count
    return kept


def load(root, build_dirs=()):
    """Read every crashes.csv, then merge reports that sit close together.

    Proximity has to be single linkage, not a fixed bucket. ExportPackageList raises the
    same construct every 13 lines from 3277 to 3368; bucketing by line // 32 split that
    one defect across four clusters purely on where the boundaries fell, which is the
    opposite of what this is for.

    A sanitizer row names the interceptor's own source file, so without a module it
    clusters with every other caller of that interceptor. The campaign's serial capture
    carries the dispatch narration when the firmware was built with DEBUG_ON_SERIAL_PORT,
    so the ip in the message can be turned back into a driver here -- one image map per
    protocol, because each campaign is its own boot at its own addresses.
    """
    groups = defaultdict(list)
    rows = 0
    for protocol in sorted(os.listdir(root)):
        path = os.path.join(root, protocol, 'crashes.csv')
        serial = os.path.join(root, protocol, 'fuzz.txt')
        if not os.path.isfile(path):
            continue
        # The dispatch narration is NOT in fuzz.txt and never was. OVMF sends DEBUG to
        # the ISA debug port, which the campaign captures separately, so fuzz.txt holds
        # AsanLib's own SerialOutput and nothing else -- measured across four CI runs,
        # 0 load lines in every fuzz.txt and 95 in every debugcon.log beside it. Reading
        # only fuzz.txt is what left the image map empty and every finding unattributed;
        # no build flag was needed to produce the lines, only the right file.
        debugcon = os.path.join(root, protocol, 'qemu', 'debugcon.log')
        maps = [serial, debugcon]
        imap = resolve_modules.map_from_logs(maps, build_dirs)
        smap = resolve_modules.source_map(build_dirs) if build_dirs else None
        calibrate(maps, build_dirs)
        # One per campaign, because the handler set and the recorded struct layouts are
        # this campaign's. Built once rather than per report: a double fetch arrives
        # thousands of times and laying out seven parameter blocks for each of them is
        # work with one answer.
        join = CommBufferJoin(os.path.join(root, protocol))

        def source_of(ip):
            """file:line for an ip, by the same rules locate() uses, or ''.

            The first read of a double fetch is an ip and nothing else -- it is recorded by
            the detector, not reported by a sanitizer handler with a source position -- so
            this is the only way it gets a line. Same conservatism: a base the map is not
            certain of names a line in the wrong function.
            """
            if not ip or not len(imap) or not build_dirs:
                return ''
            found = imap.resolve(ip)
            if not found or not found[2]:
                return ''
            answer = symbolise_offset(f'{found[0]}.efi', f'+{found[1]:#x}', build_dirs)
            where = answer.split(' -- ', 1)[1] if ' -- ' in answer else ''
            return where if ':' in where else ''

        def name_field(report):
            """Join a double fetch's offset to the field of the handler's struct."""
            # Re-read from the message rather than trusting what __init__ parsed:
            # merge_by_ip hands a twin the other row's message when the other row's class
            # is the more specific of the two, and a field parsed before that would then
            # describe an access the row no longer carries.
            report.field = untrusted_field(report.message)
            if not report.field:
                return report
            size = SIZE_RE.search(report.message)
            width = int(size.group(1), 16) if size else 0
            report.field_note = join.describe(report.field['offset'], width)
            report.field_handlers = join.handler_names(report.field['offset'], width)
            report.first_site = source_of(report.field.get('first_ip', 0))
            return report

        def locate(report):
            """Fill in the source for a report that only has an ip.

            A sanitizer handler is an outline call with no source position of its own, so
            AsanLib writes a marker where the file goes -- "fwsan",
            "asan-outline-instrumentation" -- and says as much in its own comment. The ip
            it carries is the caller's, and every piece needed to turn that into a line
            already existed: the image map places the ip in a module and
            symbolise_offset() resolves the offset against that module's .debug, which is
            why triage runs inside the campaign image.

            The one missing piece was the map. It is built from "Loading driver at" lines,
            which only exist when the firmware was built with -D DEBUG_ON_SERIAL_PORT --
            four scripts here document that dependency and nothing supplied it, so every
            fwsan finding arrived as "fwsan:<ip>" with no file. This is inert on a capture
            with no image loads, which is what makes it safe to run unconditionally.

            Only a certain base is used. An uncertain one would name a line in the wrong
            function with full confidence, which is worse than naming none.
            """
            if '/' in report.path or not report.ip or not len(imap) or not build_dirs:
                return report
            try:
                found = imap.resolve(int(report.ip, 16))
            except ValueError:
                return report
            if not found or not found[2]:
                return report
            name, offset = found[0], found[1]
            answer = symbolise_offset(f'{name}.efi', f'+{offset:#x}', build_dirs)
            where = answer.split(' -- ', 1)[1] if ' -- ' in answer else ''
            if ':' in where:
                path, _, line = where.rpartition(':')
                if path and line.isdigit():
                    report.path, report.line = path, line
                    # Take the module from the map that produced the path. A marker row
                    # arrives with Module already filled by the firmware, and that answer
                    # and this one are separate lookups that can disagree: the same
                    # EfiHiiFont site was filed as DxeCore.efi on one run and
                    # HiiDatabase.efi on the next, while BOTH runs symbolised it to
                    # HiiDatabaseDxe/Font.c:1106 -- a file no DxeCore image contains. The
                    # candidate then showed one source's module beside the other's path.
                    # This branch has already required a base the map is certain of, so
                    # prefer it and keep the pair consistent.
                    report.module = f'{name}.efi'
            return report

        def attribute(report):
            if report.module:
                return report
            # An ASan report carries the faulting address, so the image map places it
            # exactly, including code from a library instance. A UBSan report carries only
            # a file and a line, and for those the build tree says which module compiled
            # that file. Neither covers the other's rows.
            found = imap.resolve(int(report.ip, 16)) if report.ip and len(imap) else None
            if found:
                report.module = f'{found[0]}.efi'
            elif smap is not None:
                owner = smap.resolve(report.path)
                if owner:
                    report.module = f'{owner}.efi'
            return report

        collected = []
        with open(path, newline='') as handle:
            for row in csv.DictReader(handle):
                collected.append(attribute(Report(row, protocol)))
                rows += 1
        # Only the sanitizer's own rows are merged. A guest fault is a separate observation
        # of the machine, not a second row for one access, and nothing measured says an
        # exception at the same ip is the same event.
        #
        # Merge BEFORE locating. merge_by_ip pairs a report that names a source with its
        # twin that names a marker, so it can only see the pair while the marker is still
        # there -- locating first gives the twin a real path, the pair stops looking like
        # one, and both survive as separate candidates for one access. Measured on run
        # 40532555997: locate-then-merge gave 5 candidates with UefiDriverModel.c:731
        # twice, merge-then-locate gives 4.
        for report in merge_by_ip(collected):
            groups[name_field(locate(report)).group_key()].append(report)
        for report in guest_faults(protocol, serial):
            rows += 1
            groups[report.group_key()].append(report)
        # Both captures: an ASSERT reaches the debug console, and reaches the serial one
        # too when the firmware was built with DEBUG_ON_SERIAL_PORT. attribute() fills in
        # the module from the source path when the build tree knows which module compiled
        # that file, exactly as it does for a UBSan row.
        for report in guest_asserts(protocol, maps, build_dirs):
            rows += 1
            groups[attribute(report).group_key()].append(report)

    clusters = {}
    for base, reports in groups.items():
        runs, current, previous = [], [], None
        for report in sorted(reports, key=lambda r: r.line_number()):
            line = report.line_number()
            if current and previous is not None and line >= 0 and previous >= 0 \
                    and line - previous > CLUSTER_WINDOW:
                runs.append(current)
                current = []
            current.append(report)
            previous = line
        if current:
            runs.append(current)
        for index, run in enumerate(runs):
            key = base if len(runs) == 1 else (base[0], base[1], f'{base[2]}~{index}')
            cluster = Cluster(key)
            for report in run:
                cluster.add(report)
            clusters[key] = cluster
    return clusters, rows


# The 32-bit PCI hole. A BAR mapped here is device memory, and the shadow only covers
# RAM, so a write to a framebuffer reads a shadow byte that describes nothing. QEMU's VGA
# aperture sits at 0xC0000000 and produced thousands of "unknown-crash" reports that are
# a graphics driver doing its job.
MMIO_LOW, MMIO_HIGH = 0xC0000000, 0x100000000


def in_mmio(cluster):
    for report in cluster.reports:
        found = ADDR_RE.search(report.message)
        if found and MMIO_LOW <= int(found.group(1), 16) < MMIO_HIGH:
            return int(found.group(1), 16)
    return 0


def verdict(cluster, boot_keys, ubiquity):
    """Why a cluster is or is not a candidate firmware bug."""
    sample = cluster.reports[0]
    address = in_mmio(cluster)
    if address:
        return 'artefact', (f'the access is at {address:#x}, inside the PCI hole -- device '
                            f'memory, which the shadow does not describe')
    reason = match_reason(sample.module, HARNESS_SOURCES) or \
        match_reason(sample.path, HARNESS_SOURCES)
    if 'Firness' in sample.module:
        return 'harness', 'raised inside the harness image itself'
    if reason:
        return 'harness', reason
    reason = match_reason(sample.path, KNOWN_ARTEFACTS)
    if reason:
        return 'artefact', reason
    for klass, path, why, module in CLASS_ARTEFACTS:
        if klass not in cluster.klass.lower() or path not in sample.path:
            continue
        # A module condition narrows a path that is not an artefact on its own. BaseLib is
        # linked into everything and a re-read inside it is a real double fetch when the
        # caller validated the first read -- it is only noise when the caller is the
        # dispatcher walking its handler list.
        if module and module != cluster.module:
            continue
        return 'artefact', why
    if len(cluster.protocols) >= ubiquity:
        # Before the background drop below, not after. A real defect can be ubiquitous:
        # the ExportPackageList pointer overflow fires under every protocol that touches
        # HII, and it is still a defect. Ubiquity says the input did not provoke it, which
        # changes how it is investigated, not whether it counts.
        #
        # That was the intent and the order defeated it. These fire during boot and only
        # during boot, so "background" matched first and dropped them, and the section
        # this bucket feeds -- "Firmware, present on every run: a real defect can sit
        # here" -- printed None while the filter held 1896 hits at 8 sites. The one it
        # was hiding is the case this comment already named: HiiExportPackageLists
        # computes (UINT8 *)Buffer + ResultSize eight times with Buffer NULL, on the
        # size-query path every caller uses first. Nothing dereferences it, and adding a
        # non-zero integer to a null pointer is still undefined behaviour.
        return 'ubiquitous', (f'seen under {len(cluster.protocols)} unrelated protocols, '
                              f'so it is not input driven -- review, do not dismiss')
    if cluster.key in boot_keys and cluster.phases == {'boot'}:
        return 'background', 'only ever seen during boot, with no input in play'
    if 'boot' in cluster.phases:
        # Reported during the boot AND under fuzzing. The boot sighting happened before
        # any input existed, so whatever this is, an input did not provoke it -- but it is
        # not background either, because the harness reaches it too. The equality test
        # above sent it to 'candidate': on run 42749754933 that put
        # CpuHotplugSmm.efi|global-buffer-overflow|String.c in "Firmware, provoked by an
        # input" while "Firmware, present on every run" printed None, and its own boot
        # rows were in the same crashes.csv. firness.py's AtBoot column says the same
        # thing and nothing here read it.
        return 'ubiquitous', (f'also reported during the boot, before any input was fed, '
                              f'so the input did not provoke it -- review, do not '
                              f'dismiss')
    return 'candidate', ''


VERDICT_NOTE = {
    'candidate': 'input driven, in firmware code',
    'ubiquitous': 'present regardless of the input',
    'harness': 'the harness, not the firmware',
    'artefact': 'how that code works, not a defect',
}


# A CPU exception carries a module and an offset and nothing else -- no source file, no
# line -- because the fault is reported by the exception handler rather than by a
# sanitizer that knows where it is. The .debug image beside the build turns that offset
# into a function and a line, which is the difference between "DxeCore+0x170f2" and
# "CoreGetProtocolInterface at Handle.c:1013". It needs the build that produced the
# running firmware: pass --build a tree whose Build directory is present, which for a
# campaign means running this inside the image rather than on the host.
# Tried in order. The absolute path is where the campaign image keeps it, which is why
# triage run INSIDE the image has always symbolised and triage run on the host never did --
# neither of the first two exists here, and the failure is silent, so every CPU exception
# rendered as "no source" with nothing saying the symbolizer was missing. addr2line is the
# fallback that is actually installed on a plain host; it takes different flags and resolves
# inlined frames less well, so it goes last.
SYMBOLIZERS = ('/workspace/llvm-15.0.7/build/bin/llvm-symbolizer', 'llvm-symbolizer',
               'llvm-symbolizer-15', 'llvm-symbolizer-14', 'addr2line')


def _symbolizer_argv(tool, debug, addr):
    if os.path.basename(tool).startswith('addr2line'):
        return [tool, '--exe=' + debug, '--functions', '--demangle', addr]
    return [tool, f'--obj={debug}', '--functions=linkage', '--demangle', addr]
OFFSET = re.compile(r'^\+0x([0-9a-fA-F]+)$')
_DEBUG_INDEX = None
_OFFSET_CACHE = {}


def _debug_index(build_dirs):
    """module name -> the .debug beside it, for every build dir given."""
    global _DEBUG_INDEX
    if _DEBUG_INDEX is None:
        _DEBUG_INDEX = {}
        for root in build_dirs:
            # Walk <root>/Build when that exists, and otherwise <root> itself. Only the
            # first was tried before, so handing this the output directory that actually
            # holds the .debug files -- Build/OvmfX64/DEBUG_CLANGSAN/X64, which is what
            # you get from a docker cp of a campaign image -- indexed nothing, and every
            # CPU exception rendered as "no source -- symbolise the offset" with no hint
            # that the build dir was the problem.
            starts = [os.path.join(root, 'Build')]
            if not os.path.isdir(starts[0]):
                starts = [root]
            for start in starts:
                for base, _dirs, files in os.walk(start):
                    for name in files:
                        if name.endswith('.debug'):
                            _DEBUG_INDEX.setdefault(name[:-len('.debug')],
                                                    os.path.join(base, name))
    return _DEBUG_INDEX


_CALIBRATION = {}


def calibrate(serial_logs, build_dirs):
    """Learn the runtime-to-.debug offset for every module this boot dispatched.

    Both kinds of site reach symbolise_offset as an offset from the image's load
    address: the exception handler measures it that way, and an ASan ip resolves to it.
    Neither is the address the .debug file knows, so the delta is applied in the one
    place both of them pass through.
    """
    if build_dirs:
        _CALIBRATION.update(resolve_modules.calibration(serial_logs, build_dirs))


def symbolise_offset(module, site, build_dirs):
    """"Function -- path:line" for "+0xNNN" in module, or '' when it cannot be resolved.

    Nothing here is fatal. A tree built without debug output, a symbolizer that is not
    installed, an offset in a module nobody kept the .debug for: each just leaves the
    offset as the only thing said about the site, which is what it was before.
    """
    found = OFFSET.match((site or '').strip())
    if not found or not module or not build_dirs:
        return ''
    name = module[:-len('.efi')] if module.endswith('.efi') else module
    # the delta belongs in the key: the same offset in the same module resolves
    # differently once that module has been calibrated
    key = (module, site, _CALIBRATION.get(name, 0))
    if key in _OFFSET_CACHE:
        return _OFFSET_CACHE[key]
    debug = _debug_index(build_dirs).get(name)
    answer = ''
    if debug:
        # Uncalibrated, the offset still names a function -- just the wrong one, most of
        # the time. 0 is the honest default: without a dispatch line for this module
        # there is nothing to calibrate against.
        address = int(found.group(1), 16) + _CALIBRATION.get(name, 0)
        for tool in SYMBOLIZERS:
            try:
                done = subprocess.run(
                    _symbolizer_argv(tool, debug, hex(address)),
                    capture_output=True, text=True, timeout=30)
            except (OSError, subprocess.SubprocessError):
                continue
            lines = [l.strip() for l in done.stdout.splitlines() if l.strip()]
            if len(lines) >= 2 and not lines[0].startswith('??'):
                func, where = lines[0], lines[1]
                for marker in ('/edk2/', '/edk2-master/', '/edk2-platforms/'):
                    if marker in where:
                        where = where.split(marker, 1)[1]
                        break
                # a trailing ":0:0" is "no line known"; rstrip would eat the zero off
                # a real line number like ":10:0" and leave ":1"
                answer = f'{func} -- {re.sub(r"(:0)+$", "", where)}'
            if answer:
                break
    _OFFSET_CACHE[key] = answer
    return answer


def cluster_source(cluster, build_dirs):
    """Where a reader can open this cluster's code, as a repo-relative path.

    The markdown table and the JSON payload both need this, and the JSON one is what
    file_issues.py builds an issue body from. Only the table computed it, so a CPU
    exception was named in the table -- "CoreInsertEventTimer -- Core/Dxe/Event/Timer.c:54"
    -- and then filed as an issue that said "No source line to show" and told the reader to
    symbolise an offset this function had already symbolised. One definition, both callers.
    """
    if cluster.klass.startswith('cpu-exception'):
        # the fault comes from the exception handler, which knows the address and
        # nothing else; the .debug beside the build knows the rest
        return (symbolise_offset(cluster.module, cluster.site, build_dirs)
                or 'no source -- symbolise the offset')
    where = cluster.reports[0].path or ''
    # the repo-relative path is what a reader can actually open
    for marker in ('/edk2/', '/edk2-platforms/'):
        if marker in where:
            return where.split(marker, 1)[1]
    return where


def source_crossings(root):
    """Peer-protocol crossings the analyzer found, from every campaign's smi-call-edges.json.

    These are not sanitizer reports and were not provoked by an input: they are places in
    the source where an SMI handler hands caller-controlled data to another module's
    interface, which arrives there without the validation that module does on its own SMI
    entry path. Read into bugs.md because the alternative is where they lived before --
    campaigns/<name>/log.txt, which nothing in the pipeline output points at. Measured on
    EVAL-1 run 42310220335: the two crossings below were in that file, and the run summary,
    the triage output and bugs.md all said nothing about them.
    """
    #
    # The generator does not sit in the same place in a checkout and in the CI image.
    # ci.Dockerfile puts it at /workspace/harness_generator and the scripts at
    # /workspace/scripts, while a checkout has firness/harness_generator beside scripts/.
    # Only the checkout layout was tried, so in the image the import raised, the except
    # returned [], and run 42483193618 wrote "None." into bugs.md while log.txt in the same
    # run reported two crossings. A silent failure that reads as a clean result is the
    # same defect this section exists to fix, so the miss is reported rather than swallowed.
    #
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(os.path.dirname(here), 'firness', 'harness_generator'),
        os.path.join(os.path.dirname(here), 'harness_generator'),
        os.path.join(here, 'harness_generator'),
    ]
    cross_module_edges = None
    for candidate in candidates:
        # Defensive only, and not covered by a check: in any layout where the first
        # candidate exists the later ones are never reached, so a check could only
        # falsify this by contriving a tree where it does not -- and a check that passes
        # whatever the code does is worse than none. It is here so a candidate that does
        # not hold the package cannot be left on sys.path for an unrelated import to
        # resolve out of.
        if not os.path.isdir(os.path.join(candidate, 'data_analysis')):
            continue
        if candidate not in sys.path:
            sys.path.insert(0, candidate)
        try:
            from data_analysis.cross_module import cross_module_edges
            break
        except Exception:
            cross_module_edges = None

    edge_files = sorted(glob.glob(os.path.join(root, '*', 'smi-call-edges.json')))
    if cross_module_edges is None:
        if edge_files:
            print(f'::warning::found {len(edge_files)} smi-call-edges.json but could not '
                  f'import data_analysis.cross_module from any of {candidates} -- the '
                  f'source findings section will be empty for that reason, not because '
                  f'there are none')
        return []

    seen, findings = set(), []
    for path in edge_files:
        try:
            with open(path, 'r') as handle:
                edges = json.load(handle)
        except (OSError, ValueError):
            continue
        if not isinstance(edges, list):
            continue
        for find in cross_module_edges(edges):
            if find.get('kind') != 'peer-protocol':
                continue
            # Same handler and callee in two campaigns is one place in the source.
            key = (find['handler'], find['service'], find['function'])
            if key in seen:
                continue
            seen.add(key)
            findings.append(find)
    return findings


# Libraries whose code is instrumented but which no module owns. A finding here names the
# interceptor, never the code that chose its arguments.
CALLER_BLIND_LIBS = (
    'MdePkg/Library/BaseLib/',
    'MdePkg/Library/BaseMemoryLib',
    'MdePkg/Library/BasePrintLib/',
)


def likely_callers(cluster_path, module, crossings, only=()):
    """Handlers the source says pass caller-controlled data, for a library-attributed find.

    Reports carry one frame -- __builtin_return_address(N) for N > 0 is documented unsafe
    and a nine-frame walk #GP'd inside __asan_store1, which capped every boot at one
    finding -- so a fault inside StrLen is attributed to the image StrLen was linked into
    and never to the code that handed it the pointer. That is why issues #47 and #48 were
    filed against VariableSmm.efi when the defect is in RWVariable.c.

    The frame walk is not coming back for that. The static crossings answer the same
    question without touching a stack: if a handler in this campaign hands caller-controlled
    data to another module's interface, it is worth reading next to a library fault in that
    module. This is a pointer and says so -- it does not claim the handler is the cause,
    because nothing here proves this fault came through that call.

    `only` narrows it to the handlers whose parameter block actually has a field at the
    offset the report named. Without that this was the same paragraph on every row of
    every campaign -- a list of handlers pasted beside a finding that had nothing to do
    with most of them -- which is a list a reader stops reading. A handler whose comm
    buffer has no field where the double fetch happened did not do this one.
    """
    if not crossings or not module:
        return []
    if not any(lib in (cluster_path or '') for lib in CALLER_BLIND_LIBS):
        return []
    picked = [f for f in crossings if not only or f['handler'] in only]
    if not picked:
        return []
    return sorted({f"{f['handler']} -> {f['service']}->{f['function']}" for f in picked})


def write_source_section(handle, findings):
    """The source-derived findings, kept clearly apart from the sanitizer ones."""
    handle.write('## Firmware, found in the source\n\n')
    handle.write('Not sanitizer reports and not provoked by an input: an SMI handler hands '
                 'caller-controlled data to another module\'s interface, so the callee '
                 'receives it without the checks it applies on its own SMI entry path. '
                 'A row here is a place to read, not a confirmed defect -- a handler that '
                 'validates thoroughly before the call looks the same from here.\n\n')
    if not findings:
        handle.write('None.\n\n')
        return
    handle.write('| handler | source | reaches | argument | derived from |\n'
                 '|---|---|---|---|---|\n')

    def repo_path(path):
        """The package-relative path, as the sanitizer rows in this file already show.

        The analyzer records the path it compiled, which is inside the builder container
        (/workspace/tmp/edk2/OvmfPkg/...). Printing that beside
        `MdePkg/Library/BaseLib/String.c` in the table above invites the reader to think
        the two came from different trees.
        """
        parts = (path or '').replace('\\', '/').split('/')
        for index, part in enumerate(parts):
            if part.endswith('Pkg'):
                return '/'.join(parts[index:])
        return parts[-1] if parts else ''

    for find in findings:
        for carry in find['carries']:
            flag = ' **offset arithmetic**' if carry['offset_arithmetic'] else ''
            shown = (carry['assignment'] or carry['variable'] or '').replace('|', r'\|')
            handle.write(f"| {find['handler']} | `{repo_path(find['file'])}` | "
                         f"{find['service']}->{find['function']} | {carry['arg']} "
                         f"{carry['data_type']} | `{shown}`{flag} |\n")
    handle.write('\n')


def write_markdown(path, title, preamble, buckets, rows, clusters, build_dirs=(),
                   crossings=()):
    """One row per bug, with enough beside it to act on without rerunning anything."""
    crossing_list = list(crossings)

    def line(cluster, reason, verdict):
        detail = cluster.detail() or ''
        note = reason or VERDICT_NOTE.get(verdict, '')
        where = cluster_source(cluster, build_dirs)
        callers = likely_callers(where, cluster.module, crossing_list,
                                 cluster.field_handlers())
        if callers:
            note += (' -- the report names the library, not the caller; the source says '
                     + '; '.join(callers) + ' passes caller-controlled data into another '
                     'module, so read that beside this')
        protocols = ', '.join(sorted(cluster.protocols)[:4])
        if len(cluster.protocols) > 4:
            protocols += f' +{len(cluster.protocols) - 4}'
        return (f'| {cluster.module or "(unattributed)"} | `{where}` | {cluster.site} | '
                f'{cluster.klass} | {cluster.hits} | {protocols} | {detail} {note} |')

    with open(path, 'w') as handle:
        handle.write(f'# {title}\n\n{preamble}\n\n')
        handle.write(f'{rows} report rows from the campaigns, clustered into '
                     f'{clusters} distinct sites.\n\n')
        # Firmware only. The harness and artefact buckets are counted, not listed: a
        # report raised inside Firness.efi is not a bug in the thing under test, and
        # printing it beside real findings is how a solution count gets quoted as a bug
        # count. The count stays so the filtering is visible rather than silent.
        dropped = sum(len(buckets.get(k, [])) for k in ('harness', 'artefact', 'background'))
        if dropped:
            handle.write(f'{dropped} further cluster(s) were the harness itself, a library '
                         f'linked into it that the firmware never calls, or code whose '
                         f'reports are inherent to what it does. Run `bug_report.py '
                         f'--show-filtered` to see them with the reason for each.\n\n')
        for verdict, heading, blurb in (
            ('candidate', 'Firmware, provoked by an input',
             'Reached because a testcase drove it there. Ordered by severity.'),
            ('ubiquitous', 'Firmware, present on every run',
             'In firmware code but not provoked by any input -- they fire on a plain '
             'boot. A real defect can sit here; confirm by reading the source.'),
        ):
            entries = sorted(buckets.get(verdict, []),
                             key=lambda pair: (-pair[0].severity(), -pair[0].hits))
            handle.write(f'## {heading}\n\n{blurb}\n\n')
            if not entries:
                handle.write('None.\n\n')
                continue
            handle.write('| module | source | location | bug type | hits | reached by | '
                         'detail |\n|---|---|---|---|---|---|---|\n')
            for cluster, reason in entries:
                handle.write(line(cluster, reason, verdict) + '\n')
            handle.write('\n')
        write_source_section(handle, list(crossings))


def main():
    parser = argparse.ArgumentParser(
        description='Cluster sanitizer reports into bugs and drop the harness ones')
    parser.add_argument('-r', '--root', required=True,
                        help='directory holding one subdirectory per protocol')
    parser.add_argument('--ubiquity', type=int, default=8,
                        help='a cluster under this many protocols or more is background '
                             '(default 8)')
    parser.add_argument('--json', default='', help='write the full result here')
    parser.add_argument('--markdown', default='', help='write a readable bug list here')
    parser.add_argument('--title', default='Bugs', help='heading for --markdown')
    parser.add_argument('--preamble', default='', help='paragraph under the heading')
    parser.add_argument('--show-filtered', action='store_true',
                        help='list every filtered cluster, not just the counts')
    parser.add_argument('--known', default='',
                        help='a json list of cluster ids already accounted for; anything '
                             'not in it is reported as new')
    parser.add_argument('--build', action='append', default=[],
                        help='a build tree, so an unattributed ip can be resolved to the '
                             'driver that issued it (repeatable)')
    args = parser.parse_args()

    if not os.path.isdir(args.root):
        print(f'no such directory: {args.root}', file=sys.stderr)
        return 2
    clusters, rows = load(args.root, args.build)
    if not clusters:
        # A campaign that ran and found nothing is a result: the version was fuzzed and
        # the sanitizer reported nothing the filters did not explain. Only a root with no
        # campaigns in it at all is a failure -- "there were no crashes" and "nothing ran"
        # must not look the same to an unattended run.
        campaigns = [d for d in sorted(os.listdir(args.root))
                     if os.path.isdir(os.path.join(args.root, d))]
        if not campaigns:
            print(f'no campaign directories under {args.root}', file=sys.stderr)
            return 1
        print(f'{len(campaigns)} campaign(s) under {args.root} and no crashes.csv in any '
              f'of them: nothing was reported')
        empty = {'rows': [], 'clusters': 0, 'candidates': [], 'ubiquitous': [],
                 'filtered': {'harness': [], 'artefact': [], 'background': []}}
        if args.json:
            with open(args.json, 'w') as handle:
                json.dump(empty, handle, indent=2)
            print(f'Wrote {args.json}')
        if args.markdown:
            with open(args.markdown, 'w') as handle:
                handle.write(f'# {args.title or "Bug report"}\n\n'
                             f'{len(campaigns)} campaign(s) produced no sanitizer '
                             f'reports.\n')
            print(f'Wrote {args.markdown}')
        return 0

    boot_keys = {k for k, c in clusters.items() if 'boot' in c.phases}
    buckets = defaultdict(list)
    for cluster in clusters.values():
        kind, reason = verdict(cluster, boot_keys, args.ubiquity)
        buckets[kind].append((cluster, reason))

    known = set()
    if args.known and os.path.isfile(args.known):
        with open(args.known) as handle:
            known = set(json.load(handle))

    print(f'{rows} report row(s) -> {len(clusters)} cluster(s)')
    for kind in ('harness', 'artefact', 'background'):
        print(f'  filtered as {kind:11} {len(buckets[kind]):4}')
    print(f'  not input driven      {len(buckets["ubiquitous"]):4}  (reported below)')
    print(f'  candidates            {len(buckets["candidate"]):4}')

    def cluster_id(cluster):
        # The fingerprint is what stops a weekly run refiling an issue already open, so
        # nothing in it may move between builds. A CPU exception's key IS the offset --
        # its report carries no source file at all -- so the id contained "+0x30d63" and
        # would have filed a fresh issue for the same fault every build. Key it on the
        # source the .debug resolves the offset to, and keep the offset only when nothing
        # resolved it, where an unstable id is still better than lumping faults together.
        part = cluster.key[2]
        if OFFSET.match(str(part).strip()):
            path = cluster_source(cluster, args.build).split(' -- ')[-1].strip()
            if '/' in path:
                part = os.path.basename(path).split(':')[0]
        return f'{cluster.module}|{cluster.klass}|{part}'

    print('\n=== candidate bugs, most severe first ===')
    candidates = sorted(buckets['candidate'],
                        key=lambda pair: (-pair[0].severity(), -pair[0].hits))
    if not candidates:
        print('  (none)')
    new_ids = []
    for cluster, _ in candidates:
        ident = cluster_id(cluster)
        flag = ''
        if known:
            flag = '  [NEW]' if ident not in known else '  [known]'
            if ident not in known:
                new_ids.append(ident)
        detail = cluster.detail()
        print(f'  sev{cluster.severity()} x{cluster.hits:<5} {cluster.module:22} '
              f'{cluster.site:34} {cluster.klass:22}{flag}')
        if detail:
            print(f'          {detail}')
        print(f'          protocols: {", ".join(sorted(cluster.protocols)[:6])}'
              f'{" ..." if len(cluster.protocols) > 6 else ""}')

    if buckets['ubiquitous']:
        print('\n=== present regardless of the input, most severe first ===')
        print('    These are in firmware code and were not provoked by a testcase. A real')
        print('    defect can sit here -- confirm by reading the source, not by rerunning.')
        for cluster, reason in sorted(buckets['ubiquitous'],
                                      key=lambda p: (-p[0].severity(), -p[0].hits)):
            print(f'  sev{cluster.severity()} x{cluster.hits:<5} {cluster.module:22} '
                  f'{cluster.site:34} {cluster.klass}')
            print(f'          {len(cluster.protocols)} protocols')

    if args.show_filtered:
        for kind in ('harness', 'artefact', 'background'):
            if not buckets[kind]:
                continue
            print(f'\n=== filtered as {kind} ===')
            for cluster, reason in sorted(buckets[kind], key=lambda p: -p[0].hits):
                print(f'  x{cluster.hits:<5} {cluster.module:22} {cluster.site:34} '
                      f'{cluster.klass}')
                print(f'          {reason}')

    if known:
        print(f'\nnew clusters against the known set: {len(new_ids)}')
        for ident in new_ids:
            print(f'  {ident}')

    if args.markdown:
        write_markdown(args.markdown, args.title, args.preamble, buckets, rows,
                       len(clusters), args.build, source_crossings(args.root))
        print(f'\nWrote {args.markdown}')

    if args.json:
        payload = {
            'rows': rows,
            'clusters': len(clusters),
            'candidates': [
                {'id': cluster_id(c), 'module': c.module, 'site': c.site,
                 'class': c.klass, 'hits': c.hits, 'severity': c.severity(),
                 'detail': c.detail(), 'protocols': sorted(c.protocols),
                 'source': cluster_source(c, args.build),
                 # Structured as well as in the detail text, so file_issues.py and
                 # anything else reading bugs.json can key on the field rather than
                 # re-parse a sentence. Absent on every class that has no untrusted
                 # buffer behind it, which is all of them but this one.
                 **untrusted_payload(c)}
                for c, _ in candidates],
            'ubiquitous': [
                {'id': cluster_id(c), 'module': c.module, 'site': c.site,
                 'class': c.klass, 'hits': c.hits, 'severity': c.severity(),
                 'protocols': sorted(c.protocols)}
                for c, _ in buckets['ubiquitous']],
            'filtered': {
                kind: [{'id': cluster_id(c), 'module': c.module, 'site': c.site,
                        'class': c.klass, 'hits': c.hits, 'reason': reason}
                       for c, reason in buckets[kind]]
                for kind in ('harness', 'artefact', 'background')},
        }
        with open(args.json, 'w') as handle:
            json.dump(payload, handle, indent=2)
        print(f'\nWrote {args.json}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
