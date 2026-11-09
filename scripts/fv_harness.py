"""Place the generated harness in the firmware volume, for the dxe harness timing.

WHY THIS EXISTS. The harness is normally a UEFI_APPLICATION written to the ESP as
EFI/BOOT/BOOTX64.EFI, so BDS launches it as a boot option. That is after EndOfDxe, and a
handler that latches on EndOfDxe is already shut. Measured on EVAL-1 run 42633354713's
campaigns/*/qemu/debugcon.log:

    line 1688  SmmEndOfDxeHandler
    line 3183  FSOpen: Open '\\EFI\\BOOT\\BOOTX64.EFI' Success
    line 3188  [Security] 3rd party image[0] can be loaded after EndOfDxe: ...BOOTX64.EFI
               SmmFtwHandler: Not safe to do the operation ... after End Of Dxe, so
               access denied!

The latch closes 1495 narration lines before the harness exists, and no boot-time
mechanism gets ahead of it: OVMF signals EndOfDxe in PlatformBootManagerBeforeConsole
(BdsPlatform.c:451), which BDS calls BEFORE it processes Driver#### options
(BdsEntry.c:899), and SMM locks down immediately after. The only way earlier is to be a
DXE_DRIVER in the firmware volume.

In this tree that unlocks SmmSpi entirely, FaultTolerantWriteSmm, two paths in Tcg2Smm,
and 3 of VariableSmm's 13 commands including INIT_RUNTIME_VARIABLE_CACHE_CONTEXT.

TWO HAZARDS THIS FILE IS WRITTEN AROUND.

edk2 is CRLF throughout and Python text mode silently rewrites it -- a whole-file rewrite
once cost a merge its anchor. Everything here reads and writes BYTES.

OvmfPkgX64.dsc holds its whole body TWICE, and apply_asan.dedup_sections() finds the
duplicate by the longest repeated run of section HEADERS. So: no new section header is
ever added, and the component goes into EVERY [Components] section rather than one, so
whichever copy survives dedup carries it.
"""

import os
import re

# The INF the generator writes, relative to the edk2 workspace.
HARNESS_INF = 'Firness/FirnessHarnesses.inf'

# Resolutions OvmfPkgX64.dsc does not already provide for a DXE_DRIVER. Checked against
# the real file: of everything the harness INF asks for, only RegisterFilterLib is absent
# (UefiDriverEntryPoint, TimeBaseLib, HiiLib, PerformanceLib, HobLib, DevicePathLib and
# MemoryAllocationLib are all resolved there). AsanLib is not a resolution but a NULL
# link, and it is what opens the window that turns a sanitizer report into a solution --
# without it AsanSetFuzzingActive resolves to the weak no-op in FirnessHarnesses.h and
# findings go to the serial port and nowhere else.
COMPONENT_OVERRIDES = (
    'RegisterFilterLib|MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf',
    'NULL|MdeModulePkg/Library/AsanLib/AsanLib.inf',
)

_MARK = b'# FuzzUEr: harness in the FV, for the dxe harness timing'


def _eol(data: bytes) -> bytes:
    """The line ending this file actually uses, so an edit matches it."""
    return b'\r\n' if data.count(b'\r\n') > data.count(b'\n') - data.count(b'\r\n') else b'\n'


def component_block(eol: bytes) -> bytes:
    lines = [_MARK,
             b'  ' + HARNESS_INF.encode() + b' {',
             b'    <LibraryClasses>']
    for one in COMPONENT_OVERRIDES:
        lines.append(b'      ' + one.encode())
    lines.append(b'  }')
    return eol.join(lines) + eol


def add_to_dsc(path: str) -> int:
    """Add the harness component to every [Components] section. Returns how many.

    Idempotent: a tree that already carries it is left alone, because the port runs over
    a tree that may already have been ported.
    """
    with open(path, 'rb') as handle:
        data = handle.read()
    if _MARK in data:
        return 0
    eol = _eol(data)
    block = component_block(eol)
    out, added = [], 0
    for line in data.split(eol):
        out.append(line)
        if line.strip() == b'[Components]':
            out.append(block.rstrip(eol))
            added += 1
    if added:
        with open(path, 'wb') as handle:
            handle.write(eol.join(out))
    return added


def add_to_fdf(path: str) -> int:
    """Add the harness to [FV.DXEFV], after the last UNCONDITIONAL INF line there.

    After the last one rather than right after the header, because the header is followed
    by the FV's own attribute lines and an INF among those is not valid; and because an
    FDF's INF order is the order the FV lays modules out, so appending cannot displace
    anything.

    Unconditional matters, and this is the bug the first version of this function had.
    OvmfPkgX64.fdf's DXEFV ends inside

        !if $(CC_MEASUREMENT_ENABLE) == TRUE
        INF SecurityPkg/Tcg/TdTcg2Dxe/TdTcg2Dxe.inf
        !endif

    so "the last INF line" put the harness between that INF and the !endif. The harness
    would then be in the FV only when CC measurement is on, which by default it is not --
    the firmware would build cleanly, boot cleanly, and simply not contain the harness,
    and the campaign would report that every boot spent its budget without reaching it.
    Tracking !if depth and taking the last INF at depth 0 is what makes the placement
    unconditional.
    """
    with open(path, 'rb') as handle:
        data = handle.read()
    if _MARK in data:
        return 0
    eol = _eol(data)
    lines = data.split(eol)

    start = None
    for index, line in enumerate(lines):
        if line.strip() == b'[FV.DXEFV]':
            start = index
            break
    if start is None:
        return 0

    depth, last_inf = 0, None
    for index in range(start + 1, len(lines)):
        stripped = lines[index].strip()
        if stripped.startswith(b'[') and stripped.endswith(b']'):
            break
        if re.match(rb'^!\s*(if|ifdef|ifndef)\b', stripped):
            depth += 1
            continue
        if re.match(rb'^!\s*endif\b', stripped):
            depth = max(0, depth - 1)
            continue
        # !else and !elseif keep the depth they are in
        if depth == 0 and re.match(rb'^INF\b', stripped):
            last_inf = index
    if last_inf is None:
        return 0

    insert = [_MARK, b'INF  ' + HARNESS_INF.encode()]
    lines[last_inf + 1:last_inf + 1] = insert
    with open(path, 'wb') as handle:
        handle.write(eol.join(lines))
    return 1


def place(edk2_dir: str, dsc: str = 'OvmfPkg/OvmfPkgX64.dsc',
          fdf: str = 'OvmfPkg/OvmfPkgX64.fdf'):
    """Put the harness in the DXE FV. Returns (components added, fdf entries added)."""
    dsc_path = os.path.join(edk2_dir, dsc)
    fdf_path = os.path.join(edk2_dir, fdf)
    for one in (dsc_path, fdf_path):
        if not os.path.isfile(one):
            raise FileNotFoundError(one)
    return add_to_dsc(dsc_path), add_to_fdf(fdf_path)
