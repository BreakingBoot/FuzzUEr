# Bugs found under QEMU

12 protocols, 600s each, on OVMF built from this tree at ASAN_SCOPE=full with DEBUG_ON_SERIAL_PORT and the IPv6 stack enabled. Regenerate with

    python3 scripts/bug_report.py -r <campaign dir> --build eval_source/edk2/Build/OvmfX64 --markdown results/bugs-qemu.md

**Reading a row.** `module` is the driver the report belongs to and `source` is the file it was raised in; for an `AsanMemoryLibRepStr` wrapper that file is the interceptor and the bug is in the caller. Every row here names a driver. An ASan report gives the faulting address, which resolves against the images the DXE core announced during that boot -- that needs the firmware built with `-D DEBUG_ON_SERIAL_PORT`, or the load addresses go to the ISA debug port and the capture never sees them. A UBSan report has no address, and its module comes from the build tree instead.

**Severity** ranks by what an attacker gets: a write past an allocation above a read, both above arithmetic on a pointer that is never dereferenced.

**Comparability.** These 12 protocols are installed on both this firmware and the Simics board. `scripts/protocol_presence.py --against --matched` writes the set present on both; outside it a difference in findings is a difference in the two firmware builds rather than in the backends.

137 report rows from the campaigns, clustered into 8 distinct sites.

5 further cluster(s) were the harness itself, a library linked into it that the firmware never calls, or code whose reports are inherent to what it does. Run `bug_report.py --show-filtered` to see them with the reason for each.

## Firmware, provoked by an input

Reached because a testcase drove it there. Ordered by severity.

| module | source | location | bug type | hits | reached by | detail |
|---|---|---|---|---|---|---|
| EnglishDxe.efi | `MdeModulePkg/Universal/Disk/UnicodeCollation/EnglishDxe/UnicodeCollationEng.c` | UnicodeCollationEng.c:211 | null-pointer-read | 861 | EfiUnicodeCollation | load of null pointer of type 'CHAR16' (aka 'unsigned short') input driven, in firmware code |
| QemuVideoDxe.efi | `MdeModulePkg/Library/FrameBufferBltLib/FrameBufferBltLib.c` | FrameBufferBltLib.c:526 | null-pointer-arithmetic | 532 | EfiGraphicsOutput | offset applied to a null pointer base 0x0000000000000000 result 0x0000000000000000 input driven, in firmware code |
| DiskIoDxe.efi | `MdeModulePkg/Universal/Disk/DiskIoDxe/DiskIo.c` | DiskIo.c:617 | null-pointer-arithmetic | 28 | EfiDiskIo2 | offset applied to a null pointer base 0x0000000000000000 result 0x00000000000006F2 input driven, in firmware code |

## Firmware, present on every run

In firmware code but not provoked by any input -- they fire on a plain boot. A real defect can sit here; confirm by reading the source.

None.

