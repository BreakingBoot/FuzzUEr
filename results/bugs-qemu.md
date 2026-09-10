# Bugs found under QEMU

13 campaigns at 600s each on OVMF built from this tree at ASAN_SCOPE=full, 265 of 312 modules instrumented. Regenerate with

    python3 scripts/bug_report.py -r <campaign dir> --markdown results/bugs-qemu.md

**Reading a row.** `module` is often empty here and `source` carries the attribution instead: DXE announces each image it loads on the ISA debug port, not on the serial capture these reports come from, so an address cannot be tied back to an image. A row whose location is an offset (`+0x1be8f`) is a CPU fault rather than a sanitizer report; symbolise it with

    llvm-symbolizer --obj=Build/OvmfX64/DEBUG_CLANGSAN/X64/<path>/<Module>.debug --functions=linkage <offset>

Both fault rows resolve, and both are the harness rather than firmware: `DxeCore+0x35671` is `CoreSignalEvent` at Event.c:526, reached by BlockIo2 passing a fuzzed `EFI_EVENT`, and `HiiDatabase+0x1be8f` is `IsHiiHandleValid` at Database.c:135, reached by a fuzzed `EFI_HII_HANDLE`. An opaque handle fuzzed as a raw value is a wild pointer the firmware can only NULL-check before dereferencing.

**Overlap with Simics.** `UnicodeCollationEng.c:211`, `FrameBufferBltLib.c:526` and `DiskIo.c:617` are all in the Simics list too -- same file, same line, same bug type.

187 report rows from the campaigns, clustered into 9 distinct sites.

4 further cluster(s) were the harness itself, a library linked into it that the firmware never calls, or code whose reports are inherent to what it does. Run `bug_report.py --show-filtered` to see them with the reason for each.

## Firmware, provoked by an input

Reached because a testcase drove it there. Ordered by severity.

| module | source | location | bug type | hits | reached by | detail |
|---|---|---|---|---|---|---|
| HiiDatabase.efi | `no source -- symbolise the offset` | +0x1be8f | cpu-exception (#GP) | 8 | EfiHiiString | 8 fault(s) at HiiDatabase+0x1be8f input driven, in firmware code |
| DxeCore.efi | `no source -- symbolise the offset` | +0x35671 | cpu-exception (#GP) | 1 | EfiBlockIo2 | 1 fault(s) at DxeCore+0x35671 input driven, in firmware code |
| (unattributed) | `MdeModulePkg/Universal/Disk/UnicodeCollation/EnglishDxe/UnicodeCollationEng.c` | UnicodeCollationEng.c:211 | null-pointer-read | 5667 | EfiUnicodeCollation, EfiUnicodeCollation_qmark2 | load of null pointer of type 'CHAR16' (aka 'unsigned short') input driven, in firmware code |
| (unattributed) | `MdeModulePkg/Library/FrameBufferBltLib/FrameBufferBltLib.c` | FrameBufferBltLib.c:526 | null-pointer-arithmetic | 1368 | EfiGraphicsOutput, EfiGraphicsOutput_qmark2 | offset applied to a null pointer base 0x0000000000000000 result 0x0000000000000000 input driven, in firmware code |
| (unattributed) | `MdeModulePkg/Universal/Disk/DiskIoDxe/DiskIo.c` | DiskIo.c:617 | null-pointer-arithmetic | 252 | EfiDiskIo2, EfiDiskIo2_qmark2 | offset applied to a null pointer base 0x0000000000000000 result 0x00000000000006F2 input driven, in firmware code |

## Firmware, present on every run

In firmware code but not provoked by any input -- they fire on a plain boot. A real defect can sit here; confirm by reading the source.

None.

