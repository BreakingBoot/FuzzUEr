# Bugs found under QEMU

145 protocols, 600s each, on OVMF built from this tree at ASAN_SCOPE=full. Regenerate with

    python3 scripts/bug_report.py -r <campaign dir> --build eval_source/edk2/Build/OvmfX64 --markdown results/bugs-qemu.md

**Reading a row.** `module` is the driver the report belongs to and `source` is the file it was raised in; for an `AsanMemoryLibRepStr` wrapper that file is the interceptor and the bug is in the caller. An ASan report is placed by its faulting address against the images the boot loaded; a UBSan report has no address and is placed by the build tree instead.

**Severity** ranks by what an attacker gets: a write past an allocation above a read, both above arithmetic on a pointer that is never dereferenced.

1518 report rows from the campaigns, clustered into 13 distinct sites.

8 further cluster(s) were the harness itself, a library linked into it that the firmware never calls, or code whose reports are inherent to what it does. Run `bug_report.py --show-filtered` to see them with the reason for each.

## Firmware, provoked by an input

Reached because a testcase drove it there. Ordered by severity.

| module | source | location | bug type | hits | reached by | detail |
|---|---|---|---|---|---|---|
| EbcDxe.efi | `no source -- symbolise the offset` | +0xbae5 | cpu-exception (#GP) | 6 | EdkiiPeCoffImageEmulator | 6 fault(s) at EbcDxe+0xbae5 input driven, in firmware code |
| DxeCore.efi | `MdeModulePkg/Core/Dxe/FwVol/FwVolRead.c` | FwVolRead.c:146-155 (2 sites) | null-pointer-read | 2884 | EfiFirmwareVolume2 | load of null pointer of type 'EFI_FV_FILETYPE' (aka 'unsigned char') across 2 types input driven, in firmware code |
| EnglishDxe.efi | `MdeModulePkg/Universal/Disk/UnicodeCollation/EnglishDxe/UnicodeCollationEng.c` | UnicodeCollationEng.c:211 | null-pointer-read | 790 | EfiUnicodeCollation | load of null pointer of type 'CHAR16' (aka 'unsigned short') input driven, in firmware code |
| AtaBusDxe.efi | `MdeModulePkg/Bus/Ata/AtaBusDxe/AtaBus.c` | AtaBus.c:1380 | null-pointer-read | 161 | EfiDiskInfo | load of null pointer of type 'UINT32' (aka 'unsigned int') input driven, in firmware code |
| QemuVideoDxe.efi | `MdeModulePkg/Library/FrameBufferBltLib/FrameBufferBltLib.c` | FrameBufferBltLib.c:526 | null-pointer-arithmetic | 76 | EfiGraphicsOutput | offset applied to a null pointer base 0x0000000000000000 result 0x0000000000000000 input driven, in firmware code |

## Firmware, present on every run

In firmware code but not provoked by any input -- they fire on a plain boot. A real defect can sit here; confirm by reading the source.

None.

