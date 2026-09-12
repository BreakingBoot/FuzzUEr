# Bugs found under Simics

145 protocols, 600s each, on BoardX58Ich10 firmware built from this tree. Regenerate with

    python3 scripts/bug_report.py -r <campaign dir> --build <Simics build tree> --markdown results/bugs-simics.md

**Reading a row.** `module` is the driver the report belongs to and `source` is the file it was raised in. Most rows are UBSan, which reports a file and a line and no address, so the module comes from the build tree.

**Severity** ranks by what an attacker gets: a write past an allocation above a read, both above arithmetic on a pointer that is never dereferenced.

**Two classes that look like firmware defects and are not.** A size-driven finding should be checked against the generated harness first, and an opaque handle fuzzed as a raw value is a wild pointer the firmware can only NULL-check.

2305 report rows from the campaigns, clustered into 42 distinct sites.

11 further cluster(s) were the harness itself, a library linked into it that the firmware never calls, or code whose reports are inherent to what it does. Run `bug_report.py --show-filtered` to see them with the reason for each.

## Firmware, provoked by an input

Reached because a testcase drove it there. Ordered by severity.

| module | source | location | bug type | hits | reached by | detail |
|---|---|---|---|---|---|---|
| DxeCore.efi | `MdeModulePkg/Core/Dxe/FwVolBlock/FwVolBlock.c` | FwVolBlock.c:217 | null-pointer-write | 42 | EfiFirmwareVolumeBlock | store to null pointer of type 'UINTN' (aka 'unsigned long long') input driven, in firmware code |
| HiiDatabase.efi | `MdeModulePkg/Universal/HiiDatabaseDxe/Font.c` | Font.c:1989 | pointer-arithmetic-overflow | 3 | EfiHiiFont | pointer index expression overflowed base 0x00000000D9A9DCA8 result 0x00000000D9A9DC9E input driven, in firmware code |
| PcdDxe.efi | `MdeModulePkg/Universal/PCD/Dxe/Pcd.c` | Pcd.c:507 | pointer-arithmetic-overflow | 2 | Pcd | pointer index expression overflowed base 0x00000000DEDF1744 result 0x00000000DEDF1740 input driven, in firmware code |
| PcdDxe.efi | `MdeModulePkg/Universal/PCD/Dxe/Service.c` | Service.c:1734 | pointer-arithmetic-overflow | 2 | Pcd | pointer index expression overflowed base 0x00000000DEDF1744 result 0x00000000DEDF1740 input driven, in firmware code |
| DxeCore.efi | `MdeModulePkg/Core/Dxe/FwVol/FwVolRead.c` | FwVolRead.c:146-155 (2 sites) | null-pointer-read | 4665 | EfiFirmwareVolume2 | load of null pointer of type 'EFI_FV_FILETYPE' (aka 'unsigned char') across 2 types input driven, in firmware code |
| EnglishDxe.efi | `MdeModulePkg/Universal/Disk/UnicodeCollation/EnglishDxe/UnicodeCollationEng.c` | UnicodeCollationEng.c:184-281 (8 sites) | null-pointer-read | 3714 | EfiUnicodeCollation | load of null pointer of type 'CHAR16' (aka 'unsigned short') input driven, in firmware code |
| QemuVideoDxe.efi | `MdeModulePkg/Library/FrameBufferBltLib/FrameBufferBltLib.c` | FrameBufferBltLib.c:526 | null-pointer-arithmetic | 2684 | EfiGraphicsOutput, EfiUgaDraw | offset applied to a null pointer base 0x0000000000000000 result 0x0000000000000000 input driven, in firmware code |
| SmmAccess2Dxe.efi | `Silicon/Intel/SimicsX58SktPkg/Smm/Access/SmramInternal.c` | SmramInternal.c:144 | null-pointer-read | 1940 | EfiMmAccess | load of null pointer of type 'UINTN' (aka 'unsigned long long') input driven, in firmware code |
| AtaBusDxe.efi | `MdeModulePkg/Bus/Ata/AtaBusDxe/AtaBus.c` | AtaBus.c:1380 | null-pointer-read | 1567 | EfiDiskInfo | load of null pointer of type 'UINT32' (aka 'unsigned int') input driven, in firmware code |
| QemuVideoDxe.efi | `MdeModulePkg/Library/FrameBufferBltLib/FrameBufferBltLib.c` | FrameBufferBltLib.c:421 | null-pointer-arithmetic | 686 | EfiGraphicsOutput, EfiUgaDraw | offset applied to a null pointer base 0x0000000000000000 result 0x0000000000000000 input driven, in firmware code |
| DxeCore.efi | `MdeModulePkg/Core/Dxe/FwVolBlock/FwVolBlock.c` | FwVolBlock.c:229 | null-pointer-read | 482 | EfiFirmwareVolumeBlock | load of null pointer of type 'UINTN' (aka 'unsigned long long') input driven, in firmware code |
| EnglishDxe.efi | `MdeModulePkg/Universal/Disk/UnicodeCollation/EnglishDxe/UnicodeCollationEng.c` | UnicodeCollationEng.c:435 | null-pointer-read | 471 | EfiUnicodeCollation | load of null pointer of type 'CHAR16' (aka 'unsigned short') input driven, in firmware code |
| GraphicsConsoleDxe.efi | `MdeModulePkg/Universal/Console/GraphicsConsoleDxe/GraphicsConsole.c` | GraphicsConsole.c:1222 | null-pointer-arithmetic | 396 | EfiSimpleTextOut | offset applied to a null pointer base 0x0000000000000000 result 0x0000000000000000 input driven, in firmware code |
| EnglishDxe.efi | `MdeModulePkg/Universal/Disk/UnicodeCollation/EnglishDxe/UnicodeCollationEng.c` | UnicodeCollationEng.c:398 | null-pointer-read | 388 | EfiUnicodeCollation | load of null pointer of type 'CHAR8' (aka 'char') input driven, in firmware code |
| GraphicsConsoleDxe.efi | `MdeModulePkg/Universal/Console/GraphicsConsoleDxe/GraphicsConsole.c` | GraphicsConsole.c:994 | null-pointer-read | 241 | EfiSimpleTextOut | load of null pointer of type 'CHAR16' (aka 'unsigned short') input driven, in firmware code |
| EnglishDxe.efi | `MdeModulePkg/Universal/Disk/UnicodeCollation/EnglishDxe/UnicodeCollationEng.c` | UnicodeCollationEng.c:364 | null-pointer-read | 240 | EfiUnicodeCollation | load of null pointer of type 'CHAR16' (aka 'unsigned short') input driven, in firmware code |
| DiskIoDxe.efi | `MdeModulePkg/Universal/Disk/DiskIoDxe/DiskIo.c` | DiskIo.c:617 | null-pointer-arithmetic | 224 | EfiDiskIo2 | offset applied to a null pointer base 0x0000000000000000 result 0x00000000000002B7 input driven, in firmware code |
| DxeCore.efi | `MdeModulePkg/Core/Dxe/FwVol/FwVolRead.c` | FwVolRead.c:175 | null-pointer-member-access | 109 | EfiFirmwareVolume2 | member access within null pointer of type 'FFS_FILE_LIST_ENTRY' input driven, in firmware code |
| LegacySioDxe.efi | `Platform/Intel/BoardModulePkg/LegacySioDxe/SioService.c` | SioService.c:111 | null-pointer-member-access | 78 | EfiSio | member access within null pointer of type 'ACPI_SMALL_RESOURCE_HEADER' input driven, in firmware code |
| EbcDxe.efi | `MdeModulePkg/Universal/EbcDxe/EbcExecute.c` | EbcExecute.c:1373-1393 (3 sites) | null-pointer-read | 74 | EfiEbcVmTest | load of null pointer of type 'UINTN' (aka 'unsigned long long') across 2 types input driven, in firmware code |
| QemuVideoDxe.efi | `MdeModulePkg/Library/FrameBufferBltLib/FrameBufferBltLib.c` | FrameBufferBltLib.c:237 | null-pointer-read | 60 | EfiGraphicsOutput, EfiUgaDraw | load of null pointer of type 'UINT32' (aka 'unsigned int') input driven, in firmware code |
| EhciDxe.efi | `MdeModulePkg/Bus/Pci/EhciDxe/Ehci.c` | Ehci.c:1011 | null-pointer-read | 42 | EfiUsb2Hc | load of null pointer of type 'UINT8' (aka 'unsigned char') input driven, in firmware code |
| EbcDxe.efi | `MdeModulePkg/Universal/EbcDxe/EbcExecute.c` | EbcExecute.c:1840 | null-pointer-arithmetic | 34 | EfiEbcVmTest | offset applied to a null pointer base 0x0000000000000000 result 0x0000000000000001 input driven, in firmware code |
| EhciDxe.efi | `MdeModulePkg/Bus/Pci/EhciDxe/Ehci.c` | Ehci.c:1129 | null-pointer-read | 20 | EfiUsb2Hc | load of null pointer of type 'UINT8' (aka 'unsigned char') input driven, in firmware code |
| AcpiTableDxe.efi | `MdeModulePkg/Universal/Acpi/AcpiTableDxe/AmlString.c` | AmlString.c:298 | null-pointer-read | 19 | EfiAcpiSdt | load of null pointer of type 'UINT8' (aka 'unsigned char') input driven, in firmware code |
| AcpiTableDxe.efi | `MdeModulePkg/Universal/Acpi/AcpiTableDxe/AmlString.c` | AmlString.c:438 | null-pointer-read | 19 | EfiAcpiSdt | load of null pointer of type 'UINT8' (aka 'unsigned char') input driven, in firmware code |
| EhciDxe.efi | `MdeModulePkg/Bus/Pci/EhciDxe/Ehci.c` | Ehci.c:862 | null-pointer-read | 10 | EfiUsb2Hc | load of null pointer of type 'UINT8' (aka 'unsigned char') input driven, in firmware code |
| EhciDxe.efi | `MdeModulePkg/Bus/Pci/EhciDxe/Ehci.c` | Ehci.c:701-707 (2 sites) | null-pointer-read | 7 | EfiUsb2Hc | load of null pointer of type 'UINTN' (aka 'unsigned long long') input driven, in firmware code |
| EhciDxe.efi | `MdeModulePkg/Bus/Pci/EhciDxe/Ehci.c` | Ehci.c:1051 | null-pointer-read | 7 | EfiUsb2Hc | load of null pointer of type 'UINT8' (aka 'unsigned char') input driven, in firmware code |

## Firmware, present on every run

In firmware code but not provoked by any input -- they fire on a plain boot. A real defect can sit here; confirm by reading the source.

| module | source | location | bug type | hits | reached by | detail |
|---|---|---|---|---|---|---|
| HiiDatabase.efi | `MdeModulePkg/Universal/HiiDatabaseDxe/Database.c` | Database.c:3277-3368 (8 sites) | null-pointer-arithmetic | 60864 | EdkiiFormBrowserEx, EdkiiFormBrowserEx2, EdkiiFormDisplayEngine, EdkiiIoMmu +141 | offset applied to a null pointer base 0x0000000000000000 result 0x0000000000000014 seen under 145 unrelated protocols, so it is not input driven -- review, do not dismiss |
| HiiDatabase.efi | `MdeModulePkg/Universal/HiiDatabaseDxe/Database.c` | Database.c:4177 | null-pointer-arithmetic | 37594 | EdkiiFormBrowserEx, EdkiiFormBrowserEx2, EdkiiFormDisplayEngine, EdkiiIoMmu +141 | offset applied to a null pointer base 0x0000000000000000 result 0x0000000000000000 seen under 145 unrelated protocols, so it is not input driven -- review, do not dismiss |

