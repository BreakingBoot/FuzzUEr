# Bugs found under Simics

142 protocols, 600s each, on BoardX58Ich10 firmware built from this tree. 233 of 235 modules instrumented. Regenerate with

    python3 scripts/bug_report.py -r <campaign dir> --build <Simics build tree> --markdown results/bugs-simics.md

**Reading a row.** `module` is the driver the report belongs to and `source` is the file it was raised in. Most rows here are UBSan, which reports a file and a line and no address, so the module comes from the build tree: edk2 compiles each module from a known directory, and that is what ties the file to the driver. Where `source` is an `AsanMemoryLibRepStr` wrapper the report is from the interceptor and the bug is in the caller, whose address resolves against the images this boot loaded.

**Severity** ranks by what an attacker gets: a write past an allocation above a read, both above arithmetic on a pointer that is never dereferenced.

**Two classes that look like firmware defects and are not.** A size-driven finding should be checked against the generated harness first: `call-database.json` carries no parameter names for some calls, so their size arguments fall back to a blanket 4096 bound against a much smaller buffer. And an opaque handle fuzzed as a raw value is a wild pointer the firmware can only NULL-check before dereferencing, so a fault through one is the harness.

2281 report rows from the campaigns, clustered into 48 distinct sites.

15 further cluster(s) were the harness itself, a library linked into it that the firmware never calls, or code whose reports are inherent to what it does. Run `bug_report.py --show-filtered` to see them with the reason for each.

## Firmware, provoked by an input

Reached because a testcase drove it there. Ordered by severity.

| module | source | location | bug type | hits | reached by | detail |
|---|---|---|---|---|---|---|
| (unattributed) | `no source -- symbolise the offset` | unattributed | cpu-exception (#BP) | 1 | EfiScsiIo | 1 fault(s) input driven, in firmware code |
| DxeCore.efi | `MdeModulePkg/Core/Dxe/FwVolBlock/FwVolBlock.c` | FwVolBlock.c:217 | null-pointer-write | 20 | EfiFirmwareVolumeBlock | store to null pointer of type 'UINTN' (aka 'unsigned long long') input driven, in firmware code |
| DxeCore.efi | `MdeModulePkg/Core/Dxe/FwVol/FwVolRead.c` | FwVolRead.c:146-155 (2 sites) | null-pointer-read | 3603 | EfiFirmwareVolume2 | load of null pointer of type 'EFI_FV_FILETYPE' (aka 'unsigned char') across 2 types input driven, in firmware code |
| EnglishDxe.efi | `MdeModulePkg/Universal/Disk/UnicodeCollation/EnglishDxe/UnicodeCollationEng.c` | UnicodeCollationEng.c:184-271 (7 sites) | null-pointer-read | 1791 | EfiUnicodeCollation | load of null pointer of type 'CHAR16' (aka 'unsigned short') input driven, in firmware code |
| EbcDxe.efi | `MdeModulePkg/Universal/EbcDxe/EbcInt.c` | EbcInt.c:873-902 (13 sites) | null-pointer-member-access | 1071 | EfiEbcVmTest | member access within null pointer of type 'VM_CONTEXT' input driven, in firmware code |
| GraphicsConsoleDxe.efi | `MdeModulePkg/Universal/Console/GraphicsConsoleDxe/GraphicsConsole.c` | GraphicsConsole.c:1222 | pointer-arithmetic (undetailed) | 996 | EfiSimpleTextOut |  input driven, in firmware code |
| SmmAccess2Dxe.efi | `Silicon/Intel/SimicsX58SktPkg/Smm/Access/SmramInternal.c` | SmramInternal.c:144 | null-pointer-read | 988 | EfiMmAccess | load of null pointer of type 'UINTN' (aka 'unsigned long long') input driven, in firmware code |
| (unattributed) | `MdeModulePkg/Library/FrameBufferBltLib/FrameBufferBltLib.c` | FrameBufferBltLib.c:526 | pointer-arithmetic (undetailed) | 840 | EfiGraphicsOutput, EfiUgaDraw |  input driven, in firmware code |
| AtaBusDxe.efi | `MdeModulePkg/Bus/Ata/AtaBusDxe/AtaBus.c` | AtaBus.c:1380 | null-pointer-read | 650 | EfiDiskInfo | load of null pointer of type 'UINT32' (aka 'unsigned int') input driven, in firmware code |
| EnglishDxe.efi | `MdeModulePkg/Universal/Disk/UnicodeCollation/EnglishDxe/UnicodeCollationEng.c` | UnicodeCollationEng.c:398 | null-pointer-read | 511 | EfiUnicodeCollation | load of null pointer of type 'CHAR8' (aka 'char') input driven, in firmware code |
| GraphicsConsoleDxe.efi | `MdeModulePkg/Universal/Console/GraphicsConsoleDxe/GraphicsConsole.c` | GraphicsConsole.c:994 | null-pointer-read | 415 | EfiSimpleTextOut | load of null pointer of type 'CHAR16' (aka 'unsigned short') input driven, in firmware code |
| DxeCore.efi | `MdeModulePkg/Core/Dxe/FwVolBlock/FwVolBlock.c` | FwVolBlock.c:229 | null-pointer-read | 305 | EfiFirmwareVolumeBlock | load of null pointer of type 'UINTN' (aka 'unsigned long long') input driven, in firmware code |
| (unattributed) | `MdeModulePkg/Library/FrameBufferBltLib/FrameBufferBltLib.c` | FrameBufferBltLib.c:418-421 (2 sites) | pointer-arithmetic (undetailed) | 269 | EfiUgaDraw |  input driven, in firmware code |
| EnglishDxe.efi | `MdeModulePkg/Universal/Disk/UnicodeCollation/EnglishDxe/UnicodeCollationEng.c` | UnicodeCollationEng.c:435 | null-pointer-read | 217 | EfiUnicodeCollation | load of null pointer of type 'CHAR16' (aka 'unsigned short') input driven, in firmware code |
| EbcDxe.efi | `MdeModulePkg/Universal/EbcDxe/EbcExecute.c` | EbcExecute.c:1388-1393 (2 sites) | null-pointer-member-access | 204 | EfiEbcVmTest | member access within null pointer of type 'VM_CONTEXT' input driven, in firmware code |
| DiskIoDxe.efi | `MdeModulePkg/Universal/Disk/DiskIoDxe/DiskIo.c` | DiskIo.c:617 | pointer-arithmetic (undetailed) | 144 | EfiDiskIo2 |  input driven, in firmware code |
| DxeCore.efi | `MdeModulePkg/Core/Dxe/FwVol/FwVolRead.c` | FwVolRead.c:175 | null-pointer-member-access | 140 | EfiFirmwareVolume2 | member access within null pointer of type 'FFS_FILE_LIST_ENTRY' input driven, in firmware code |
| EnglishDxe.efi | `MdeModulePkg/Universal/Disk/UnicodeCollation/EnglishDxe/UnicodeCollationEng.c` | UnicodeCollationEng.c:364 | null-pointer-read | 127 | EfiUnicodeCollation | load of null pointer of type 'CHAR16' (aka 'unsigned short') input driven, in firmware code |
| EbcDxe.efi | `MdeModulePkg/Universal/EbcDxe/EbcExecute.c` | EbcExecute.c:1840 | null-pointer-member-access | 102 | EfiEbcVmTest | member access within null pointer of type 'VM_CONTEXT' input driven, in firmware code |
| LegacySioDxe.efi | `Platform/Intel/BoardModulePkg/LegacySioDxe/SioService.c` | SioService.c:111 | null-pointer-member-access | 98 | EfiSio | member access within null pointer of type 'ACPI_SMALL_RESOURCE_HEADER' input driven, in firmware code |
| (unattributed) | `MdeModulePkg/Library/FrameBufferBltLib/FrameBufferBltLib.c` | FrameBufferBltLib.c:237 | null-pointer-read | 26 | EfiGraphicsOutput, EfiUgaDraw | load of null pointer of type 'UINT32' (aka 'unsigned int') input driven, in firmware code |
| AcpiTableDxe.efi | `MdeModulePkg/Universal/Acpi/AcpiTableDxe/AmlString.c` | AmlString.c:298 | null-pointer-read | 6 | EfiAcpiSdt | load of null pointer of type 'UINT8' (aka 'unsigned char') input driven, in firmware code |
| AcpiTableDxe.efi | `MdeModulePkg/Universal/Acpi/AcpiTableDxe/AmlString.c` | AmlString.c:438 | null-pointer-read | 6 | EfiAcpiSdt | load of null pointer of type 'UINT8' (aka 'unsigned char') input driven, in firmware code |
| EbcDxe.efi | `MdeModulePkg/Universal/EbcDxe/EbcExecute.c` | EbcExecute.c:1373 | null-pointer-read | 5 | EfiEbcVmTest | load of null pointer of type 'UINTN' (aka 'unsigned long long') input driven, in firmware code |
| EhciDxe.efi | `MdeModulePkg/Bus/Pci/EhciDxe/Ehci.c` | Ehci.c:707 | null-pointer-read | 2 | EfiUsb2Hc | load of null pointer of type 'UINTN' (aka 'unsigned long long') input driven, in firmware code |
| EhciDxe.efi | `MdeModulePkg/Bus/Pci/EhciDxe/Ehci.c` | Ehci.c:1011 | null-pointer-read | 2 | EfiUsb2Hc | load of null pointer of type 'UINT8' (aka 'unsigned char') input driven, in firmware code |
| PcdDxe.efi | `MdeModulePkg/Universal/PCD/Dxe/Service.c` | Service.c:1734 | pointer-arithmetic (undetailed) | 2 | Pcd |  input driven, in firmware code |
| PcdDxe.efi | `MdeModulePkg/Universal/PCD/Dxe/Pcd.c` | Pcd.c:507 | pointer-arithmetic (undetailed) | 1 | Pcd |  input driven, in firmware code |
| (unattributed) | `Access Address= 0x00000000DEFCAB44` | Access Address= 0x00000000DEFCAB44:0 | pointer-arithmetic (undetailed) | 1 | Pcd |  input driven, in firmware code |

## Firmware, present on every run

In firmware code but not provoked by any input -- they fire on a plain boot. A real defect can sit here; confirm by reading the source.

| module | source | location | bug type | hits | reached by | detail |
|---|---|---|---|---|---|---|
| HiiDatabase.efi | `MdeModulePkg/Universal/HiiDatabaseDxe/Database.c` | Database.c:3277-3368 (8 sites) | pointer-arithmetic (undetailed) | 59640 | EdkiiFormBrowserEx, EdkiiFormBrowserEx2, EdkiiFormDisplayEngine, EdkiiIoMmu +138 |  seen under 142 unrelated protocols, so it is not input driven -- review, do not dismiss |
| HiiDatabase.efi | `MdeModulePkg/Universal/HiiDatabaseDxe/Database.c` | Database.c:4177 | pointer-arithmetic (undetailed) | 36920 | EdkiiFormBrowserEx, EdkiiFormBrowserEx2, EdkiiFormDisplayEngine, EdkiiIoMmu +138 |  seen under 142 unrelated protocols, so it is not input driven -- review, do not dismiss |
| (unattributed) | `MdePkg/Library/AsanMemoryLibRepStr/MemLibGuid.c` | MemLibGuid.c:50 | pointer-arithmetic (undetailed) | 20 | EdkiiIoMmu, EfiAtaPassThru, EfiDevicePathUtilities, EfiDriverConfiguration +16 |  seen under 20 unrelated protocols, so it is not input driven -- review, do not dismiss |
| (unattributed) | `MdePkg/Library/BaseLib/Unaligned.c` | Unaligned.c:186 | null-pointer-read | 20 | EdkiiIoMmu, EfiAtaPassThru, EfiDevicePathUtilities, EfiDriverConfiguration +16 | load of null pointer of type 'const UINT64' (aka 'const unsigned long long') seen under 20 unrelated protocols, so it is not input driven -- review, do not dismiss |

