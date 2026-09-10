# Bugs found under Simics

145 protocols, 600s each, on BoardX58Ich10 firmware built from this tree with per-module ASan. Regenerate with

    python3 scripts/bug_report.py -r <campaign dir> --markdown results/bugs-simics.md

**Reading a row.** Severity ranks by what an attacker gets: a write past an allocation above a read, both above arithmetic on a pointer that is never dereferenced. Where `source` is one of the `AsanMemoryLibRepStr` wrappers, that is the interceptor reporting at its own line -- the bug is in the caller, and `module` is the attribution you have, because the report carries no caller address. `(unattributed)` means the faulting address fell outside every image the boot announced. `(undetailed)` marks a capture from before the firmware recorded that detail.

**Two classes that look like firmware defects and are not.** A size-driven finding should be checked against the generated harness first: `call-database.json` carries no parameter names for some calls, so their size arguments fall back to a blanket 4096 bound against a much smaller buffer, which manufactures severity 5 reports -- the two SnpDxe rows below are that, from `Statistics (This, Reset, StatisticsSize, StatisticsTable)`. And an opaque handle fuzzed as a raw value is a wild pointer the firmware can only NULL-check before dereferencing, so a fault through one is the harness.

2300 report rows from the campaigns, clustered into 38 distinct sites.

## Firmware, provoked by an input

Reached because a testcase drove it there. Ordered by severity.

| module | source | location | bug type | hits | reached by | detail |
|---|---|---|---|---|---|---|
| SnpDxe.efi | `MdePkg/Library/AsanMemoryLibRepStr/SetMemWrapper.c` | SetMemWrapper.c:63 | heap-buffer-overflow (write) | 10 | EfiSimpleNetwork | write of 8 bytes at 0x00000000D9A242F8 input driven, in firmware code |
| DxeCore.efi | `MdePkg/Library/AsanMemoryLibRepStr/CopyMemWrapper.c` | CopyMemWrapper.c:72 | heap-buffer-overflow (write) | 6 | EfiFirmwareVolumeBlock | write of 62728 bytes at 0x00000000D9A220A8 input driven, in firmware code |
| SnpDxe.efi | `MdePkg/Library/AsanMemoryLibRepStr/ZeroMemWrapper.c` | ZeroMemWrapper.c:62 | heap-buffer-overflow (write) | 1 | EfiSimpleNetwork | write of 2845 bytes at 0x00000000D9A24228 input driven, in firmware code |
| (unattributed) | `MdePkg/Library/AsanMemoryLibRepStr/CopyMemWrapper.c` | CopyMemWrapper.c:72 | heap-buffer-overflow (read) | 2 | EfiHiiDatabase, HiiStack | read of 4 bytes at 0x00000000D9AA34BC input driven, in firmware code |
| DevicePathDxe.efi | `MdePkg/Library/AsanMemoryLibRepStr/CopyMemWrapper.c` | CopyMemWrapper.c:72 | heap-buffer-overflow (read) | 1 | EfiDevicePathUtilities | read of 24171 bytes at 0x00000000D9A970A8 input driven, in firmware code |
| DxeCore.efi | `MdeModulePkg/Core/Dxe/FwVolBlock/FwVolBlock.c` | FwVolBlock.c:217 | null-pointer-write | 10 | EfiFirmwareVolumeBlock | store to null pointer of type 'UINTN' (aka 'unsigned long long') input driven, in firmware code |
| QemuVideoDxe.efi | `MdeModulePkg/Library/FrameBufferBltLib/FrameBufferBltLib.c` | FrameBufferBltLib.c:526 | null-pointer-arithmetic | 5632 | EfiGraphicsOutput, EfiUgaDraw | offset applied to a null pointer base 0x0000000000000000 result 0x0000000000000100 input driven, in firmware code |
| DxeCore.efi | `MdeModulePkg/Core/Dxe/FwVol/FwVolRead.c` | FwVolRead.c:146-155 (2 sites) | null-pointer-read | 3678 | EfiFirmwareVolume2 | load of null pointer of type 'EFI_FV_FILETYPE' (aka 'unsigned char') across 2 types input driven, in firmware code |
| EnglishDxe.efi | `MdeModulePkg/Universal/Disk/UnicodeCollation/EnglishDxe/UnicodeCollationEng.c` | UnicodeCollationEng.c:184-271 (7 sites) | null-pointer-read | 3317 | EfiUnicodeCollation | load of null pointer of type 'CHAR16' (aka 'unsigned short') input driven, in firmware code |
| QemuVideoDxe.efi | `MdeModulePkg/Library/FrameBufferBltLib/FrameBufferBltLib.c` | FrameBufferBltLib.c:421 | null-pointer-arithmetic | 1629 | EfiGraphicsOutput, EfiUgaDraw | offset applied to a null pointer base 0x0000000000000000 result 0x0000000000000150 input driven, in firmware code |
| AtaBusDxe.efi | `MdeModulePkg/Bus/Ata/AtaBusDxe/AtaBus.c` | AtaBus.c:1380 | null-pointer-read | 1510 | EfiDiskInfo | load of null pointer of type 'UINT32' (aka 'unsigned int') input driven, in firmware code |
| SmmAccess2Dxe.efi | `Silicon/Intel/SimicsX58SktPkg/Smm/Access/SmramInternal.c` | SmramInternal.c:144 | null-pointer-read | 1383 | EfiMmAccess | load of null pointer of type 'UINTN' (aka 'unsigned long long') input driven, in firmware code |
| EnglishDxe.efi | `MdeModulePkg/Universal/Disk/UnicodeCollation/EnglishDxe/UnicodeCollationEng.c` | UnicodeCollationEng.c:398 | null-pointer-read | 548 | EfiUnicodeCollation | load of null pointer of type 'CHAR8' (aka 'char') input driven, in firmware code |
| EnglishDxe.efi | `MdeModulePkg/Universal/Disk/UnicodeCollation/EnglishDxe/UnicodeCollationEng.c` | UnicodeCollationEng.c:435 | null-pointer-read | 363 | EfiUnicodeCollation | load of null pointer of type 'CHAR16' (aka 'unsigned short') input driven, in firmware code |
| GraphicsConsoleDxe.efi | `MdeModulePkg/Universal/Console/GraphicsConsoleDxe/GraphicsConsole.c` | GraphicsConsole.c:1222 | null-pointer-arithmetic | 362 | EfiSimpleTextOut | offset applied to a null pointer base 0x0000000000000000 result 0x0000000000000000 input driven, in firmware code |
| DxeCore.efi | `MdeModulePkg/Core/Dxe/FwVolBlock/FwVolBlock.c` | FwVolBlock.c:229 | null-pointer-read | 292 | EfiFirmwareVolumeBlock | load of null pointer of type 'UINTN' (aka 'unsigned long long') input driven, in firmware code |
| EnglishDxe.efi | `MdeModulePkg/Universal/Disk/UnicodeCollation/EnglishDxe/UnicodeCollationEng.c` | UnicodeCollationEng.c:364 | null-pointer-read | 259 | EfiUnicodeCollation | load of null pointer of type 'CHAR16' (aka 'unsigned short') input driven, in firmware code |
| DiskIoDxe.efi | `MdeModulePkg/Universal/Disk/DiskIoDxe/DiskIo.c` | DiskIo.c:617-669 (3 sites) | null-pointer-arithmetic | 170 | EfiDiskIo2 | offset applied to a null pointer base 0x0000000000000000 result 0x000000000000023C input driven, in firmware code |
| GraphicsConsoleDxe.efi | `MdeModulePkg/Universal/Console/GraphicsConsoleDxe/GraphicsConsole.c` | GraphicsConsole.c:994 | null-pointer-read | 167 | EfiSimpleTextOut | load of null pointer of type 'CHAR16' (aka 'unsigned short') input driven, in firmware code |
| EbcDxe.efi | `MdeModulePkg/Universal/EbcDxe/EbcExecute.c` | EbcExecute.c:1373-1393 (3 sites) | null-pointer-read | 81 | EfiEbcVmTest | load of null pointer of type 'UINTN' (aka 'unsigned long long') across 2 types input driven, in firmware code |
| LegacySioDxe.efi | `Platform/Intel/BoardModulePkg/LegacySioDxe/SioService.c` | SioService.c:111 | null-pointer-member-access | 70 | EfiSio | member access within null pointer of type 'ACPI_SMALL_RESOURCE_HEADER' input driven, in firmware code |
| QemuVideoDxe.efi | `MdeModulePkg/Library/FrameBufferBltLib/FrameBufferBltLib.c` | FrameBufferBltLib.c:237 | null-pointer-read | 64 | EfiGraphicsOutput, EfiUgaDraw | load of null pointer of type 'UINT32' (aka 'unsigned int') input driven, in firmware code |
| DxeCore.efi | `MdeModulePkg/Core/Dxe/FwVol/FwVolRead.c` | FwVolRead.c:175 | null-pointer-member-access | 43 | EfiFirmwareVolume2 | member access within null pointer of type 'FFS_FILE_LIST_ENTRY' input driven, in firmware code |
| EbcDxe.efi | `MdeModulePkg/Universal/EbcDxe/EbcExecute.c` | EbcExecute.c:1840 | null-pointer-arithmetic | 36 | EfiEbcVmTest | offset applied to a null pointer base 0x0000000000000000 result 0x0000000000000001 input driven, in firmware code |
| AcpiTableDxe.efi | `MdeModulePkg/Universal/Acpi/AcpiTableDxe/AmlString.c` | AmlString.c:298 | null-pointer-read | 16 | EfiAcpiSdt | load of null pointer of type 'UINT8' (aka 'unsigned char') input driven, in firmware code |
| AcpiTableDxe.efi | `MdeModulePkg/Universal/Acpi/AcpiTableDxe/AmlString.c` | AmlString.c:438 | null-pointer-read | 16 | EfiAcpiSdt | load of null pointer of type 'UINT8' (aka 'unsigned char') input driven, in firmware code |
| EhciDxe.efi | `MdeModulePkg/Bus/Pci/EhciDxe/Ehci.c` | Ehci.c:1011 | null-pointer-read | 10 | EfiUsb2Hc | load of null pointer of type 'UINT8' (aka 'unsigned char') input driven, in firmware code |
| EhciDxe.efi | `MdeModulePkg/Bus/Pci/EhciDxe/Ehci.c` | Ehci.c:1129 | null-pointer-read | 10 | EfiUsb2Hc | load of null pointer of type 'UINT8' (aka 'unsigned char') input driven, in firmware code |
| EhciDxe.efi | `MdeModulePkg/Bus/Pci/EhciDxe/Ehci.c` | Ehci.c:862 | null-pointer-read | 7 | EfiUsb2Hc | load of null pointer of type 'UINT8' (aka 'unsigned char') input driven, in firmware code |
| EhciDxe.efi | `MdeModulePkg/Bus/Pci/EhciDxe/Ehci.c` | Ehci.c:707 | null-pointer-read | 4 | EfiUsb2Hc | load of null pointer of type 'UINTN' (aka 'unsigned long long') input driven, in firmware code |

## Firmware, present on every run

In firmware code but not provoked by any input -- they fire on a plain boot. A real defect can sit here; confirm by reading the source.

| module | source | location | bug type | hits | reached by | detail |
|---|---|---|---|---|---|---|
| HiiDatabase.efi | `MdeModulePkg/Universal/HiiDatabaseDxe/Database.c` | Database.c:3277-3368 (8 sites) | null-pointer-arithmetic | 60744 | EdkiiFormBrowserEx, EdkiiFormBrowserEx2, EdkiiFormDisplayEngine, EdkiiIoMmu +141 | offset applied to a null pointer base 0x0000000000000000 result 0x0000000000000014 seen under 145 unrelated protocols, so it is not input driven -- review, do not dismiss |
| HiiDatabase.efi | `MdeModulePkg/Universal/HiiDatabaseDxe/Database.c` | Database.c:4177 | null-pointer-arithmetic | 37132 | EdkiiFormBrowserEx, EdkiiFormBrowserEx2, EdkiiFormDisplayEngine, EdkiiIoMmu +141 | offset applied to a null pointer base 0x0000000000000000 result 0x0000000000000000 seen under 145 unrelated protocols, so it is not input driven -- review, do not dismiss |

## Not firmware: the harness

Raised inside the harness image, or by a library linked into it that the firmware never calls. Listed so they are accounted for, not hidden.

| module | source | location | bug type | hits | reached by | detail |
|---|---|---|---|---|---|---|
| Firness.efi | `ShellPkg/Library/UefiHandleParsingLib/UefiHandleParsingLib.c` | UefiHandleParsingLib.c:3359 | null-pointer-write | 7 | EfiDriverConfiguration | store to null pointer of type 'UINTN' (aka 'unsigned long long') raised inside the harness image itself |
| Firness.efi | `MdeModulePkg/Library/PiDxeS3BootScriptLib/BootScriptSave.c` | BootScriptSave.c:191-205 (3 sites) | null-pointer-member-access | 348 | EdkiiFormDisplayEngine, EdkiiIoMmu, EdkiiSmmMemoryAttribute, EdkiiUfsHostController +83 | member access within null pointer of type 'SCRIPT_TABLE_PRIVATE_DATA' raised inside the harness image itself |
| Firness.efi | `MdeModulePkg/Library/PiDxeS3BootScriptLib/BootScriptSave.c` | BootScriptSave.c:144 | null-pointer-member-access | 174 | EdkiiFormDisplayEngine, EdkiiIoMmu, EdkiiSmmMemoryAttribute, EdkiiUfsHostController +83 | member access within null pointer of type 'SCRIPT_TABLE_PRIVATE_DATA' raised inside the harness image itself |
| Firness.efi | `MdeModulePkg/Library/PiDxeS3BootScriptLib/BootScriptSave.c` | BootScriptSave.c:248-255 (2 sites) | null-pointer-member-access | 174 | EdkiiFormDisplayEngine, EdkiiIoMmu, EdkiiSmmMemoryAttribute, EdkiiUfsHostController +83 | member access within null pointer of type 'SCRIPT_TABLE_PRIVATE_DATA' raised inside the harness image itself |
| Firness.efi | `MdePkg/Library/BaseLib/Unaligned.c` | Unaligned.c:186 | null-pointer-read | 21 | EdkiiIoMmu, EfiAtaPassThru, EfiDevicePathUtilities, EfiDriverConfiguration +17 | load of null pointer of type 'const UINT64' (aka 'const unsigned long long') raised inside the harness image itself |

## Not firmware: how that code works

Firmware code whose reports are inherent to what it does.

| module | source | location | bug type | hits | reached by | detail |
|---|---|---|---|---|---|---|
| QemuVideoDxe.efi | `Platform/Intel/SimicsOpenBoardPkg/SimicsVideoDxe/VbeShim.c` | VbeShim.c:97 | null-pointer-arithmetic | 145 | EdkiiFormBrowserEx, EdkiiFormBrowserEx2, EdkiiFormDisplayEngine, EdkiiIoMmu +141 | offset applied to a null pointer base 0x0000000000000000 result 0x0000000000000040 QemuVideoDxe writes its int10h shim into reserved low memory on purpose |

