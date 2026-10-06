# Bugs found under QEMU

245 protocols discovered, 113 fuzzable after the presence census, 600s each, on OVMF built from this tree at ASAN_SCOPE=full with NETWORK_IP6_ENABLE and NETWORK_HTTP_BOOT_ENABLE. 98 campaigns reached the harness, 695135 iterations, edge stability median 100%. Regenerate with

    python3 scripts/bug_report.py -r <campaign dir> --build <Build>/OvmfX64/DEBUG_CLANGSAN/X64 --markdown results/bugs-qemu.md

730 report rows from the campaigns, clustered into 25 distinct sites.

## Firmware, provoked by an input

Reached because a testcase drove it there. Ordered by severity.

| module | source | location | bug type | hits | reached by | detail |
|---|---|---|---|---|---|---|
| AcpiTableDxe.efi | `asan-outline-instrumentation` | asan-outline-instrumentation:480740825 | heap-buffer-overflow (read) | 39 | EfiAcpiTable | read of 4 bytes at 0x000000001BC35E2C input driven, in firmware code |
| HiiDatabase.efi | `StrLen -- ??:?` | +0x441e4 | cpu-exception (#GP) | 1 | EfiConfigKeywordHandler | 1 fault(s) at HiiDatabase+0x441e4 input driven, in firmware code |
| (unattributed) | `asan-outline-instrumentation` | asan-outline-instrumentation:530506094 | unknown-crash (read) | 1 | EfiTimerArch | read of 4 bytes at 0x000000001FA9A790 input driven, in firmware code |
| HiiDatabase.efi | `MdeModulePkg/Universal/HiiDatabaseDxe/ConfigKeywordHandler.c` | ConfigKeywordHandler.c:3402 | null-pointer-arithmetic | 17 | EfiConfigKeywordHandler | offset applied to a null pointer base 0x0000000000000000 result 0x0000000000000000 input driven, in firmware code |
| EbcDxe.efi | `fwsan` | fwsan:490306147-490306164 (2 sites) | fwsan-double-fetch (read) | 1629 | EfiEbcVmTest | read of 8 bytes at 0x000000001B9210A8 input driven, in firmware code |
| SetupBrowser.efi | `fwsan` | fwsan:478098842 | fwsan-double-fetch (read) | 271 | EdkiiFormBrowserEx | read of 2 bytes at 0x000000001BC35E28 input driven, in firmware code |
| DevicePathDxe.efi | `fwsan` | fwsan:491210228 | fwsan-double-fetch (read) | 77 | EfiDevicePathFromText | read of 2 bytes at 0x000000001BC300A8 input driven, in firmware code |
| PciSioSerialDxe.efi | `fwsan` | fwsan:468301874 | fwsan-double-fetch (read) | 74 | EfiSerialIo | read of 8 bytes at 0x000000001B9210A8 input driven, in firmware code |
| PciSioSerialDxe.efi | `fwsan` | fwsan:468300820 | fwsan-double-fetch (read) | 70 | EfiSerialIo | read of 8 bytes at 0x000000001B9210A8 input driven, in firmware code |
| DxeCore.efi | `fwsan` | fwsan:530644210 | fwsan-double-fetch (read) | 53 | EfiFirmwareVolumeBlock | read of 8 bytes at 0x000000001B91F0A8 input driven, in firmware code |
| AcpiTableDxe.efi | `MdePkg/Library/UefiLib/UefiDriverModel.c` | UefiDriverModel.c:731 | [ASan] | 39 | EfiAcpiTable | ip 0x000000001CA785D9 input driven, in firmware code |
| SmbiosDxe.efi | `fwsan` | fwsan:478826012 | fwsan-double-fetch (read) | 24 | EfiSmbios | read of 2 bytes at 0x000000001C00CB28 input driven, in firmware code |
| TerminalDxe.efi | `fwsan` | fwsan:471264209 | fwsan-double-fetch (read) | 16 | EfiHiiImageEx | read of 1 bytes at 0x000000001C00D729 input driven, in firmware code |
| DevicePathDxe.efi | `fwsan` | fwsan:491231988 | fwsan-double-fetch (read) | 9 | EfiDevicePathToText | read of 1 bytes at 0x000000001B9210A8 input driven, in firmware code |
| Ps2KeyboardDxe.efi | `fwsan` | fwsan:468058974 | fwsan-double-fetch (read) | 8 | EdkiiVariablePolicy | read of 8 bytes at 0x000000001C000150 input driven, in firmware code |
| CpuIo2Dxe.efi | `fwsan` | fwsan:485917414-485917445 (2 sites) | fwsan-double-fetch (read) | 3 | EfiCpuIo2 | read of 1 bytes at 0x000000001B9210A9 input driven, in firmware code |
| DevicePathDxe.efi | `fwsan` | fwsan:491232098 | fwsan-double-fetch (read) | 3 | EfiDevicePathToText | read of 1 bytes at 0x000000001B9210A9 input driven, in firmware code |
| Ps2KeyboardDxe.efi | `fwsan` | fwsan:479747765 | fwsan-double-fetch (read) | 2 | EdkiiVariablePolicy | read of 4 bytes at 0x000000001C3AA728 input driven, in firmware code |
| DxeCore.efi | `fwsan` | fwsan:530774980 | fwsan-double-fetch (read) | 2 | EfiSecurity2Arch | read of 1 bytes at 0x000000001B9210A8 input driven, in firmware code |
| TerminalDxe.efi | `fwsan` | fwsan:468299411 | fwsan-double-fetch (read) | 1 | EfiHiiImageEx | read of 4 bytes at 0x000000001C009B28 input driven, in firmware code |
| TerminalDxe.efi | `fwsan` | fwsan:481024693 | fwsan-double-fetch (read) | 1 | EfiHiiImageEx | read of 8 bytes at 0x000000001BE16F28 input driven, in firmware code |
| TerminalDxe.efi | `fwsan` | fwsan:481030864 | fwsan-double-fetch (read) | 1 | EfiHiiImageEx | read of 2 bytes at 0x000000001C00D22A input driven, in firmware code |
| (unattributed) | `fwsan` | fwsan:468299411 | fwsan-double-fetch (read) | 1 | EfiHiiString | read of 4 bytes at 0x000000001C009B28 input driven, in firmware code |
| DxeCore.efi | `MdeModulePkg/Core/Dxe/Library/Library.c` | Library.c:87 | __asan_load0x04 | 1 | EfiTimerArch | ip 0x000000001F9EE16E input driven, in firmware code |

## Firmware, present on every run

In firmware code but not provoked by any input -- they fire on a plain boot. A real defect can sit here; confirm by reading the source.

| module | source | location | bug type | hits | reached by | detail |
|---|---|---|---|---|---|---|
| HiiDatabase.efi | `MdeModulePkg/Universal/HiiDatabaseDxe/Database.c` | Database.c:3393-3484 (8 sites) | null-pointer-arithmetic | 704 | EdkiiBootLogo2, EdkiiFormBrowserEx, EdkiiFormBrowserEx2, EdkiiPeCoffImageEmulator +84 | offset applied to a null pointer base 0x0000000000000000 result 0x0000000000000014 seen under 88 unrelated protocols, so it is not input driven -- review, do not dismiss |

