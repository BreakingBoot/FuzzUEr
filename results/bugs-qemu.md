# Bugs found under QEMU

15 campaigns -- 12 protocols, an SMI handler, 2 repeats -- at 600s each, on OVMF built from this tree with per-module ASan. Regenerate with

    python3 scripts/bug_report.py -r <campaign dir> --markdown results/bugs-qemu.md

Most findings here are CPU faults rather than sanitizer reports, because this OVMF instruments 3 of 312 modules. A fault has no source line; symbolise its offset with

    llvm-symbolizer --obj=Build/OvmfX64/DEBUG_CLANGSAN/X64/<path>/<Module>.debug --functions=linkage <offset>

Both rows below resolve, and both are the same defect class rather than firmware bugs: `DxeCore+0x35671` is `CoreSignalEvent` at Event.c:526, reached by BlockIo2 passing a fuzzed `EFI_EVENT`; `HiiDatabase+0x1be8f` is `IsHiiHandleValid` at Database.c:135, reached by a fuzzed `EFI_HII_HANDLE`. Both are opaque handles fuzzed as raw values -- the firmware NULL-checks them and then dereferences, which it cannot avoid, so these are the harness violating a caller contract.

165 report rows from the campaigns, clustered into 3 distinct sites.

## Firmware, provoked by an input

Reached because a testcase drove it there. Ordered by severity.

| module | source | location | bug type | hits | reached by | detail |
|---|---|---|---|---|---|---|
| DxeCore.efi | `no source -- symbolise the offset` | +0x35671 | cpu-exception (#GP) | 39 | EfiBlockIo2 | 39 fault(s) at DxeCore+0x35671 input driven, in firmware code |
| HiiDatabase.efi | `no source -- symbolise the offset` | +0x1be8f | cpu-exception (#GP) | 6 | EfiHiiString | 6 fault(s) at HiiDatabase+0x1be8f input driven, in firmware code |

## Firmware, present on every run

In firmware code but not provoked by any input -- they fire on a plain boot. A real defect can sit here; confirm by reading the source.

None.

## Not firmware: the harness

Raised inside the harness image, or by a library linked into it that the firmware never calls. Listed so they are accounted for, not hidden.

None.

## Not firmware: how that code works

Firmware code whose reports are inherent to what it does.

None.

