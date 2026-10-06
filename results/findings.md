# Triaged findings

`bugs-qemu.md` and `bugs-simics.md` are generated from the sanitizer report stream, so every
row there is a *report*, not a defect: one site can produce thousands of hits, most sites are
the harness rather than the firmware, and a defect that never trips a sanitizer cannot appear
at all. This file is the hand-written other half -- the reports that were read back to source
and the question "is this a defect in EDK2?" answered either way.

Four are defects in EDK2. One class of 24 reports is not, and is recorded here so it is not
re-triaged.

| # | where | class | input driven | upstream | severity |
|---|---|---|---|---|---|
| 1 | `ConvertDevicePathToText` | unbounded loop | yes | yes | DoS, heap exhaustion |
| 2 | `InstallAcpiTable` | OOB read, 4 bytes | yes | yes | low, can fault at a page edge |
| 3 | `CoreInsertEventTimer` | NULL list link | unknown | yes | crash, cause not yet attributed |
| 4 | `HiiExportPackageLists` | undefined behaviour | no | yes | UB only, nothing dereferenced |

None are reported upstream as of 2026-10-06.

## 1. ConvertDevicePathToText loops forever on a zero-length node

`MdePkg/Library/UefiDevicePathLib/DevicePathToText.c`,
`UefiDevicePathLibConvertDevicePathToText` guards only `DevicePath == NULL`, then walks:

```c
Node = (EFI_DEVICE_PATH_PROTOCOL *)DevicePath;
while (!IsDevicePathEnd (Node)) {
    ...
    AlignedNode = AllocateCopyPool (DevicePathNodeLength (Node), Node);
    ToText (&Str, AlignedNode, DisplayOnly, AllowShortcuts);
    FreePool (AlignedNode);
    Node = NextDevicePathNode (Node);
}
```

`NextDevicePathNode` advances by `DevicePathNodeLength (Node)`, which is a bare
`ReadUnaligned16` of the node header (`DevicePathUtilities.c:177`) with no validation, so zero
is representable. A zero-length node is not an End node, the loop condition stays false, and
the pointer never moves -- an unbounded loop that also allocates and grows a string on every
iteration, so it exhausts the pool on the way round.

What makes this reportable rather than theoretical is that the check already exists in the
same library. `IsDevicePathValid` rejects exactly this:

```c
NodeLength = DevicePathNodeLength (DevicePath);
if (NodeLength < sizeof (EFI_DEVICE_PATH_PROTOCOL)) {
  return FALSE;
}
```

and six sibling functions in `DevicePathUtilities.c` call it (lines 369, 474, 614, 683, 794).
`ConvertDevicePathToText` is the one that does not. `DevicePathDxe/DevicePath.c:32` installs
it directly as `EFI_DEVICE_PATH_TO_TEXT_PROTOCOL.ConvertDevicePathToText` with no validating
wrapper, and device paths reach that protocol from UEFI variables (`Boot####`, `BootOrder`)
and from devices. Fix is one call, with the precedent beside it.

Observed as a hang, not as a report: `EfiDevicePathToText` campaigns reach the harness and are
flagged "never came back out of the call" after ~12 executions in 900s. No sanitizer fires, which
is why this was carried as infrastructure noise for weeks -- a campaign hung inside a call
reports near-zero iterations, indistinguishable at a glance from a boot that never reached the
harness or a contended guest.

## 2. InstallAcpiTable reads the header length before validating the size

`MdeModulePkg/Universal/Acpi/AcpiTableDxe/AcpiTableProtocol.c`:

```c
if ((AcpiTableBuffer == NULL) || (TableKey == NULL)
   || (((EFI_ACPI_DESCRIPTION_HEADER *)AcpiTableBuffer)->Length != AcpiTableBufferSize))
```

`->Length` is a `UINT32` at offset 4, so this reads bytes 4..7 of the caller's buffer *before*
`AcpiTableBufferSize` has been checked. The size is never compared against
`sizeof (EFI_ACPI_DESCRIPTION_HEADER)`, so any call with a buffer under 8 bytes reads out of
bounds.

Reachable by a correct caller: the harness does `AllocateZeroPool (Size > 0 ? Size : 1)` and
passes exactly `(buffer, Size)`, which is the documented contract -- not a harness artifact.
646 reports as `heap-buffer-overflow (read)` from `EfiAcpiTable`. Severity is modest and worth
stating plainly: at most 4 bytes, the value is only compared so there is no disclosure channel,
but it can fault when the allocation ends at a page boundary. Fix is to require
`AcpiTableBufferSize >= sizeof (EFI_ACPI_DESCRIPTION_HEADER)` first.

## 3. CoreInsertEventTimer traverses the timer list with a NULL link

`DxeCore.efi Timer.c:54` is `Event2 = CR (Link, IEVENT, Timer.Link, EVENT_SIGNATURE);`. The UB
report gives `base 0x0 result 0xFFFFFFFFFFFFFF68` = -152, and `offsetof(IEVENT, Timer.Link)`
is 152 read from `DxeCore.debug` DWARF, so `BASE_CR` ran with `Link == NULL`.

`mEfiTimerList` is `INITIALIZE_LIST_HEAD_VARIABLE`, statically self-referential, so the head
cannot be NULL; the NULL came from `Link = Link->ForwardLink`, i.e. an event *on the list* with
a NULL forward link. So this is list corruption -- an event zeroed or freed while still linked,
or inserted without its link initialised -- not an initialisation-order problem.

The separately reported `DxeCore.efi +0x34cb3 cpu-exception (#PF)` symbolises to the same line
and is the next step: dereferencing that bogus pointer. Two triage rows, one defect.

Open: which event carries the NULL link, and whether a harness call sequence produces it.
`CR` looks like the benign NULL-offsetof idiom at a glance, which is what makes this easy to
dismiss -- but under clang `OFFSET_OF` expands to `__builtin_offsetof`, not the
`&(((TYPE *)0)->Field)` fallback, so the NULL is real.

## 4. HiiExportPackageLists applies an offset to NULL on the size-query path

`MdeModulePkg/Universal/HiiDatabaseDxe/Database.c` computes
`(VOID *)((UINT8 *)Buffer + ResultSize)` to pass a write position to each `Export*Packages`
helper. On the size-query path -- the one every caller uses first, `Buffer = NULL`,
`BufferSize = 0`, to learn how much to allocate -- that is `NULL + n` with n non-zero, which is
undefined behaviour (C11 6.5.6p8).

Eight sites fire on every boot (lines 3393..3484 on master), and the construct appears nine
times in every version from `edk2-stable202305` to master -- unchanged for three years. Nothing
is dereferenced: each helper is guarded by `if (ResultSize + *UsedSize <= BufferSize)`. So it is
not a memory-safety bug, but it is genuine UB in shipping firmware, and it is the cleanest
instance here of a defect that is unambiguously EDK2's rather than shaped by the harness.

## Not defects: the 24 FWSAN double-fetch reports

The sweep produces 24 `fwsan-double-fetch` rows across 12 modules, named to function
(`EbcExecuteInstructions` 1629 hits, `GetHotKeyFromRegisterList` 271, `SerialRead` 144,
`SmbiosAdd` 24, `IsRawFiFoEmpty` 17). They are pattern locations, not vulnerabilities.

The giveaway is the address: most report the same faulting address, `0x1B9210A8`, across
unrelated modules. That is the harness's own argument buffer. FWSAN marks the fuzzer's input
untrusted and these functions re-read a header field they already read -- which is a true
observation about the code, but the buffer in production belongs to *firmware*, not to an
attacker, because these are protocol members whose caller is another driver.
`EbcExecuteInstructions` is the clearest case: it takes a caller-owned `VM_CONTEXT *` on a
debug/test protocol.

Two consequences worth keeping. The `UefiDevicePathLib` pair is a genuine double fetch of a
genuinely untrusted buffer -- `DevicePathType` at `DevicePathUtilities.c:130` and
`DevicePathSubType` at `:152`, validated with one read and used with another, on paths fed from
UEFI variables -- so the pattern is real even where this sweep's instances are not. And the
triage exposed that the SMI harness never registered the comm buffer as untrusted, making the
check inert in the one place where a double fetch genuinely matters, since the comm buffer is
written by the OS and read by SMM. Fixed in firness.
