# Use-after-free in `BootGraphicsResourceTableDxe`, reachable through `EDKII_BOOT_LOGO2_PROTOCOL`

A caller that hands `SetBootLogo2()` the buffer pointer `GetBootLogo2()` just returned makes
the driver free that buffer and then copy out of it. The stale bytes become the driver's new
logo, and at the next `ReadyToBoot` they become the image of the **BGRT — an ACPI table the
operating system reads.**

This directory is a self-contained reproducer: one UEFI application, its own platform
description, a build script and a QEMU runner. It reaches one of five named verdicts from
observables it prints, and it does not print a verdict it has no evidence for.

The line numbers below are from upstream edk2
**`fdbcc125a620f63c8ba81daefa094fea16d9e235`** (master), and are the same in
`edk2-stable202305`, `edk2-stable202408`, `edk2-stable202502` and `edk2-stable202608` —
checked, not assumed. The firmware the reproducer was actually *run* against is named with
each result in §5; the oldest of them is the `edk2` **2022.02** OVMF Ubuntu ships, where it
also reproduces.

---

## 1. The defect

`MdeModulePkg/Universal/Acpi/BootGraphicsResourceTableDxe/BootGraphicsResourceTableDxe.c`

```c
GetBootLogo2 (...)                                              /* :367 */
  ...
  *BltBuffer    = mLogoBltBuffer;                               /* :398  hands out its own pointer */

SetBootLogo2 (..., BltBuffer, ..., Width, Height)               /* :239 */
  ...
  SafeUintnMult (Width, Height, &BufferSize);                   /* :293  size from the NEW call */
  SafeUintnMult (BufferSize, sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL), &BufferSize);
  mAcpiBgrtBufferChanged = TRUE;                                /* :314 */
  if (mLogoBltBuffer != NULL) {
    FreePool (mLogoBltBuffer);                                  /* :320  frees it */
    mLogoBltBuffer = NULL;
  }
  mLogoBltBuffer = AllocateCopyPool (BufferSize, BltBuffer);    /* :327  reads from the caller's pointer */
```

`BltBuffer == mLogoBltBuffer` is all it takes. `:320` frees the memory `:327` then copies
from — `AllocateCopyPool` allocates and `CopyMem`s, so the read happens after the free, in
the same call, with no code of the caller's in between.

Nothing in the protocol forbids the call. `MdeModulePkg/Include/Protocol/BootLogo2.h`
says of the pointer `GetBootLogo2` returns, at `:62-64`:

> `@param[out] BltBuffer     Returns pointer to the GOP BLT buffer that was previously
> registered with SetBootLogo2(). The buffer returned must not be modified or freed.`

This PoC does neither. It does not write to the buffer and it does not call `FreePool` on
it. `SetBootLogo2`'s own documentation for its `BltBuffer` parameter says only *"The BLT
buffer for logo drawn on screen"* — no aliasing restriction, no lifetime statement.

The original `EFI_BOOT_LOGO_PROTOCOL` is not affected: `MdeModulePkg/Include/Protocol/
BootLogo.h:52-54` gives it one member, `SetBootLogo`, so there is no way for a caller to
obtain the driver's pointer in the first place. This needs Boot Logo Protocol **2**.

### Why it reaches the operating system

The buffer is not private state that gets discarded. `BgrtReadyToBootEventNotify()` turns
it into the published ACPI table:

```c
  Status = TranslateGopBltToBmp (mLogoBltBuffer, ..., &ImageBuffer, &BmpSize);   /* :484 */
  ...
  mBootGraphicsResourceTableTemplate.ImageAddress = (UINT64)(UINTN)ImageBuffer;  /* :503 */
  ...
  AcpiTableProtocol->InstallAcpiTable (...)                                      /* :530 */
```

So whatever `:327` copied out of the freed block is converted to a BMP and installed as
the BGRT. The table is rebuilt on every `ReadyToBoot` for which `mAcpiBgrtBufferChanged`
is set, and `SetBootLogo2` sets it at `:314` — including on the call that performs the
use-after-free.

This PoC demonstrates that end to end: see outcome 1 in §4.

### What is **not** claimed

Whether an attacker can *groom* what lands in the freed block has not been established and
is not claimed anywhere in this artefact. What is shown is that the firmware reads freed
heap and publishes the result to the OS. On a build that poisons freed pool memory the
content is the poison byte; on one that does not, it is whatever the allocator leaves
there. Nobody has shown here that a chosen value can be placed in that window.

---

## 2. What you need

* an edk2 checkout with `BaseTools` built: `gcc`, `python3`, `make`, `nasm`
* to run it: `qemu-system-x86_64`, `mkfs.vfat` (dosfstools), `mcopy`/`mdir` (mtools), and
  an OVMF `CODE`/`VARS` pair. Any OVMF built from `OvmfPkgX64.dsc` will do —
  `BootGraphicsResourceTableDxe.inf` is at `OvmfPkgX64.dsc:1028` — including the one your
  distribution ships.

Two notes from doing this on a fresh checkout. `build.sh` needs no edk2 submodules, but
`build.py` validates every `[Includes]` path declared in `MdePkg.dec` and
`MdeModulePkg.dec` before it compiles anything, so a checkout without
`MdePkg/Library/MipiSysTLib/mipisyst` and
`MdeModulePkg/Library/BrotliCustomDecompressLib/brotli` fails with `error 000E:
File/directory not found in workspace` naming a submodule this application never uses.
`git submodule update --init` fixes it; so does creating those two include directories
empty. And `make -C BaseTools` only needs `GenFw` here, so a `BrotliCompress` failure from
the same missing submodule is harmless.

---

## 3. Build and run

Nothing in the build touches your edk2 working tree except a new `BootLogo2Uaf/`
directory, which `build.sh` writes and rewrites.

```sh
# build
EDK2=/path/to/edk2 ./build.sh
#   -> /path/to/edk2/Build/BootLogo2Uaf/RELEASE_GCC/X64/BootLogo2Uaf.efi

# run
./run-qemu.sh /path/to/edk2/Build/BootLogo2Uaf/RELEASE_GCC/X64/BootLogo2Uaf.efi
```

`build.sh` honours `TARGET` (`RELEASE`/`DEBUG`/`NOOPT`), `ARCH`, `TOOLCHAIN` and
`DOCKER_IMAGE`. The toolchain tag is **detected**, because edk2 renamed it: a release
branch up to `edk2-stable202502` defines `GCC5` and master defines `GCC`. The wrong tag
fails with `error 4000: Not available -- [GCC5] not defined`, which reads like a missing
compiler and is not one.

By hand, without the scripts:

```sh
cp -r poc/bootlogo2-uaf <edk2>/BootLogo2Uaf
cd <edk2> && make -C BaseTools && . edksetup.sh
build -a X64 -b RELEASE -t GCC -p BootLogo2Uaf/BootLogo2Uaf.dsc
```

`run-qemu.sh` honours `OVMF_CODE`, `OVMF_VARS`, `TIMEOUT` and `REPUBLISH` (see §5). It
lays the application down as `EFI/BOOT/BOOTX64.EFI` on a FAT image, boots it once, and
prints the report the guest wrote to `\bootlogo2-uaf.log`. One boot, a few seconds of
work; no fuzzer, no snapshots, no persistent state.

On a target with a console, you can also just run `BootLogo2Uaf.efi` from a UEFI shell and
read the report on screen.

---

## 4. The five outcomes, and how to tell them apart

This is the part that matters. **The use-after-free can execute and still leave the
content looking correct**: if the allocator hands the just-freed block straight back to
the `AllocateCopyPool` at `:327`, the copy reads its own fresh allocation. A reproducer
that printed VULNERABLE unconditionally would be worthless, so this one distinguishes the
cases and says which it saw.

| verdict | what it means | the observable that decides it |
| --- | --- | --- |
| `REPRODUCED-OBSERVED` | the copy read memory that had been freed, and the bytes it read were not the ones the PoC put there | the destination address differs from the source address **and** the copied bytes are not the PoC's pattern |
| `REPRODUCED-UNCHANGED` | free-then-read executed and source ≠ destination, but the bytes were unchanged | addresses differ, pattern intact — this firmware does not poison freed pool (`PcdDebugPropertyMask` bit `0x08` clear) |
| `RECYCLED` | the free and the read both executed, but the allocator returned the very block it had just released, so the copy read its own allocation | `GetBootLogo2` returns the **same** address after the call as before it |
| `ABSENT` | the protocol is not installed; nothing was exercised and nothing was changed | `LocateProtocol(gEdkiiBootLogo2ProtocolGuid)` failed |
| `INCONCLUSIVE` | the driver holds no buffer after the call, so what the copy produced cannot be read back | `GetBootLogo2` after the call returned an error or `NULL` |

Three mechanisms make the distinction possible.

**A size that changes the pool bucket.** The first logo is 16x16 (1024 bytes) and the
second is 8x8 (256 bytes). `MdeModulePkg/Core/Dxe/Mem/Pool.c:51` keeps a free list per
bucket,

```c
STATIC CONST UINT16  mPoolSizeTable[] = {
  128, 256, 384, 640, 1024, 1664, 2688, 4352, 7040, 11392, 18432, 29824
};
```

and the index comes from `requested size + POOL_OVERHEAD`, which is
`OFFSET_OF(POOL_HEAD, Data) + sizeof(POOL_TAIL)` = 24 + 16 = 40 on X64. So 1024 + 40 lands
in bucket 5 (1664) and 256 + 40 in bucket 2 (384) — different buckets, so the allocator
cannot trivially hand the block back.

The §5.1 addresses confirm that arithmetic rather than assuming it: the first logo's data
is at `0x7E905018` and the driver's copy at `0x7E905698`, `0x680` = **1664** apart, and the
eight seeded blocks are `0x180` = **384** apart.

**Seeding the destination bucket.** Before the aliased call the PoC allocates and frees
eight 256-byte blocks, so bucket 2's free list is not empty. Without that, bucket 2 can be
empty at the call, `CoreAllocatePoolI` walks up to the next non-empty bucket
(`Pool.c:451`) — which is the bucket the free at `:320` has just filled — and carves the
allocation out of the head of the source block itself. The destination then equals the
source and the run can only report `RECYCLED`. The report prints the eight addresses and
says which one the driver came back with, so the destination is not just "different", it
is a block this PoC itself put on the free list.

The seeding and the aliased call have to be adjacent in the code, with no `Rpt()` between
them: every report line goes through `ConOut->OutputString` and the console drivers
allocate pool, which empties the seeded list again.

**Debug-build pool poisoning.** `CoreFreePoolI` does `DEBUG_CLEAR_MEMORY (Head, Size)`
(`Pool.c:789`), overwriting a freed block with `PcdDebugClearMemoryValue`, default `0xAF`.
The PoC's pattern byte is `0x21 + (offset & 0x3F)`, which contains no `0xAF` at any offset,
so "the copy produced `0xAF`" means "the copy did not read the pattern".

Read that inference the right way round, because `CoreAllocatePoolI` poisons too
(`Pool.c:538`). `0xAF` in the destination does **not** by itself say which write put it
there. What it says is that the *pattern is gone*: had the source still held the pattern,
`CopyMem` would have written the pattern over the allocation poison — and it did not. The
PoC reads the source in step `[4]` and confirms the pattern is there, so the only thing
that ran between that read and the copy is `FreePool` at `:320`.

A fourth, weaker observable is also printed: immediately after the aliased call the PoC
asks `AllocatePool` for the source's bucket and checks whether the source address comes
back out of it, which only happens for a block on the free list. It is weak in one
direction only — a "no" proves nothing, because anything else that allocated from that
bucket in between takes the block first. The report says so where it prints it.

### What it does *not* rely on

Not the return status (`SetBootLogo2` returns `EFI_SUCCESS` for the aliased call), not a
crash, not a timing window, and not pointer inequality alone.

---

## 5. Observed results

### 5.1 Upstream driver, distribution OVMF, nothing instrumented

Reproducer built from edk2 `fdbcc125a6`, `RELEASE_GCC`, X64 — but the driver that executes
is the firmware's, and here that firmware is `/usr/share/OVMF/OVMF_CODE_4M.fd` from Ubuntu's
`ovmf 2022.02-3ubuntu0.22.04.7`, built from unmodified upstream with no sanitizer of any
kind. QEMU 6.2.0, `q35`, 2 GiB, `-smp 1`. Verbatim from `\bootlogo2-uaf.log`
(`evidence/run-distro-ovmf.txt`):

```
=== BootLogo2 use-after-free reproducer ===============================
target: MdeModulePkg/Universal/Acpi/BootGraphicsResourceTableDxe
        GetBootLogo2 :398 hands out mLogoBltBuffer
        SetBootLogo2 :320 frees it, :327 copies from the caller's pointer
sizes : first logo 16x16 = 1024 bytes, second logo 8x8 = 256 bytes

[1] protocol at 0x000000007EBB4A30
[2] GetBootLogo2 before we set anything: Not Ready (buffer 0x0000000000000000, 0x0)
BGRT (before): at 0x000000007FB73000  Status=0x0001 ImageType=0x0000 ImageAddress=0x000000007E069018 Offset=(415,355)
BGRT (before): BMP 193x58, 24 bpp, image data at +0x36, 33694 bytes
  bgrt-image +0000: FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
  bgrt-image +0010: FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
  bgrt-image +0020: FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
BGRT (before): 0 of the first 48 image bytes are 0xAF
[3] SetBootLogo2(my buffer 0x000000007E905018, 16x16): Success
[4] GetBootLogo2: Success -> 0x000000007E905698 (16x16 at 0,0)
    the driver returned its own copy (my buffer was 0x000000007E905018)
    the copy matches my pattern for 1024 of 1024 bytes
  held +0000: 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30
  held +0010: 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F 40
[5] seeding the 256-byte bin with 8 freed blocks
[6] SetBootLogo2(the driver's own pointer 0x000000007E905698, 8x8) -- this is the UAF
    returned Success
    the seeded blocks were:
      0x000000007E90CC18
      0x000000007E90CD98
      0x000000007E904018
      0x000000007E904C18
      0x000000007E904D98
      0x000000007E904198
      0x000000007E904998
      0x000000007E904318
[7] GetBootLogo2: Success -> 0x000000007E90CC18 (8x8)
[8] source block 0x000000007E905698, destination block 0x000000007E90CC18
    destination is the same block as the source : no
    destination is one of the blocks step 5 freed : yes, index 0
    the source address came back from AllocatePool(1024) right after the call: yes -- it was on the free list
    the copied bytes match my pattern for 0 of 256 bytes
    the copied bytes are all 0xAF (the pool free poison): yes
  copied +0000: AF AF AF AF AF AF AF AF AF AF AF AF AF AF AF AF
  copied +0010: AF AF AF AF AF AF AF AF AF AF AF AF AF AF AF AF
  copied +0020: AF AF AF AF AF AF AF AF AF AF AF AF AF AF AF AF

VERDICT: REPRODUCED-OBSERVED
```

Then the OS-visible half, after `ReadyToBoot`:

```
BGRT (after): at 0x000000007FB73000  Status=0x0001 ImageType=0x0000 ImageAddress=0x000000007E904018 Offset=(0,0)
BGRT (after): BMP 8x8, 24 bpp, image data at +0x36, 246 bytes
  bgrt-image +0000: AF AF AF AF AF AF AF AF AF AF AF AF AF AF AF AF
  bgrt-image +0010: AF AF AF AF AF AF AF AF AF AF AF AF AF AF AF AF
  bgrt-image +0020: AF AF AF AF AF AF AF AF AF AF AF AF AF AF AF AF
BGRT (after): 48 of the first 48 image bytes are 0xAF
BGRT (after): 0xAF is PcdDebugClearMemoryValue, the byte DxeCore writes over a pool
BGRT (after): block in CoreFreePoolI. Freed firmware heap has reached an ACPI table
BGRT (after): the operating system reads.
```

The `before` table is the platform's own 193x58 logo. The `after` table is 8x8 and every
sampled byte of its image is the pool free poison: the BGRT the OS would read now consists
of bytes from a freed firmware heap block. No exception was raised
(`Exception Type` count 0 on both the serial and the debug-port streams), and
`SetBootLogo2` returned `EFI_SUCCESS` for the aliased call — a caller has no way to tell
from the API that anything went wrong.

A detail worth not over-reading: the `after` table's `ImageAddress` (`0x7E904018`) is one
of the eight blocks this PoC seeded in step `[5]` — `TranslateGopBltToBmp` allocated the
BMP out of that free list. It says nothing about the defect; it is mentioned only so the
coincidence is not mistaken for evidence.

The BGRT is only rebuilt at `ReadyToBoot`, and BDS already signalled it once before the
application was launched, so getting the `after` table needs a second one. Two ways:

* `REPUBLISH=1` (`run-qemu.sh`'s default) puts a `\BL2UAF.RTB` marker next to the
  application and the application signals `ReadyToBoot` itself, so the whole chain is
  visible in one boot. **It re-runs every `ReadyToBoot` notification in the firmware** —
  see §6.
* `REPUBLISH=0` leaves it to the firmware. The next boot option signals `ReadyToBoot`
  anyway, so the table *is* rebuilt; whether anything then reads it back depends on what
  that option is. Debian's OVMF goes to `UiApp` and sits in the setup menu, so the chain
  executes but nothing reports it. A firmware whose next option is the UEFI shell runs the
  `startup.nsh` that `run-qemu.sh` also writes, which launches the application a second
  time and prints the rebuilt table.

### 5.2 ASan-instrumented firmware: the sanitizer names the defect

The same unmodified `BootLogo2Uaf.efi`, booted on an OVMF built with this project's
AddressSanitizer port of edk2 (an instrumented `BootGraphicsResourceTableDxe` plus an
instrumented `CopyMem`). Verbatim from COM1 — `AsanLib` prints every number as `0x` plus
16 hex digits, and the shadow dump is abbreviated here to one hex byte per entry for
width; `evidence/asan-report.txt` has it unedited:

```
[6] SetBootLogo2(the driver's own pointer 0x000000007B16F0A8, 8x8) -- this is the UAF
[ASan] ===================================================
[ASan] ERROR: Invalid memory access: address 0x000000007B16F0A8, size 0x0000000000000100, is_write 0x00, ip 0x000000007ABC2546
bug_descr=heap-use-after-free in file: .../MdePkg/Library/AsanMemoryLibRepStr/CopyMemWrapper.c at line: 0x48
[ASan] Shadow bytes around the buggy address 0x000000007B16F0A8 (shadow 0x000000001462DE15):
[ASan]   0x000000001462DDE0: 0xFA 0xFA 0xFA 0xFA 0xFA 0x00 0x00 0x00 0x00 0x00 0x00 0x05 0xFA 0xFA 0xFA 0xFA
[ASan]   0x000000001462DDF0: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
[ASan]   0x000000001462DE00: 0x00 0x00 0x00 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD
[ASan] =>0x000000001462DE10: 0xFD 0xFD 0xFD 0xFD 0xFD[0xFD] 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD
[ASan]   0x000000001462DE20: 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD
[ASan]   0x000000001462DE30: 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD
[ASan]   0x000000001462DE40: 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD 0xFD
    returned Success
```

Line by line:

* `address 0x000000007B16F0A8` is the pointer `GetBootLogo2` handed out at step `[4]`, the
  exact pointer step `[6]` passed back in.
* `size 0x100` is 256 bytes — 8x8 `EFI_GRAPHICS_OUTPUT_BLT_PIXEL`, the second logo's size,
  which is `BufferSize` as `:327` computed it.
* `is_write 0x00` — it is a **read**. That is the `CopyMem` inside `AllocateCopyPool`.
* `heap-use-after-free`, shadow byte **`0xFD`**: freed heap, not a redzone (`0xFA`) and not
  addressable memory (`0x00`). The whole 256-byte span is `0xFD`.
* The report arrives *between* the PoC's `[6]` line and `returned Success`, so it fired
  inside the `SetBootLogo2` call, and that call still returned `EFI_SUCCESS`.

An ASan report names no module, only an `ip`. The firmware's own DEBUG stream attributes
it:

```
Loading driver at 0x0007ABC1000 EntryPoint=0x0007ABC77B8 BootGraphicsResourceTableDxe.efi
```

`ip 0x7ABC2546` is `0x7ABC1000 + 0x1546`, inside that image. `AsanMemoryLibRepStr` is a
library statically linked into it, so the faulting instruction is in
`BootGraphicsResourceTableDxe.efi`'s own image. **One ASan report in the entire boot, and
it is this one**: `[ASan] ERROR` count 1, `bug_descr=` count 1, `Exception Type` count 0
on both streams.

The verdict logic agreed independently on this firmware, and the BGRT half reproduced
identically (`BMP 8x8`, `48 of the first 48 image bytes are 0xAF`).

One difference worth recording, because it is a limitation of the PoC and not of the
defect. On this firmware the destination was **not** one of the eight blocks step `[5]`
seeded, and the free-list probe answered "no". The seeded addresses explain why: on the
plain build they are `0x180` apart, and here they are `0x79DE88A8`, `0x7BF18728`,
`0x7BF170A8`, `0x7AD58B28`, `0x798328A8` … — scattered over megabytes. Whatever this
allocator does with a freed pool block, it is not putting it at the head of a 384-byte
bucket for the next same-sized request, so neither the seeding nor the probe can mean
anything there. (The shadow dump is consistent with a redzone-wrapped allocator — `0xFA`,
heap left redzone, immediately before the block — but the exact strategy was not
investigated and nothing here depends on it.) The verdict still held on the two
observables that do not depend on the seeding: source address ≠ destination address, and
the copied bytes are not the pattern. Both runs are in `evidence/`.

### 5.3 Independent evidence: the fuzzer that found it

This defect was not found by reading the code. It came out of a `EDKII_BOOT_LOGO2_PROTOCOL`
fuzzing campaign whose generated harness keeps a pool of live out-parameters and feeds them
back as in-parameters, which produces the aliasing by itself:

```c
if (FirnessLive_EFI_GRAPHICS_OUTPUT_BLT_PIXEL___Count > 0 && (SetBootLogo_Arg_1_LiveChoice & 1)) {
    SetBootLogo_Arg_1 = FirnessLive_EFI_GRAPHICS_OUTPUT_BLT_PIXEL__[...];
}
```

Its `crashes.csv` row, with a different block size and address, same class and same module:

```
Phase,AtBoot,Module,Function,File,Line,Asan Msg,ErrorType,Message,Count
fuzz,,BootGraphicsResourceTableDxe.efi,AsanInternalMemCopyMem,.../AsanMemoryLibRepStr/CopyMemWrapper.c,72,heap-use-after-free,asan,"address 0x00000000169904A8, size 0x0000000000000100, is_write 0x0000000000000000, ip 0x0000000017C8D546",10
```

Ten occurrences across the campaign, at nine distinct read sizes — `0x10`, `0x14`, `0x78`,
`0xC0`, `0xF0`, `0x100`, `0x134`, `0x168`, `0x1C0`. Every one is a multiple of 4, i.e. a
`Width * Height * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL)` the mutator happened to produce,
which is what you would expect if `BufferSize` comes from the second call while the source
is the first call's block. The `Line,72` in that row is decimal for the `at line: 0x48` the
sanitizer prints.

---

## 6. Safety

**What this does.** Sets a boot logo twice through a protocol any UEFI application can
call, then reads back the driver's buffer and the ACPI BGRT. Writes a plain-text report to
`\bootlogo2-uaf.log` on the volume it was loaded from.

**What it does not do.** No flash writes. No NVRAM/UEFI-variable writes of its own. No
SMM, no SMI. No change to boot order, boot options or Secure Boot state. Nothing
persistent: `SetBootLogo2` only affects the BGRT of the boot it runs in, and the BGRT is
rebuilt from scratch on every boot. Power-cycle the machine and no trace of it remains
except the log file it wrote.

**What can go wrong.** The second `SetBootLogo2` *is* the use-after-free. It reads 256
bytes out of a block the firmware just released. In the pool allocator that block stays
mapped, which is why this is observable rather than fatal — but it is undefined behaviour
in firmware, and a platform with heap guard pages, a different allocator, or a free path
that unmaps can fault instead. **A firmware fault on a physical machine means a power
cycle**, and on some platforms an unexpected reset during boot is itself disruptive. Run
it on a machine you can power-cycle. Prefer QEMU.

**The `\BL2UAF.RTB` marker is a separate risk and is opt-in for that reason.** With it
present, the application signals `ReadyToBoot`, which re-runs *every* `ReadyToBoot`
notification the firmware registered. On edk2 that includes
`BmSetMemoryTypeInformationVariable` in `UefiBootManagerLib`, **which writes an NVRAM
variable** — so with the marker the run is no longer NVRAM-clean. A real platform's
`ReadyToBoot` handlers are its own and may lock hardware. Under QEMU with a throwaway
`VARS` copy none of that matters. **Do not place the marker on hardware** unless you
have read your platform's `ReadyToBoot` handlers; without it the application signals
nothing at all.

### Running it from a USB key

1. `mkfs.vfat` a USB key (or use an existing FAT32 one).
2. Copy `BootLogo2Uaf.efi` to it. Either path works:
   * `\EFI\BOOT\BOOTX64.EFI` — the removable-media path, so the firmware boots it without
     any setup. It runs, prints, writes its log and returns to BDS.
   * anywhere, and launch it by name from a UEFI shell: `fs0:`, then
     `BootLogo2Uaf.efi`. Preferred, because you keep the console and can read the report
     on screen.
3. Do **not** create `\BL2UAF.RTB`. See above.
4. Boot the machine from the key. Secure Boot must be off, or the binary signed — it is
   not signed here.
5. Read the verdict on screen, or afterwards from `\bootlogo2-uaf.log` on the key.

---

## 7. Suggested fix

`SetBootLogo2` should not free the old buffer until it no longer needs it, and should
notice the aliasing. Either reject `BltBuffer == mLogoBltBuffer` outright, or allocate and
copy first and free the old buffer afterwards:

```c
  NewBuffer = AllocateCopyPool (BufferSize, BltBuffer);
  if (NewBuffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  if (mLogoBltBuffer != NULL) {
    FreePool (mLogoBltBuffer);
  }
  mLogoBltBuffer = NewBuffer;
```

Allocate-then-free is the better of the two, at the cost of one buffer's worth of peak
memory. It also removes a smaller state problem on the error path: as written, a failed
`AllocateCopyPool` returns `EFI_OUT_OF_RESOURCES` having already freed the previous logo
and set `mAcpiBgrtBufferChanged` at `:314`, leaving `mLogoBltBuffer == NULL` with
`mIsLogoValid` and `mLogoWidth`/`mLogoHeight` still describing the old logo. The next
`ReadyToBoot` then uninstalls the existing BGRT at `:452` and returns without reinstalling
one, because `TranslateGopBltToBmp` rejects the `NULL` (`BmpSupportLib.c:478`) — so a
transient allocation failure silently drops the table for that boot. Not a memory-safety
issue, but allocate-then-free makes it impossible.

Documenting the aliasing restriction in `BootLogo2.h` would not be enough on its own,
since the driver is reachable by any third-party UEFI application.

---

## 8. Files

| file | what it is |
| --- | --- |
| `BootLogo2Uaf.c` | the reproducer; all the reasoning is in comments next to the code that takes each observable |
| `BootLogo2Uaf.inf` | module description, `UEFI_APPLICATION` |
| `BootLogo2Uaf.dsc` | standalone platform description, so no platform DSC has to be edited |
| `build.sh` | copies the module into an edk2 workspace and builds it; detects `GCC`/`GCC5` |
| `run-qemu.sh` | lays down the ESP, boots once under QEMU, prints the report and any sanitizer findings |
| `linux/read-bgrt.py` | reads the BGRT from a booted Linux and dumps the image it points at, as a cross-check from the OS side. Read-only: `/sys/firmware/acpi/bgrt/image` if the kernel exposes it, otherwise the raw table plus `/dev/mem` |
| `evidence/run-distro-ovmf.txt` | §5.1, the guest's own report, unedited |
| `evidence/run-asan-ovmf.txt` | §5.2, the guest's own report on the instrumented firmware, unedited |
| `evidence/asan-report.txt` | §5.2, the ASan report and the module-load line that attributes its `ip`, unedited |

`linux/read-bgrt.py` is a cross-check and not the proof: once Linux is up, the BMP lives in
`EfiBootServicesData`, which the OS is entitled to reuse, so a *mismatch* there proves
nothing. `drivers/firmware/efi/efi-bgrt.c` copies the image out early in boot, which is
why `/sys/firmware/acpi/bgrt/image` is worth preferring when it exists — it is literally
what the OS read from the firmware.

---

## 9. Disclosure

This artefact is local and deliberately unpublished. Nothing here opens an issue or a pull
request, and nothing is pushed anywhere upstream. The disclosure is the repository owner's
to make.
