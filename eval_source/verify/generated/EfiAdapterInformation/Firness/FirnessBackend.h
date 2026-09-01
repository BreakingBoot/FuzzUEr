/** @file
  Backend-neutral fuzzing protocol for generated Firness UEFI harnesses.

  WHAT THIS IS
    One header that supplies HARNESS_START / HARNESS_STOP / HARNESS_ASSERT for
    whichever fuzzer the harness is built against, selected at EDK2 build time
    from the FIRNESS_BACKEND macro. The macro spellings are the upstream TSFFS
    ones, so switching backends is a one-line change in the generator.

  HOW IT SHIPS
    harness_generator/main.py copies every file in HarnessHelpers wholesale into
    each generated harness folder, so dropping this file there is all the
    plumbing it needs. uefi_harness/main_template.py then includes it instead of
    including "tsffs-gcc-x86_64.h" directly.

  HOW A BACKEND IS SELECTED
    uefi_harness/dsc_template.py emits, into the generated Firness.dsc:

        [BuildOptions]
          GCC:*_*_*_CC_FLAGS = -D FIRNESS_BACKEND=2

    "GCC" is the tool FAMILY, not a tag. The harness is built by
    scripts/firness.py with "-t CLANGSAN", and BaseTools/Conf/tools_def.template
    line 2703 declares "*_CLANGSAN_*_*_FAMILY = GCC", so the GCC: prefix is what
    matches CLANGSAN. CLANGDWARF, CLANGPDB and GCC5 are FAMILY=GCC too.
    A single "=" APPENDS to the toolchain CC_FLAGS. "==" would REPLACE them and
    silently drop -mno-red-zone, -mcmodel=small and
    -DEFIAPI=__attribute__((ms_abi)) -- so it must stay a single "=".

    Backend id 0 is reserved as invalid on purpose. An unrecognised identifier
    expands to 0 in #if, so a typo such as -D FIRNESS_BACKEND=TSFF trips the
    #error at the bottom of this file instead of silently selecting a backend.
    An absent -D falls back to TSFFS, the only backend proven end to end here.

  ABI RULE -- READ BEFORE EDITING THE ASM
    EDK2 X64 compiles with -DEFIAPI=__attribute__((ms_abi))
    (tools_def.template:1913), so FirnessMain takes RCX,RDX,R8,R9 while
    compiler-emitted helpers are SysV. The helpers below sidestep that entirely
    by being ALWAYS INLINED: the asm pins RAX/RDI/RSI with explicit register
    constraints inside whatever function it lands in, so the enclosing calling
    convention is irrelevant. That holds only while they are inlined.

      Do NOT put EFIAPI on them, and do NOT move them into a .c file. A
      non-EFIAPI out-of-line function called from EFIAPI code would take its
      arguments in RCX/RDX while its body reads RDI/RSI, so the command and
      arguments would be garbage and the guest would issue nonsense commands
      with no diagnostic. __attribute__((always_inline)) makes that impossible
      rather than merely unlikely.

    "static inline" and not plain "static": EDK2 builds with -Wall -Werror
    (tools_def.template:1876) and does not pass -Wno-unused-function, so a
    translation unit that uses only one of these macros would otherwise fail to
    compile with "defined but not used".

  CONTRACT EVERY BACKEND ARM MUST DEFINE
    FIRNESS_BACKEND_NAME       string, for diagnostics
    FIRNESS_MAX_INPUT_SIZE     bytes the harness must reserve for the testcase
    HARNESS_START(buf, szp)    IN OUT: *szp is the cap on entry, the actual
                               testcase length on return
    HARNESS_STOP()             end this iteration, normal
    HARNESS_ASSERT()           end this iteration, objective/crash
**/

#ifndef FIRNESS_BACKEND_H_
#define FIRNESS_BACKEND_H_

//
// Base.h, not Uefi.h: all this needs is UINT8/UINT64/UINTN, and Base.h is valid
// in every module type. FirnessMain.c includes FirnessHarnesses.h first anyway.
//
#include <Base.h>

#define FIRNESS_BACKEND_INVALID      0
#define FIRNESS_BACKEND_TSFFS        1
#define FIRNESS_BACKEND_LIBAFL_QEMU  2
#define FIRNESS_BACKEND_NYX          3
#define FIRNESS_BACKEND_NONE         4

#ifndef FIRNESS_BACKEND
#define FIRNESS_BACKEND  FIRNESS_BACKEND_TSFFS
#endif

// ---------------------------------------------------------------------------
#if FIRNESS_BACKEND == FIRNESS_BACKEND_TSFFS
// ---------------------------------------------------------------------------
//
// Simics / TSFFS. Straight passthrough to the upstream header, which already
// lives in HarnessHelpers, so the emitted CPUID sequences are unchanged.
// Reference (line numbers checked against the shipped file):
//   MAGIC                       0x4711  tsffs-gcc-x86_64.h:130
//   DEFAULT_INDEX               0       :135
//   N_START_BUFFER_PTR_SIZE_PTR 1       :140
//   N_STOP_NORMAL               4       :380
//   N_STOP_ASSERT               5       :429
//   HARNESS_START :172   HARNESS_STOP :396   HARNESS_ASSERT :446
// HARNESS_START is a cpuid with eax = (n << 16) | 0x4711, rdi = index,
// rsi = buffer, rdx = size_ptr. TSFFS writes the length THROUGH the pointer.
//
#define FIRNESS_BACKEND_NAME  "tsffs"

#ifndef FIRNESS_MAX_INPUT_SIZE
#define FIRNESS_MAX_INPUT_SIZE  0x1000
#endif

#include "tsffs-gcc-x86_64.h"

//
// BUG FIX, and it is not cosmetic. Upstream's __cpuid_extended3 (:118-125) has
// NO "memory" clobber, even though HARNESS_START hands it a POINTER that the
// hypervisor writes the testcase length through. The compiler is therefore
// entitled to assume *size_ptr is unchanged across the CPUID -- and it does.
// Verified on the unmodified generator output at EDK2's own GCC5 X64 flags:
//
//     1e:  movq   $0x1000,0x28(%rsp)     ; InputSize = MaxInputSize
//     39:  lea    0x28(%rsp),%rdx        ; &InputSize into the CPUID arg
//     45:  cpuid                         ; HARNESS_START -- TSFFS writes here
//     58:  mov    %rsi,<Input.Buffer>
//     5f:  movq   $0x1000,<Input.Length> ; <-- CONSTANT, not the reloaded value
//
// So Input.Length is pinned at the buffer capacity and the harness parses the
// whole 4 KiB page as the testcase on every iteration, dragging in whatever the
// previous iteration left past the end of the current input. That costs
// reproducibility and wastes mutation signal, on the CURRENT Simics setup, with
// no visible symptom.
//
// The fix keeps upstream's CPUID sequence byte-for-byte -- it reuses upstream's
// own __cpuid_extended3, MAGIC, DEFAULT_INDEX and N_START_BUFFER_PTR_SIZE_PTR
// -- and only adds an empty asm with a "memory" clobber, which emits no
// instruction and forces the reload. HARNESS_STOP and HARNESS_ASSERT pass no
// pointer, so they need no barrier and are left exactly as upstream defines
// them.
//
#undef HARNESS_START
#define HARNESS_START(buffer, size_ptr)                                    \
  do {                                                                     \
    unsigned int  value = (N_START_BUFFER_PTR_SIZE_PTR << 0x10U) | MAGIC;  \
    __cpuid_extended3 (value, DEFAULT_INDEX, (buffer), (size_ptr));        \
    __asm__ __volatile__ ("" : : : "memory");                              \
  } while (0)

// ---------------------------------------------------------------------------
#elif FIRNESS_BACKEND == FIRNESS_BACKEND_LIBAFL_QEMU
// ---------------------------------------------------------------------------

#define FIRNESS_BACKEND_NAME  "libafl-qemu"

#ifndef FIRNESS_MAX_INPUT_SIZE
#define FIRNESS_MAX_INPUT_SIZE  0x1000
#endif

//
// The register constraints below ("a"/"D"/"S" on 64-bit values) are x86-64
// only; on IA32 they fail with "invalid output size for constraint" pointing at
// this header rather than at the real cause. Say what actually went wrong.
//
#if !defined (__x86_64__) || defined (__ILP32__)
  #error "FirnessBackend.h: the LibAFL-QEMU backend is X64 only. Do not include it from IA32 modules."
#endif
#if !defined (__GNUC__) && !defined (__clang__)
  #error "FirnessBackend.h: the LibAFL-QEMU backend needs GNU-style inline asm (GCC5, CLANGSAN, CLANGDWARF or CLANGPDB)."
#endif

//
// ABI PROVENANCE. The guest-side ABI is NOT in the LibAFL repo. It was split
// out into github.com/rmalmain/libvharness, and LibAFL vendors it at a PINNED
// commit: crates/libafl_qemu/libvharness_sys/build.rs declares
//   const LIBVHARNESS_COMMIT: &str = "9a316966ce7aa4bd9f733491511e6ac4be6dd980";
// and bindgens it, so these numbers and LibAFL's own host-side parsers are two
// views of one file. Every value below was transcribed from that commit:
//   include/api/lqemu/common.h:13-15   opcodes, test value
//   include/api/lqemu/common.h:37-41   end status enum
//   include/api/lqemu/common.h:43-55   command enum
//   include/api/lqemu/lqemu.h:19-20    version 0.1
//   src/api/lqemu/arch/x86_64/calls.c  cmd->RAX, arg1->RDI, arg2->RSI, ret<-RAX
// and cross-checked against the checked-in bindings
//   crates/libafl_qemu/libvharness_sys/src/stub.rs:290-294
// Host side: crates/libafl_qemu/src/arch/x86_64.rs:44-51 maps
//   Cmd=Rax, Arg1=Rdi, Arg2=Rsi, Ret=Rax.
//
// !! THE ABI DECLARES ITSELF VERSION 0.1 AND IS NOT STABLE. libvharness moves
// !! independently of LibAFL. Re-derive on any bump. FIRNESS_LQEMU_VERSION_CHECK
// !! below is the cheap way to make drift loud instead of silent.
//
#define LIBAFL_CUSTOM_INSN_OPCODE  0x66f23a0f
#define LIBAFL_QEMU_TEST_VALUE     0xcafebabeULL

//
// Command ids and end statuses are given PRIVATE names on purpose. Upstream
// declares them as C ENUMERATORS, not macros (common.h:37-55), so an #ifndef
// guard would never fire and a #define of the upstream spelling would rewrite
// the enum body into "0 = 0," if libvharness's common.h were ever included
// after this file. Ids 2 and 3 are a deliberate gap: they were INPUT_VIRT and
// INPUT_PHYS, which no longer exist -- see the note on HARNESS_START.
//
#define FIRNESS_LQEMU_CMD_START_VIRT          0
#define FIRNESS_LQEMU_CMD_START_PHYS          1
#define FIRNESS_LQEMU_CMD_END                 4
#define FIRNESS_LQEMU_CMD_SAVE                5
#define FIRNESS_LQEMU_CMD_LOAD                6
#define FIRNESS_LQEMU_CMD_VERSION             7
#define FIRNESS_LQEMU_CMD_VADDR_FILTER_ALLOW  8
#define FIRNESS_LQEMU_CMD_INTERNAL_ERROR      9
#define FIRNESS_LQEMU_CMD_LQPRINTF            10
#define FIRNESS_LQEMU_CMD_TEST                11
#define FIRNESS_LQEMU_CMD_SET_MAP             12

#define FIRNESS_LQEMU_END_UNKNOWN  0
#define FIRNESS_LQEMU_END_OK       1
#define FIRNESS_LQEMU_END_CRASH    2

#define FIRNESS_LQEMU_VERSION_MAJOR  0
#define FIRNESS_LQEMU_VERSION_MINOR  1

//
// The four bytes 0f 3a f2 66 (little-endian 0x66f23a0f) are NOT an x86
// instruction. qemu-libafl-bridge pattern-matches them in
// accel/tcg/translator.c, inside translator_loop(), BEFORE ops->translate_insn
// runs. Consequences, all of which matter here:
//   * no ModRM, no operand-size semantics, exactly 4 bytes consumed;
//   * no CPL gating and no CPUID feature bit, so it works from a DXE driver
//     and (in principle) from inside an SMI handler;
//   * matching happens at TCG translation time, so this is TCG-ONLY. It will
//     never work under KVM, which rules out "add KVM later for speed";
//   * on real silicon and under stock QEMU these bytes are #UD. Unlike TSFFS's
//     CPUID magic, which is a legal no-op with no fuzzer attached, a harness
//     built with this backend FAULTS if booted standalone. Use
//     FIRNESS_BACKEND=4 (none) for a standalone smoke test.
// objdump renders the sequence as "(bad)" plus a stray operand-size prefix on
// the following instruction. That is cosmetic; a raw byte scan of .text finds
// the pattern intact.
//
// The explicit .byte form assembles to exactly the same four bytes as upstream's
// ".4byte 0x66f23a0f" and does not depend on the assembler's endianness for a
// value that is really a byte pattern.
//
#define FIRNESS_LQEMU_INSN  ".byte 0x0f, 0x3a, 0xf2, 0x66\n\t"

//
// "+a" ties the RAX input and the RAX result into one operand, which is exactly
// what these hypercalls do. RDI/RSI are pure inputs; the host never writes them
// back. "memory" is load-bearing, not decoration: the host writes the testcase
// into the guest buffer across the START instruction, and the snapshot restore
// resumes here with different memory contents, so nothing may be cached across
// it. Upstream's macro instead uses "g" constraints plus explicit movs into
// rax/rdi/rsi; pinning the operands directly is both shorter and immune to the
// allocator placing an input in a register an earlier mov already overwrote.
//
#define FIRNESS_LQEMU_INLINE  static inline __attribute__ ((always_inline))

FIRNESS_LQEMU_INLINE UINT64
FirnessLqemuCall1 (
  UINT64  Cmd,
  UINT64  Arg1
  )
{
  UINT64  Ret = Cmd;

  __asm__ __volatile__ (
    FIRNESS_LQEMU_INSN
    : "+a" (Ret)
    : "D" (Arg1)
    : "memory", "cc"
    );
  return Ret;
}

FIRNESS_LQEMU_INLINE UINT64
FirnessLqemuCall2 (
  UINT64  Cmd,
  UINT64  Arg1,
  UINT64  Arg2
  )
{
  UINT64  Ret = Cmd;

  __asm__ __volatile__ (
    FIRNESS_LQEMU_INSN
    : "+a" (Ret)
    : "D" (Arg1), "S" (Arg2)
    : "memory", "cc"
    );
  return Ret;
}

/**
  Start (or resume) one fuzzing iteration and fetch the testcase.

  There is NO separate input command in this ABI version: START is the input
  fetch. libafl_qemu_input_virt / input_phys are still declared in libvharness
  lqemu.h but have no implementation and no command id.

  Host behaviour (crates/libafl_qemu/src/command/lqemu/):
    - the first time this instruction retires, StartCommand::run snapshots the
      VM, records Buffer/MaxLen plus RAX as the return register, flushes the JIT
      and hands control back to the fuzzer WITHOUT writing RAX;
    - before the guest is resumed -- on that first return and on every iteration
      after it -- GenericEmulatorDriver::pre_harness_exec calls
      LqemuInputSetter::write_input, which copies the testcase into Buffer and
      writes the byte count into RAX.
  So the value returned here is always host-written; the guest never observes an
  unwritten RAX.

  Buffer must be mapped in the page tables the CPU is using when this executes:
  the host resolves it with a CR3 walk (QemuMemoryChunk::virt). Inside an SMI
  handler that means SMM's page tables, not DXE's. A single page-aligned
  AllocatePages allocation satisfies this in both cases.

  @param  Buffer  Guest VIRTUAL address of the input buffer.
  @param  MaxLen  Capacity of Buffer in bytes, passed BY VALUE (TSFFS passes a
                  pointer; the HARNESS_START macro below absorbs the difference).
  @return Bytes the host wrote into Buffer.
**/
FIRNESS_LQEMU_INLINE UINT64
FirnessLqemuStartVirt (
  volatile VOID  *Buffer,
  UINT64         MaxLen
  )
{
  //
  // (UINT64)(UINTN) and never (unsigned long): UINTN is pointer-sized on every
  // EDK2 target, whereas unsigned long is 32 bits under CLANGPDB/VS
  // (x86_64-pc-windows-msvc) and would hand the fuzzer a truncated buffer
  // address -- silently, so every testcase would land in the wrong page.
  //
  return FirnessLqemuCall2 (
           (UINT64)FIRNESS_LQEMU_CMD_START_VIRT,
           (UINT64)(UINTN)Buffer,
           MaxLen
           );
}

/**
  As FirnessLqemuStartVirt, but Buffer is a guest PHYSICAL address so the host
  skips the page-table walk. Registered in the systemmode command manager, which
  is what a UEFI target uses. Prefer it if the harness ever runs with paging off
  or from a CR3 the host cannot walk.
**/
FIRNESS_LQEMU_INLINE UINT64
FirnessLqemuStartPhys (
  volatile VOID  *Buffer,
  UINT64         MaxLen
  )
{
  return FirnessLqemuCall2 (
           (UINT64)FIRNESS_LQEMU_CMD_START_PHYS,
           (UINT64)(UINTN)Buffer,
           MaxLen
           );
}

/**
  End the current iteration. The host restores the snapshot taken at START, so
  in steady state this does not return. Status must be OK or CRASH: EndCommand
  unwraps the mapped exit kind, so END(UNKNOWN) or an out-of-range status panics
  the fuzzer. Calling it before any START aborts the run with EndBeforeStart.
**/
FIRNESS_LQEMU_INLINE VOID
FirnessLqemuEnd (
  UINT64  Status
  )
{
  (VOID)FirnessLqemuCall1 ((UINT64)FIRNESS_LQEMU_CMD_END, Status);
}

//
// Evaluate size_ptr exactly once; it is a public macro contract, and
// HARNESS_START(g, &sizes[i++]) must not fire the side effect twice.
//
#define HARNESS_START(buffer, size_ptr)                                    \
  do {                                                                     \
    UINTN  *FirnessSizePtr_ = (size_ptr);                                  \
    *FirnessSizePtr_ = (UINTN)FirnessLqemuStartVirt (                      \
                         (volatile VOID *)(buffer),                        \
                         (UINT64)*FirnessSizePtr_                          \
                         );                                                \
  } while (0)

#define HARNESS_STOP()    FirnessLqemuEnd ((UINT64)FIRNESS_LQEMU_END_OK)
#define HARNESS_ASSERT()  FirnessLqemuEnd ((UINT64)FIRNESS_LQEMU_END_CRASH)

/**
  Optional handshake. The host compares against its own 0.1 and, on mismatch,
  fails the run with CommandError::VersionDifference rather than warning. Call
  it only when a hard failure on ABI drift is what you want; it is deliberately
  not part of HARNESS_START.
**/
#define FIRNESS_LQEMU_VERSION_CHECK()                       \
  do {                                                      \
    (VOID)FirnessLqemuCall2 (                               \
            (UINT64)FIRNESS_LQEMU_CMD_VERSION,              \
            (UINT64)FIRNESS_LQEMU_VERSION_MAJOR,            \
            (UINT64)FIRNESS_LQEMU_VERSION_MINOR             \
            );                                              \
  } while (0)

/**
  Round-trip check: the host asserts Arg1 == 0xcafebabe. Worth issuing once,
  early, to prove the four magic bytes are actually being decoded before
  spending a full boot on a harness that turns out to be talking to nobody.
**/
#define FIRNESS_LQEMU_SELFTEST()                            \
  do {                                                      \
    (VOID)FirnessLqemuCall1 (                               \
            (UINT64)FIRNESS_LQEMU_CMD_TEST,                 \
            (UINT64)LIBAFL_QEMU_TEST_VALUE                  \
            );                                              \
  } while (0)

// ---------------------------------------------------------------------------
#elif FIRNESS_BACKEND == FIRNESS_BACKEND_NYX
// ---------------------------------------------------------------------------
//
// Reserved, deliberately not implemented. Two independent blockers:
//
//  1. Real kAFL/Nyx needs the KVM-Nyx kernel module plus Intel PT with
//     multi-entry ToPA and IP filtering. This host reports
//     topa_multiple_entries=0, ip_filtering=0, num_address_ranges=0, and no
//     kernel module may be installed.
//
//  2. LibAFL-QEMU does emulate the Nyx command protocol in TCG, with no KVM and
//     no PT -- but its GetHostConfigCommand::run hardcodes
//     payload_buffer_size: 0 (crates/libafl_qemu/src/command/nyx/mod.rs, marked
//     TODO) while still reporting correct magic and version. A guest that sizes
//     its payload buffer from the host handshake therefore gets a capacity of
//     zero, the handshake succeeds, and every iteration receives an empty
//     testcase -- forever, with healthy-looking coverage and exec counters.
//     That is the exact silent-failure mode this whole design is meant to avoid.
//
// If this is ever revived: the guest must treat its OWN allocation as the source
// of truth and use the host value only as an upper bound when it is non-zero,
// kAFL's payload_buffer_size covers the whole kAFL_payload struct (usable data
// is that minus OFFSET_OF(data), 4 bytes), and agent_non_reload_mode must be 1
// or the in-guest persistent loop never actually iterates.
//
  #error "FirnessBackend.h: the kAFL/Nyx backend is not implemented. Intel PT is unavailable on this host (topa_multiple_entries=0) and LibAFL-QEMU's Nyx frontend reports payload_buffer_size=0, which yields silent zero-length inputs. Use FIRNESS_BACKEND=2 (libafl-qemu) instead."

// ---------------------------------------------------------------------------
#elif FIRNESS_BACKEND == FIRNESS_BACKEND_NONE
// ---------------------------------------------------------------------------
//
// No fuzzer. Replays one compiled-in testcase, then returns normally. This is
// what a standalone boot smoke test and a crash reproducer should be built
// with: it emits no magic instruction at all, so the image boots on real
// hardware and under stock QEMU.
//
// Deliberately depends on NOTHING beyond Base.h -- no CopyMem, no gBS, no
// CpuDeadLoop -- so it adds no [LibraryClasses] or [Protocols] entry to the
// generated .inf.
//
#define FIRNESS_BACKEND_NAME  "none"

#ifndef FIRNESS_MAX_INPUT_SIZE
#define FIRNESS_MAX_INPUT_SIZE  0x1000
#endif

//
// Override with e.g. -D "FIRNESS_NONE_INPUT_ARRAY={0x03,0xff,0x41}" to replay a
// specific testcase.
//
#ifndef FIRNESS_NONE_INPUT_ARRAY
#define FIRNESS_NONE_INPUT_ARRAY  { 0x00 }
#endif

static CONST UINT8  mFirnessNoneInput[] __attribute__ ((unused)) = FIRNESS_NONE_INPUT_ARRAY;

static inline __attribute__ ((always_inline)) VOID
FirnessNoneLoad (
  UINT8  *Buffer,
  UINTN  *SizePtr
  )
{
  UINTN  Len;
  UINTN  Index;

  Len = sizeof (mFirnessNoneInput);
  if (Len > *SizePtr) {
    Len = *SizePtr;
  }

  for (Index = 0; Index < Len; Index++) {
    Buffer[Index] = mFirnessNoneInput[Index];
  }

  *SizePtr = Len;
}

#define HARNESS_START(buffer, size_ptr)                       \
  do {                                                        \
    UINTN  *FirnessSizePtr_ = (size_ptr);                     \
    FirnessNoneLoad ((UINT8 *)(buffer), FirnessSizePtr_);     \
  } while (0)

#define HARNESS_STOP()  do { } while (0)

//
// Default is to fall through and let FirnessMain return, so a smoke test exits
// cleanly. -D FIRNESS_NONE_DEADLOOP_ON_CRASH=1 parks the CPU instead, which is
// what you want when reproducing an objective under a debugger.
//
#if defined (FIRNESS_NONE_DEADLOOP_ON_CRASH) && FIRNESS_NONE_DEADLOOP_ON_CRASH
#define HARNESS_ASSERT()  do { for ( ; ;) { } } while (0)
#else
#define HARNESS_ASSERT()  do { } while (0)
#endif

// ---------------------------------------------------------------------------
#else
// ---------------------------------------------------------------------------
  #error "FirnessBackend.h: unknown FIRNESS_BACKEND. Pass exactly one of -D FIRNESS_BACKEND=1 (tsffs, the default), 2 (libafl-qemu), 3 (nyx, unimplemented) or 4 (none). 0 is reserved and invalid: an unrecognised identifier expands to 0 in #if, so this also fires on a typo such as -D FIRNESS_BACKEND=TSFF."
#endif

//
// Completeness check, so a half-written arm fails here rather than at the first
// use site in generated code.
//
#if !defined (FIRNESS_BACKEND_NAME) || !defined (FIRNESS_MAX_INPUT_SIZE)
  #error "FirnessBackend.h: the selected backend did not define the full contract (FIRNESS_BACKEND_NAME / FIRNESS_MAX_INPUT_SIZE)."
#endif

#endif // FIRNESS_BACKEND_H_
