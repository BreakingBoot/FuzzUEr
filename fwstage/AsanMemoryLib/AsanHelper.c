/** @file
  The compiler instrumentation routines for AddressSanitizer(ASan).

  Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/
#include "MemLibInternals.h"

static const UINT64 kDefaultShadowScale = 3;
#define SHADOW_SCALE kDefaultShadowScale
static const UINT32 kStackTraceMax = 255;

#define kAsanHeapLeftRedzoneMagic  0xfa
#define kAsanHeapFreeMagic  0xfd
#define kAsanStackLeftRedzoneMagic  0xf1
#define kAsanStackMidRedzoneMagic  0xf2
#define kAsanStackRightRedzoneMagic  0xf3
#define kAsanStackAfterReturnMagic  0xf5
#define kAsanInitializationOrderMagic  0xf6
#define kAsanUserPoisonedMemoryMagic  0xf7
#define kAsanContiguousContainerOOBMagic  0xfc
#define kAsanStackUseAfterScopeMagic  0xf8
#define kAsanGlobalRedzoneMagic  0xf9
#define kAsanInternalHeapMagic  0xfe
#define kAsanArrayCookieMagic  0xac
#define kAsanIntraObjectRedzone  0xbb
#define kAsanAllocaLeftMagic  0xca
#define kAsanAllocaRightMagic  0xcb
#define SHADOW_OFFSET 0x5000000

#define MEM_TO_SHADOW(mem) (((mem) >> SHADOW_SCALE) + (SHADOW_OFFSET))
#define SHADOW_TO_MEM(shadow) (((shadow) - SHADOW_OFFSET) << SHADOW_SCALE)
#define SHADOW_GRANULARITY (1ULL << SHADOW_SCALE)
#define SHADOW_MASK ((1 << SHADOW_SCALE) - 1)

#define ASAN_ASSERT(Expression)   \
do {                            \
  if (!(Expression)) {          \
    SerialOut ("ASAN_ASSERT! ");   \
    SerialOut (": ");        \
    SerialOut (#Expression); \
    SerialOut ("\n");        \
    ASSERT (FALSE);    \
  }                             \
} while (FALSE)


// implemented in AsanLib, which is linked into every module that gets this library
// A weak definition, not a weak declaration. AsanSignalSolution lives in AsanLib,
// which is not linked into every module that uses AsanMemoryLib; an undefined
// weak reference leaves a relocation GenFw rejects with "ERROR 3000: Invalid",
// so define a no-op here and let AsanLib's strong definition take precedence.
__attribute__((weak)) void AsanSignalSolution (VOID) { }

UINT64 mAsanShadowMemoryStart_mem = 0x5000000;
UINT64 mAsanShadowMemorySize_mem  = 0x1C000000;
UINT64 mAsanShadowMemoryEnd_mem   = 0x21000000;


UINTN RoundUp(UINTN size, UINTN boundary);
UINTN RoundDown(UINTN x, UINTN boundary);

static const UINTN kCurrentStackFrameMagic = 0x41B58AB3;
static const UINTN kRetiredStackFrameMagic = 0x45E0360E;



#  define GET_CURRENT_PC()                \
    (__extension__({                      \
      UINTN pc;                            \
      asm("lea 0(%%rip), %0" : "=r"(pc)); \
      pc;                                 \
    }))

#define GET_CURRENT_FRAME() (UINTN) __builtin_frame_address(0)

#define GET_CURRENT_PC_BP \
  UINTN bp = GET_CURRENT_FRAME();              \
  UINTN pc = GET_CURRENT_PC()

#define GET_CURRENT_PC_BP_SP \
  GET_CURRENT_PC_BP;                          \
  UINTN local_stack;                           \
  UINTN sp = (UINTN)&local_stack




#define ASAN_ROUND_UP(x, b)    ((((UINTN)(x)) + ((UINTN)(b)) - 1) & ~(((UINTN)(b)) - 1))
#define ASAN_ROUND_DOWN(x, b)  (((UINTN)(x)) & ~(((UINTN)(b)) - 1))

//
// The scanners below run over shadow memory.  They MUST NOT be instrumented:
// AsanMemoryLib* is compiled with -fsanitize=address and
// -mllvm -asan-instrumentation-with-call-threshold=0, so an instrumented
// shadow read compiles to a "call __asan_load1" -- one call per shadow byte.
// no_sanitize_address turns that back into a plain load.
//
#if defined (__clang__) || defined (__GNUC__)
  #define ASAN_NO_INSTRUMENT  __attribute__((no_sanitize("address")))
#else
  #define ASAN_NO_INSTRUMENT
#endif

//
// TRUE when the single application byte at Addr is not accessible.
// This is the general form of the "partial granule" rule: a non-zero shadow
// byte N means only the first N bytes of that 8-byte granule are addressable.
//
ASAN_NO_INSTRUMENT
static inline BOOLEAN asan_address_is_poisoned (UINTN Addr)
{
  UINTN  ShadowAddr;
  INT8   ShadowValue;

  ShadowAddr = MEM_TO_SHADOW (Addr);
  if ((ShadowAddr < mAsanShadowMemoryStart_mem) ||
      (ShadowAddr > mAsanShadowMemoryEnd_mem)) {
    return FALSE;
  }

  ShadowValue = *(INT8 *)ShadowAddr;
  if (ShadowValue != 0) {
    return (BOOLEAN)((INT8)(Addr & SHADOW_MASK) >= ShadowValue);
  }

  return FALSE;
}

//
// Word-at-a-time "is this shadow run all zero" test over [Beg, Beg+Size).
// -fno-strict-aliasing is in CLANGSAN's CC_FLAGS, so the UINTN pun is fine.
// The loop never reads past Beg+Size.
//
ASAN_NO_INSTRUMENT
static inline BOOLEAN asan_shadow_is_zero (UINTN Beg, UINTN Size)
{
  UINTN  End;
  UINTN  AlignedBeg;
  UINTN  AlignedEnd;
  UINTN  All;
  UINTN  P;

  End        = Beg + Size;
  AlignedBeg = ASAN_ROUND_UP (Beg, sizeof (UINTN));
  AlignedEnd = ASAN_ROUND_DOWN (End, sizeof (UINTN));
  All        = 0;

  if (AlignedBeg > End) {
    AlignedBeg = End;
  }

  if (AlignedEnd < AlignedBeg) {
    AlignedEnd = AlignedBeg;
  }

  for (P = Beg; P < AlignedBeg; P++) {
    All |= *(UINT8 *)P;
  }

  for (P = AlignedBeg; P < AlignedEnd; P += sizeof (UINTN)) {
    All |= *(UINTN *)P;
  }

  for (P = AlignedEnd; P < End; P++) {
    All |= *(UINT8 *)P;
  }

  return (BOOLEAN)(All == 0);
}

//
// Returns the SHADOW address of the first poisoned byte in [addr, addr+size),
// or 0 when the whole range is addressable.  Callers (asan_bug_report) expect
// a shadow address, so the slow path maps back through MEM_TO_SHADOW.
//
// Fast path is the compiler-rt __asan_region_is_poisoned algorithm: probe the
// first and last application byte (covers both partial granules), then test
// the granule-aligned interior 8 shadow bytes at a time.  That is exact -- no
// sampling -- and turns the old O(Size/8) instrumented byte loop into
// O(Size/64) plain loads.
//
ASAN_NO_INSTRUMENT
static inline UINTN get_poisoned_shadow_address (UINTN addr, UINTN size)
{
  UINTN  aligned_b;
  UINTN  aligned_e;
  UINTN  shadow_beg;
  UINTN  shadow_end;
  UINTN  p;
  UINTN  end;

  if (size == 0) {
    return 0;
  }

  end        = addr + size;
  aligned_b  = ASAN_ROUND_UP (addr, SHADOW_GRANULARITY);
  aligned_e  = ASAN_ROUND_DOWN (end, SHADOW_GRANULARITY);
  shadow_beg = MEM_TO_SHADOW (aligned_b);
  shadow_end = MEM_TO_SHADOW (aligned_e);

  if (!asan_address_is_poisoned (addr) &&
      !asan_address_is_poisoned (end - 1) &&
      ((shadow_end <= shadow_beg) ||
       asan_shadow_is_zero (shadow_beg, shadow_end - shadow_beg))) {
    return 0;
  }

  //
  // Something in the range is poisoned; find the first byte slowly.
  //
  for (p = addr; p < end; p++) {
    if (asan_address_is_poisoned (p)) {
      return MEM_TO_SHADOW (p);
    }
  }

  return 0;
}

static void asan_print_16_bytes_no_bug(CONST CHAR8 *prefix,
                                        UINTN address) {
  // printf("%s0x%X:", prefix, address);
  CHAR8 NumStr[19];
  SerialOut(prefix);
  NumStr64bit(address, NumStr);
  SerialOut(NumStr);
  SerialOut(":");
  
  for (int i = 0; i < 16; i++) {
    // printf(" %02X", *(UINT8 *)(address + i));
    SerialOut(" ");
    NumStr64bit(*(UINT8 *)(address + i), NumStr); 
    SerialOut(NumStr);
  }
  SerialOut("\n");
}

static void asan_print_16_bytes_with_bug(CONST CHAR8 *prefix,
                                          UINTN address,
                                          INTN buggy_offset) {
  // printf("%s0x%X:", prefix, address);
  CHAR8 NumStr[19];
  SerialOut(prefix);
  NumStr64bit(address, NumStr);
  SerialOut(NumStr);
  SerialOut(":");

  for (int i = 0; i < buggy_offset; i++){
    // printf(" %02X", *(UINT8 *)(address + i));
    SerialOut(" ");
    NumStr64bit(*(UINT8 *)(address + i), NumStr);
    SerialOut(NumStr);
  }
  // printf("[%02X]", *(UINT8 *)(address + buggy_offset));
  SerialOut("[");
  NumStr64bit(*(UINT8 *)(address + buggy_offset), NumStr);
  SerialOut(NumStr);
  SerialOut("]");
  if (buggy_offset < 15){
    // printf("%02X", *(UINT8 *)(address + buggy_offset + 1));
    SerialOut(" ");
    NumStr64bit(*(UINT8 *)(address + buggy_offset + 1), NumStr);
    SerialOut(NumStr);
  }
  for (int i = buggy_offset + 2; i < 16; i++){
    // printf(" %02X", *(UINT8 *)(address + i));
    SerialOut(" ");
    NumStr64bit(*(UINT8 *)(address + i), NumStr);
    SerialOut(NumStr);
  }
  // printf("\n");
  SerialOut("\n");
}

static void asan_print_shadow_memory(UINTN address, INTN range_before,
                                      INTN range_after) {
  UINTN shadow_address = MEM_TO_SHADOW(address);
  UINTN aligned_shadow = shadow_address & 0xfffffff0;
  INTN buggy_offset = shadow_address - aligned_shadow;

  // printf("[ASan] Shadow bytes around the buggy address 0x%X (shadow 0x%X):\n", address, shadow_address);
  CHAR8 NumStr[19];
  SerialOut("[ASan] Shadow bytes around the buggy address ");
  NumStr64bit(address, NumStr);
  SerialOut(NumStr);
  SerialOut(" (shadow ");
  NumStr64bit(shadow_address, NumStr);
  SerialOut(NumStr);
  SerialOut("):\n");

  for (INTN i = range_before; i > 0; i--) {
    asan_print_16_bytes_no_bug("[ASan]   ", aligned_shadow - i * 16);
  }

  asan_print_16_bytes_with_bug("[ASan] =>", aligned_shadow, buggy_offset);

  for (INTN i = 1; i <= range_after; i++) {
    asan_print_16_bytes_no_bug("[ASan]   ", aligned_shadow + i * 16);
  }
}

void asan_print_bug(UINTN addr, UINTN size, CHAR8 *file, UINTN line)
{
    // Determine the error type.
  const CHAR8 *bug_descr = "unknown-crash";
  UINT8 shadow_val = 0;
  int read_after_free_bonus = 0;
  BOOLEAN far_from_bounds = FALSE;
  UINT8 *shadow_addr = (UINT8*)MEM_TO_SHADOW(addr);
  // If we are accessing 16 bytes, look at the second shadow byte.
  if (*shadow_addr == 0 && size > SHADOW_GRANULARITY)
    shadow_addr++;
  // If we are in the partial right redzone, look at the next shadow byte.
  if (*shadow_addr > 0 && *shadow_addr < 128)
    shadow_addr++;
  far_from_bounds = FALSE;
  shadow_val = *shadow_addr;
//    int bug_type_score = 0;
  // For use-after-frees reads are almost as bad as writes.
  read_after_free_bonus = 0;
  switch (shadow_val) {
    case kAsanHeapLeftRedzoneMagic:
    case kAsanArrayCookieMagic:
      bug_descr = "heap-buffer-overflow";
      break;
    case kAsanHeapFreeMagic:
      bug_descr = "heap-use-after-free";
      break;
    case kAsanStackLeftRedzoneMagic:
      bug_descr = "stack-buffer-underflow";
      break;
    case kAsanInitializationOrderMagic:
      bug_descr = "initialization-order-fiasco";
      break;
    case kAsanStackMidRedzoneMagic:
    case kAsanStackRightRedzoneMagic:
      bug_descr = "stack-buffer-overflow";
      break;
    case kAsanStackAfterReturnMagic:
      bug_descr = "stack-use-after-return";
      break;
    case kAsanUserPoisonedMemoryMagic:
      bug_descr = "use-after-poison";
      break;
    case kAsanContiguousContainerOOBMagic:
      bug_descr = "container-overflow";
      break;
    case kAsanStackUseAfterScopeMagic:
      bug_descr = "stack-use-after-scope";
      break;
    case kAsanGlobalRedzoneMagic:
      bug_descr = "global-buffer-overflow";
      break;
    case kAsanIntraObjectRedzone:
      bug_descr = "intra-object-overflow";
      break;
    case kAsanAllocaLeftMagic:
     case kAsanAllocaRightMagic:
      bug_descr = "dynamic-stack-buffer-overflow";
      break;
    }
  SerialOut("bug_descr=");
  SerialOut(bug_descr);
  SerialOut(" in file: ");
  SerialOut(file);
  SerialOut(" at line: ");
  CHAR8 NumStr[19];
  NumStr64bit(line, NumStr);
  SerialOut(NumStr);
  SerialOut("\n");
}

void asan_bug_report(UINTN addr, UINTN size,
                      UINTN buggy_shadow_address, UINT8 is_write,
                      UINTN ip, CHAR8 *file, UINTN line) {
  UINTN buggy_address = SHADOW_TO_MEM(buggy_shadow_address);
  // printf("[ASan] ===================================================\n");
  SerialOut("[ASan] ===================================================\n");
  // printf(
  //     "[ASan] ERROR: Invalid memory access: address 0x%X, size 0x%X, is_write "
  //     "%d, ip 0x%X\n",
  //     addr, size, is_write, ip);
  CHAR8 NumStr[19];
  SerialOut("[ASan] ERROR: Invalid memory access: address ");
  NumStr64bit(addr, NumStr);
  SerialOut(NumStr);
  SerialOut(", size ");
  NumStr64bit(size, NumStr);
  SerialOut(NumStr);
  SerialOut(", is_write ");
  NumStr64bit(is_write, NumStr);
  SerialOut(NumStr);
  SerialOut(", ip ");
  NumStr64bit(ip, NumStr);
  SerialOut(NumStr);
  SerialOut("\n");
  asan_print_bug(addr, size, file, line);

  asan_print_shadow_memory(buggy_address, 3, 3);
  // AsanLib owns the escalation; this library has its own reporter and would
  // otherwise print a CopyMem/SetMem overflow and let the iteration continue
  AsanSignalSolution ();
}

static inline int asan_check_memory(UINTN addr, UINTN size,
                                     BOOLEAN write, UINTN pc, CHAR8 *file, UINTN line) {
  int buggy_shadow_address;
  UINTN shadow_beg, shadow_end;
  if (size == 0) return 1;

  // mAsanShadowMemory*_mem bound the SHADOW region (0x5000000..0x21000000),
  // not the addresses being checked, so the guard has to be applied to the
  // mapped shadow address -- exactly as the load/store callbacks in Asan.c do.
  // As shipped this read `addr > Start || addr < End`, which is a tautology
  // (Start < End) and made every CopyMem/SetMem check unreachable.
  shadow_beg = MEM_TO_SHADOW(addr);
  shadow_end = MEM_TO_SHADOW(addr + size - 1);
  if (shadow_beg < mAsanShadowMemoryStart_mem ||
      shadow_end > mAsanShadowMemoryEnd_mem) return 1;

  buggy_shadow_address = get_poisoned_shadow_address(addr, size);
  if (buggy_shadow_address == 0) return 1;

  asan_bug_report(addr, size, buggy_shadow_address, write, pc, file, line);
  return 0;
}

VOID *
EFIAPI
AsanInternalMemCopyMem (
  OUT     VOID        *DestinationBuffer,
  IN      CONST VOID  *SourceBuffer,
  IN      UINTN       Length,
  IN CHAR8  *File,
  IN UINTN  Line
  )
{
  asan_check_memory((UINTN)SourceBuffer, Length, FALSE, GET_CURRENT_PC(), File, Line);
  asan_check_memory((UINTN)DestinationBuffer, Length, TRUE, GET_CURRENT_PC(), File, Line);
  return InternalMemCopyMem(DestinationBuffer, SourceBuffer, Length);
}

VOID *
EFIAPI
AsanInternalMemSetMem (
  OUT     VOID   *Buffer,
  IN      UINTN  Length,
  IN      UINT8  Value,
  IN CHAR8  *File,
  IN UINTN  Line 
  )
{
  asan_check_memory((UINTN)Buffer, Length, TRUE, GET_CURRENT_PC(), File, Line);
  return InternalMemSetMem(Buffer, Length, Value);
}

VOID *
EFIAPI
AsanInternalMemZeroMem (
  OUT     VOID   *Buffer,
  IN      UINTN  Length,
  IN CHAR8  *File,
  IN UINTN  Line
  )
{
  asan_check_memory ((UINTN)Buffer, Length, TRUE, GET_CURRENT_PC (), File, Line);
  return InternalMemZeroMem (Buffer, Length);
}

INTN
EFIAPI
AsanInternalMemCompareMem (
  IN      CONST VOID  *DestinationBuffer,
  IN      CONST VOID  *SourceBuffer,
  IN      UINTN       Length,
  IN CHAR8  *File,
  IN UINTN  Line
  )
{
  asan_check_memory ((UINTN)DestinationBuffer, Length, FALSE, GET_CURRENT_PC (), File, Line);
  asan_check_memory ((UINTN)SourceBuffer, Length, FALSE, GET_CURRENT_PC (), File, Line);
  return InternalMemCompareMem (DestinationBuffer, SourceBuffer, Length);
}

BOOLEAN
EFIAPI
AsanInternalMemIsZeroBuffer (
  IN CONST VOID  *Buffer,
  IN UINTN       Length,
  IN CHAR8  *File,
  IN UINTN  Line
  )
{
  asan_check_memory ((UINTN)Buffer, Length, FALSE, GET_CURRENT_PC (), File, Line);
  return InternalMemIsZeroBuffer (Buffer, Length);
}

CONST VOID *
EFIAPI
AsanInternalMemScanMem8 (
  IN      CONST VOID  *Buffer,
  IN      UINTN       Length,
  IN      UINT8       Value,
  IN CHAR8  *File,
  IN UINTN  Line
  )
{
  //
  // Length is a byte count here (element width is 1).
  //
  asan_check_memory ((UINTN)Buffer, Length, FALSE, GET_CURRENT_PC (), File, Line);
  return InternalMemScanMem8 (Buffer, Length, Value);
}

CONST VOID *
EFIAPI
AsanInternalMemScanMem16 (
  IN      CONST VOID  *Buffer,
  IN      UINTN       Length,
  IN      UINT16      Value,
  IN CHAR8  *File,
  IN UINTN  Line
  )
{
  //
  // Length is a COUNT of UINT16 elements (ScanMem16Wrapper already divided
  // the caller's byte length by sizeof (UINT16)).
  //
  asan_check_memory ((UINTN)Buffer, Length * sizeof (UINT16), FALSE, GET_CURRENT_PC (), File, Line);
  return InternalMemScanMem16 (Buffer, Length, Value);
}

CONST VOID *
EFIAPI
AsanInternalMemScanMem32 (
  IN      CONST VOID  *Buffer,
  IN      UINTN       Length,
  IN      UINT32      Value,
  IN CHAR8  *File,
  IN UINTN  Line
  )
{
  asan_check_memory ((UINTN)Buffer, Length * sizeof (UINT32), FALSE, GET_CURRENT_PC (), File, Line);
  return InternalMemScanMem32 (Buffer, Length, Value);
}

CONST VOID *
EFIAPI
AsanInternalMemScanMem64 (
  IN      CONST VOID  *Buffer,
  IN      UINTN       Length,
  IN      UINT64      Value,
  IN CHAR8  *File,
  IN UINTN  Line
  )
{
  asan_check_memory ((UINTN)Buffer, Length * sizeof (UINT64), FALSE, GET_CURRENT_PC (), File, Line);
  return InternalMemScanMem64 (Buffer, Length, Value);
}

VOID *
EFIAPI
AsanInternalMemSetMem16 (
  OUT     VOID    *Buffer,
  IN      UINTN   Length,
  IN      UINT16  Value,
  IN CHAR8  *File,
  IN UINTN  Line
  )
{
  //
  // Length is a COUNT of UINT16 elements.
  //
  asan_check_memory ((UINTN)Buffer, Length * sizeof (UINT16), TRUE, GET_CURRENT_PC (), File, Line);
  return InternalMemSetMem16 (Buffer, Length, Value);
}

VOID *
EFIAPI
AsanInternalMemSetMem32 (
  OUT     VOID    *Buffer,
  IN      UINTN   Length,
  IN      UINT32  Value,
  IN CHAR8  *File,
  IN UINTN  Line
  )
{
  asan_check_memory ((UINTN)Buffer, Length * sizeof (UINT32), TRUE, GET_CURRENT_PC (), File, Line);
  return InternalMemSetMem32 (Buffer, Length, Value);
}

VOID *
EFIAPI
AsanInternalMemSetMem64 (
  OUT     VOID    *Buffer,
  IN      UINTN   Length,
  IN      UINT64  Value,
  IN CHAR8  *File,
  IN UINTN  Line
  )
{
  asan_check_memory ((UINTN)Buffer, Length * sizeof (UINT64), TRUE, GET_CURRENT_PC (), File, Line);
  return InternalMemSetMem64 (Buffer, Length, Value);
}
