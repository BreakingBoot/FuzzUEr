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




static inline UINTN get_poisoned_shadow_address(UINTN addr,
                                                        UINTN size) {
  UINTN addr_shadow_start = MEM_TO_SHADOW(addr);
  UINTN addr_shadow_end = MEM_TO_SHADOW(addr + size - 1) + 1;
  UINTN non_zero_shadow_addr = 0;

  for (UINTN i = 0; i < addr_shadow_end - addr_shadow_start; i++) {
    if (*(UINT8 *)(addr_shadow_start + i) != 0) {
      non_zero_shadow_addr = addr_shadow_start + i;
      break;
    }
  }

  if (non_zero_shadow_addr) {
    UINTN last_byte = addr + size - 1;
    INT8 *last_shadow_byte = (INT8 *)MEM_TO_SHADOW(last_byte);

    // Non-zero bytes in shadow memory may indicate either:
    //  1) invalid memory access (0xff, 0xfa, ...)
    //  2) access to a 8-byte region which isn't entirely accessible, i.e. only
    //     n bytes can be read/written in the 8-byte region, where n < 8
    //     (in this case shadow byte encodes how much bytes in an 8-byte region
    //     are accessible).
    // Thus, if there is a non-zero shadow byte we need to check if it
    // corresponds to the last byte in the checked region:
    //   not last - OOB memory access
    //   last - check if we don't access beyond what's encoded in the shadow
    //          byte.
    if (non_zero_shadow_addr != (UINTN)last_shadow_byte ||
        ((INT8)(last_byte & SHADOW_MASK) >= *last_shadow_byte))
      return non_zero_shadow_addr;
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
  // ASAN_ASSERT(FALSE);
}

static inline int asan_check_memory(UINTN addr, UINTN size,
                                     BOOLEAN write, UINTN pc, CHAR8 *file, UINTN line) {
  int buggy_shadow_address;
  if (size == 0) return 1;

  if (addr > mAsanShadowMemoryStart_mem || addr < mAsanShadowMemoryEnd_mem) return 1;

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
