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
#ifndef _ASAN_H_
#define _ASAN_H_

#include <Guid/AsanInfo.h>

// These magic values are written to shadow for better error reporting.
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

#define ASAN_HEAP_LEFT_RZ_SIGNATURE   SIGNATURE_32('a','h','l','r')


void PoisonPages (
  IN const UINT64 Start,
  IN const UINTN  PageNum,
  IN const UINT8  Value
  ) ;

void UnpoisonPages (
  IN const UINT64 Start, 
  IN const UINTN  PageNum
  );

void 
PoisonPool(
  IN const UINTN aligned_addr, 
  IN UINTN Size,
  IN const UINT8 Value
  );

void 
UnpoisonPool(
  IN const UINTN aligned_addr,
  IN UINTN Size
  );

UINTN 
ComputePoolRightRedzoneSize(
  IN UINTN user_requested_size
  );

VOID
Num2Str64bit(
  IN  UINT64 Number,
  IN  CHAR8* NumStr
  );

RETURN_STATUS
EFIAPI
SetupAsanShadowMemory (
  VOID
  );
extern UINTN __asan_shadow_memory_dynamic_address;
extern int __asan_option_detect_stack_use_after_return;
extern UINT64 mAsanShadowMemoryStart;
extern UINT64 mAsanShadowMemorySize;
extern UINT64 mShadowOffset;
extern int gSerialOutputSwitch;

#endif