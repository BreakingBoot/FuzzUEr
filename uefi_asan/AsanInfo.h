/** @file
  GUID for an event that is signaled on the first attempt to check for a keystroke 
  from the ConIn device.

  Copyright (c) 2012, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __ASAN_INFO_GUID_H__
#define __ASAN_INFO_GUID_H__

#define ASAN_INFO_GUID \
          { 0xac0634da, 0x320e, 0x4f1d, { 0x8d, 0xc, 0x2e, 0x99, 0x1e, 0xab, 0xe5, 0xae } };

typedef struct {
  UINT64       AsanShadowMemorySize;
  UINT64       AsanShadowMemoryStart;
  UINT32       AsanInited;
  UINT32       AsanActivated;
} ASAN_INFO;

extern EFI_GUID gAsanInfoGuid;

#endif
