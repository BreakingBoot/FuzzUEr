
/** @file
  This sample application bases on BreakingBoot PCD setting
  to run the Breaking Boot fuzzer to the UEFI Console.

  Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "BBClientFuzz.h"

INPUT_BUFFER  Input;

/**
  The user Entry Point for Application. The user code starts with this function
  as the real entry point for the application.

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.
  @param[in] SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval other             Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
BBClientMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS Status = EFI_SUCCESS;
  UINT32 _a, _b, _c, _d = 0;

  UINT8 buffer[0x20];
  UINTN size = sizeof(buffer) - 1;
  UINT8 *buffer_ptr = &buffer[0];
  UINTN *size_ptr = &size;

  __asm__ __volatile__(
      "cpuid\n\t"
      : "=a"(_a), "=b"(_b), "=c"(_c), "=d"(_d), "=S"(buffer_ptr), "=D"(size_ptr)
      : "0"((0x0001U << 16U) | 0x4711U), "S"(buffer_ptr), "D"(size_ptr));


  Input.Buffer = buffer_ptr;
  Input.Length = size;


  UINT8 Driver_Choice = 0;
  ReadInput(&Input, 1, &Driver_Choice);
  switch(Driver_Choice%9)
  {
    case PROCESS_FIRMWARE_VOLUME:
      Status = FuzzProcessFirmwareVolume(&Input);
      break;
    case EVENT:
      Status = FuzzEvent(&Input);
      break;
    case LOAD_IMAGE:
      Status = FuzzLoadImage(&Input, ImageHandle);
      break;
    // case PROTOCOL:
    //   Status = FuzzProtocolServices(&Input);
    //   break;
    case MEMORY:
      Status = FuzzMemory(&Input);
      break;
  }
  __asm__ __volatile__("cpuid\n\t"
                       : "=a"(_a), "=b"(_b), "=c"(_c), "=d"(_d)
                       : "0"((0x0002U << 16U) | 0x4711U));

  return Status;
}
