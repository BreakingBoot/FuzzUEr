#ifndef __FIRNESS_HARNESSES__
#define __FIRNESS_HARNESSES__

#include "FirnessIncludes.h"
#include "FirnessHelpers.h"

#define NULL ((VOID *) 0)
#define kEmptyHashValue 0

extern EFI_GUID gEfiTimerArchProtocolGuid;

EFI_STATUS
EFIAPI
FuzzGetTimerPeriod(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzSetTimerPeriod(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzRegisterHandler(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzGenerateSoftInterrupt(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

#endif // __FIRNESS_HARNESSES__
