#ifndef __FIRNESS_HARNESSES__
#define __FIRNESS_HARNESSES__

#include "FirnessIncludes.h"
#include "FirnessHelpers.h"

#define kEmptyHashValue 0
#define NULL ((VOID *) 0)

extern EFI_GUID gEfiIdeControllerInitProtocolGuid;

EFI_STATUS
EFIAPI
FuzzSubmitData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzCalculateMode(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzSetTiming(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzNotifyPhase(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzGetChannelInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzDisqualifyMode(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

#endif // __FIRNESS_HARNESSES__
