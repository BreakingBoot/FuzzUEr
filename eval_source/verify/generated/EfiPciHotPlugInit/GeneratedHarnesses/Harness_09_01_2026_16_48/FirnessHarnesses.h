#ifndef __FIRNESS_HARNESSES__
#define __FIRNESS_HARNESSES__

#include "FirnessIncludes.h"
#include "FirnessHelpers.h"

#define kEmptyHashValue 0

extern EFI_GUID gBdsEventAfterConsoleReadyBeforeBootOptionGuid;
extern EFI_GUID gBdsEventBeforeConsoleAfterTrustedConsoleGuid;
extern EFI_GUID gBdsEventBeforeConsoleBeforeEndOfDxeGuid;
extern EFI_GUID gEfiPciHotPlugInitProtocolGuid;

EFI_STATUS
EFIAPI
FuzzGetRootHpcList(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzGetResourcePadding(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzInitializeRootHpc(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

#endif // __FIRNESS_HARNESSES__
