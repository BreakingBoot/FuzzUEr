#ifndef __FIRNESS_HARNESSES__
#define __FIRNESS_HARNESSES__

#include "FirnessIncludes.h"
#include "FirnessHelpers.h"

#define NULL ((VOID *) 0)
#define kEmptyHashValue 0

extern EFI_GUID gEdkiiDeviceIdentifierTypePciGuid;
extern EFI_GUID gEfiAdapterInformationProtocolGuid;
extern EFI_GUID gEfiAuthenticatedVariableGuid;
extern EFI_GUID gEfiCallerIdGuid;
extern EFI_GUID gEfiDebugPortProtocolGuid;
extern EFI_GUID gEfiDiskInfoAhciInterfaceGuid;
extern EFI_GUID gEfiDiskInfoIdeInterfaceGuid;
extern EFI_GUID gEfiDiskInfoUfsInterfaceGuid;
extern EFI_GUID gEfiFirmwareFileSystem2Guid;
extern EFI_GUID gEfiGlobalVariableGuid;
extern EFI_GUID gEfiHobMemoryAllocBspStoreGuid;
extern EFI_GUID gEfiHobMemoryAllocModuleGuid;
extern EFI_GUID gEfiHobMemoryAllocStackGuid;
extern EFI_GUID gEfiPcAnsiGuid;
extern EFI_GUID gEfiPersistentVirtualCdGuid;
extern EFI_GUID gEfiPersistentVirtualDiskGuid;
extern EFI_GUID gEfiSasDevicePathGuid;
extern EFI_GUID gEfiSmmVariableProtocolGuid;
extern EFI_GUID gEfiUartDevicePathGuid;
extern EFI_GUID gEfiVT100Guid;
extern EFI_GUID gEfiVT100PlusGuid;
extern EFI_GUID gEfiVTUTF8Guid;
extern EFI_GUID gEfiVariableGuid;
extern EFI_GUID gEfiVirtualCdGuid;
extern EFI_GUID gEfiVirtualDiskGuid;
extern EFI_GUID gVarCheckPolicyLibMmiHandlerGuid;
extern EFI_GUID gZeroGuid;

EFI_STATUS
EFIAPI
FuzzGetSupportedTypes(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzGetInformation(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzSetInformation(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

#endif // __FIRNESS_HARNESSES__
