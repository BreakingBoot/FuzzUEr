#ifndef __FIRNESS_HARNESSES__
#define __FIRNESS_HARNESSES__

#include "FirnessIncludes.h"
#include "FirnessHelpers.h"


extern EFI_GUID gEfiPrint2ProtocolGuid;

EFI_STATUS
EFIAPI
FuzzUnicodeBSPrint(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzUnicodeBSPrintAsciiFormat(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzUnicodeValueToString(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzAsciiBSPrint(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzAsciiBSPrintUnicodeFormat(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzAsciiValueToString(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

#endif // __FIRNESS_HARNESSES__
