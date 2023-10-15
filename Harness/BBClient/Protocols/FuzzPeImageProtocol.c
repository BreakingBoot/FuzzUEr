#include "FuzzLoadPeImageProtocol.h"

EFI_STATUS
EFIAPI
FuzzLoadPeImageProtocol(
    IN INPUT_BUFFER* Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: LoadPeImageProtocol\n"));
    UINTN ProtocolChoice = 0;
    ReadInput(Input, 1, ProtocolChoice);
    switch(ProtocolChoice%2)
    {
        case LOAD_PE32_PROTOCOL:
            Status = FuzzLoadPeImageProtocol(Input);
            break;
        case UNLOAD_PE32_PROTCOL:
            Status = FuzzUnloadPeImageProtocol(Input);
            break;
    }

    return Status;
}

EFI_STATUS
EFIAPI
FuzzLoadPeImageProtocol(
    IN INPUT_BUFFER* Input
)
{
    EFI_STATUS Status = EFI_STATUS;
    DEBUG((DEBUG_ERROR, "FUZZING: LoadPeImageProtocol\n"));
    EFI_PE32_IMAGE_PROTOCOL *Pe32ImageProtocol;
    gBS->LocateProtocol(&gEfiLoadPeImageProtocolGuid, NULL, (VOID **)&Pe32ImageProtocol);

EFI_STATUS
(EFIAPI *LOAD_PE_IMAGE)(
  IN EFI_PE32_IMAGE_PROTOCOL           *This,
  IN  EFI_HANDLE                       ParentImageHandle,
  IN  EFI_DEVICE_PATH_PROTOCOL         *FilePath,
  IN  VOID                             *SourceBuffer       OPTIONAL,
  IN  UINTN                            SourceSize,
  IN  EFI_PHYSICAL_ADDRESS             DstBuffer           OPTIONAL,
  IN OUT UINTN                         *NumberOfPages      OPTIONAL,
  OUT EFI_HANDLE                       *ImageHandle,
  OUT EFI_PHYSICAL_ADDRESS             *EntryPoint         OPTIONAL,
  IN  UINT32                           Attribute
  );

    EFI_PHYSICAL_ADDRESS EntryPoint;
    EFI_HANDLE *ImageHandle = NULL;
#define EFI_LOAD_PE_IMAGE_ATTRIBUTE_NONE                                 0x00
#define EFI_LOAD_PE_IMAGE_ATTRIBUTE_RUNTIME_REGISTRATION                 0x01
#define EFI_LOAD_PE_IMAGE_ATTRIBUTE_DEBUG_IMAGE_INFO_TABLE_REGISTRATION  0x02

    Status = Pe32ImageProtocol->LoadPeImage(Pe32ImageProtocol, NULL, ImageHandle, &EntryPoint, Attributes);

    return Status;
}


EFI_STATUS
EFIAPI
FuzzUnloadPeImageProtocol(
    IN INPUT_BUFFER* Input
)
{
    EFI_STATUS Status = EFI_STATUS;
    DEBUG((DEBUG_ERROR, "FUZZING: UnloadPeImageProtocol\n"));
    EFI_PE32_IMAGE_PROTOCOL *Pe32ImageProtocol;
    gBS->LocateProtocol(&gEfiLoadPeImageProtocolGuid, NULL, (VOID **)&Pe32ImageProtocol);

    Status = Pe32ImageProtocol->UnLoadPeImage();

    return Status;
}