#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called GetImageDecoderName.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetImageDecoderName(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_IMAGE_DECODER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiImageDecoderProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * GetImageDecoderName_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINT16 * GetImageDecoderName_Arg_2 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    
    
    // Fuzzable Variable Initialization
    UINT8 GetImageDecoderName_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetImageDecoderName_Arg_2_choice), (VOID *)&GetImageDecoderName_Arg_2_choice);
    switch(GetImageDecoderName_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetImageDecoderName_Arg_2), (VOID *)GetImageDecoderName_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(GetImageDecoderName_Arg_2);
            GetImageDecoderName_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetImageDecoderName(
        ProtocolVariable,
        (EFI_GUID **)&GetImageDecoderName_Arg_1,
        GetImageDecoderName_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetImageInfo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetImageInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_IMAGE_DECODER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiImageDecoderProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  GetImageInfo_Arg_1 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN GetImageInfo_Arg_2 = 0;
    EFI_HII_IMAGE_DECODER_IMAGE_INFO_HEADER * GetImageInfo_Arg_3 = (EFI_HII_IMAGE_DECODER_IMAGE_INFO_HEADER *)AllocateZeroPool(sizeof(EFI_HII_IMAGE_DECODER_IMAGE_INFO_HEADER));
    
    // Fuzzable Variable Initialization
    UINT8 GetImageInfo_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetImageInfo_Arg_1_choice), (VOID *)&GetImageInfo_Arg_1_choice);
    switch(GetImageInfo_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetImageInfo_Arg_1), (VOID *)GetImageInfo_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(GetImageInfo_Arg_1);
            GetImageInfo_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetImageInfo_Arg_2), (VOID *)&GetImageInfo_Arg_2);
    
    
    Status = ProtocolVariable->GetImageInfo(
        ProtocolVariable,
        (void *)GetImageInfo_Arg_1,
        GetImageInfo_Arg_2,
        (EFI_HII_IMAGE_DECODER_IMAGE_INFO_HEADER **)&GetImageInfo_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called DecodeImage.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDecodeImage(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_IMAGE_DECODER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiImageDecoderProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  DecodeImage_Arg_1 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN DecodeImage_Arg_2 = 0;
    EFI_IMAGE_OUTPUT * DecodeImage_Arg_3 = (EFI_IMAGE_OUTPUT *)AllocateZeroPool(sizeof(EFI_IMAGE_OUTPUT));
    BOOLEAN DecodeImage_Arg_4 = FALSE;
    
    // Fuzzable Variable Initialization
    UINT8 DecodeImage_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(DecodeImage_Arg_1_choice), (VOID *)&DecodeImage_Arg_1_choice);
    switch(DecodeImage_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(DecodeImage_Arg_1), (VOID *)DecodeImage_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(DecodeImage_Arg_1);
            DecodeImage_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(DecodeImage_Arg_2), (VOID *)&DecodeImage_Arg_2);
    
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(DecodeImage_Arg_4), (VOID *)&DecodeImage_Arg_4);
    
    Status = ProtocolVariable->DecodeImage(
        ProtocolVariable,
        (void *)DecodeImage_Arg_1,
        DecodeImage_Arg_2,
        (EFI_IMAGE_OUTPUT **)&DecodeImage_Arg_3,
        DecodeImage_Arg_4
    );
    return Status;
}

