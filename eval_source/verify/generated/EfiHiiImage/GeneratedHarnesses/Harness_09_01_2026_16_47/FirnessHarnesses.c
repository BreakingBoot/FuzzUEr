#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called NewImage.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzNewImage(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_IMAGE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiImageProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE NewImage_Arg_1 = 0;
    
    UINT8* NewImage_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(NewImage_Arg_1_choice), (VOID *)NewImage_Arg_1_choice);
    switch(*NewImage_Arg_1_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(NewImage_Arg_1), (VOID *)&NewImage_Arg_1);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * FindHiiHandleViaDevPath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            
            // Generator Struct Variable Initialization
            {
                UINT8 Firness_Type;
                ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
                FindHiiHandleViaDevPath_Arg_0->Type = Firness_Type;
            }
            {
                UINT8 Firness_SubType;
                ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
                FindHiiHandleViaDevPath_Arg_0->SubType = Firness_SubType;
            }
            ReadBytes(Input, sizeof(FindHiiHandleViaDevPath_Arg_0->Length), (VOID *)&(FindHiiHandleViaDevPath_Arg_0->Length));
            
            Status = FindHiiHandleViaDevPath(
                FindHiiHandleViaDevPath_Arg_0,
                &NewImage_Arg_1,
                NULL
            );
    
            break;
        }
    }
    /*
        Output Variable(s)
    */
    EFI_IMAGE_ID * NewImage_Arg_2 = (EFI_IMAGE_ID *)AllocateZeroPool(sizeof(EFI_IMAGE_ID));
    UINT8* NewImage_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(NewImage_Arg_2_OutputChoice), (VOID *)NewImage_Arg_2_OutputChoice);
    if(*NewImage_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*NewImage_Arg_2), (VOID *)NewImage_Arg_2);
    }
    Status = ProtocolVariable->NewImage(
        ProtocolVariable,
        NewImage_Arg_1,
        NewImage_Arg_2,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetImage.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetImage(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_IMAGE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiImageProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE GetImage_Arg_1 = 0;
    EFI_IMAGE_ID GetImage_Arg_2 = 0;
    
    UINT8* GetImage_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetImage_Arg_1_choice), (VOID *)GetImage_Arg_1_choice);
    switch(*GetImage_Arg_1_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(GetImage_Arg_1), (VOID *)&GetImage_Arg_1);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * FindHiiHandleViaDevPath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            
            // Generator Struct Variable Initialization
            {
                UINT8 Firness_Type;
                ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
                FindHiiHandleViaDevPath_Arg_0->Type = Firness_Type;
            }
            {
                UINT8 Firness_SubType;
                ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
                FindHiiHandleViaDevPath_Arg_0->SubType = Firness_SubType;
            }
            ReadBytes(Input, sizeof(FindHiiHandleViaDevPath_Arg_0->Length), (VOID *)&(FindHiiHandleViaDevPath_Arg_0->Length));
            
            Status = FindHiiHandleViaDevPath(
                FindHiiHandleViaDevPath_Arg_0,
                &GetImage_Arg_1,
                NULL
            );
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetImage_Arg_2), (VOID *)&GetImage_Arg_2);
    
    /*
        Output Variable(s)
    */
    EFI_IMAGE_INPUT * GetImage_Arg_3 = (EFI_IMAGE_INPUT *)AllocateZeroPool(sizeof(EFI_IMAGE_INPUT));
    UINT8* GetImage_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetImage_Arg_3_OutputChoice), (VOID *)GetImage_Arg_3_OutputChoice);
    if(*GetImage_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetImage_Arg_3), (VOID *)GetImage_Arg_3);
    }
    Status = ProtocolVariable->GetImage(
        ProtocolVariable,
        GetImage_Arg_1,
        GetImage_Arg_2,
        GetImage_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetImage.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetImage(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_IMAGE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiImageProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE SetImage_Arg_1 = 0;
    EFI_IMAGE_ID SetImage_Arg_2 = 0;
    
    UINT8* SetImage_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SetImage_Arg_1_choice), (VOID *)SetImage_Arg_1_choice);
    switch(*SetImage_Arg_1_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(SetImage_Arg_1), (VOID *)&SetImage_Arg_1);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * FindHiiHandleViaDevPath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            
            // Generator Struct Variable Initialization
            {
                UINT8 Firness_Type;
                ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
                FindHiiHandleViaDevPath_Arg_0->Type = Firness_Type;
            }
            {
                UINT8 Firness_SubType;
                ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
                FindHiiHandleViaDevPath_Arg_0->SubType = Firness_SubType;
            }
            ReadBytes(Input, sizeof(FindHiiHandleViaDevPath_Arg_0->Length), (VOID *)&(FindHiiHandleViaDevPath_Arg_0->Length));
            
            Status = FindHiiHandleViaDevPath(
                FindHiiHandleViaDevPath_Arg_0,
                &SetImage_Arg_1,
                NULL
            );
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetImage_Arg_2), (VOID *)&SetImage_Arg_2);
    
    Status = ProtocolVariable->SetImage(
        ProtocolVariable,
        SetImage_Arg_1,
        SetImage_Arg_2,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called DrawImage.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDrawImage(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_IMAGE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiImageProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_DRAW_FLAGS DrawImage_Arg_1 = 0;
    EFI_IMAGE_OUTPUT * DrawImage_Arg_3 = (EFI_IMAGE_OUTPUT *)AllocateZeroPool(sizeof(EFI_IMAGE_OUTPUT));
    UINTN DrawImage_Arg_4 = 0;
    UINTN DrawImage_Arg_5 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(DrawImage_Arg_1), (VOID *)&DrawImage_Arg_1);
    
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(DrawImage_Arg_4), (VOID *)&DrawImage_Arg_4);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(DrawImage_Arg_5), (VOID *)&DrawImage_Arg_5);
    
    Status = ProtocolVariable->DrawImage(
        ProtocolVariable,
        DrawImage_Arg_1,
        NULL,
        (EFI_IMAGE_OUTPUT **)&DrawImage_Arg_3,
        DrawImage_Arg_4,
        DrawImage_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called DrawImageId.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDrawImageId(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_IMAGE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiImageProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_DRAW_FLAGS DrawImageId_Arg_1 = 0;
    EFI_HII_HANDLE DrawImageId_Arg_2 = 0;
    EFI_IMAGE_ID DrawImageId_Arg_3 = 0;
    EFI_IMAGE_OUTPUT * DrawImageId_Arg_4 = (EFI_IMAGE_OUTPUT *)AllocateZeroPool(sizeof(EFI_IMAGE_OUTPUT));
    UINTN DrawImageId_Arg_5 = 0;
    UINTN DrawImageId_Arg_6 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(DrawImageId_Arg_1), (VOID *)&DrawImageId_Arg_1);
    
    UINT8* DrawImageId_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(DrawImageId_Arg_2_choice), (VOID *)DrawImageId_Arg_2_choice);
    switch(*DrawImageId_Arg_2_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(DrawImageId_Arg_2), (VOID *)&DrawImageId_Arg_2);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * FindHiiHandleViaDevPath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            
            // Generator Struct Variable Initialization
            {
                UINT8 Firness_Type;
                ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
                FindHiiHandleViaDevPath_Arg_0->Type = Firness_Type;
            }
            {
                UINT8 Firness_SubType;
                ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
                FindHiiHandleViaDevPath_Arg_0->SubType = Firness_SubType;
            }
            ReadBytes(Input, sizeof(FindHiiHandleViaDevPath_Arg_0->Length), (VOID *)&(FindHiiHandleViaDevPath_Arg_0->Length));
            
            Status = FindHiiHandleViaDevPath(
                FindHiiHandleViaDevPath_Arg_0,
                &DrawImageId_Arg_2,
                NULL
            );
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(DrawImageId_Arg_3), (VOID *)&DrawImageId_Arg_3);
    
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(DrawImageId_Arg_5), (VOID *)&DrawImageId_Arg_5);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(DrawImageId_Arg_6), (VOID *)&DrawImageId_Arg_6);
    
    Status = ProtocolVariable->DrawImageId(
        ProtocolVariable,
        DrawImageId_Arg_1,
        DrawImageId_Arg_2,
        DrawImageId_Arg_3,
        (EFI_IMAGE_OUTPUT **)&DrawImageId_Arg_4,
        DrawImageId_Arg_5,
        DrawImageId_Arg_6
    );
    return Status;
}

