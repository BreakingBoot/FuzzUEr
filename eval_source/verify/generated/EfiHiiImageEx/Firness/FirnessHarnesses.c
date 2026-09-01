#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called NewImageEx.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzNewImageEx(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_IMAGE_EX_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiImageExProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE NewImageEx_Arg_1 = 0;
    
    UINT8* NewImageEx_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(NewImageEx_Arg_1_choice), (VOID *)NewImageEx_Arg_1_choice);
    switch(*NewImageEx_Arg_1_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(NewImageEx_Arg_1), (VOID *)&NewImageEx_Arg_1);
    
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
                &NewImageEx_Arg_1,
                NULL
            );
    
            break;
        }
    }
    /*
        Output Variable(s)
    */
    EFI_IMAGE_ID * NewImageEx_Arg_2 = (EFI_IMAGE_ID *)AllocateZeroPool(sizeof(EFI_IMAGE_ID));
    UINT8* NewImageEx_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(NewImageEx_Arg_2_OutputChoice), (VOID *)NewImageEx_Arg_2_OutputChoice);
    if(*NewImageEx_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*NewImageEx_Arg_2), (VOID *)NewImageEx_Arg_2);
    }
    Status = ProtocolVariable->NewImageEx(
        ProtocolVariable,
        NewImageEx_Arg_1,
        NewImageEx_Arg_2,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetImageEx.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetImageEx(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_IMAGE_EX_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiImageExProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE GetImageEx_Arg_1 = 0;
    EFI_IMAGE_ID GetImageEx_Arg_2 = 0;
    
    UINT8* GetImageEx_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetImageEx_Arg_1_choice), (VOID *)GetImageEx_Arg_1_choice);
    switch(*GetImageEx_Arg_1_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(GetImageEx_Arg_1), (VOID *)&GetImageEx_Arg_1);
    
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
                &GetImageEx_Arg_1,
                NULL
            );
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetImageEx_Arg_2), (VOID *)&GetImageEx_Arg_2);
    
    /*
        Output Variable(s)
    */
    EFI_IMAGE_INPUT * GetImageEx_Arg_3 = (EFI_IMAGE_INPUT *)AllocateZeroPool(sizeof(EFI_IMAGE_INPUT));
    UINT8* GetImageEx_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetImageEx_Arg_3_OutputChoice), (VOID *)GetImageEx_Arg_3_OutputChoice);
    if(*GetImageEx_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetImageEx_Arg_3), (VOID *)GetImageEx_Arg_3);
    }
    Status = ProtocolVariable->GetImageEx(
        ProtocolVariable,
        GetImageEx_Arg_1,
        GetImageEx_Arg_2,
        GetImageEx_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetImageEx.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetImageEx(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_IMAGE_EX_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiImageExProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE SetImageEx_Arg_1 = 0;
    EFI_IMAGE_ID SetImageEx_Arg_2 = 0;
    
    UINT8* SetImageEx_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SetImageEx_Arg_1_choice), (VOID *)SetImageEx_Arg_1_choice);
    switch(*SetImageEx_Arg_1_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(SetImageEx_Arg_1), (VOID *)&SetImageEx_Arg_1);
    
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
                &SetImageEx_Arg_1,
                NULL
            );
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetImageEx_Arg_2), (VOID *)&SetImageEx_Arg_2);
    
    Status = ProtocolVariable->SetImageEx(
        ProtocolVariable,
        SetImageEx_Arg_1,
        SetImageEx_Arg_2,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called DrawImageEx.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDrawImageEx(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_IMAGE_EX_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiImageExProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_DRAW_FLAGS DrawImageEx_Arg_1 = 0;
    EFI_IMAGE_OUTPUT * DrawImageEx_Arg_3 = (EFI_IMAGE_OUTPUT *)AllocateZeroPool(sizeof(EFI_IMAGE_OUTPUT));
    UINTN DrawImageEx_Arg_4 = 0;
    UINTN DrawImageEx_Arg_5 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(DrawImageEx_Arg_1), (VOID *)&DrawImageEx_Arg_1);
    
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(DrawImageEx_Arg_4), (VOID *)&DrawImageEx_Arg_4);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(DrawImageEx_Arg_5), (VOID *)&DrawImageEx_Arg_5);
    
    Status = ProtocolVariable->DrawImageEx(
        ProtocolVariable,
        DrawImageEx_Arg_1,
        NULL,
        (EFI_IMAGE_OUTPUT **)&DrawImageEx_Arg_3,
        DrawImageEx_Arg_4,
        DrawImageEx_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called DrawImageIdEx.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDrawImageIdEx(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_IMAGE_EX_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiImageExProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_DRAW_FLAGS DrawImageIdEx_Arg_1 = 0;
    EFI_HII_HANDLE DrawImageIdEx_Arg_2 = 0;
    EFI_IMAGE_ID DrawImageIdEx_Arg_3 = 0;
    EFI_IMAGE_OUTPUT * DrawImageIdEx_Arg_4 = (EFI_IMAGE_OUTPUT *)AllocateZeroPool(sizeof(EFI_IMAGE_OUTPUT));
    UINTN DrawImageIdEx_Arg_5 = 0;
    UINTN DrawImageIdEx_Arg_6 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(DrawImageIdEx_Arg_1), (VOID *)&DrawImageIdEx_Arg_1);
    
    UINT8* DrawImageIdEx_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(DrawImageIdEx_Arg_2_choice), (VOID *)DrawImageIdEx_Arg_2_choice);
    switch(*DrawImageIdEx_Arg_2_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(DrawImageIdEx_Arg_2), (VOID *)&DrawImageIdEx_Arg_2);
    
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
                &DrawImageIdEx_Arg_2,
                NULL
            );
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(DrawImageIdEx_Arg_3), (VOID *)&DrawImageIdEx_Arg_3);
    
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(DrawImageIdEx_Arg_5), (VOID *)&DrawImageIdEx_Arg_5);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(DrawImageIdEx_Arg_6), (VOID *)&DrawImageIdEx_Arg_6);
    
    Status = ProtocolVariable->DrawImageIdEx(
        ProtocolVariable,
        DrawImageIdEx_Arg_1,
        DrawImageIdEx_Arg_2,
        DrawImageIdEx_Arg_3,
        (EFI_IMAGE_OUTPUT **)&DrawImageIdEx_Arg_4,
        DrawImageIdEx_Arg_5,
        DrawImageIdEx_Arg_6
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
    EFI_HII_IMAGE_EX_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiImageExProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE GetImageInfo_Arg_1 = 0;
    EFI_IMAGE_ID GetImageInfo_Arg_2 = 0;
    
    UINT8* GetImageInfo_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetImageInfo_Arg_1_choice), (VOID *)GetImageInfo_Arg_1_choice);
    switch(*GetImageInfo_Arg_1_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(GetImageInfo_Arg_1), (VOID *)&GetImageInfo_Arg_1);
    
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
                &GetImageInfo_Arg_1,
                NULL
            );
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetImageInfo_Arg_2), (VOID *)&GetImageInfo_Arg_2);
    
    /*
        Output Variable(s)
    */
    EFI_IMAGE_OUTPUT * GetImageInfo_Arg_3 = (EFI_IMAGE_OUTPUT *)AllocateZeroPool(sizeof(EFI_IMAGE_OUTPUT));
    UINT8* GetImageInfo_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetImageInfo_Arg_3_OutputChoice), (VOID *)GetImageInfo_Arg_3_OutputChoice);
    if(*GetImageInfo_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetImageInfo_Arg_3), (VOID *)GetImageInfo_Arg_3);
    }
    Status = ProtocolVariable->GetImageInfo(
        ProtocolVariable,
        GetImageInfo_Arg_1,
        GetImageInfo_Arg_2,
        GetImageInfo_Arg_3
    );
    return Status;
}

