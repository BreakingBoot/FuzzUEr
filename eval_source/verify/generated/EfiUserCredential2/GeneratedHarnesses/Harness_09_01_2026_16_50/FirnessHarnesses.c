#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called Enroll.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzEnroll(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USER_CREDENTIAL2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUserCredential2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_USER_PROFILE_HANDLE Enroll_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Enroll_Arg_1), (VOID *)&Enroll_Arg_1);
    
    Status = ProtocolVariable->Enroll(
        ProtocolVariable,
        Enroll_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Form.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzForm(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USER_CREDENTIAL2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUserCredential2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_HII_HANDLE * Form_Arg_1 = (EFI_HII_HANDLE *)AllocateZeroPool(sizeof(EFI_HII_HANDLE));
    UINT8* Form_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Form_Arg_1_OutputChoice), (VOID *)Form_Arg_1_OutputChoice);
    if(*Form_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Form_Arg_1), (VOID *)Form_Arg_1);
    }
    EFI_GUID * Form_Arg_2 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINT8* Form_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Form_Arg_2_OutputChoice), (VOID *)Form_Arg_2_OutputChoice);
    if(*Form_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Form_Arg_2), (VOID *)Form_Arg_2);
    }
    EFI_FORM_ID * Form_Arg_3 = (EFI_FORM_ID *)AllocateZeroPool(sizeof(EFI_FORM_ID));
    UINT8* Form_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Form_Arg_3_OutputChoice), (VOID *)Form_Arg_3_OutputChoice);
    if(*Form_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Form_Arg_3), (VOID *)Form_Arg_3);
    }
    Status = ProtocolVariable->Form(
        ProtocolVariable,
        Form_Arg_1,
        Form_Arg_2,
        Form_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Tile.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzTile(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USER_CREDENTIAL2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUserCredential2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * Tile_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN * Tile_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    UINT8 Tile_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(Tile_Arg_1_choice), (VOID *)&Tile_Arg_1_choice);
    switch(Tile_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Tile_Arg_1), (VOID *)Tile_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(Tile_Arg_1);
            Tile_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 Tile_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(Tile_Arg_2_choice), (VOID *)&Tile_Arg_2_choice);
    switch(Tile_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Tile_Arg_2), (VOID *)Tile_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(Tile_Arg_2);
            Tile_Arg_2 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_HII_HANDLE * Tile_Arg_3 = (EFI_HII_HANDLE *)AllocateZeroPool(sizeof(EFI_HII_HANDLE));
    UINT8* Tile_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Tile_Arg_3_OutputChoice), (VOID *)Tile_Arg_3_OutputChoice);
    if(*Tile_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Tile_Arg_3), (VOID *)Tile_Arg_3);
    }
    EFI_IMAGE_ID * Tile_Arg_4 = (EFI_IMAGE_ID *)AllocateZeroPool(sizeof(EFI_IMAGE_ID));
    UINT8* Tile_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Tile_Arg_4_OutputChoice), (VOID *)Tile_Arg_4_OutputChoice);
    if(*Tile_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Tile_Arg_4), (VOID *)Tile_Arg_4);
    }
    Status = ProtocolVariable->Tile(
        ProtocolVariable,
        Tile_Arg_1,
        Tile_Arg_2,
        Tile_Arg_3,
        Tile_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Title.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzTitle(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USER_CREDENTIAL2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUserCredential2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_HII_HANDLE * Title_Arg_1 = (EFI_HII_HANDLE *)AllocateZeroPool(sizeof(EFI_HII_HANDLE));
    UINT8* Title_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Title_Arg_1_OutputChoice), (VOID *)Title_Arg_1_OutputChoice);
    if(*Title_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Title_Arg_1), (VOID *)Title_Arg_1);
    }
    EFI_STRING_ID * Title_Arg_2 = (EFI_STRING_ID *)AllocateZeroPool(sizeof(EFI_STRING_ID));
    UINT8* Title_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Title_Arg_2_OutputChoice), (VOID *)Title_Arg_2_OutputChoice);
    if(*Title_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Title_Arg_2), (VOID *)Title_Arg_2);
    }
    Status = ProtocolVariable->Title(
        ProtocolVariable,
        Title_Arg_1,
        Title_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called User.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUser(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USER_CREDENTIAL2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUserCredential2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_USER_PROFILE_HANDLE User_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(User_Arg_1), (VOID *)&User_Arg_1);
    
    /*
        Output Variable(s)
    */
    EFI_USER_INFO_IDENTIFIER * User_Arg_2 = (EFI_USER_INFO_IDENTIFIER *)AllocateZeroPool(sizeof(EFI_USER_INFO_IDENTIFIER));
    UINT8* User_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(User_Arg_2_OutputChoice), (VOID *)User_Arg_2_OutputChoice);
    if(*User_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*User_Arg_2), (VOID *)User_Arg_2);
    }
    Status = ProtocolVariable->User(
        ProtocolVariable,
        User_Arg_1,
        User_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Select.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSelect(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USER_CREDENTIAL2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUserCredential2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_CREDENTIAL_LOGON_FLAGS * Select_Arg_1 = (EFI_CREDENTIAL_LOGON_FLAGS *)AllocateZeroPool(sizeof(EFI_CREDENTIAL_LOGON_FLAGS));
    UINT8* Select_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Select_Arg_1_OutputChoice), (VOID *)Select_Arg_1_OutputChoice);
    if(*Select_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Select_Arg_1), (VOID *)Select_Arg_1);
    }
    Status = ProtocolVariable->Select(
        ProtocolVariable,
        Select_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Deselect.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDeselect(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USER_CREDENTIAL2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUserCredential2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Deselect(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Default.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDefault(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USER_CREDENTIAL2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUserCredential2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_CREDENTIAL_LOGON_FLAGS * Default_Arg_1 = (EFI_CREDENTIAL_LOGON_FLAGS *)AllocateZeroPool(sizeof(EFI_CREDENTIAL_LOGON_FLAGS));
    UINT8* Default_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Default_Arg_1_OutputChoice), (VOID *)Default_Arg_1_OutputChoice);
    if(*Default_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Default_Arg_1), (VOID *)Default_Arg_1);
    }
    Status = ProtocolVariable->Default(
        ProtocolVariable,
        Default_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetInfo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USER_CREDENTIAL2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUserCredential2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_USER_INFO_HANDLE GetInfo_Arg_1 = 0;
    UINTN * GetInfo_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetInfo_Arg_1), (VOID *)&GetInfo_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 GetInfo_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(GetInfo_Arg_3_choice), (VOID *)&GetInfo_Arg_3_choice);
    switch(GetInfo_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetInfo_Arg_3), (VOID *)GetInfo_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(GetInfo_Arg_3);
            GetInfo_Arg_3 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_USER_INFO * GetInfo_Arg_2 = (EFI_USER_INFO *)AllocateZeroPool(sizeof(EFI_USER_INFO));
    UINT8* GetInfo_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetInfo_Arg_2_OutputChoice), (VOID *)GetInfo_Arg_2_OutputChoice);
    if(*GetInfo_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetInfo_Arg_2), (VOID *)GetInfo_Arg_2);
    }
    Status = ProtocolVariable->GetInfo(
        ProtocolVariable,
        GetInfo_Arg_1,
        GetInfo_Arg_2,
        GetInfo_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetNextInfo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetNextInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USER_CREDENTIAL2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUserCredential2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_USER_INFO_HANDLE * GetNextInfo_Arg_1 = (EFI_USER_INFO_HANDLE *)AllocateZeroPool(sizeof(EFI_USER_INFO_HANDLE));
    
    // Fuzzable Variable Initialization
    UINT8 GetNextInfo_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetNextInfo_Arg_1_choice), (VOID *)&GetNextInfo_Arg_1_choice);
    switch(GetNextInfo_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetNextInfo_Arg_1), (VOID *)GetNextInfo_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(GetNextInfo_Arg_1);
            GetNextInfo_Arg_1 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetNextInfo(
        ProtocolVariable,
        GetNextInfo_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Delete.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDelete(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USER_CREDENTIAL2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUserCredential2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_USER_PROFILE_HANDLE Delete_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Delete_Arg_1), (VOID *)&Delete_Arg_1);
    
    Status = ProtocolVariable->Delete(
        ProtocolVariable,
        Delete_Arg_1
    );
    return Status;
}

