#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called Current.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzCurrent(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USER_MANAGER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUserManagerProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_USER_PROFILE_HANDLE * Current_Arg_1 = (EFI_USER_PROFILE_HANDLE *)AllocateZeroPool(sizeof(EFI_USER_PROFILE_HANDLE));
    UINT8* Current_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Current_Arg_1_OutputChoice), (VOID *)Current_Arg_1_OutputChoice);
    if(*Current_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Current_Arg_1), (VOID *)Current_Arg_1);
    }
    Status = ProtocolVariable->Current(
        ProtocolVariable,
        Current_Arg_1
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
    EFI_USER_MANAGER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUserManagerProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_USER_INFO_HANDLE * GetNextInfo_Arg_2 = (EFI_USER_INFO_HANDLE *)AllocateZeroPool(sizeof(EFI_USER_INFO_HANDLE));
    
    
    Status = ProtocolVariable->GetNextInfo(
        ProtocolVariable,
        (EFI_USER_PROFILE_HANDLE){0},
        GetNextInfo_Arg_2
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
    EFI_USER_MANAGER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUserManagerProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * GetInfo_Arg_4 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    UINT8 GetInfo_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(GetInfo_Arg_4_choice), (VOID *)&GetInfo_Arg_4_choice);
    switch(GetInfo_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetInfo_Arg_4), (VOID *)GetInfo_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(GetInfo_Arg_4);
            GetInfo_Arg_4 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_USER_INFO * GetInfo_Arg_3 = (EFI_USER_INFO *)AllocateZeroPool(sizeof(EFI_USER_INFO));
    UINT8* GetInfo_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetInfo_Arg_3_OutputChoice), (VOID *)GetInfo_Arg_3_OutputChoice);
    if(*GetInfo_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetInfo_Arg_3), (VOID *)GetInfo_Arg_3);
    }
    Status = ProtocolVariable->GetInfo(
        ProtocolVariable,
        (EFI_USER_PROFILE_HANDLE){0},
        (EFI_USER_INFO_HANDLE){0},
        GetInfo_Arg_3,
        GetInfo_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Create.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzCreate(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USER_MANAGER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUserManagerProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_USER_PROFILE_HANDLE * Create_Arg_1 = (EFI_USER_PROFILE_HANDLE *)AllocateZeroPool(sizeof(EFI_USER_PROFILE_HANDLE));
    UINT8* Create_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Create_Arg_1_OutputChoice), (VOID *)Create_Arg_1_OutputChoice);
    if(*Create_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Create_Arg_1), (VOID *)Create_Arg_1);
    }
    Status = ProtocolVariable->Create(
        ProtocolVariable,
        Create_Arg_1
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
    EFI_USER_MANAGER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUserManagerProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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

/*
    This is a harness for fuzzing the protocol service
    called GetNext.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetNext(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USER_MANAGER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUserManagerProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_USER_PROFILE_HANDLE * GetNext_Arg_1 = (EFI_USER_PROFILE_HANDLE *)AllocateZeroPool(sizeof(EFI_USER_PROFILE_HANDLE));
    
    // Fuzzable Variable Initialization
    UINT8 GetNext_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetNext_Arg_1_choice), (VOID *)&GetNext_Arg_1_choice);
    switch(GetNext_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetNext_Arg_1), (VOID *)GetNext_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(GetNext_Arg_1);
            GetNext_Arg_1 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetNext(
        ProtocolVariable,
        GetNext_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Identify.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzIdentify(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USER_MANAGER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUserManagerProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_USER_PROFILE_HANDLE * Identify_Arg_1 = (EFI_USER_PROFILE_HANDLE *)AllocateZeroPool(sizeof(EFI_USER_PROFILE_HANDLE));
    UINT8* Identify_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Identify_Arg_1_OutputChoice), (VOID *)Identify_Arg_1_OutputChoice);
    if(*Identify_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Identify_Arg_1), (VOID *)Identify_Arg_1);
    }
    Status = ProtocolVariable->Identify(
        ProtocolVariable,
        Identify_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Find.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFind(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USER_MANAGER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUserManagerProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_USER_PROFILE_HANDLE * Find_Arg_1 = (EFI_USER_PROFILE_HANDLE *)AllocateZeroPool(sizeof(EFI_USER_PROFILE_HANDLE));
    EFI_USER_INFO * Find_Arg_3 = (EFI_USER_INFO *)AllocateZeroPool(sizeof(EFI_USER_INFO));
    UINTN Find_Arg_4 = 0;
    
    // Fuzzable Variable Initialization
    UINT8 Find_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(Find_Arg_1_choice), (VOID *)&Find_Arg_1_choice);
    switch(Find_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Find_Arg_1), (VOID *)Find_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(Find_Arg_1);
            Find_Arg_1 = NULL;
            break;
        }
    }
    
    // Generator Struct Variable Initialization
    {
        EFI_GUID Firness_Credential;
        ReadBytes(Input, sizeof(Firness_Credential), (VOID *)&Firness_Credential);
        Find_Arg_3->Credential = Firness_Credential;
    }
    {
        UINT8 Firness_InfoType;
        ReadBytes(Input, sizeof(Firness_InfoType), (VOID *)&Firness_InfoType);
        Find_Arg_3->InfoType = Firness_InfoType;
    }
    {
        UINT8 Firness_Reserved1;
        ReadBytes(Input, sizeof(Firness_Reserved1), (VOID *)&Firness_Reserved1);
        Find_Arg_3->Reserved1 = Firness_Reserved1;
    }
    {
        EFI_USER_INFO_ATTRIBS Firness_InfoAttribs;
        ReadBytes(Input, sizeof(Firness_InfoAttribs), (VOID *)&Firness_InfoAttribs);
        Find_Arg_3->InfoAttribs = Firness_InfoAttribs;
    }
    {
        UINT32 Firness_InfoSize;
        ReadBytes(Input, sizeof(Firness_InfoSize), (VOID *)&Firness_InfoSize);
        Find_Arg_3->InfoSize = Firness_InfoSize;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Find_Arg_4), (VOID *)&Find_Arg_4);
    
    Status = ProtocolVariable->Find(
        ProtocolVariable,
        Find_Arg_1,
        NULL,
        Find_Arg_3,
        Find_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Notify.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzNotify(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USER_MANAGER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUserManagerProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Notify(
        ProtocolVariable,
        ImageHandle
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetInfo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USER_MANAGER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUserManagerProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_USER_PROFILE_HANDLE SetInfo_Arg_1 = 0;
    EFI_USER_INFO_HANDLE * SetInfo_Arg_2 = (EFI_USER_INFO_HANDLE *)AllocateZeroPool(sizeof(EFI_USER_INFO_HANDLE));
    EFI_USER_INFO * SetInfo_Arg_3 = (EFI_USER_INFO *)AllocateZeroPool(sizeof(EFI_USER_INFO));
    UINTN SetInfo_Arg_4 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetInfo_Arg_1), (VOID *)&SetInfo_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 SetInfo_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(SetInfo_Arg_2_choice), (VOID *)&SetInfo_Arg_2_choice);
    switch(SetInfo_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetInfo_Arg_2), (VOID *)SetInfo_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(SetInfo_Arg_2);
            SetInfo_Arg_2 = NULL;
            break;
        }
    }
    
    // Generator Struct Variable Initialization
    {
        EFI_GUID Firness_Credential;
        ReadBytes(Input, sizeof(Firness_Credential), (VOID *)&Firness_Credential);
        SetInfo_Arg_3->Credential = Firness_Credential;
    }
    {
        UINT8 Firness_InfoType;
        ReadBytes(Input, sizeof(Firness_InfoType), (VOID *)&Firness_InfoType);
        SetInfo_Arg_3->InfoType = Firness_InfoType;
    }
    {
        UINT8 Firness_Reserved1;
        ReadBytes(Input, sizeof(Firness_Reserved1), (VOID *)&Firness_Reserved1);
        SetInfo_Arg_3->Reserved1 = Firness_Reserved1;
    }
    {
        EFI_USER_INFO_ATTRIBS Firness_InfoAttribs;
        ReadBytes(Input, sizeof(Firness_InfoAttribs), (VOID *)&Firness_InfoAttribs);
        SetInfo_Arg_3->InfoAttribs = Firness_InfoAttribs;
    }
    {
        UINT32 Firness_InfoSize;
        ReadBytes(Input, sizeof(Firness_InfoSize), (VOID *)&Firness_InfoSize);
        SetInfo_Arg_3->InfoSize = Firness_InfoSize;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetInfo_Arg_4), (VOID *)&SetInfo_Arg_4);
    
    Status = ProtocolVariable->SetInfo(
        ProtocolVariable,
        SetInfo_Arg_1,
        SetInfo_Arg_2,
        SetInfo_Arg_3,
        SetInfo_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called DeleteInfo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDeleteInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USER_MANAGER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUserManagerProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_USER_PROFILE_HANDLE DeleteInfo_Arg_1 = 0;
    EFI_USER_INFO_HANDLE DeleteInfo_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(DeleteInfo_Arg_1), (VOID *)&DeleteInfo_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(DeleteInfo_Arg_2), (VOID *)&DeleteInfo_Arg_2);
    
    Status = ProtocolVariable->DeleteInfo(
        ProtocolVariable,
        DeleteInfo_Arg_1,
        DeleteInfo_Arg_2
    );
    return Status;
}

