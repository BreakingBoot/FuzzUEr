#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called GetServiceStatus.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetServiceStatus(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_KMS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiKmsProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->GetServiceStatus(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RegisterClient.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterClient(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_KMS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiKmsProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->RegisterClient(
        ProtocolVariable,
        NULL,
        NULL,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called CreateKey.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzCreateKey(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_KMS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiKmsProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT16 * CreateKey_Arg_2 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    EFI_KMS_KEY_DESCRIPTOR * CreateKey_Arg_3 = (EFI_KMS_KEY_DESCRIPTOR *)AllocateZeroPool(sizeof(EFI_KMS_KEY_DESCRIPTOR));
    
    // Fuzzable Variable Initialization
    UINT8 CreateKey_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(CreateKey_Arg_2_choice), (VOID *)&CreateKey_Arg_2_choice);
    switch(CreateKey_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(CreateKey_Arg_2), (VOID *)CreateKey_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(CreateKey_Arg_2);
            CreateKey_Arg_2 = NULL;
            break;
        }
    }
    
    
    Status = ProtocolVariable->CreateKey(
        ProtocolVariable,
        NULL,
        CreateKey_Arg_2,
        CreateKey_Arg_3,
        NULL,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetKey.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetKey(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_KMS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiKmsProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT16 * GetKey_Arg_2 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    EFI_KMS_KEY_DESCRIPTOR * GetKey_Arg_3 = (EFI_KMS_KEY_DESCRIPTOR *)AllocateZeroPool(sizeof(EFI_KMS_KEY_DESCRIPTOR));
    
    // Fuzzable Variable Initialization
    UINT8 GetKey_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetKey_Arg_2_choice), (VOID *)&GetKey_Arg_2_choice);
    switch(GetKey_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetKey_Arg_2), (VOID *)GetKey_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(GetKey_Arg_2);
            GetKey_Arg_2 = NULL;
            break;
        }
    }
    
    
    Status = ProtocolVariable->GetKey(
        ProtocolVariable,
        NULL,
        GetKey_Arg_2,
        GetKey_Arg_3,
        NULL,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called AddKey.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAddKey(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_KMS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiKmsProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT16 * AddKey_Arg_2 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    EFI_KMS_KEY_DESCRIPTOR * AddKey_Arg_3 = (EFI_KMS_KEY_DESCRIPTOR *)AllocateZeroPool(sizeof(EFI_KMS_KEY_DESCRIPTOR));
    
    // Fuzzable Variable Initialization
    UINT8 AddKey_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(AddKey_Arg_2_choice), (VOID *)&AddKey_Arg_2_choice);
    switch(AddKey_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(AddKey_Arg_2), (VOID *)AddKey_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(AddKey_Arg_2);
            AddKey_Arg_2 = NULL;
            break;
        }
    }
    
    
    Status = ProtocolVariable->AddKey(
        ProtocolVariable,
        NULL,
        AddKey_Arg_2,
        AddKey_Arg_3,
        NULL,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called DeleteKey.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDeleteKey(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_KMS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiKmsProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT16 * DeleteKey_Arg_2 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    EFI_KMS_KEY_DESCRIPTOR * DeleteKey_Arg_3 = (EFI_KMS_KEY_DESCRIPTOR *)AllocateZeroPool(sizeof(EFI_KMS_KEY_DESCRIPTOR));
    
    // Fuzzable Variable Initialization
    UINT8 DeleteKey_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(DeleteKey_Arg_2_choice), (VOID *)&DeleteKey_Arg_2_choice);
    switch(DeleteKey_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(DeleteKey_Arg_2), (VOID *)DeleteKey_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(DeleteKey_Arg_2);
            DeleteKey_Arg_2 = NULL;
            break;
        }
    }
    
    
    Status = ProtocolVariable->DeleteKey(
        ProtocolVariable,
        NULL,
        DeleteKey_Arg_2,
        DeleteKey_Arg_3,
        NULL,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetKeyAttributes.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetKeyAttributes(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_KMS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiKmsProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 * GetKeyAttributes_Arg_2 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINTN*  GetKeyAttributes_Arg_3 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT16 * GetKeyAttributes_Arg_4 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    EFI_KMS_KEY_ATTRIBUTE * GetKeyAttributes_Arg_5 = (EFI_KMS_KEY_ATTRIBUTE *)AllocateZeroPool(sizeof(EFI_KMS_KEY_ATTRIBUTE));
    
    // Fuzzable Variable Initialization
    UINT8 GetKeyAttributes_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetKeyAttributes_Arg_2_choice), (VOID *)&GetKeyAttributes_Arg_2_choice);
    switch(GetKeyAttributes_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetKeyAttributes_Arg_2), (VOID *)GetKeyAttributes_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(GetKeyAttributes_Arg_2);
            GetKeyAttributes_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetKeyAttributes_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(GetKeyAttributes_Arg_3_choice), (VOID *)&GetKeyAttributes_Arg_3_choice);
    switch(GetKeyAttributes_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetKeyAttributes_Arg_3), (VOID *)GetKeyAttributes_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(GetKeyAttributes_Arg_3);
            GetKeyAttributes_Arg_3 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetKeyAttributes_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(GetKeyAttributes_Arg_4_choice), (VOID *)&GetKeyAttributes_Arg_4_choice);
    switch(GetKeyAttributes_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetKeyAttributes_Arg_4), (VOID *)GetKeyAttributes_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(GetKeyAttributes_Arg_4);
            GetKeyAttributes_Arg_4 = NULL;
            break;
        }
    }
    
    
    Status = ProtocolVariable->GetKeyAttributes(
        ProtocolVariable,
        NULL,
        GetKeyAttributes_Arg_2,
        (VOID *)GetKeyAttributes_Arg_3,
        GetKeyAttributes_Arg_4,
        GetKeyAttributes_Arg_5,
        NULL,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called AddKeyAttributes.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAddKeyAttributes(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_KMS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiKmsProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 * AddKeyAttributes_Arg_2 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINTN*  AddKeyAttributes_Arg_3 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT16 * AddKeyAttributes_Arg_4 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    EFI_KMS_KEY_ATTRIBUTE * AddKeyAttributes_Arg_5 = (EFI_KMS_KEY_ATTRIBUTE *)AllocateZeroPool(sizeof(EFI_KMS_KEY_ATTRIBUTE));
    
    // Fuzzable Variable Initialization
    UINT8 AddKeyAttributes_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(AddKeyAttributes_Arg_2_choice), (VOID *)&AddKeyAttributes_Arg_2_choice);
    switch(AddKeyAttributes_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(AddKeyAttributes_Arg_2), (VOID *)AddKeyAttributes_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(AddKeyAttributes_Arg_2);
            AddKeyAttributes_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 AddKeyAttributes_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(AddKeyAttributes_Arg_3_choice), (VOID *)&AddKeyAttributes_Arg_3_choice);
    switch(AddKeyAttributes_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(AddKeyAttributes_Arg_3), (VOID *)AddKeyAttributes_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(AddKeyAttributes_Arg_3);
            AddKeyAttributes_Arg_3 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 AddKeyAttributes_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(AddKeyAttributes_Arg_4_choice), (VOID *)&AddKeyAttributes_Arg_4_choice);
    switch(AddKeyAttributes_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(AddKeyAttributes_Arg_4), (VOID *)AddKeyAttributes_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(AddKeyAttributes_Arg_4);
            AddKeyAttributes_Arg_4 = NULL;
            break;
        }
    }
    
    
    Status = ProtocolVariable->AddKeyAttributes(
        ProtocolVariable,
        NULL,
        AddKeyAttributes_Arg_2,
        (VOID *)AddKeyAttributes_Arg_3,
        AddKeyAttributes_Arg_4,
        AddKeyAttributes_Arg_5,
        NULL,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called DeleteKeyAttributes.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDeleteKeyAttributes(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_KMS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiKmsProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 * DeleteKeyAttributes_Arg_2 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINTN*  DeleteKeyAttributes_Arg_3 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT16 * DeleteKeyAttributes_Arg_4 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    EFI_KMS_KEY_ATTRIBUTE * DeleteKeyAttributes_Arg_5 = (EFI_KMS_KEY_ATTRIBUTE *)AllocateZeroPool(sizeof(EFI_KMS_KEY_ATTRIBUTE));
    
    // Fuzzable Variable Initialization
    UINT8 DeleteKeyAttributes_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(DeleteKeyAttributes_Arg_2_choice), (VOID *)&DeleteKeyAttributes_Arg_2_choice);
    switch(DeleteKeyAttributes_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(DeleteKeyAttributes_Arg_2), (VOID *)DeleteKeyAttributes_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(DeleteKeyAttributes_Arg_2);
            DeleteKeyAttributes_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 DeleteKeyAttributes_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(DeleteKeyAttributes_Arg_3_choice), (VOID *)&DeleteKeyAttributes_Arg_3_choice);
    switch(DeleteKeyAttributes_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(DeleteKeyAttributes_Arg_3), (VOID *)DeleteKeyAttributes_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(DeleteKeyAttributes_Arg_3);
            DeleteKeyAttributes_Arg_3 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 DeleteKeyAttributes_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(DeleteKeyAttributes_Arg_4_choice), (VOID *)&DeleteKeyAttributes_Arg_4_choice);
    switch(DeleteKeyAttributes_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(DeleteKeyAttributes_Arg_4), (VOID *)DeleteKeyAttributes_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(DeleteKeyAttributes_Arg_4);
            DeleteKeyAttributes_Arg_4 = NULL;
            break;
        }
    }
    
    
    Status = ProtocolVariable->DeleteKeyAttributes(
        ProtocolVariable,
        NULL,
        DeleteKeyAttributes_Arg_2,
        (VOID *)DeleteKeyAttributes_Arg_3,
        DeleteKeyAttributes_Arg_4,
        DeleteKeyAttributes_Arg_5,
        NULL,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetKeyByAttributes.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetKeyByAttributes(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_KMS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiKmsProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * GetKeyByAttributes_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    EFI_KMS_KEY_ATTRIBUTE * GetKeyByAttributes_Arg_3 = (EFI_KMS_KEY_ATTRIBUTE *)AllocateZeroPool(sizeof(EFI_KMS_KEY_ATTRIBUTE));
    UINTN * GetKeyByAttributes_Arg_4 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    EFI_KMS_KEY_DESCRIPTOR * GetKeyByAttributes_Arg_5 = (EFI_KMS_KEY_DESCRIPTOR *)AllocateZeroPool(sizeof(EFI_KMS_KEY_DESCRIPTOR));
    
    // Fuzzable Variable Initialization
    UINT8 GetKeyByAttributes_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetKeyByAttributes_Arg_2_choice), (VOID *)&GetKeyByAttributes_Arg_2_choice);
    switch(GetKeyByAttributes_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetKeyByAttributes_Arg_2), (VOID *)GetKeyByAttributes_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(GetKeyByAttributes_Arg_2);
            GetKeyByAttributes_Arg_2 = NULL;
            break;
        }
    }
    
    
    // Fuzzable Variable Initialization
    UINT8 GetKeyByAttributes_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(GetKeyByAttributes_Arg_4_choice), (VOID *)&GetKeyByAttributes_Arg_4_choice);
    switch(GetKeyByAttributes_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetKeyByAttributes_Arg_4), (VOID *)GetKeyByAttributes_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(GetKeyByAttributes_Arg_4);
            GetKeyByAttributes_Arg_4 = NULL;
            break;
        }
    }
    
    
    Status = ProtocolVariable->GetKeyByAttributes(
        ProtocolVariable,
        NULL,
        GetKeyByAttributes_Arg_2,
        GetKeyByAttributes_Arg_3,
        GetKeyByAttributes_Arg_4,
        GetKeyByAttributes_Arg_5,
        NULL,
        NULL
    );
    return Status;
}

