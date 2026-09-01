#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called GetContext.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetContext(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMART_CARD_EDGE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmartCardEdgeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINTN * GetContext_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetContext_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetContext_Arg_1_OutputChoice), (VOID *)GetContext_Arg_1_OutputChoice);
    if(*GetContext_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetContext_Arg_1), (VOID *)GetContext_Arg_1);
    }
    UINTN * GetContext_Arg_4 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetContext_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetContext_Arg_4_OutputChoice), (VOID *)GetContext_Arg_4_OutputChoice);
    if(*GetContext_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetContext_Arg_4), (VOID *)GetContext_Arg_4);
    }
    Status = ProtocolVariable->GetContext(
        ProtocolVariable,
        GetContext_Arg_1,
        NULL,
        NULL,
        GetContext_Arg_4,
        NULL,
        NULL,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Connect.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzConnect(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMART_CARD_EDGE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmartCardEdgeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_HANDLE * Connect_Arg_1 = (EFI_HANDLE *)AllocateZeroPool(sizeof(EFI_HANDLE));
    UINT8* Connect_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Connect_Arg_1_OutputChoice), (VOID *)Connect_Arg_1_OutputChoice);
    if(*Connect_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Connect_Arg_1), (VOID *)Connect_Arg_1);
    }
    Status = ProtocolVariable->Connect(
        ProtocolVariable,
        Connect_Arg_1,
        NULL,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Disconnect.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDisconnect(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMART_CARD_EDGE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmartCardEdgeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Disconnect(
        ProtocolVariable,
        ImageHandle
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetCsn.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetCsn(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMART_CARD_EDGE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmartCardEdgeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINT8 * GetCsn_Arg_2 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT8* GetCsn_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetCsn_Arg_2_OutputChoice), (VOID *)GetCsn_Arg_2_OutputChoice);
    if(*GetCsn_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetCsn_Arg_2), (VOID *)GetCsn_Arg_2);
    }
    Status = ProtocolVariable->GetCsn(
        ProtocolVariable,
        ImageHandle,
        GetCsn_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetReaderName.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetReaderName(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMART_CARD_EDGE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmartCardEdgeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * GetReaderName_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    UINT8 GetReaderName_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetReaderName_Arg_2_choice), (VOID *)&GetReaderName_Arg_2_choice);
    switch(GetReaderName_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetReaderName_Arg_2), (VOID *)GetReaderName_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(GetReaderName_Arg_2);
            GetReaderName_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetReaderName(
        ProtocolVariable,
        ImageHandle,
        GetReaderName_Arg_2,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called VerifyPin.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzVerifyPin(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMART_CARD_EDGE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmartCardEdgeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    INT32 VerifyPin_Arg_2 = 0;
    UINT8 * VerifyPin_Arg_3 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(VerifyPin_Arg_2), (VOID *)&VerifyPin_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 VerifyPin_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(VerifyPin_Arg_3_choice), (VOID *)&VerifyPin_Arg_3_choice);
    switch(VerifyPin_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(VerifyPin_Arg_3), (VOID *)VerifyPin_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(VerifyPin_Arg_3);
            VerifyPin_Arg_3 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    BOOLEAN * VerifyPin_Arg_4 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
    UINT8* VerifyPin_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(VerifyPin_Arg_4_OutputChoice), (VOID *)VerifyPin_Arg_4_OutputChoice);
    if(*VerifyPin_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*VerifyPin_Arg_4), (VOID *)VerifyPin_Arg_4);
    }
    Status = ProtocolVariable->VerifyPin(
        ProtocolVariable,
        ImageHandle,
        VerifyPin_Arg_2,
        VerifyPin_Arg_3,
        VerifyPin_Arg_4,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetPinRemaining.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetPinRemaining(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMART_CARD_EDGE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmartCardEdgeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINT32 * GetPinRemaining_Arg_2 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT8* GetPinRemaining_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetPinRemaining_Arg_2_OutputChoice), (VOID *)GetPinRemaining_Arg_2_OutputChoice);
    if(*GetPinRemaining_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetPinRemaining_Arg_2), (VOID *)GetPinRemaining_Arg_2);
    }
    Status = ProtocolVariable->GetPinRemaining(
        ProtocolVariable,
        ImageHandle,
        GetPinRemaining_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetData.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMART_CARD_EDGE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmartCardEdgeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * GetData_Arg_2 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINTN * GetData_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        GetData_Arg_2->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        GetData_Arg_2->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        GetData_Arg_2->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(GetData_Arg_2->Data4), (VOID *)&(GetData_Arg_2->Data4));
    
    // Fuzzable Variable Initialization
    UINT8 GetData_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(GetData_Arg_3_choice), (VOID *)&GetData_Arg_3_choice);
    switch(GetData_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetData_Arg_3), (VOID *)GetData_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(GetData_Arg_3);
            GetData_Arg_3 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetData(
        ProtocolVariable,
        ImageHandle,
        GetData_Arg_2,
        GetData_Arg_3,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetCredential.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetCredential(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMART_CARD_EDGE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmartCardEdgeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * GetCredential_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    UINT8 GetCredential_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetCredential_Arg_2_choice), (VOID *)&GetCredential_Arg_2_choice);
    switch(GetCredential_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetCredential_Arg_2), (VOID *)GetCredential_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(GetCredential_Arg_2);
            GetCredential_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetCredential(
        ProtocolVariable,
        ImageHandle,
        GetCredential_Arg_2,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SignData.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSignData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMART_CARD_EDGE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmartCardEdgeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN SignData_Arg_2 = 0;
    UINTN SignData_Arg_3 = 0;
    EFI_GUID * SignData_Arg_4 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    EFI_GUID * SignData_Arg_5 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINT8 * SignData_Arg_6 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SignData_Arg_2), (VOID *)&SignData_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SignData_Arg_3), (VOID *)&SignData_Arg_3);
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        SignData_Arg_4->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        SignData_Arg_4->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        SignData_Arg_4->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(SignData_Arg_4->Data4), (VOID *)&(SignData_Arg_4->Data4));
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        SignData_Arg_5->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        SignData_Arg_5->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        SignData_Arg_5->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(SignData_Arg_5->Data4), (VOID *)&(SignData_Arg_5->Data4));
    
    // Fuzzable Variable Initialization
    UINT8 SignData_Arg_6_choice = 0;
    ReadBytes(Input, sizeof(SignData_Arg_6_choice), (VOID *)&SignData_Arg_6_choice);
    switch(SignData_Arg_6_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SignData_Arg_6), (VOID *)SignData_Arg_6);
            break;
        case 1:
        {
            gBS->FreePool(SignData_Arg_6);
            SignData_Arg_6 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    UINT8 * SignData_Arg_7 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT8* SignData_Arg_7_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SignData_Arg_7_OutputChoice), (VOID *)SignData_Arg_7_OutputChoice);
    if(*SignData_Arg_7_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*SignData_Arg_7), (VOID *)SignData_Arg_7);
    }
    Status = ProtocolVariable->SignData(
        ProtocolVariable,
        ImageHandle,
        SignData_Arg_2,
        SignData_Arg_3,
        SignData_Arg_4,
        SignData_Arg_5,
        SignData_Arg_6,
        SignData_Arg_7
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called DecryptData.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDecryptData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMART_CARD_EDGE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmartCardEdgeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN DecryptData_Arg_2 = 0;
    EFI_GUID * DecryptData_Arg_3 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    EFI_GUID * DecryptData_Arg_4 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINTN DecryptData_Arg_5 = 0;
    UINT8 * DecryptData_Arg_6 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINTN * DecryptData_Arg_7 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(DecryptData_Arg_2), (VOID *)&DecryptData_Arg_2);
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        DecryptData_Arg_3->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        DecryptData_Arg_3->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        DecryptData_Arg_3->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(DecryptData_Arg_3->Data4), (VOID *)&(DecryptData_Arg_3->Data4));
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        DecryptData_Arg_4->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        DecryptData_Arg_4->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        DecryptData_Arg_4->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(DecryptData_Arg_4->Data4), (VOID *)&(DecryptData_Arg_4->Data4));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(DecryptData_Arg_5), (VOID *)&DecryptData_Arg_5);
    
    // Fuzzable Variable Initialization
    UINT8 DecryptData_Arg_6_choice = 0;
    ReadBytes(Input, sizeof(DecryptData_Arg_6_choice), (VOID *)&DecryptData_Arg_6_choice);
    switch(DecryptData_Arg_6_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(DecryptData_Arg_6), (VOID *)DecryptData_Arg_6);
            break;
        case 1:
        {
            gBS->FreePool(DecryptData_Arg_6);
            DecryptData_Arg_6 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 DecryptData_Arg_7_choice = 0;
    ReadBytes(Input, sizeof(DecryptData_Arg_7_choice), (VOID *)&DecryptData_Arg_7_choice);
    switch(DecryptData_Arg_7_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(DecryptData_Arg_7), (VOID *)DecryptData_Arg_7);
            break;
        case 1:
        {
            gBS->FreePool(DecryptData_Arg_7);
            DecryptData_Arg_7 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    UINT8 * DecryptData_Arg_8 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT8* DecryptData_Arg_8_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(DecryptData_Arg_8_OutputChoice), (VOID *)DecryptData_Arg_8_OutputChoice);
    if(*DecryptData_Arg_8_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*DecryptData_Arg_8), (VOID *)DecryptData_Arg_8);
    }
    Status = ProtocolVariable->DecryptData(
        ProtocolVariable,
        ImageHandle,
        DecryptData_Arg_2,
        DecryptData_Arg_3,
        DecryptData_Arg_4,
        DecryptData_Arg_5,
        DecryptData_Arg_6,
        DecryptData_Arg_7,
        DecryptData_Arg_8
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called BuildDHAgreement.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzBuildDHAgreement(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMART_CARD_EDGE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmartCardEdgeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN BuildDHAgreement_Arg_2 = 0;
    UINT8 * BuildDHAgreement_Arg_3 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT8 * BuildDHAgreement_Arg_4 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(BuildDHAgreement_Arg_2), (VOID *)&BuildDHAgreement_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 BuildDHAgreement_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(BuildDHAgreement_Arg_3_choice), (VOID *)&BuildDHAgreement_Arg_3_choice);
    switch(BuildDHAgreement_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(BuildDHAgreement_Arg_3), (VOID *)BuildDHAgreement_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(BuildDHAgreement_Arg_3);
            BuildDHAgreement_Arg_3 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 BuildDHAgreement_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(BuildDHAgreement_Arg_4_choice), (VOID *)&BuildDHAgreement_Arg_4_choice);
    switch(BuildDHAgreement_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(BuildDHAgreement_Arg_4), (VOID *)BuildDHAgreement_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(BuildDHAgreement_Arg_4);
            BuildDHAgreement_Arg_4 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    UINT8 * BuildDHAgreement_Arg_5 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT8* BuildDHAgreement_Arg_5_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(BuildDHAgreement_Arg_5_OutputChoice), (VOID *)BuildDHAgreement_Arg_5_OutputChoice);
    if(*BuildDHAgreement_Arg_5_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*BuildDHAgreement_Arg_5), (VOID *)BuildDHAgreement_Arg_5);
    }
    Status = ProtocolVariable->BuildDHAgreement(
        ProtocolVariable,
        ImageHandle,
        BuildDHAgreement_Arg_2,
        BuildDHAgreement_Arg_3,
        BuildDHAgreement_Arg_4,
        BuildDHAgreement_Arg_5
    );
    return Status;
}

