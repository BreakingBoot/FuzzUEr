#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called Initialize.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzInitialize(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BIS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBisProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_BIS_VERSION * Initialize_Arg_2 = (EFI_BIS_VERSION *)AllocateZeroPool(sizeof(EFI_BIS_VERSION));
    EFI_BIS_DATA * Initialize_Arg_3 = (EFI_BIS_DATA *)AllocateZeroPool(sizeof(EFI_BIS_DATA));
    
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Length;
        ReadBytes(Input, sizeof(Firness_Length), (VOID *)&Firness_Length);
        Initialize_Arg_3->Length = Firness_Length;
    }
    ReadBytes(Input, sizeof(Initialize_Arg_3->Data), (VOID *)(Initialize_Arg_3->Data));
    
    /*
        Output Variable(s)
    */
    BIS_APPLICATION_HANDLE * Initialize_Arg_1 = (BIS_APPLICATION_HANDLE *)AllocateZeroPool(sizeof(BIS_APPLICATION_HANDLE));
    UINT8* Initialize_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Initialize_Arg_1_OutputChoice), (VOID *)Initialize_Arg_1_OutputChoice);
    if(*Initialize_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Initialize_Arg_1), (VOID *)Initialize_Arg_1);
    }
    Status = ProtocolVariable->Initialize(
        ProtocolVariable,
        Initialize_Arg_1,
        Initialize_Arg_2,
        Initialize_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called Shutdown.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzShutdown(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BIS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBisProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BIS_APPLICATION_HANDLE Shutdown_Arg_0 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Shutdown_Arg_0), (VOID *)&Shutdown_Arg_0);
    
    Status = ProtocolVariable->Shutdown(
        Shutdown_Arg_0
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called Free.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFree(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BIS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBisProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BIS_APPLICATION_HANDLE Free_Arg_0 = 0;
    EFI_BIS_DATA * Free_Arg_1 = (EFI_BIS_DATA *)AllocateZeroPool(sizeof(EFI_BIS_DATA));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Free_Arg_0), (VOID *)&Free_Arg_0);
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Length;
        ReadBytes(Input, sizeof(Firness_Length), (VOID *)&Firness_Length);
        Free_Arg_1->Length = Firness_Length;
    }
    ReadBytes(Input, sizeof(Free_Arg_1->Data), (VOID *)(Free_Arg_1->Data));
    
    Status = ProtocolVariable->Free(
        Free_Arg_0,
        Free_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetBootObjectAuthorizationCertificate.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetBootObjectAuthorizationCertificate(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BIS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBisProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BIS_APPLICATION_HANDLE GetBootObjectAuthorizationCertificate_Arg_0 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetBootObjectAuthorizationCertificate_Arg_0), (VOID *)&GetBootObjectAuthorizationCertificate_Arg_0);
    
    /*
        Output Variable(s)
    */
    EFI_BIS_DATA * * GetBootObjectAuthorizationCertificate_Arg_1 = (EFI_BIS_DATA * *)AllocateZeroPool(sizeof(EFI_BIS_DATA));
    UINT8* GetBootObjectAuthorizationCertificate_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetBootObjectAuthorizationCertificate_Arg_1_OutputChoice), (VOID *)GetBootObjectAuthorizationCertificate_Arg_1_OutputChoice);
    if(*GetBootObjectAuthorizationCertificate_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetBootObjectAuthorizationCertificate_Arg_1), (VOID *)GetBootObjectAuthorizationCertificate_Arg_1);
    }
    Status = ProtocolVariable->GetBootObjectAuthorizationCertificate(
        GetBootObjectAuthorizationCertificate_Arg_0,
        &GetBootObjectAuthorizationCertificate_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetBootObjectAuthorizationCheckFlag.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetBootObjectAuthorizationCheckFlag(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BIS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBisProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BIS_APPLICATION_HANDLE GetBootObjectAuthorizationCheckFlag_Arg_0 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetBootObjectAuthorizationCheckFlag_Arg_0), (VOID *)&GetBootObjectAuthorizationCheckFlag_Arg_0);
    
    /*
        Output Variable(s)
    */
    BOOLEAN * GetBootObjectAuthorizationCheckFlag_Arg_1 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
    UINT8* GetBootObjectAuthorizationCheckFlag_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetBootObjectAuthorizationCheckFlag_Arg_1_OutputChoice), (VOID *)GetBootObjectAuthorizationCheckFlag_Arg_1_OutputChoice);
    if(*GetBootObjectAuthorizationCheckFlag_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetBootObjectAuthorizationCheckFlag_Arg_1), (VOID *)GetBootObjectAuthorizationCheckFlag_Arg_1);
    }
    Status = ProtocolVariable->GetBootObjectAuthorizationCheckFlag(
        GetBootObjectAuthorizationCheckFlag_Arg_0,
        GetBootObjectAuthorizationCheckFlag_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetBootObjectAuthorizationUpdateToken.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetBootObjectAuthorizationUpdateToken(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BIS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBisProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BIS_APPLICATION_HANDLE GetBootObjectAuthorizationUpdateToken_Arg_0 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetBootObjectAuthorizationUpdateToken_Arg_0), (VOID *)&GetBootObjectAuthorizationUpdateToken_Arg_0);
    
    /*
        Output Variable(s)
    */
    EFI_BIS_DATA * * GetBootObjectAuthorizationUpdateToken_Arg_1 = (EFI_BIS_DATA * *)AllocateZeroPool(sizeof(EFI_BIS_DATA));
    UINT8* GetBootObjectAuthorizationUpdateToken_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetBootObjectAuthorizationUpdateToken_Arg_1_OutputChoice), (VOID *)GetBootObjectAuthorizationUpdateToken_Arg_1_OutputChoice);
    if(*GetBootObjectAuthorizationUpdateToken_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetBootObjectAuthorizationUpdateToken_Arg_1), (VOID *)GetBootObjectAuthorizationUpdateToken_Arg_1);
    }
    Status = ProtocolVariable->GetBootObjectAuthorizationUpdateToken(
        GetBootObjectAuthorizationUpdateToken_Arg_0,
        &GetBootObjectAuthorizationUpdateToken_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetSignatureInfo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetSignatureInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BIS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBisProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BIS_APPLICATION_HANDLE GetSignatureInfo_Arg_0 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetSignatureInfo_Arg_0), (VOID *)&GetSignatureInfo_Arg_0);
    
    /*
        Output Variable(s)
    */
    EFI_BIS_DATA * * GetSignatureInfo_Arg_1 = (EFI_BIS_DATA * *)AllocateZeroPool(sizeof(EFI_BIS_DATA));
    UINT8* GetSignatureInfo_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetSignatureInfo_Arg_1_OutputChoice), (VOID *)GetSignatureInfo_Arg_1_OutputChoice);
    if(*GetSignatureInfo_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetSignatureInfo_Arg_1), (VOID *)GetSignatureInfo_Arg_1);
    }
    Status = ProtocolVariable->GetSignatureInfo(
        GetSignatureInfo_Arg_0,
        &GetSignatureInfo_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called UpdateBootObjectAuthorization.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUpdateBootObjectAuthorization(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BIS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBisProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BIS_APPLICATION_HANDLE UpdateBootObjectAuthorization_Arg_0 = 0;
    EFI_BIS_DATA * UpdateBootObjectAuthorization_Arg_1 = (EFI_BIS_DATA *)AllocateZeroPool(sizeof(EFI_BIS_DATA));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UpdateBootObjectAuthorization_Arg_0), (VOID *)&UpdateBootObjectAuthorization_Arg_0);
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Length;
        ReadBytes(Input, sizeof(Firness_Length), (VOID *)&Firness_Length);
        UpdateBootObjectAuthorization_Arg_1->Length = Firness_Length;
    }
    ReadBytes(Input, sizeof(UpdateBootObjectAuthorization_Arg_1->Data), (VOID *)(UpdateBootObjectAuthorization_Arg_1->Data));
    
    /*
        Output Variable(s)
    */
    EFI_BIS_DATA * * UpdateBootObjectAuthorization_Arg_2 = (EFI_BIS_DATA * *)AllocateZeroPool(sizeof(EFI_BIS_DATA));
    UINT8* UpdateBootObjectAuthorization_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(UpdateBootObjectAuthorization_Arg_2_OutputChoice), (VOID *)UpdateBootObjectAuthorization_Arg_2_OutputChoice);
    if(*UpdateBootObjectAuthorization_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*UpdateBootObjectAuthorization_Arg_2), (VOID *)UpdateBootObjectAuthorization_Arg_2);
    }
    Status = ProtocolVariable->UpdateBootObjectAuthorization(
        UpdateBootObjectAuthorization_Arg_0,
        UpdateBootObjectAuthorization_Arg_1,
        &UpdateBootObjectAuthorization_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called VerifyBootObject.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzVerifyBootObject(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BIS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBisProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BIS_APPLICATION_HANDLE VerifyBootObject_Arg_0 = 0;
    EFI_BIS_DATA * VerifyBootObject_Arg_1 = (EFI_BIS_DATA *)AllocateZeroPool(sizeof(EFI_BIS_DATA));
    EFI_BIS_DATA * VerifyBootObject_Arg_2 = (EFI_BIS_DATA *)AllocateZeroPool(sizeof(EFI_BIS_DATA));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(VerifyBootObject_Arg_0), (VOID *)&VerifyBootObject_Arg_0);
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Length;
        ReadBytes(Input, sizeof(Firness_Length), (VOID *)&Firness_Length);
        VerifyBootObject_Arg_1->Length = Firness_Length;
    }
    ReadBytes(Input, sizeof(VerifyBootObject_Arg_1->Data), (VOID *)(VerifyBootObject_Arg_1->Data));
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Length;
        ReadBytes(Input, sizeof(Firness_Length), (VOID *)&Firness_Length);
        VerifyBootObject_Arg_2->Length = Firness_Length;
    }
    ReadBytes(Input, sizeof(VerifyBootObject_Arg_2->Data), (VOID *)(VerifyBootObject_Arg_2->Data));
    
    /*
        Output Variable(s)
    */
    BOOLEAN * VerifyBootObject_Arg_3 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
    UINT8* VerifyBootObject_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(VerifyBootObject_Arg_3_OutputChoice), (VOID *)VerifyBootObject_Arg_3_OutputChoice);
    if(*VerifyBootObject_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*VerifyBootObject_Arg_3), (VOID *)VerifyBootObject_Arg_3);
    }
    Status = ProtocolVariable->VerifyBootObject(
        VerifyBootObject_Arg_0,
        VerifyBootObject_Arg_1,
        VerifyBootObject_Arg_2,
        VerifyBootObject_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called VerifyObjectWithCredential.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzVerifyObjectWithCredential(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BIS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBisProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BIS_APPLICATION_HANDLE VerifyObjectWithCredential_Arg_0 = 0;
    EFI_BIS_DATA * VerifyObjectWithCredential_Arg_1 = (EFI_BIS_DATA *)AllocateZeroPool(sizeof(EFI_BIS_DATA));
    EFI_BIS_DATA * VerifyObjectWithCredential_Arg_2 = (EFI_BIS_DATA *)AllocateZeroPool(sizeof(EFI_BIS_DATA));
    EFI_BIS_DATA * VerifyObjectWithCredential_Arg_3 = (EFI_BIS_DATA *)AllocateZeroPool(sizeof(EFI_BIS_DATA));
    EFI_BIS_DATA * VerifyObjectWithCredential_Arg_4 = (EFI_BIS_DATA *)AllocateZeroPool(sizeof(EFI_BIS_DATA));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(VerifyObjectWithCredential_Arg_0), (VOID *)&VerifyObjectWithCredential_Arg_0);
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Length;
        ReadBytes(Input, sizeof(Firness_Length), (VOID *)&Firness_Length);
        VerifyObjectWithCredential_Arg_1->Length = Firness_Length;
    }
    ReadBytes(Input, sizeof(VerifyObjectWithCredential_Arg_1->Data), (VOID *)(VerifyObjectWithCredential_Arg_1->Data));
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Length;
        ReadBytes(Input, sizeof(Firness_Length), (VOID *)&Firness_Length);
        VerifyObjectWithCredential_Arg_2->Length = Firness_Length;
    }
    ReadBytes(Input, sizeof(VerifyObjectWithCredential_Arg_2->Data), (VOID *)(VerifyObjectWithCredential_Arg_2->Data));
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Length;
        ReadBytes(Input, sizeof(Firness_Length), (VOID *)&Firness_Length);
        VerifyObjectWithCredential_Arg_3->Length = Firness_Length;
    }
    ReadBytes(Input, sizeof(VerifyObjectWithCredential_Arg_3->Data), (VOID *)(VerifyObjectWithCredential_Arg_3->Data));
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Length;
        ReadBytes(Input, sizeof(Firness_Length), (VOID *)&Firness_Length);
        VerifyObjectWithCredential_Arg_4->Length = Firness_Length;
    }
    ReadBytes(Input, sizeof(VerifyObjectWithCredential_Arg_4->Data), (VOID *)(VerifyObjectWithCredential_Arg_4->Data));
    
    /*
        Output Variable(s)
    */
    BOOLEAN * VerifyObjectWithCredential_Arg_5 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
    UINT8* VerifyObjectWithCredential_Arg_5_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(VerifyObjectWithCredential_Arg_5_OutputChoice), (VOID *)VerifyObjectWithCredential_Arg_5_OutputChoice);
    if(*VerifyObjectWithCredential_Arg_5_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*VerifyObjectWithCredential_Arg_5), (VOID *)VerifyObjectWithCredential_Arg_5);
    }
    Status = ProtocolVariable->VerifyObjectWithCredential(
        VerifyObjectWithCredential_Arg_0,
        VerifyObjectWithCredential_Arg_1,
        VerifyObjectWithCredential_Arg_2,
        VerifyObjectWithCredential_Arg_3,
        VerifyObjectWithCredential_Arg_4,
        VerifyObjectWithCredential_Arg_5
    );
    return Status;
}

