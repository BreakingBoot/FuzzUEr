#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called GetSystemConfiguration.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetSystemConfiguration(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_EAP_MANAGEMENT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiEapManagementProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    BOOLEAN * GetSystemConfiguration_Arg_1 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
    UINT8* GetSystemConfiguration_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetSystemConfiguration_Arg_1_OutputChoice), (VOID *)GetSystemConfiguration_Arg_1_OutputChoice);
    if(*GetSystemConfiguration_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetSystemConfiguration_Arg_1), (VOID *)GetSystemConfiguration_Arg_1);
    }
    Status = ProtocolVariable->GetSystemConfiguration(
        ProtocolVariable,
        GetSystemConfiguration_Arg_1,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetSystemConfiguration.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetSystemConfiguration(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_EAP_MANAGEMENT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiEapManagementProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN SetSystemConfiguration_Arg_1 = FALSE;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetSystemConfiguration_Arg_1), (VOID *)&SetSystemConfiguration_Arg_1);
    
    Status = ProtocolVariable->SetSystemConfiguration(
        ProtocolVariable,
        SetSystemConfiguration_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called InitializePort.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzInitializePort(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_EAP_MANAGEMENT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiEapManagementProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->InitializePort(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UserLogon.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUserLogon(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_EAP_MANAGEMENT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiEapManagementProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->UserLogon(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UserLogoff.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUserLogoff(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_EAP_MANAGEMENT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiEapManagementProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->UserLogoff(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetSupplicantStatus.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetSupplicantStatus(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_EAP_MANAGEMENT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiEapManagementProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_EAPOL_SUPPLICANT_PAE_STATE * GetSupplicantStatus_Arg_1 = (EFI_EAPOL_SUPPLICANT_PAE_STATE *)AllocateZeroPool(sizeof(EFI_EAPOL_SUPPLICANT_PAE_STATE));
    UINT8* GetSupplicantStatus_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetSupplicantStatus_Arg_1_OutputChoice), (VOID *)GetSupplicantStatus_Arg_1_OutputChoice);
    if(*GetSupplicantStatus_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetSupplicantStatus_Arg_1), (VOID *)GetSupplicantStatus_Arg_1);
    }
    Status = ProtocolVariable->GetSupplicantStatus(
        ProtocolVariable,
        GetSupplicantStatus_Arg_1,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetSupplicantConfiguration.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetSupplicantConfiguration(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_EAP_MANAGEMENT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiEapManagementProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_EAPOL_SUPPLICANT_PAE_CONFIGURATION * SetSupplicantConfiguration_Arg_1 = (EFI_EAPOL_SUPPLICANT_PAE_CONFIGURATION *)AllocateZeroPool(sizeof(EFI_EAPOL_SUPPLICANT_PAE_CONFIGURATION));
    
    // Generator Struct Variable Initialization
    {
        UINT8 Firness_ValidFieldMask;
        ReadBytes(Input, sizeof(Firness_ValidFieldMask), (VOID *)&Firness_ValidFieldMask);
        SetSupplicantConfiguration_Arg_1->ValidFieldMask = Firness_ValidFieldMask;
    }
    {
        UINTN Firness_AuthPeriod;
        ReadBytes(Input, sizeof(Firness_AuthPeriod), (VOID *)&Firness_AuthPeriod);
        SetSupplicantConfiguration_Arg_1->AuthPeriod = Firness_AuthPeriod;
    }
    {
        UINTN Firness_HeldPeriod;
        ReadBytes(Input, sizeof(Firness_HeldPeriod), (VOID *)&Firness_HeldPeriod);
        SetSupplicantConfiguration_Arg_1->HeldPeriod = Firness_HeldPeriod;
    }
    {
        UINTN Firness_StartPeriod;
        ReadBytes(Input, sizeof(Firness_StartPeriod), (VOID *)&Firness_StartPeriod);
        SetSupplicantConfiguration_Arg_1->StartPeriod = Firness_StartPeriod;
    }
    {
        UINTN Firness_MaxStart;
        ReadBytes(Input, sizeof(Firness_MaxStart), (VOID *)&Firness_MaxStart);
        SetSupplicantConfiguration_Arg_1->MaxStart = Firness_MaxStart;
    }
    
    Status = ProtocolVariable->SetSupplicantConfiguration(
        ProtocolVariable,
        SetSupplicantConfiguration_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetSupplicantStatistics.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetSupplicantStatistics(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_EAP_MANAGEMENT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiEapManagementProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_EAPOL_SUPPLICANT_PAE_STATISTICS * GetSupplicantStatistics_Arg_1 = (EFI_EAPOL_SUPPLICANT_PAE_STATISTICS *)AllocateZeroPool(sizeof(EFI_EAPOL_SUPPLICANT_PAE_STATISTICS));
    UINT8* GetSupplicantStatistics_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetSupplicantStatistics_Arg_1_OutputChoice), (VOID *)GetSupplicantStatistics_Arg_1_OutputChoice);
    if(*GetSupplicantStatistics_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetSupplicantStatistics_Arg_1), (VOID *)GetSupplicantStatistics_Arg_1);
    }
    Status = ProtocolVariable->GetSupplicantStatistics(
        ProtocolVariable,
        GetSupplicantStatistics_Arg_1
    );
    return Status;
}

