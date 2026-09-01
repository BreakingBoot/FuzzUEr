#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called GetNumberOfProcessors.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetNumberOfProcessors(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MP_SERVICES_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMpServiceProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINTN * GetNumberOfProcessors_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetNumberOfProcessors_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetNumberOfProcessors_Arg_1_OutputChoice), (VOID *)GetNumberOfProcessors_Arg_1_OutputChoice);
    if(*GetNumberOfProcessors_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetNumberOfProcessors_Arg_1), (VOID *)GetNumberOfProcessors_Arg_1);
    }
    UINTN * GetNumberOfProcessors_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetNumberOfProcessors_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetNumberOfProcessors_Arg_2_OutputChoice), (VOID *)GetNumberOfProcessors_Arg_2_OutputChoice);
    if(*GetNumberOfProcessors_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetNumberOfProcessors_Arg_2), (VOID *)GetNumberOfProcessors_Arg_2);
    }
    Status = ProtocolVariable->GetNumberOfProcessors(
        ProtocolVariable,
        GetNumberOfProcessors_Arg_1,
        GetNumberOfProcessors_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetProcessorInfo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetProcessorInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MP_SERVICES_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMpServiceProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN GetProcessorInfo_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetProcessorInfo_Arg_1), (VOID *)&GetProcessorInfo_Arg_1);
    
    /*
        Output Variable(s)
    */
    EFI_PROCESSOR_INFORMATION * GetProcessorInfo_Arg_2 = (EFI_PROCESSOR_INFORMATION *)AllocateZeroPool(sizeof(EFI_PROCESSOR_INFORMATION));
    UINT8* GetProcessorInfo_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetProcessorInfo_Arg_2_OutputChoice), (VOID *)GetProcessorInfo_Arg_2_OutputChoice);
    if(*GetProcessorInfo_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetProcessorInfo_Arg_2), (VOID *)GetProcessorInfo_Arg_2);
    }
    Status = ProtocolVariable->GetProcessorInfo(
        ProtocolVariable,
        GetProcessorInfo_Arg_1,
        GetProcessorInfo_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called StartupAllAPs.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStartupAllAPs(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MP_SERVICES_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMpServiceProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN StartupAllAPs_Arg_2 = FALSE;
    UINTN StartupAllAPs_Arg_4 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StartupAllAPs_Arg_2), (VOID *)&StartupAllAPs_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StartupAllAPs_Arg_4), (VOID *)&StartupAllAPs_Arg_4);
    
    Status = ProtocolVariable->StartupAllAPs(
        ProtocolVariable,
        (EFI_AP_PROCEDURE){0},
        StartupAllAPs_Arg_2,
        (EFI_EVENT){0},
        StartupAllAPs_Arg_4,
        NULL,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called StartupThisAP.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStartupThisAP(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MP_SERVICES_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMpServiceProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN StartupThisAP_Arg_2 = 0;
    UINTN StartupThisAP_Arg_4 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StartupThisAP_Arg_2), (VOID *)&StartupThisAP_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StartupThisAP_Arg_4), (VOID *)&StartupThisAP_Arg_4);
    
    Status = ProtocolVariable->StartupThisAP(
        ProtocolVariable,
        (EFI_AP_PROCEDURE){0},
        StartupThisAP_Arg_2,
        (EFI_EVENT){0},
        StartupThisAP_Arg_4,
        NULL,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SwitchBSP.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSwitchBSP(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MP_SERVICES_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMpServiceProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN SwitchBSP_Arg_1 = 0;
    BOOLEAN SwitchBSP_Arg_2 = FALSE;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SwitchBSP_Arg_1), (VOID *)&SwitchBSP_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SwitchBSP_Arg_2), (VOID *)&SwitchBSP_Arg_2);
    
    Status = ProtocolVariable->SwitchBSP(
        ProtocolVariable,
        SwitchBSP_Arg_1,
        SwitchBSP_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called EnableDisableAP.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzEnableDisableAP(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MP_SERVICES_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMpServiceProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN EnableDisableAP_Arg_1 = 0;
    BOOLEAN EnableDisableAP_Arg_2 = FALSE;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(EnableDisableAP_Arg_1), (VOID *)&EnableDisableAP_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(EnableDisableAP_Arg_2), (VOID *)&EnableDisableAP_Arg_2);
    
    Status = ProtocolVariable->EnableDisableAP(
        ProtocolVariable,
        EnableDisableAP_Arg_1,
        EnableDisableAP_Arg_2,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called WhoAmI.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzWhoAmI(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MP_SERVICES_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMpServiceProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINTN * WhoAmI_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* WhoAmI_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(WhoAmI_Arg_1_OutputChoice), (VOID *)WhoAmI_Arg_1_OutputChoice);
    if(*WhoAmI_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*WhoAmI_Arg_1), (VOID *)WhoAmI_Arg_1);
    }
    Status = ProtocolVariable->WhoAmI(
        ProtocolVariable,
        WhoAmI_Arg_1
    );
    return Status;
}

