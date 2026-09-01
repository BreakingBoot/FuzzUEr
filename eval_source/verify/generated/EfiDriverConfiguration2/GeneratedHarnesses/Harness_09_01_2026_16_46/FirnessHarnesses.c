#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called SetOptions.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetOptions(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DRIVER_CONFIGURATION2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDriverConfiguration2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR8 * SetOptions_Arg_3 = (CHAR8 *)AllocateZeroPool(sizeof(CHAR8));
    
    // Fuzzable Variable Initialization
    UINT8 SetOptions_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(SetOptions_Arg_3_choice), (VOID *)&SetOptions_Arg_3_choice);
    switch(SetOptions_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetOptions_Arg_3), (VOID *)SetOptions_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(SetOptions_Arg_3);
            SetOptions_Arg_3 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_DRIVER_CONFIGURATION_ACTION_REQUIRED * SetOptions_Arg_4 = (EFI_DRIVER_CONFIGURATION_ACTION_REQUIRED *)AllocateZeroPool(sizeof(EFI_DRIVER_CONFIGURATION_ACTION_REQUIRED));
    UINT8* SetOptions_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SetOptions_Arg_4_OutputChoice), (VOID *)SetOptions_Arg_4_OutputChoice);
    if(*SetOptions_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*SetOptions_Arg_4), (VOID *)SetOptions_Arg_4);
    }
    Status = ProtocolVariable->SetOptions(
        ProtocolVariable,
        ImageHandle,
        (EFI_HANDLE){0},
        SetOptions_Arg_3,
        SetOptions_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called OptionsValid.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzOptionsValid(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DRIVER_CONFIGURATION2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDriverConfiguration2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->OptionsValid(
        ProtocolVariable,
        ImageHandle,
        (EFI_HANDLE){0}
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ForceDefaults.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzForceDefaults(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DRIVER_CONFIGURATION2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDriverConfiguration2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 ForceDefaults_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ForceDefaults_Arg_3), (VOID *)&ForceDefaults_Arg_3);
    
    /*
        Output Variable(s)
    */
    EFI_DRIVER_CONFIGURATION_ACTION_REQUIRED * ForceDefaults_Arg_4 = (EFI_DRIVER_CONFIGURATION_ACTION_REQUIRED *)AllocateZeroPool(sizeof(EFI_DRIVER_CONFIGURATION_ACTION_REQUIRED));
    UINT8* ForceDefaults_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ForceDefaults_Arg_4_OutputChoice), (VOID *)ForceDefaults_Arg_4_OutputChoice);
    if(*ForceDefaults_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ForceDefaults_Arg_4), (VOID *)ForceDefaults_Arg_4);
    }
    Status = ProtocolVariable->ForceDefaults(
        ProtocolVariable,
        ImageHandle,
        (EFI_HANDLE){0},
        ForceDefaults_Arg_3,
        ForceDefaults_Arg_4
    );
    return Status;
}

