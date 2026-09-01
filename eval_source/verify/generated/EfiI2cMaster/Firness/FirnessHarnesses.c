#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called SetBusFrequency.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetBusFrequency(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_I2C_MASTER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiI2cMasterProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * SetBusFrequency_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    UINT8 SetBusFrequency_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(SetBusFrequency_Arg_1_choice), (VOID *)&SetBusFrequency_Arg_1_choice);
    switch(SetBusFrequency_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetBusFrequency_Arg_1), (VOID *)SetBusFrequency_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(SetBusFrequency_Arg_1);
            SetBusFrequency_Arg_1 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->SetBusFrequency(
        ProtocolVariable,
        SetBusFrequency_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Reset.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzReset(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_I2C_MASTER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiI2cMasterProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Reset(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called StartRequest.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStartRequest(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_I2C_MASTER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiI2cMasterProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN StartRequest_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StartRequest_Arg_1), (VOID *)&StartRequest_Arg_1);
    
    Status = ProtocolVariable->StartRequest(
        ProtocolVariable,
        StartRequest_Arg_1,
        NULL,
        (EFI_EVENT){0},
        NULL
    );
    return Status;
}

