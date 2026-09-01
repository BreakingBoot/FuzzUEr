#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called Start.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStart(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_IP4_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIp4ConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_EVENT Start_Arg_1 = 0;
    EFI_EVENT Start_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Start_Arg_1), (VOID *)&Start_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Start_Arg_2), (VOID *)&Start_Arg_2);
    
    Status = ProtocolVariable->Start(
        ProtocolVariable,
        Start_Arg_1,
        Start_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Stop.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStop(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_IP4_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIp4ConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Stop(
        ProtocolVariable
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
    EFI_IP4_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIp4ConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * GetData_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    UINT8 GetData_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetData_Arg_1_choice), (VOID *)&GetData_Arg_1_choice);
    switch(GetData_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetData_Arg_1), (VOID *)GetData_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(GetData_Arg_1);
            GetData_Arg_1 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetData(
        ProtocolVariable,
        GetData_Arg_1,
        NULL
    );
    return Status;
}

