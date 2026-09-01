#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called GetTimerPeriod.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetTimerPeriod(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_TIMER_ARCH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTimerArchProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINT64 * GetTimerPeriod_Arg_1 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    UINT8* GetTimerPeriod_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetTimerPeriod_Arg_1_OutputChoice), (VOID *)GetTimerPeriod_Arg_1_OutputChoice);
    if(*GetTimerPeriod_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetTimerPeriod_Arg_1), (VOID *)GetTimerPeriod_Arg_1);
    }
    Status = ProtocolVariable->GetTimerPeriod(
        ProtocolVariable,
        GetTimerPeriod_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetTimerPeriod.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetTimerPeriod(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_TIMER_ARCH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTimerArchProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT64 SetTimerPeriod_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetTimerPeriod_Arg_1), (VOID *)&SetTimerPeriod_Arg_1);
    
    Status = ProtocolVariable->SetTimerPeriod(
        ProtocolVariable,
        SetTimerPeriod_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RegisterHandler.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterHandler(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_TIMER_ARCH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTimerArchProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->RegisterHandler(
        ProtocolVariable,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GenerateSoftInterrupt.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGenerateSoftInterrupt(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_TIMER_ARCH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTimerArchProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->GenerateSoftInterrupt(
        ProtocolVariable
    );
    return Status;
}

