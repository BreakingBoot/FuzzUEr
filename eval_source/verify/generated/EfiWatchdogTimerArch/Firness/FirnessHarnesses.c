#include "FirnessHarnesses.h"

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
    EFI_WATCHDOG_TIMER_ARCH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiWatchdogTimerArchProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    EFI_WATCHDOG_TIMER_ARCH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiWatchdogTimerArchProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->RegisterHandler(
        ProtocolVariable,
        (EFI_WATCHDOG_TIMER_NOTIFY){0}
    );
    return Status;
}

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
    EFI_WATCHDOG_TIMER_ARCH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiWatchdogTimerArchProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT64 * GetTimerPeriod_Arg_1 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    
    // Fuzzable Variable Initialization
    UINT8 GetTimerPeriod_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetTimerPeriod_Arg_1_choice), (VOID *)&GetTimerPeriod_Arg_1_choice);
    switch(GetTimerPeriod_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetTimerPeriod_Arg_1), (VOID *)GetTimerPeriod_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(GetTimerPeriod_Arg_1);
            GetTimerPeriod_Arg_1 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetTimerPeriod(
        ProtocolVariable,
        GetTimerPeriod_Arg_1
    );
    return Status;
}

