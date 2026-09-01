#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called Register.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegister(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MM_PERIODIC_TIMER_DISPATCH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMmPeriodicTimerDispatchProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_MM_HANDLER_ENTRY_POINT Register_Arg_1 = 0;
    EFI_MM_PERIODIC_TIMER_REGISTER_CONTEXT * Register_Arg_2 = (EFI_MM_PERIODIC_TIMER_REGISTER_CONTEXT *)AllocateZeroPool(sizeof(EFI_MM_PERIODIC_TIMER_REGISTER_CONTEXT));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Register_Arg_1), (VOID *)&Register_Arg_1);
    
    // Generator Struct Variable Initialization
    {
        UINT64 Firness_Period;
        ReadBytes(Input, sizeof(Firness_Period), (VOID *)&Firness_Period);
        Register_Arg_2->Period = Firness_Period;
    }
    {
        UINT64 Firness_MmiTickInterval;
        ReadBytes(Input, sizeof(Firness_MmiTickInterval), (VOID *)&Firness_MmiTickInterval);
        Register_Arg_2->MmiTickInterval = Firness_MmiTickInterval;
    }
    
    /*
        Output Variable(s)
    */
    EFI_HANDLE * Register_Arg_3 = (EFI_HANDLE *)AllocateZeroPool(sizeof(EFI_HANDLE));
    UINT8* Register_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Register_Arg_3_OutputChoice), (VOID *)Register_Arg_3_OutputChoice);
    if(*Register_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Register_Arg_3), (VOID *)Register_Arg_3);
    }
    Status = ProtocolVariable->Register(
        ProtocolVariable,
        Register_Arg_1,
        Register_Arg_2,
        Register_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UnRegister.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUnRegister(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MM_PERIODIC_TIMER_DISPATCH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMmPeriodicTimerDispatchProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->UnRegister(
        ProtocolVariable,
        ImageHandle
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetNextShorterInterval.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetNextShorterInterval(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MM_PERIODIC_TIMER_DISPATCH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMmPeriodicTimerDispatchProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT64 * * GetNextShorterInterval_Arg_1 = (UINT64 * *)AllocateZeroPool(sizeof(UINT64));
    
    // Fuzzable Variable Initialization
    UINT8 GetNextShorterInterval_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetNextShorterInterval_Arg_1_choice), (VOID *)&GetNextShorterInterval_Arg_1_choice);
    switch(GetNextShorterInterval_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetNextShorterInterval_Arg_1), (VOID *)GetNextShorterInterval_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(GetNextShorterInterval_Arg_1);
            GetNextShorterInterval_Arg_1 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetNextShorterInterval(
        ProtocolVariable,
        &GetNextShorterInterval_Arg_1
    );
    return Status;
}

