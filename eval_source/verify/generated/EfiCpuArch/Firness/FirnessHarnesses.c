#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called DisableInterrupt.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDisableInterrupt(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_CPU_ARCH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiCpuArchProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->DisableInterrupt(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called EnableInterrupt.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzEnableInterrupt(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_CPU_ARCH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiCpuArchProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->EnableInterrupt(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetMemoryAttributes.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetMemoryAttributes(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_CPU_ARCH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiCpuArchProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT64 SetMemoryAttributes_Arg_1 = 0;
    UINT64 SetMemoryAttributes_Arg_2 = 0;
    UINT64 SetMemoryAttributes_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetMemoryAttributes_Arg_1), (VOID *)&SetMemoryAttributes_Arg_1);
    
    UINT8* SetMemoryAttributes_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SetMemoryAttributes_Arg_2_choice), (VOID *)SetMemoryAttributes_Arg_2_choice);
    switch(*SetMemoryAttributes_Arg_2_choice % 5) {
        case 0:
        {
        // Constant Variable Initialization
        SetMemoryAttributes_Arg_2 = 0;
    
            break;
        }
        case 1:
        {
        // Constant Variable Initialization
        SetMemoryAttributes_Arg_2 = NVME_ASQ_BUF_OFFSET;
    
            break;
        }
        case 2:
        {
        // Constant Variable Initialization
        SetMemoryAttributes_Arg_2 = 0;
    
            break;
        }
        case 3:
        {
        // Constant Variable Initialization
        SetMemoryAttributes_Arg_2 = 0;
    
            break;
        }
        case 4:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(SetMemoryAttributes_Arg_2), (VOID *)&SetMemoryAttributes_Arg_2);
    
            break;
        }
    }
    UINT8* SetMemoryAttributes_Arg_3_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SetMemoryAttributes_Arg_3_choice), (VOID *)SetMemoryAttributes_Arg_3_choice);
    switch(*SetMemoryAttributes_Arg_3_choice % 2) {
        case 0:
        {
        // Constant Variable Initialization
        SetMemoryAttributes_Arg_3 = kEmptyHashValue;
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(SetMemoryAttributes_Arg_3), (VOID *)&SetMemoryAttributes_Arg_3);
    
            break;
        }
    }
    Status = ProtocolVariable->SetMemoryAttributes(
        ProtocolVariable,
        SetMemoryAttributes_Arg_1,
        SetMemoryAttributes_Arg_2,
        SetMemoryAttributes_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RegisterInterruptHandler.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterInterruptHandler(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_CPU_ARCH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiCpuArchProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_EXCEPTION_TYPE RegisterInterruptHandler_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RegisterInterruptHandler_Arg_1), (VOID *)&RegisterInterruptHandler_Arg_1);
    
    Status = ProtocolVariable->RegisterInterruptHandler(
        ProtocolVariable,
        RegisterInterruptHandler_Arg_1,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called FlushDataCache.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFlushDataCache(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_CPU_ARCH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiCpuArchProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PHYSICAL_ADDRESS FlushDataCache_Arg_1 = 0;
    UINT64 FlushDataCache_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(FlushDataCache_Arg_1), (VOID *)&FlushDataCache_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(FlushDataCache_Arg_2), (VOID *)&FlushDataCache_Arg_2);
    
    Status = ProtocolVariable->FlushDataCache(
        ProtocolVariable,
        FlushDataCache_Arg_1,
        FlushDataCache_Arg_2,
        (EFI_CPU_FLUSH_TYPE){0}
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Init.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzInit(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_CPU_ARCH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiCpuArchProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Init(
        ProtocolVariable,
        (EFI_CPU_INIT_TYPE){0}
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetTimerValue.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetTimerValue(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_CPU_ARCH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiCpuArchProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 GetTimerValue_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetTimerValue_Arg_1), (VOID *)&GetTimerValue_Arg_1);
    
    /*
        Output Variable(s)
    */
    UINT64 * GetTimerValue_Arg_2 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    UINT8* GetTimerValue_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetTimerValue_Arg_2_OutputChoice), (VOID *)GetTimerValue_Arg_2_OutputChoice);
    if(*GetTimerValue_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetTimerValue_Arg_2), (VOID *)GetTimerValue_Arg_2);
    }
    UINT64 * GetTimerValue_Arg_3 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    UINT8* GetTimerValue_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetTimerValue_Arg_3_OutputChoice), (VOID *)GetTimerValue_Arg_3_OutputChoice);
    if(*GetTimerValue_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetTimerValue_Arg_3), (VOID *)GetTimerValue_Arg_3);
    }
    Status = ProtocolVariable->GetTimerValue(
        ProtocolVariable,
        GetTimerValue_Arg_1,
        GetTimerValue_Arg_2,
        GetTimerValue_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetInterruptState.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetInterruptState(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_CPU_ARCH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiCpuArchProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    BOOLEAN * GetInterruptState_Arg_1 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
    UINT8* GetInterruptState_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetInterruptState_Arg_1_OutputChoice), (VOID *)GetInterruptState_Arg_1_OutputChoice);
    if(*GetInterruptState_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetInterruptState_Arg_1), (VOID *)GetInterruptState_Arg_1);
    }
    Status = ProtocolVariable->GetInterruptState(
        ProtocolVariable,
        GetInterruptState_Arg_1
    );
    return Status;
}

