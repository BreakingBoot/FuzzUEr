#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called GetMaximumProcessorIndex.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetMaximumProcessorIndex(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DEBUG_SUPPORT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDebugSupportProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINTN * GetMaximumProcessorIndex_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetMaximumProcessorIndex_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetMaximumProcessorIndex_Arg_1_OutputChoice), (VOID *)GetMaximumProcessorIndex_Arg_1_OutputChoice);
    if(*GetMaximumProcessorIndex_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetMaximumProcessorIndex_Arg_1), (VOID *)GetMaximumProcessorIndex_Arg_1);
    }
    Status = ProtocolVariable->GetMaximumProcessorIndex(
        ProtocolVariable,
        GetMaximumProcessorIndex_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RegisterPeriodicCallback.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterPeriodicCallback(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DEBUG_SUPPORT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDebugSupportProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN RegisterPeriodicCallback_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RegisterPeriodicCallback_Arg_1), (VOID *)&RegisterPeriodicCallback_Arg_1);
    
    Status = ProtocolVariable->RegisterPeriodicCallback(
        ProtocolVariable,
        RegisterPeriodicCallback_Arg_1,
        (EFI_PERIODIC_CALLBACK){0}
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RegisterExceptionCallback.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterExceptionCallback(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DEBUG_SUPPORT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDebugSupportProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN RegisterExceptionCallback_Arg_1 = 0;
    EFI_EXCEPTION_TYPE RegisterExceptionCallback_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RegisterExceptionCallback_Arg_1), (VOID *)&RegisterExceptionCallback_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RegisterExceptionCallback_Arg_3), (VOID *)&RegisterExceptionCallback_Arg_3);
    
    Status = ProtocolVariable->RegisterExceptionCallback(
        ProtocolVariable,
        RegisterExceptionCallback_Arg_1,
        (EFI_EXCEPTION_CALLBACK){0},
        RegisterExceptionCallback_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called InvalidateInstructionCache.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzInvalidateInstructionCache(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DEBUG_SUPPORT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDebugSupportProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN InvalidateInstructionCache_Arg_1 = 0;
    UINTN*  InvalidateInstructionCache_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT64 InvalidateInstructionCache_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(InvalidateInstructionCache_Arg_1), (VOID *)&InvalidateInstructionCache_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 InvalidateInstructionCache_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(InvalidateInstructionCache_Arg_2_choice), (VOID *)&InvalidateInstructionCache_Arg_2_choice);
    switch(InvalidateInstructionCache_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(InvalidateInstructionCache_Arg_2), (VOID *)InvalidateInstructionCache_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(InvalidateInstructionCache_Arg_2);
            InvalidateInstructionCache_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(InvalidateInstructionCache_Arg_3), (VOID *)&InvalidateInstructionCache_Arg_3);
    
    Status = ProtocolVariable->InvalidateInstructionCache(
        ProtocolVariable,
        InvalidateInstructionCache_Arg_1,
        (void *)InvalidateInstructionCache_Arg_2,
        InvalidateInstructionCache_Arg_3
    );
    return Status;
}

