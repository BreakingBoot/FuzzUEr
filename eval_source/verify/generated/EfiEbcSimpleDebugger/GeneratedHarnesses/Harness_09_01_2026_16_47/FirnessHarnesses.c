#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called Debugger.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDebugger(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_EBC_SIMPLE_DEBUGGER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiEbcSimpleDebuggerProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    ProtocolVariable->Debugger(
        ProtocolVariable,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SignalException.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSignalException(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_EBC_SIMPLE_DEBUGGER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiEbcSimpleDebuggerProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_EXCEPTION_TYPE SignalException_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SignalException_Arg_2), (VOID *)&SignalException_Arg_2);
    
    Status = ProtocolVariable->SignalException(
        ProtocolVariable,
        NULL,
        SignalException_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Dasm.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDasm(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_EBC_SIMPLE_DEBUGGER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiEbcSimpleDebuggerProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 Dasm_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Dasm_Arg_3), (VOID *)&Dasm_Arg_3);
    
    ProtocolVariable->Dasm(
        ProtocolVariable,
        NULL,
        NULL,
        Dasm_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Configure.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzConfigure(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_EBC_SIMPLE_DEBUGGER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiEbcSimpleDebuggerProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 Configure_Arg_1 = 0;
    UINTN Configure_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Configure_Arg_1), (VOID *)&Configure_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Configure_Arg_2), (VOID *)&Configure_Arg_2);
    
    Status = ProtocolVariable->Configure(
        ProtocolVariable,
        Configure_Arg_1,
        Configure_Arg_2
    );
    return Status;
}

