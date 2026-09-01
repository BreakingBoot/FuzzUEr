#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called SendCommand.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSendCommand(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * SendCommand_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN*  SendCommand_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN SendCommand_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    UINT8 SendCommand_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(SendCommand_Arg_1_choice), (VOID *)&SendCommand_Arg_1_choice);
    switch(SendCommand_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SendCommand_Arg_1), (VOID *)SendCommand_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(SendCommand_Arg_1);
            SendCommand_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 SendCommand_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(SendCommand_Arg_2_choice), (VOID *)&SendCommand_Arg_2_choice);
    switch(SendCommand_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SendCommand_Arg_2), (VOID *)SendCommand_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(SendCommand_Arg_2);
            SendCommand_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SendCommand_Arg_3), (VOID *)&SendCommand_Arg_3);
    
    Status = ProtocolVariable->SendCommand(
        ProtocolVariable,
        SendCommand_Arg_1,
        (VOID *)SendCommand_Arg_2,
        SendCommand_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ReceiveEvent.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzReceiveEvent(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * ReceiveEvent_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN ReceiveEvent_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    UINT8 ReceiveEvent_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(ReceiveEvent_Arg_1_choice), (VOID *)&ReceiveEvent_Arg_1_choice);
    switch(ReceiveEvent_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(ReceiveEvent_Arg_1), (VOID *)ReceiveEvent_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(ReceiveEvent_Arg_1);
            ReceiveEvent_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ReceiveEvent_Arg_3), (VOID *)&ReceiveEvent_Arg_3);
    
    /*
        Output Variable(s)
    */
    UINTN*  ReceiveEvent_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT8* ReceiveEvent_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ReceiveEvent_Arg_2_OutputChoice), (VOID *)ReceiveEvent_Arg_2_OutputChoice);
    if(*ReceiveEvent_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ReceiveEvent_Arg_2), (VOID *)ReceiveEvent_Arg_2);
    }
    Status = ProtocolVariable->ReceiveEvent(
        ProtocolVariable,
        ReceiveEvent_Arg_1,
        (VOID *)ReceiveEvent_Arg_2,
        ReceiveEvent_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called AsyncReceiveEvent.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAsyncReceiveEvent(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN AsyncReceiveEvent_Arg_1 = FALSE;
    UINTN AsyncReceiveEvent_Arg_2 = 0;
    UINTN AsyncReceiveEvent_Arg_3 = 0;
    UINTN*  AsyncReceiveEvent_Arg_5 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AsyncReceiveEvent_Arg_1), (VOID *)&AsyncReceiveEvent_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AsyncReceiveEvent_Arg_2), (VOID *)&AsyncReceiveEvent_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AsyncReceiveEvent_Arg_3), (VOID *)&AsyncReceiveEvent_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 AsyncReceiveEvent_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(AsyncReceiveEvent_Arg_5_choice), (VOID *)&AsyncReceiveEvent_Arg_5_choice);
    switch(AsyncReceiveEvent_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(AsyncReceiveEvent_Arg_5), (VOID *)AsyncReceiveEvent_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(AsyncReceiveEvent_Arg_5);
            AsyncReceiveEvent_Arg_5 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->AsyncReceiveEvent(
        ProtocolVariable,
        AsyncReceiveEvent_Arg_1,
        AsyncReceiveEvent_Arg_2,
        AsyncReceiveEvent_Arg_3,
        (EFI_BLUETOOTH_HC_ASYNC_FUNC_CALLBACK){0},
        (VOID *)AsyncReceiveEvent_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SendACLData.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSendACLData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * SendACLData_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN*  SendACLData_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN SendACLData_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    UINT8 SendACLData_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(SendACLData_Arg_1_choice), (VOID *)&SendACLData_Arg_1_choice);
    switch(SendACLData_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SendACLData_Arg_1), (VOID *)SendACLData_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(SendACLData_Arg_1);
            SendACLData_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 SendACLData_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(SendACLData_Arg_2_choice), (VOID *)&SendACLData_Arg_2_choice);
    switch(SendACLData_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SendACLData_Arg_2), (VOID *)SendACLData_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(SendACLData_Arg_2);
            SendACLData_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SendACLData_Arg_3), (VOID *)&SendACLData_Arg_3);
    
    Status = ProtocolVariable->SendACLData(
        ProtocolVariable,
        SendACLData_Arg_1,
        (VOID *)SendACLData_Arg_2,
        SendACLData_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ReceiveACLData.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzReceiveACLData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * ReceiveACLData_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN ReceiveACLData_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    UINT8 ReceiveACLData_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(ReceiveACLData_Arg_1_choice), (VOID *)&ReceiveACLData_Arg_1_choice);
    switch(ReceiveACLData_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(ReceiveACLData_Arg_1), (VOID *)ReceiveACLData_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(ReceiveACLData_Arg_1);
            ReceiveACLData_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ReceiveACLData_Arg_3), (VOID *)&ReceiveACLData_Arg_3);
    
    /*
        Output Variable(s)
    */
    UINTN*  ReceiveACLData_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT8* ReceiveACLData_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ReceiveACLData_Arg_2_OutputChoice), (VOID *)ReceiveACLData_Arg_2_OutputChoice);
    if(*ReceiveACLData_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ReceiveACLData_Arg_2), (VOID *)ReceiveACLData_Arg_2);
    }
    Status = ProtocolVariable->ReceiveACLData(
        ProtocolVariable,
        ReceiveACLData_Arg_1,
        (VOID *)ReceiveACLData_Arg_2,
        ReceiveACLData_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called AsyncReceiveACLData.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAsyncReceiveACLData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN AsyncReceiveACLData_Arg_1 = FALSE;
    UINTN AsyncReceiveACLData_Arg_2 = 0;
    UINTN AsyncReceiveACLData_Arg_3 = 0;
    UINTN*  AsyncReceiveACLData_Arg_5 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AsyncReceiveACLData_Arg_1), (VOID *)&AsyncReceiveACLData_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AsyncReceiveACLData_Arg_2), (VOID *)&AsyncReceiveACLData_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AsyncReceiveACLData_Arg_3), (VOID *)&AsyncReceiveACLData_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 AsyncReceiveACLData_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(AsyncReceiveACLData_Arg_5_choice), (VOID *)&AsyncReceiveACLData_Arg_5_choice);
    switch(AsyncReceiveACLData_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(AsyncReceiveACLData_Arg_5), (VOID *)AsyncReceiveACLData_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(AsyncReceiveACLData_Arg_5);
            AsyncReceiveACLData_Arg_5 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->AsyncReceiveACLData(
        ProtocolVariable,
        AsyncReceiveACLData_Arg_1,
        AsyncReceiveACLData_Arg_2,
        AsyncReceiveACLData_Arg_3,
        (EFI_BLUETOOTH_HC_ASYNC_FUNC_CALLBACK){0},
        (VOID *)AsyncReceiveACLData_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SendSCOData.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSendSCOData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * SendSCOData_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN*  SendSCOData_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN SendSCOData_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    UINT8 SendSCOData_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(SendSCOData_Arg_1_choice), (VOID *)&SendSCOData_Arg_1_choice);
    switch(SendSCOData_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SendSCOData_Arg_1), (VOID *)SendSCOData_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(SendSCOData_Arg_1);
            SendSCOData_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 SendSCOData_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(SendSCOData_Arg_2_choice), (VOID *)&SendSCOData_Arg_2_choice);
    switch(SendSCOData_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SendSCOData_Arg_2), (VOID *)SendSCOData_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(SendSCOData_Arg_2);
            SendSCOData_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SendSCOData_Arg_3), (VOID *)&SendSCOData_Arg_3);
    
    Status = ProtocolVariable->SendSCOData(
        ProtocolVariable,
        SendSCOData_Arg_1,
        (VOID *)SendSCOData_Arg_2,
        SendSCOData_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ReceiveSCOData.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzReceiveSCOData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * ReceiveSCOData_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN ReceiveSCOData_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    UINT8 ReceiveSCOData_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(ReceiveSCOData_Arg_1_choice), (VOID *)&ReceiveSCOData_Arg_1_choice);
    switch(ReceiveSCOData_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(ReceiveSCOData_Arg_1), (VOID *)ReceiveSCOData_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(ReceiveSCOData_Arg_1);
            ReceiveSCOData_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ReceiveSCOData_Arg_3), (VOID *)&ReceiveSCOData_Arg_3);
    
    /*
        Output Variable(s)
    */
    UINTN*  ReceiveSCOData_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT8* ReceiveSCOData_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ReceiveSCOData_Arg_2_OutputChoice), (VOID *)ReceiveSCOData_Arg_2_OutputChoice);
    if(*ReceiveSCOData_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ReceiveSCOData_Arg_2), (VOID *)ReceiveSCOData_Arg_2);
    }
    Status = ProtocolVariable->ReceiveSCOData(
        ProtocolVariable,
        ReceiveSCOData_Arg_1,
        (VOID *)ReceiveSCOData_Arg_2,
        ReceiveSCOData_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called AsyncReceiveSCOData.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAsyncReceiveSCOData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN AsyncReceiveSCOData_Arg_1 = FALSE;
    UINTN AsyncReceiveSCOData_Arg_2 = 0;
    UINTN AsyncReceiveSCOData_Arg_3 = 0;
    UINTN*  AsyncReceiveSCOData_Arg_5 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AsyncReceiveSCOData_Arg_1), (VOID *)&AsyncReceiveSCOData_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AsyncReceiveSCOData_Arg_2), (VOID *)&AsyncReceiveSCOData_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AsyncReceiveSCOData_Arg_3), (VOID *)&AsyncReceiveSCOData_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 AsyncReceiveSCOData_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(AsyncReceiveSCOData_Arg_5_choice), (VOID *)&AsyncReceiveSCOData_Arg_5_choice);
    switch(AsyncReceiveSCOData_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(AsyncReceiveSCOData_Arg_5), (VOID *)AsyncReceiveSCOData_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(AsyncReceiveSCOData_Arg_5);
            AsyncReceiveSCOData_Arg_5 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->AsyncReceiveSCOData(
        ProtocolVariable,
        AsyncReceiveSCOData_Arg_1,
        AsyncReceiveSCOData_Arg_2,
        AsyncReceiveSCOData_Arg_3,
        (EFI_BLUETOOTH_HC_ASYNC_FUNC_CALLBACK){0},
        (VOID *)AsyncReceiveSCOData_Arg_5
    );
    return Status;
}

