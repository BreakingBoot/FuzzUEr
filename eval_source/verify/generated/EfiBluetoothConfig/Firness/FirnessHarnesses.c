#include "FirnessHarnesses.h"

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
    EFI_BLUETOOTH_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Init(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Scan.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzScan(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN Scan_Arg_1 = FALSE;
    UINT8 Scan_Arg_2 = 0;
    UINTN*  Scan_Arg_4 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Scan_Arg_1), (VOID *)&Scan_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Scan_Arg_2), (VOID *)&Scan_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 Scan_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(Scan_Arg_4_choice), (VOID *)&Scan_Arg_4_choice);
    switch(Scan_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Scan_Arg_4), (VOID *)Scan_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(Scan_Arg_4);
            Scan_Arg_4 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->Scan(
        ProtocolVariable,
        Scan_Arg_1,
        Scan_Arg_2,
        (EFI_BLUETOOTH_CONFIG_SCAN_CALLBACK_FUNCTION){0},
        (VOID *)Scan_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Connect.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzConnect(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BLUETOOTH_ADDRESS * Connect_Arg_1 = (BLUETOOTH_ADDRESS *)AllocateZeroPool(sizeof(BLUETOOTH_ADDRESS));
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(Connect_Arg_1->Address), (VOID *)&(Connect_Arg_1->Address));
    
    Status = ProtocolVariable->Connect(
        ProtocolVariable,
        Connect_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Disconnect.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDisconnect(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BLUETOOTH_ADDRESS * Disconnect_Arg_1 = (BLUETOOTH_ADDRESS *)AllocateZeroPool(sizeof(BLUETOOTH_ADDRESS));
    UINT8 Disconnect_Arg_2 = 0;
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(Disconnect_Arg_1->Address), (VOID *)&(Disconnect_Arg_1->Address));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Disconnect_Arg_2), (VOID *)&Disconnect_Arg_2);
    
    Status = ProtocolVariable->Disconnect(
        ProtocolVariable,
        Disconnect_Arg_1,
        Disconnect_Arg_2
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
    EFI_BLUETOOTH_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * GetData_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN*  GetData_Arg_3 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    UINT8 GetData_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetData_Arg_2_choice), (VOID *)&GetData_Arg_2_choice);
    switch(GetData_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetData_Arg_2), (VOID *)GetData_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(GetData_Arg_2);
            GetData_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetData_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(GetData_Arg_3_choice), (VOID *)&GetData_Arg_3_choice);
    switch(GetData_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetData_Arg_3), (VOID *)GetData_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(GetData_Arg_3);
            GetData_Arg_3 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetData(
        ProtocolVariable,
        (EFI_BLUETOOTH_CONFIG_DATA_TYPE){0},
        GetData_Arg_2,
        (VOID *)GetData_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetData.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN SetData_Arg_2 = 0;
    UINTN*  SetData_Arg_3 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetData_Arg_2), (VOID *)&SetData_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 SetData_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(SetData_Arg_3_choice), (VOID *)&SetData_Arg_3_choice);
    switch(SetData_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetData_Arg_3), (VOID *)SetData_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(SetData_Arg_3);
            SetData_Arg_3 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->SetData(
        ProtocolVariable,
        (EFI_BLUETOOTH_CONFIG_DATA_TYPE){0},
        SetData_Arg_2,
        (VOID *)SetData_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetRemoteData.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetRemoteData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BLUETOOTH_ADDRESS * GetRemoteData_Arg_2 = (BLUETOOTH_ADDRESS *)AllocateZeroPool(sizeof(BLUETOOTH_ADDRESS));
    UINTN * GetRemoteData_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN*  GetRemoteData_Arg_4 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(GetRemoteData_Arg_2->Address), (VOID *)&(GetRemoteData_Arg_2->Address));
    
    // Fuzzable Variable Initialization
    UINT8 GetRemoteData_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(GetRemoteData_Arg_3_choice), (VOID *)&GetRemoteData_Arg_3_choice);
    switch(GetRemoteData_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetRemoteData_Arg_3), (VOID *)GetRemoteData_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(GetRemoteData_Arg_3);
            GetRemoteData_Arg_3 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetRemoteData_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(GetRemoteData_Arg_4_choice), (VOID *)&GetRemoteData_Arg_4_choice);
    switch(GetRemoteData_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetRemoteData_Arg_4), (VOID *)GetRemoteData_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(GetRemoteData_Arg_4);
            GetRemoteData_Arg_4 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetRemoteData(
        ProtocolVariable,
        (EFI_BLUETOOTH_CONFIG_DATA_TYPE){0},
        GetRemoteData_Arg_2,
        GetRemoteData_Arg_3,
        (VOID *)GetRemoteData_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RegisterPinCallback.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterPinCallback(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  RegisterPinCallback_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    UINT8 RegisterPinCallback_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(RegisterPinCallback_Arg_2_choice), (VOID *)&RegisterPinCallback_Arg_2_choice);
    switch(RegisterPinCallback_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(RegisterPinCallback_Arg_2), (VOID *)RegisterPinCallback_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(RegisterPinCallback_Arg_2);
            RegisterPinCallback_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->RegisterPinCallback(
        ProtocolVariable,
        (EFI_BLUETOOTH_CONFIG_REGISTER_PIN_CALLBACK_FUNCTION){0},
        (VOID *)RegisterPinCallback_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RegisterGetLinkKeyCallback.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterGetLinkKeyCallback(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  RegisterGetLinkKeyCallback_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    UINT8 RegisterGetLinkKeyCallback_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(RegisterGetLinkKeyCallback_Arg_2_choice), (VOID *)&RegisterGetLinkKeyCallback_Arg_2_choice);
    switch(RegisterGetLinkKeyCallback_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(RegisterGetLinkKeyCallback_Arg_2), (VOID *)RegisterGetLinkKeyCallback_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(RegisterGetLinkKeyCallback_Arg_2);
            RegisterGetLinkKeyCallback_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->RegisterGetLinkKeyCallback(
        ProtocolVariable,
        (EFI_BLUETOOTH_CONFIG_REGISTER_GET_LINK_KEY_CALLBACK_FUNCTION){0},
        (VOID *)RegisterGetLinkKeyCallback_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RegisterSetLinkKeyCallback.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterSetLinkKeyCallback(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  RegisterSetLinkKeyCallback_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    UINT8 RegisterSetLinkKeyCallback_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(RegisterSetLinkKeyCallback_Arg_2_choice), (VOID *)&RegisterSetLinkKeyCallback_Arg_2_choice);
    switch(RegisterSetLinkKeyCallback_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(RegisterSetLinkKeyCallback_Arg_2), (VOID *)RegisterSetLinkKeyCallback_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(RegisterSetLinkKeyCallback_Arg_2);
            RegisterSetLinkKeyCallback_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->RegisterSetLinkKeyCallback(
        ProtocolVariable,
        (EFI_BLUETOOTH_CONFIG_REGISTER_SET_LINK_KEY_CALLBACK_FUNCTION){0},
        (VOID *)RegisterSetLinkKeyCallback_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RegisterLinkConnectCompleteCallback.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterLinkConnectCompleteCallback(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  RegisterLinkConnectCompleteCallback_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    UINT8 RegisterLinkConnectCompleteCallback_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(RegisterLinkConnectCompleteCallback_Arg_2_choice), (VOID *)&RegisterLinkConnectCompleteCallback_Arg_2_choice);
    switch(RegisterLinkConnectCompleteCallback_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(RegisterLinkConnectCompleteCallback_Arg_2), (VOID *)RegisterLinkConnectCompleteCallback_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(RegisterLinkConnectCompleteCallback_Arg_2);
            RegisterLinkConnectCompleteCallback_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->RegisterLinkConnectCompleteCallback(
        ProtocolVariable,
        (EFI_BLUETOOTH_CONFIG_REGISTER_CONNECT_COMPLETE_CALLBACK_FUNCTION){0},
        (VOID *)RegisterLinkConnectCompleteCallback_Arg_2
    );
    return Status;
}

