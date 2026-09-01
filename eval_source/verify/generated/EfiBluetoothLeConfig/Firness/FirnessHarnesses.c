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
    EFI_BLUETOOTH_LE_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothLeConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    EFI_BLUETOOTH_LE_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothLeConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN Scan_Arg_1 = FALSE;
    UINT32 Scan_Arg_2 = 0;
    UINTN*  Scan_Arg_5 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Scan_Arg_1), (VOID *)&Scan_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Scan_Arg_2), (VOID *)&Scan_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 Scan_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(Scan_Arg_5_choice), (VOID *)&Scan_Arg_5_choice);
    switch(Scan_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Scan_Arg_5), (VOID *)Scan_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(Scan_Arg_5);
            Scan_Arg_5 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->Scan(
        ProtocolVariable,
        Scan_Arg_1,
        Scan_Arg_2,
        NULL,
        (EFI_BLUETOOTH_LE_CONFIG_SCAN_CALLBACK_FUNCTION){0},
        (VOID *)Scan_Arg_5
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
    EFI_BLUETOOTH_LE_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothLeConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN Connect_Arg_1 = FALSE;
    BOOLEAN Connect_Arg_2 = FALSE;
    BLUETOOTH_LE_ADDRESS * Connect_Arg_4 = (BLUETOOTH_LE_ADDRESS *)AllocateZeroPool(sizeof(BLUETOOTH_LE_ADDRESS));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Connect_Arg_1), (VOID *)&Connect_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Connect_Arg_2), (VOID *)&Connect_Arg_2);
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(Connect_Arg_4->Address), (VOID *)&(Connect_Arg_4->Address));
    {
        UINT8 Firness_Type;
        ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
        Connect_Arg_4->Type = Firness_Type;
    }
    
    Status = ProtocolVariable->Connect(
        ProtocolVariable,
        Connect_Arg_1,
        Connect_Arg_2,
        NULL,
        Connect_Arg_4
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
    EFI_BLUETOOTH_LE_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothLeConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BLUETOOTH_LE_ADDRESS * Disconnect_Arg_1 = (BLUETOOTH_LE_ADDRESS *)AllocateZeroPool(sizeof(BLUETOOTH_LE_ADDRESS));
    UINT8 Disconnect_Arg_2 = 0;
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(Disconnect_Arg_1->Address), (VOID *)&(Disconnect_Arg_1->Address));
    {
        UINT8 Firness_Type;
        ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
        Disconnect_Arg_1->Type = Firness_Type;
    }
    
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
    EFI_BLUETOOTH_LE_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothLeConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * GetData_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
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
    
    Status = ProtocolVariable->GetData(
        ProtocolVariable,
        (EFI_BLUETOOTH_CONFIG_DATA_TYPE){0},
        GetData_Arg_2,
        NULL
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
    EFI_BLUETOOTH_LE_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothLeConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    EFI_BLUETOOTH_LE_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothLeConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BLUETOOTH_LE_ADDRESS * GetRemoteData_Arg_2 = (BLUETOOTH_LE_ADDRESS *)AllocateZeroPool(sizeof(BLUETOOTH_LE_ADDRESS));
    UINTN * GetRemoteData_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN*  GetRemoteData_Arg_4 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(GetRemoteData_Arg_2->Address), (VOID *)&(GetRemoteData_Arg_2->Address));
    {
        UINT8 Firness_Type;
        ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
        GetRemoteData_Arg_2->Type = Firness_Type;
    }
    
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
    called RegisterSmpAuthCallback.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterSmpAuthCallback(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_LE_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothLeConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  RegisterSmpAuthCallback_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    UINT8 RegisterSmpAuthCallback_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(RegisterSmpAuthCallback_Arg_2_choice), (VOID *)&RegisterSmpAuthCallback_Arg_2_choice);
    switch(RegisterSmpAuthCallback_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(RegisterSmpAuthCallback_Arg_2), (VOID *)RegisterSmpAuthCallback_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(RegisterSmpAuthCallback_Arg_2);
            RegisterSmpAuthCallback_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->RegisterSmpAuthCallback(
        ProtocolVariable,
        (EFI_BLUETOOTH_LE_SMP_CALLBACK){0},
        (VOID *)RegisterSmpAuthCallback_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SendSmpAuthData.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSendSmpAuthData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_LE_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothLeConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BLUETOOTH_LE_ADDRESS * SendSmpAuthData_Arg_1 = (BLUETOOTH_LE_ADDRESS *)AllocateZeroPool(sizeof(BLUETOOTH_LE_ADDRESS));
    UINTN SendSmpAuthData_Arg_3 = 0;
    UINTN*  SendSmpAuthData_Arg_4 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(SendSmpAuthData_Arg_1->Address), (VOID *)&(SendSmpAuthData_Arg_1->Address));
    {
        UINT8 Firness_Type;
        ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
        SendSmpAuthData_Arg_1->Type = Firness_Type;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SendSmpAuthData_Arg_3), (VOID *)&SendSmpAuthData_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 SendSmpAuthData_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(SendSmpAuthData_Arg_4_choice), (VOID *)&SendSmpAuthData_Arg_4_choice);
    switch(SendSmpAuthData_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SendSmpAuthData_Arg_4), (VOID *)SendSmpAuthData_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(SendSmpAuthData_Arg_4);
            SendSmpAuthData_Arg_4 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->SendSmpAuthData(
        ProtocolVariable,
        SendSmpAuthData_Arg_1,
        (EFI_BLUETOOTH_LE_SMP_EVENT_DATA_TYPE){0},
        SendSmpAuthData_Arg_3,
        (VOID *)SendSmpAuthData_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RegisterSmpGetDataCallback.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterSmpGetDataCallback(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_LE_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothLeConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  RegisterSmpGetDataCallback_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    UINT8 RegisterSmpGetDataCallback_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(RegisterSmpGetDataCallback_Arg_2_choice), (VOID *)&RegisterSmpGetDataCallback_Arg_2_choice);
    switch(RegisterSmpGetDataCallback_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(RegisterSmpGetDataCallback_Arg_2), (VOID *)RegisterSmpGetDataCallback_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(RegisterSmpGetDataCallback_Arg_2);
            RegisterSmpGetDataCallback_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->RegisterSmpGetDataCallback(
        ProtocolVariable,
        (EFI_BLUETOOTH_LE_CONFIG_SMP_GET_DATA_CALLBACK){0},
        (VOID *)RegisterSmpGetDataCallback_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RegisterSmpSetDataCallback.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterSmpSetDataCallback(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_LE_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothLeConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  RegisterSmpSetDataCallback_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    UINT8 RegisterSmpSetDataCallback_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(RegisterSmpSetDataCallback_Arg_2_choice), (VOID *)&RegisterSmpSetDataCallback_Arg_2_choice);
    switch(RegisterSmpSetDataCallback_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(RegisterSmpSetDataCallback_Arg_2), (VOID *)RegisterSmpSetDataCallback_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(RegisterSmpSetDataCallback_Arg_2);
            RegisterSmpSetDataCallback_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->RegisterSmpSetDataCallback(
        ProtocolVariable,
        (EFI_BLUETOOTH_LE_CONFIG_SMP_SET_DATA_CALLBACK){0},
        (VOID *)RegisterSmpSetDataCallback_Arg_2
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
    EFI_BLUETOOTH_LE_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothLeConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
        (EFI_BLUETOOTH_LE_CONFIG_CONNECT_COMPLETE_CALLBACK){0},
        (VOID *)RegisterLinkConnectCompleteCallback_Arg_2
    );
    return Status;
}

