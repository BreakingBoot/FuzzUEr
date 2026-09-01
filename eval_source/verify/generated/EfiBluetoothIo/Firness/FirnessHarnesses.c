#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called GetDeviceInfo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetDeviceInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINTN * GetDeviceInfo_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetDeviceInfo_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetDeviceInfo_Arg_1_OutputChoice), (VOID *)GetDeviceInfo_Arg_1_OutputChoice);
    if(*GetDeviceInfo_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetDeviceInfo_Arg_1), (VOID *)GetDeviceInfo_Arg_1);
    }
    UINTN* GetDeviceInfo_Arg_2 = (UINTN*)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetDeviceInfo_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetDeviceInfo_Arg_2_OutputChoice), (VOID *)GetDeviceInfo_Arg_2_OutputChoice);
    if(*GetDeviceInfo_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetDeviceInfo_Arg_2), (VOID *)GetDeviceInfo_Arg_2);
    }
    Status = ProtocolVariable->GetDeviceInfo(
        ProtocolVariable,
        GetDeviceInfo_Arg_1,
        (VOID * *)&GetDeviceInfo_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetSdpInfo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetSdpInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINTN * GetSdpInfo_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetSdpInfo_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetSdpInfo_Arg_1_OutputChoice), (VOID *)GetSdpInfo_Arg_1_OutputChoice);
    if(*GetSdpInfo_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetSdpInfo_Arg_1), (VOID *)GetSdpInfo_Arg_1);
    }
    UINTN* GetSdpInfo_Arg_2 = (UINTN*)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetSdpInfo_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetSdpInfo_Arg_2_OutputChoice), (VOID *)GetSdpInfo_Arg_2_OutputChoice);
    if(*GetSdpInfo_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetSdpInfo_Arg_2), (VOID *)GetSdpInfo_Arg_2);
    }
    Status = ProtocolVariable->GetSdpInfo(
        ProtocolVariable,
        GetSdpInfo_Arg_1,
        (VOID * *)&GetSdpInfo_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called L2CapRawSend.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzL2CapRawSend(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * L2CapRawSend_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN*  L2CapRawSend_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN L2CapRawSend_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    UINT8 L2CapRawSend_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(L2CapRawSend_Arg_1_choice), (VOID *)&L2CapRawSend_Arg_1_choice);
    switch(L2CapRawSend_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(L2CapRawSend_Arg_1), (VOID *)L2CapRawSend_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(L2CapRawSend_Arg_1);
            L2CapRawSend_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 L2CapRawSend_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(L2CapRawSend_Arg_2_choice), (VOID *)&L2CapRawSend_Arg_2_choice);
    switch(L2CapRawSend_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(L2CapRawSend_Arg_2), (VOID *)L2CapRawSend_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(L2CapRawSend_Arg_2);
            L2CapRawSend_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(L2CapRawSend_Arg_3), (VOID *)&L2CapRawSend_Arg_3);
    
    Status = ProtocolVariable->L2CapRawSend(
        ProtocolVariable,
        L2CapRawSend_Arg_1,
        (VOID *)L2CapRawSend_Arg_2,
        L2CapRawSend_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called L2CapRawReceive.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzL2CapRawReceive(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * L2CapRawReceive_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN L2CapRawReceive_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    UINT8 L2CapRawReceive_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(L2CapRawReceive_Arg_1_choice), (VOID *)&L2CapRawReceive_Arg_1_choice);
    switch(L2CapRawReceive_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(L2CapRawReceive_Arg_1), (VOID *)L2CapRawReceive_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(L2CapRawReceive_Arg_1);
            L2CapRawReceive_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(L2CapRawReceive_Arg_3), (VOID *)&L2CapRawReceive_Arg_3);
    
    /*
        Output Variable(s)
    */
    UINTN*  L2CapRawReceive_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT8* L2CapRawReceive_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(L2CapRawReceive_Arg_2_OutputChoice), (VOID *)L2CapRawReceive_Arg_2_OutputChoice);
    if(*L2CapRawReceive_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*L2CapRawReceive_Arg_2), (VOID *)L2CapRawReceive_Arg_2);
    }
    Status = ProtocolVariable->L2CapRawReceive(
        ProtocolVariable,
        L2CapRawReceive_Arg_1,
        (VOID *)L2CapRawReceive_Arg_2,
        L2CapRawReceive_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called L2CapRawAsyncReceive.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzL2CapRawAsyncReceive(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN L2CapRawAsyncReceive_Arg_1 = FALSE;
    UINTN L2CapRawAsyncReceive_Arg_2 = 0;
    UINTN L2CapRawAsyncReceive_Arg_3 = 0;
    UINTN*  L2CapRawAsyncReceive_Arg_5 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(L2CapRawAsyncReceive_Arg_1), (VOID *)&L2CapRawAsyncReceive_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(L2CapRawAsyncReceive_Arg_2), (VOID *)&L2CapRawAsyncReceive_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(L2CapRawAsyncReceive_Arg_3), (VOID *)&L2CapRawAsyncReceive_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 L2CapRawAsyncReceive_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(L2CapRawAsyncReceive_Arg_5_choice), (VOID *)&L2CapRawAsyncReceive_Arg_5_choice);
    switch(L2CapRawAsyncReceive_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(L2CapRawAsyncReceive_Arg_5), (VOID *)L2CapRawAsyncReceive_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(L2CapRawAsyncReceive_Arg_5);
            L2CapRawAsyncReceive_Arg_5 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->L2CapRawAsyncReceive(
        ProtocolVariable,
        L2CapRawAsyncReceive_Arg_1,
        L2CapRawAsyncReceive_Arg_2,
        L2CapRawAsyncReceive_Arg_3,
        (EFI_BLUETOOTH_IO_ASYNC_FUNC_CALLBACK){0},
        (VOID *)L2CapRawAsyncReceive_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called L2CapSend.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzL2CapSend(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * L2CapSend_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN*  L2CapSend_Arg_3 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN L2CapSend_Arg_4 = 0;
    
    // Fuzzable Variable Initialization
    UINT8 L2CapSend_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(L2CapSend_Arg_2_choice), (VOID *)&L2CapSend_Arg_2_choice);
    switch(L2CapSend_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(L2CapSend_Arg_2), (VOID *)L2CapSend_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(L2CapSend_Arg_2);
            L2CapSend_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 L2CapSend_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(L2CapSend_Arg_3_choice), (VOID *)&L2CapSend_Arg_3_choice);
    switch(L2CapSend_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(L2CapSend_Arg_3), (VOID *)L2CapSend_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(L2CapSend_Arg_3);
            L2CapSend_Arg_3 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(L2CapSend_Arg_4), (VOID *)&L2CapSend_Arg_4);
    
    Status = ProtocolVariable->L2CapSend(
        ProtocolVariable,
        ImageHandle,
        L2CapSend_Arg_2,
        (VOID *)L2CapSend_Arg_3,
        L2CapSend_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called L2CapReceive.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzL2CapReceive(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN L2CapReceive_Arg_4 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(L2CapReceive_Arg_4), (VOID *)&L2CapReceive_Arg_4);
    
    /*
        Output Variable(s)
    */
    UINTN * L2CapReceive_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* L2CapReceive_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(L2CapReceive_Arg_2_OutputChoice), (VOID *)L2CapReceive_Arg_2_OutputChoice);
    if(*L2CapReceive_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*L2CapReceive_Arg_2), (VOID *)L2CapReceive_Arg_2);
    }
    UINTN* L2CapReceive_Arg_3 = (UINTN*)AllocateZeroPool(sizeof(UINTN));
    UINT8* L2CapReceive_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(L2CapReceive_Arg_3_OutputChoice), (VOID *)L2CapReceive_Arg_3_OutputChoice);
    if(*L2CapReceive_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*L2CapReceive_Arg_3), (VOID *)L2CapReceive_Arg_3);
    }
    Status = ProtocolVariable->L2CapReceive(
        ProtocolVariable,
        ImageHandle,
        L2CapReceive_Arg_2,
        (VOID * *)&L2CapReceive_Arg_3,
        L2CapReceive_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called L2CapAsyncReceive.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzL2CapAsyncReceive(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  L2CapAsyncReceive_Arg_3 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    UINT8 L2CapAsyncReceive_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(L2CapAsyncReceive_Arg_3_choice), (VOID *)&L2CapAsyncReceive_Arg_3_choice);
    switch(L2CapAsyncReceive_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(L2CapAsyncReceive_Arg_3), (VOID *)L2CapAsyncReceive_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(L2CapAsyncReceive_Arg_3);
            L2CapAsyncReceive_Arg_3 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->L2CapAsyncReceive(
        ProtocolVariable,
        ImageHandle,
        (EFI_BLUETOOTH_IO_CHANNEL_SERVICE_CALLBACK){0},
        (VOID *)L2CapAsyncReceive_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called L2CapConnect.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzL2CapConnect(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT16 L2CapConnect_Arg_2 = 0;
    UINT16 L2CapConnect_Arg_3 = 0;
    UINTN*  L2CapConnect_Arg_5 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(L2CapConnect_Arg_2), (VOID *)&L2CapConnect_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(L2CapConnect_Arg_3), (VOID *)&L2CapConnect_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 L2CapConnect_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(L2CapConnect_Arg_5_choice), (VOID *)&L2CapConnect_Arg_5_choice);
    switch(L2CapConnect_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(L2CapConnect_Arg_5), (VOID *)L2CapConnect_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(L2CapConnect_Arg_5);
            L2CapConnect_Arg_5 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_HANDLE * L2CapConnect_Arg_1 = (EFI_HANDLE *)AllocateZeroPool(sizeof(EFI_HANDLE));
    UINT8* L2CapConnect_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(L2CapConnect_Arg_1_OutputChoice), (VOID *)L2CapConnect_Arg_1_OutputChoice);
    if(*L2CapConnect_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*L2CapConnect_Arg_1), (VOID *)L2CapConnect_Arg_1);
    }
    Status = ProtocolVariable->L2CapConnect(
        ProtocolVariable,
        L2CapConnect_Arg_1,
        L2CapConnect_Arg_2,
        L2CapConnect_Arg_3,
        (EFI_BLUETOOTH_IO_CHANNEL_SERVICE_CALLBACK){0},
        (VOID *)L2CapConnect_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called L2CapDisconnect.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzL2CapDisconnect(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->L2CapDisconnect(
        ProtocolVariable,
        ImageHandle
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called L2CapRegisterService.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzL2CapRegisterService(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT16 L2CapRegisterService_Arg_2 = 0;
    UINT16 L2CapRegisterService_Arg_3 = 0;
    UINTN*  L2CapRegisterService_Arg_5 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(L2CapRegisterService_Arg_2), (VOID *)&L2CapRegisterService_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(L2CapRegisterService_Arg_3), (VOID *)&L2CapRegisterService_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 L2CapRegisterService_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(L2CapRegisterService_Arg_5_choice), (VOID *)&L2CapRegisterService_Arg_5_choice);
    switch(L2CapRegisterService_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(L2CapRegisterService_Arg_5), (VOID *)L2CapRegisterService_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(L2CapRegisterService_Arg_5);
            L2CapRegisterService_Arg_5 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_HANDLE * L2CapRegisterService_Arg_1 = (EFI_HANDLE *)AllocateZeroPool(sizeof(EFI_HANDLE));
    UINT8* L2CapRegisterService_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(L2CapRegisterService_Arg_1_OutputChoice), (VOID *)L2CapRegisterService_Arg_1_OutputChoice);
    if(*L2CapRegisterService_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*L2CapRegisterService_Arg_1), (VOID *)L2CapRegisterService_Arg_1);
    }
    Status = ProtocolVariable->L2CapRegisterService(
        ProtocolVariable,
        L2CapRegisterService_Arg_1,
        L2CapRegisterService_Arg_2,
        L2CapRegisterService_Arg_3,
        (EFI_BLUETOOTH_IO_CHANNEL_SERVICE_CALLBACK){0},
        (VOID *)L2CapRegisterService_Arg_5
    );
    return Status;
}

