#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called SendRequest.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSendRequest(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_ATTRIBUTE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothAttributeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  SendRequest_Arg_1 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN SendRequest_Arg_2 = 0;
    UINTN*  SendRequest_Arg_4 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    UINT8 SendRequest_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(SendRequest_Arg_1_choice), (VOID *)&SendRequest_Arg_1_choice);
    switch(SendRequest_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SendRequest_Arg_1), (VOID *)SendRequest_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(SendRequest_Arg_1);
            SendRequest_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SendRequest_Arg_2), (VOID *)&SendRequest_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 SendRequest_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(SendRequest_Arg_4_choice), (VOID *)&SendRequest_Arg_4_choice);
    switch(SendRequest_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SendRequest_Arg_4), (VOID *)SendRequest_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(SendRequest_Arg_4);
            SendRequest_Arg_4 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->SendRequest(
        ProtocolVariable,
        (VOID *)SendRequest_Arg_1,
        SendRequest_Arg_2,
        (EFI_BLUETOOTH_ATTRIBUTE_CALLBACK_FUNCTION){0},
        (VOID *)SendRequest_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RegisterForServerNotification.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterForServerNotification(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_ATTRIBUTE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothAttributeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  RegisterForServerNotification_Arg_3 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    UINT8 RegisterForServerNotification_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(RegisterForServerNotification_Arg_3_choice), (VOID *)&RegisterForServerNotification_Arg_3_choice);
    switch(RegisterForServerNotification_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(RegisterForServerNotification_Arg_3), (VOID *)RegisterForServerNotification_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(RegisterForServerNotification_Arg_3);
            RegisterForServerNotification_Arg_3 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->RegisterForServerNotification(
        ProtocolVariable,
        NULL,
        (EFI_BLUETOOTH_ATTRIBUTE_CALLBACK_FUNCTION){0},
        (VOID *)RegisterForServerNotification_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetServiceInfo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetServiceInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLUETOOTH_ATTRIBUTE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothAttributeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINTN * GetServiceInfo_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetServiceInfo_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetServiceInfo_Arg_1_OutputChoice), (VOID *)GetServiceInfo_Arg_1_OutputChoice);
    if(*GetServiceInfo_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetServiceInfo_Arg_1), (VOID *)GetServiceInfo_Arg_1);
    }
    UINTN* GetServiceInfo_Arg_2 = (UINTN*)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetServiceInfo_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetServiceInfo_Arg_2_OutputChoice), (VOID *)GetServiceInfo_Arg_2_OutputChoice);
    if(*GetServiceInfo_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetServiceInfo_Arg_2), (VOID *)GetServiceInfo_Arg_2);
    }
    Status = ProtocolVariable->GetServiceInfo(
        ProtocolVariable,
        GetServiceInfo_Arg_1,
        (VOID * *)&GetServiceInfo_Arg_2
    );
    return Status;
}

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
    EFI_BLUETOOTH_ATTRIBUTE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBluetoothAttributeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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

