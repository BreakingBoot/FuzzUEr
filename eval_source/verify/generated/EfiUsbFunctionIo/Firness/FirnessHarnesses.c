#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called DetectPort.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDetectPort(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USBFN_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbFunctionIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_USBFN_PORT_TYPE * DetectPort_Arg_1 = (EFI_USBFN_PORT_TYPE *)AllocateZeroPool(sizeof(EFI_USBFN_PORT_TYPE));
    UINT8* DetectPort_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(DetectPort_Arg_1_OutputChoice), (VOID *)DetectPort_Arg_1_OutputChoice);
    if(*DetectPort_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*DetectPort_Arg_1), (VOID *)DetectPort_Arg_1);
    }
    Status = ProtocolVariable->DetectPort(
        ProtocolVariable,
        DetectPort_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ConfigureEnableEndpoints.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzConfigureEnableEndpoints(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USBFN_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbFunctionIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_USB_DEVICE_INFO * ConfigureEnableEndpoints_Arg_1 = (EFI_USB_DEVICE_INFO *)AllocateZeroPool(sizeof(EFI_USB_DEVICE_INFO));
    UINT8* ConfigureEnableEndpoints_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ConfigureEnableEndpoints_Arg_1_OutputChoice), (VOID *)ConfigureEnableEndpoints_Arg_1_OutputChoice);
    if(*ConfigureEnableEndpoints_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ConfigureEnableEndpoints_Arg_1), (VOID *)ConfigureEnableEndpoints_Arg_1);
    }
    Status = ProtocolVariable->ConfigureEnableEndpoints(
        ProtocolVariable,
        ConfigureEnableEndpoints_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetEndpointMaxPacketSize.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetEndpointMaxPacketSize(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USBFN_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbFunctionIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_USB_ENDPOINT_TYPE GetEndpointMaxPacketSize_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetEndpointMaxPacketSize_Arg_1), (VOID *)&GetEndpointMaxPacketSize_Arg_1);
    
    /*
        Output Variable(s)
    */
    UINT16 * GetEndpointMaxPacketSize_Arg_3 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    UINT8* GetEndpointMaxPacketSize_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetEndpointMaxPacketSize_Arg_3_OutputChoice), (VOID *)GetEndpointMaxPacketSize_Arg_3_OutputChoice);
    if(*GetEndpointMaxPacketSize_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetEndpointMaxPacketSize_Arg_3), (VOID *)GetEndpointMaxPacketSize_Arg_3);
    }
    Status = ProtocolVariable->GetEndpointMaxPacketSize(
        ProtocolVariable,
        GetEndpointMaxPacketSize_Arg_1,
        (EFI_USB_BUS_SPEED){0},
        GetEndpointMaxPacketSize_Arg_3
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
    EFI_USBFN_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbFunctionIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * GetDeviceInfo_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    UINT8 GetDeviceInfo_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetDeviceInfo_Arg_2_choice), (VOID *)&GetDeviceInfo_Arg_2_choice);
    switch(GetDeviceInfo_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetDeviceInfo_Arg_2), (VOID *)GetDeviceInfo_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(GetDeviceInfo_Arg_2);
            GetDeviceInfo_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetDeviceInfo(
        ProtocolVariable,
        (EFI_USBFN_DEVICE_INFO_ID){0},
        GetDeviceInfo_Arg_2,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetVendorIdProductId.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetVendorIdProductId(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USBFN_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbFunctionIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINT16 * GetVendorIdProductId_Arg_1 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    UINT8* GetVendorIdProductId_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetVendorIdProductId_Arg_1_OutputChoice), (VOID *)GetVendorIdProductId_Arg_1_OutputChoice);
    if(*GetVendorIdProductId_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetVendorIdProductId_Arg_1), (VOID *)GetVendorIdProductId_Arg_1);
    }
    UINT16 * GetVendorIdProductId_Arg_2 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    UINT8* GetVendorIdProductId_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetVendorIdProductId_Arg_2_OutputChoice), (VOID *)GetVendorIdProductId_Arg_2_OutputChoice);
    if(*GetVendorIdProductId_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetVendorIdProductId_Arg_2), (VOID *)GetVendorIdProductId_Arg_2);
    }
    Status = ProtocolVariable->GetVendorIdProductId(
        ProtocolVariable,
        GetVendorIdProductId_Arg_1,
        GetVendorIdProductId_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called AbortTransfer.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAbortTransfer(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USBFN_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbFunctionIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 AbortTransfer_Arg_1 = 0;
    EFI_USBFN_ENDPOINT_DIRECTION AbortTransfer_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AbortTransfer_Arg_1), (VOID *)&AbortTransfer_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AbortTransfer_Arg_2), (VOID *)&AbortTransfer_Arg_2);
    
    Status = ProtocolVariable->AbortTransfer(
        ProtocolVariable,
        AbortTransfer_Arg_1,
        AbortTransfer_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetEndpointStallState.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetEndpointStallState(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USBFN_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbFunctionIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 GetEndpointStallState_Arg_1 = 0;
    EFI_USBFN_ENDPOINT_DIRECTION GetEndpointStallState_Arg_2 = 0;
    BOOLEAN * GetEndpointStallState_Arg_3 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetEndpointStallState_Arg_1), (VOID *)&GetEndpointStallState_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetEndpointStallState_Arg_2), (VOID *)&GetEndpointStallState_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 GetEndpointStallState_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(GetEndpointStallState_Arg_3_choice), (VOID *)&GetEndpointStallState_Arg_3_choice);
    switch(GetEndpointStallState_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetEndpointStallState_Arg_3), (VOID *)GetEndpointStallState_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(GetEndpointStallState_Arg_3);
            GetEndpointStallState_Arg_3 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetEndpointStallState(
        ProtocolVariable,
        GetEndpointStallState_Arg_1,
        GetEndpointStallState_Arg_2,
        GetEndpointStallState_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetEndpointStallState.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetEndpointStallState(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USBFN_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbFunctionIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 SetEndpointStallState_Arg_1 = 0;
    EFI_USBFN_ENDPOINT_DIRECTION SetEndpointStallState_Arg_2 = 0;
    BOOLEAN * SetEndpointStallState_Arg_3 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetEndpointStallState_Arg_1), (VOID *)&SetEndpointStallState_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetEndpointStallState_Arg_2), (VOID *)&SetEndpointStallState_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 SetEndpointStallState_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(SetEndpointStallState_Arg_3_choice), (VOID *)&SetEndpointStallState_Arg_3_choice);
    switch(SetEndpointStallState_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetEndpointStallState_Arg_3), (VOID *)SetEndpointStallState_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(SetEndpointStallState_Arg_3);
            SetEndpointStallState_Arg_3 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->SetEndpointStallState(
        ProtocolVariable,
        SetEndpointStallState_Arg_1,
        SetEndpointStallState_Arg_2,
        SetEndpointStallState_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called EventHandler.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzEventHandler(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USBFN_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbFunctionIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * EventHandler_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    UINT8 EventHandler_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(EventHandler_Arg_2_choice), (VOID *)&EventHandler_Arg_2_choice);
    switch(EventHandler_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(EventHandler_Arg_2), (VOID *)EventHandler_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(EventHandler_Arg_2);
            EventHandler_Arg_2 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_USBFN_MESSAGE * EventHandler_Arg_1 = (EFI_USBFN_MESSAGE *)AllocateZeroPool(sizeof(EFI_USBFN_MESSAGE));
    UINT8* EventHandler_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(EventHandler_Arg_1_OutputChoice), (VOID *)EventHandler_Arg_1_OutputChoice);
    if(*EventHandler_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*EventHandler_Arg_1), (VOID *)EventHandler_Arg_1);
    }
    EFI_USBFN_MESSAGE_PAYLOAD * EventHandler_Arg_3 = (EFI_USBFN_MESSAGE_PAYLOAD *)AllocateZeroPool(sizeof(EFI_USBFN_MESSAGE_PAYLOAD));
    UINT8* EventHandler_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(EventHandler_Arg_3_OutputChoice), (VOID *)EventHandler_Arg_3_OutputChoice);
    if(*EventHandler_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*EventHandler_Arg_3), (VOID *)EventHandler_Arg_3);
    }
    Status = ProtocolVariable->EventHandler(
        ProtocolVariable,
        EventHandler_Arg_1,
        EventHandler_Arg_2,
        EventHandler_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Transfer.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzTransfer(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USBFN_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbFunctionIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 Transfer_Arg_1 = 0;
    EFI_USBFN_ENDPOINT_DIRECTION Transfer_Arg_2 = 0;
    UINTN * Transfer_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN*  Transfer_Arg_4 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Transfer_Arg_1), (VOID *)&Transfer_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Transfer_Arg_2), (VOID *)&Transfer_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 Transfer_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(Transfer_Arg_3_choice), (VOID *)&Transfer_Arg_3_choice);
    switch(Transfer_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Transfer_Arg_3), (VOID *)Transfer_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(Transfer_Arg_3);
            Transfer_Arg_3 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 Transfer_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(Transfer_Arg_4_choice), (VOID *)&Transfer_Arg_4_choice);
    switch(Transfer_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Transfer_Arg_4), (VOID *)Transfer_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(Transfer_Arg_4);
            Transfer_Arg_4 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->Transfer(
        ProtocolVariable,
        Transfer_Arg_1,
        Transfer_Arg_2,
        Transfer_Arg_3,
        (VOID *)Transfer_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetMaxTransferSize.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetMaxTransferSize(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USBFN_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbFunctionIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINTN * GetMaxTransferSize_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetMaxTransferSize_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetMaxTransferSize_Arg_1_OutputChoice), (VOID *)GetMaxTransferSize_Arg_1_OutputChoice);
    if(*GetMaxTransferSize_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetMaxTransferSize_Arg_1), (VOID *)GetMaxTransferSize_Arg_1);
    }
    Status = ProtocolVariable->GetMaxTransferSize(
        ProtocolVariable,
        GetMaxTransferSize_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called AllocateTransferBuffer.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAllocateTransferBuffer(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USBFN_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbFunctionIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN AllocateTransferBuffer_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AllocateTransferBuffer_Arg_1), (VOID *)&AllocateTransferBuffer_Arg_1);
    
    /*
        Output Variable(s)
    */
    UINTN* AllocateTransferBuffer_Arg_2 = (UINTN*)AllocateZeroPool(sizeof(UINTN));
    UINT8* AllocateTransferBuffer_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(AllocateTransferBuffer_Arg_2_OutputChoice), (VOID *)AllocateTransferBuffer_Arg_2_OutputChoice);
    if(*AllocateTransferBuffer_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*AllocateTransferBuffer_Arg_2), (VOID *)AllocateTransferBuffer_Arg_2);
    }
    Status = ProtocolVariable->AllocateTransferBuffer(
        ProtocolVariable,
        AllocateTransferBuffer_Arg_1,
        (VOID * *)&AllocateTransferBuffer_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called FreeTransferBuffer.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFreeTransferBuffer(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USBFN_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbFunctionIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  FreeTransferBuffer_Arg_1 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    UINT8 FreeTransferBuffer_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(FreeTransferBuffer_Arg_1_choice), (VOID *)&FreeTransferBuffer_Arg_1_choice);
    switch(FreeTransferBuffer_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(FreeTransferBuffer_Arg_1), (VOID *)FreeTransferBuffer_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(FreeTransferBuffer_Arg_1);
            FreeTransferBuffer_Arg_1 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->FreeTransferBuffer(
        ProtocolVariable,
        (VOID *)FreeTransferBuffer_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called StartController.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStartController(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USBFN_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbFunctionIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->StartController(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called StopController.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStopController(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USBFN_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbFunctionIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->StopController(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetEndpointPolicy.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetEndpointPolicy(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USBFN_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbFunctionIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 SetEndpointPolicy_Arg_1 = 0;
    EFI_USBFN_ENDPOINT_DIRECTION SetEndpointPolicy_Arg_2 = 0;
    UINTN SetEndpointPolicy_Arg_4 = 0;
    UINTN*  SetEndpointPolicy_Arg_5 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetEndpointPolicy_Arg_1), (VOID *)&SetEndpointPolicy_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetEndpointPolicy_Arg_2), (VOID *)&SetEndpointPolicy_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetEndpointPolicy_Arg_4), (VOID *)&SetEndpointPolicy_Arg_4);
    
    // Fuzzable Variable Initialization
    UINT8 SetEndpointPolicy_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(SetEndpointPolicy_Arg_5_choice), (VOID *)&SetEndpointPolicy_Arg_5_choice);
    switch(SetEndpointPolicy_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetEndpointPolicy_Arg_5), (VOID *)SetEndpointPolicy_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(SetEndpointPolicy_Arg_5);
            SetEndpointPolicy_Arg_5 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->SetEndpointPolicy(
        ProtocolVariable,
        SetEndpointPolicy_Arg_1,
        SetEndpointPolicy_Arg_2,
        (EFI_USBFN_POLICY_TYPE){0},
        SetEndpointPolicy_Arg_4,
        (VOID *)SetEndpointPolicy_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetEndpointPolicy.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetEndpointPolicy(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USBFN_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbFunctionIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 GetEndpointPolicy_Arg_1 = 0;
    EFI_USBFN_ENDPOINT_DIRECTION GetEndpointPolicy_Arg_2 = 0;
    UINTN * GetEndpointPolicy_Arg_4 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN*  GetEndpointPolicy_Arg_5 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetEndpointPolicy_Arg_1), (VOID *)&GetEndpointPolicy_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetEndpointPolicy_Arg_2), (VOID *)&GetEndpointPolicy_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 GetEndpointPolicy_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(GetEndpointPolicy_Arg_4_choice), (VOID *)&GetEndpointPolicy_Arg_4_choice);
    switch(GetEndpointPolicy_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetEndpointPolicy_Arg_4), (VOID *)GetEndpointPolicy_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(GetEndpointPolicy_Arg_4);
            GetEndpointPolicy_Arg_4 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetEndpointPolicy_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(GetEndpointPolicy_Arg_5_choice), (VOID *)&GetEndpointPolicy_Arg_5_choice);
    switch(GetEndpointPolicy_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetEndpointPolicy_Arg_5), (VOID *)GetEndpointPolicy_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(GetEndpointPolicy_Arg_5);
            GetEndpointPolicy_Arg_5 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetEndpointPolicy(
        ProtocolVariable,
        GetEndpointPolicy_Arg_1,
        GetEndpointPolicy_Arg_2,
        (EFI_USBFN_POLICY_TYPE){0},
        GetEndpointPolicy_Arg_4,
        (VOID *)GetEndpointPolicy_Arg_5
    );
    return Status;
}

