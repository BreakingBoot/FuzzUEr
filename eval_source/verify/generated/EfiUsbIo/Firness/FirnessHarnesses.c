#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called UsbGetDeviceDescriptor.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUsbGetDeviceDescriptor(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_USB_DEVICE_DESCRIPTOR * UsbGetDeviceDescriptor_Arg_1 = (EFI_USB_DEVICE_DESCRIPTOR *)AllocateZeroPool(sizeof(EFI_USB_DEVICE_DESCRIPTOR));
    UINT8* UsbGetDeviceDescriptor_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(UsbGetDeviceDescriptor_Arg_1_OutputChoice), (VOID *)UsbGetDeviceDescriptor_Arg_1_OutputChoice);
    if(*UsbGetDeviceDescriptor_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*UsbGetDeviceDescriptor_Arg_1), (VOID *)UsbGetDeviceDescriptor_Arg_1);
    }
    Status = ProtocolVariable->UsbGetDeviceDescriptor(
        ProtocolVariable,
        UsbGetDeviceDescriptor_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UsbGetInterfaceDescriptor.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUsbGetInterfaceDescriptor(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_USB_INTERFACE_DESCRIPTOR * UsbGetInterfaceDescriptor_Arg_1 = (EFI_USB_INTERFACE_DESCRIPTOR *)AllocateZeroPool(sizeof(EFI_USB_INTERFACE_DESCRIPTOR));
    UINT8* UsbGetInterfaceDescriptor_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(UsbGetInterfaceDescriptor_Arg_1_OutputChoice), (VOID *)UsbGetInterfaceDescriptor_Arg_1_OutputChoice);
    if(*UsbGetInterfaceDescriptor_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*UsbGetInterfaceDescriptor_Arg_1), (VOID *)UsbGetInterfaceDescriptor_Arg_1);
    }
    Status = ProtocolVariable->UsbGetInterfaceDescriptor(
        ProtocolVariable,
        UsbGetInterfaceDescriptor_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UsbGetSupportedLanguages.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUsbGetSupportedLanguages(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINT16 * UsbGetSupportedLanguages_Arg_1 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    UINT8* UsbGetSupportedLanguages_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(UsbGetSupportedLanguages_Arg_1_OutputChoice), (VOID *)UsbGetSupportedLanguages_Arg_1_OutputChoice);
    if(*UsbGetSupportedLanguages_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*UsbGetSupportedLanguages_Arg_1), (VOID *)UsbGetSupportedLanguages_Arg_1);
    }
    UINT16 * UsbGetSupportedLanguages_Arg_2 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    UINT8* UsbGetSupportedLanguages_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(UsbGetSupportedLanguages_Arg_2_OutputChoice), (VOID *)UsbGetSupportedLanguages_Arg_2_OutputChoice);
    if(*UsbGetSupportedLanguages_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*UsbGetSupportedLanguages_Arg_2), (VOID *)UsbGetSupportedLanguages_Arg_2);
    }
    Status = ProtocolVariable->UsbGetSupportedLanguages(
        ProtocolVariable,
        (UINT16 **)&UsbGetSupportedLanguages_Arg_1,
        UsbGetSupportedLanguages_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UsbGetStringDescriptor.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUsbGetStringDescriptor(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT16 UsbGetStringDescriptor_Arg_1 = 0;
    UINT8 UsbGetStringDescriptor_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UsbGetStringDescriptor_Arg_1), (VOID *)&UsbGetStringDescriptor_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UsbGetStringDescriptor_Arg_2), (VOID *)&UsbGetStringDescriptor_Arg_2);
    
    /*
        Output Variable(s)
    */
    CHAR16 * UsbGetStringDescriptor_Arg_3 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    UINT8* UsbGetStringDescriptor_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(UsbGetStringDescriptor_Arg_3_OutputChoice), (VOID *)UsbGetStringDescriptor_Arg_3_OutputChoice);
    if(*UsbGetStringDescriptor_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*UsbGetStringDescriptor_Arg_3), (VOID *)UsbGetStringDescriptor_Arg_3);
    }
    Status = ProtocolVariable->UsbGetStringDescriptor(
        ProtocolVariable,
        UsbGetStringDescriptor_Arg_1,
        UsbGetStringDescriptor_Arg_2,
        (CHAR16 **)&UsbGetStringDescriptor_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UsbAsyncInterruptTransfer.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUsbAsyncInterruptTransfer(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 UsbAsyncInterruptTransfer_Arg_1 = 0;
    BOOLEAN UsbAsyncInterruptTransfer_Arg_2 = FALSE;
    UINTN UsbAsyncInterruptTransfer_Arg_3 = 0;
    UINTN UsbAsyncInterruptTransfer_Arg_4 = 0;
    UINTN*  UsbAsyncInterruptTransfer_Arg_6 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UsbAsyncInterruptTransfer_Arg_1), (VOID *)&UsbAsyncInterruptTransfer_Arg_1);
    
    UINT8* UsbAsyncInterruptTransfer_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(UsbAsyncInterruptTransfer_Arg_2_choice), (VOID *)UsbAsyncInterruptTransfer_Arg_2_choice);
    switch(*UsbAsyncInterruptTransfer_Arg_2_choice % 2) {
        case 0:
        {
        // Constant Variable Initialization
        UsbAsyncInterruptTransfer_Arg_2 = MEMORY_PROFILE_RECORDING_ENABLE;
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(UsbAsyncInterruptTransfer_Arg_2), (VOID *)&UsbAsyncInterruptTransfer_Arg_2);
    
            break;
        }
    }
    UINT8* UsbAsyncInterruptTransfer_Arg_3_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(UsbAsyncInterruptTransfer_Arg_3_choice), (VOID *)UsbAsyncInterruptTransfer_Arg_3_choice);
    switch(*UsbAsyncInterruptTransfer_Arg_3_choice % 2) {
        case 0:
        {
        // Constant Variable Initialization
        UsbAsyncInterruptTransfer_Arg_3 = USB_HUB_POLL_INTERVAL;
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(UsbAsyncInterruptTransfer_Arg_3), (VOID *)&UsbAsyncInterruptTransfer_Arg_3);
    
            break;
        }
    }
    UINT8* UsbAsyncInterruptTransfer_Arg_4_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(UsbAsyncInterruptTransfer_Arg_4_choice), (VOID *)UsbAsyncInterruptTransfer_Arg_4_choice);
    switch(*UsbAsyncInterruptTransfer_Arg_4_choice % 2) {
        case 0:
        {
        // Constant Variable Initialization
        UsbAsyncInterruptTransfer_Arg_4 = 0;
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(UsbAsyncInterruptTransfer_Arg_4), (VOID *)&UsbAsyncInterruptTransfer_Arg_4);
    
            break;
        }
    }
    UINT8* UsbAsyncInterruptTransfer_Arg_6_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(UsbAsyncInterruptTransfer_Arg_6_choice), (VOID *)UsbAsyncInterruptTransfer_Arg_6_choice);
    switch(*UsbAsyncInterruptTransfer_Arg_6_choice % 2) {
        case 0:
        {
        // Constant Variable Initialization
        UsbAsyncInterruptTransfer_Arg_6 = kEmptyHashValue;
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        UINT8 UsbAsyncInterruptTransfer_Arg_6_choice = 0;
        ReadBytes(Input, sizeof(UsbAsyncInterruptTransfer_Arg_6_choice), (VOID *)&UsbAsyncInterruptTransfer_Arg_6_choice);
        switch(UsbAsyncInterruptTransfer_Arg_6_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(UsbAsyncInterruptTransfer_Arg_6), (VOID *)UsbAsyncInterruptTransfer_Arg_6);
                break;
            case 1:
            {
                gBS->FreePool(UsbAsyncInterruptTransfer_Arg_6);
                UsbAsyncInterruptTransfer_Arg_6 = NULL;
                break;
            }
        }
    
            break;
        }
    }
    Status = ProtocolVariable->UsbAsyncInterruptTransfer(
        ProtocolVariable,
        UsbAsyncInterruptTransfer_Arg_1,
        UsbAsyncInterruptTransfer_Arg_2,
        UsbAsyncInterruptTransfer_Arg_3,
        UsbAsyncInterruptTransfer_Arg_4,
        (EFI_ASYNC_USB_TRANSFER_CALLBACK){0},
        (void *)UsbAsyncInterruptTransfer_Arg_6
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UsbGetEndpointDescriptor.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUsbGetEndpointDescriptor(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 UsbGetEndpointDescriptor_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UsbGetEndpointDescriptor_Arg_1), (VOID *)&UsbGetEndpointDescriptor_Arg_1);
    
    /*
        Output Variable(s)
    */
    EFI_USB_ENDPOINT_DESCRIPTOR * UsbGetEndpointDescriptor_Arg_2 = (EFI_USB_ENDPOINT_DESCRIPTOR *)AllocateZeroPool(sizeof(EFI_USB_ENDPOINT_DESCRIPTOR));
    UINT8* UsbGetEndpointDescriptor_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(UsbGetEndpointDescriptor_Arg_2_OutputChoice), (VOID *)UsbGetEndpointDescriptor_Arg_2_OutputChoice);
    if(*UsbGetEndpointDescriptor_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*UsbGetEndpointDescriptor_Arg_2), (VOID *)UsbGetEndpointDescriptor_Arg_2);
    }
    Status = ProtocolVariable->UsbGetEndpointDescriptor(
        ProtocolVariable,
        UsbGetEndpointDescriptor_Arg_1,
        UsbGetEndpointDescriptor_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UsbBulkTransfer.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUsbBulkTransfer(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 UsbBulkTransfer_Arg_1 = 0;
    UINTN*  UsbBulkTransfer_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN * UsbBulkTransfer_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN UsbBulkTransfer_Arg_4 = 0;
    UINT32 * UsbBulkTransfer_Arg_5 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UsbBulkTransfer_Arg_1), (VOID *)&UsbBulkTransfer_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 UsbBulkTransfer_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(UsbBulkTransfer_Arg_2_choice), (VOID *)&UsbBulkTransfer_Arg_2_choice);
    switch(UsbBulkTransfer_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UsbBulkTransfer_Arg_2), (VOID *)UsbBulkTransfer_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(UsbBulkTransfer_Arg_2);
            UsbBulkTransfer_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 UsbBulkTransfer_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(UsbBulkTransfer_Arg_3_choice), (VOID *)&UsbBulkTransfer_Arg_3_choice);
    switch(UsbBulkTransfer_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UsbBulkTransfer_Arg_3), (VOID *)UsbBulkTransfer_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(UsbBulkTransfer_Arg_3);
            UsbBulkTransfer_Arg_3 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UsbBulkTransfer_Arg_4), (VOID *)&UsbBulkTransfer_Arg_4);
    
    // Fuzzable Variable Initialization
    UINT8 UsbBulkTransfer_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(UsbBulkTransfer_Arg_5_choice), (VOID *)&UsbBulkTransfer_Arg_5_choice);
    switch(UsbBulkTransfer_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UsbBulkTransfer_Arg_5), (VOID *)UsbBulkTransfer_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(UsbBulkTransfer_Arg_5);
            UsbBulkTransfer_Arg_5 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->UsbBulkTransfer(
        ProtocolVariable,
        UsbBulkTransfer_Arg_1,
        (void *)UsbBulkTransfer_Arg_2,
        UsbBulkTransfer_Arg_3,
        UsbBulkTransfer_Arg_4,
        UsbBulkTransfer_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UsbPortReset.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUsbPortReset(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->UsbPortReset(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UsbControlTransfer.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUsbControlTransfer(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_USB_DEVICE_REQUEST * UsbControlTransfer_Arg_1 = (EFI_USB_DEVICE_REQUEST *)AllocateZeroPool(sizeof(EFI_USB_DEVICE_REQUEST));
    EFI_USB_DATA_DIRECTION UsbControlTransfer_Arg_2 = 0;
    UINT32 UsbControlTransfer_Arg_3 = 0;
    UINTN*  UsbControlTransfer_Arg_4 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN UsbControlTransfer_Arg_5 = 0;
    UINT32 * UsbControlTransfer_Arg_6 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    
    // Generator Struct Variable Initialization
    {
        UINT8 Firness_RequestType;
        ReadBytes(Input, sizeof(Firness_RequestType), (VOID *)&Firness_RequestType);
        UsbControlTransfer_Arg_1->RequestType = Firness_RequestType;
    }
    {
        UINT8 Firness_Request;
        ReadBytes(Input, sizeof(Firness_Request), (VOID *)&Firness_Request);
        UsbControlTransfer_Arg_1->Request = Firness_Request;
    }
    {
        UINT16 Firness_Value;
        ReadBytes(Input, sizeof(Firness_Value), (VOID *)&Firness_Value);
        UsbControlTransfer_Arg_1->Value = Firness_Value;
    }
    {
        UINT16 Firness_Index;
        ReadBytes(Input, sizeof(Firness_Index), (VOID *)&Firness_Index);
        UsbControlTransfer_Arg_1->Index = Firness_Index;
    }
    {
        UINT16 Firness_Length;
        ReadBytes(Input, sizeof(Firness_Length), (VOID *)&Firness_Length);
        UsbControlTransfer_Arg_1->Length = Firness_Length;
    }
    
    // Constant Variable Initialization
    UINT8* UsbControlTransfer_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(UsbControlTransfer_Arg_2_choice), (VOID *)UsbControlTransfer_Arg_2_choice);
    switch(*UsbControlTransfer_Arg_2_choice % 4) {
        case 0:
            UsbControlTransfer_Arg_2 = EfiUsbDataIn;
            break;
        case 1:
            UsbControlTransfer_Arg_2 = EfiUsbDataOut;
            break;
        case 2:
            UsbControlTransfer_Arg_2 = EfiUsbNoData;
            break;
        case 3:
            ReadBytes(Input, sizeof(UsbControlTransfer_Arg_2), (VOID *)&UsbControlTransfer_Arg_2);
            break;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UsbControlTransfer_Arg_3), (VOID *)&UsbControlTransfer_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 UsbControlTransfer_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(UsbControlTransfer_Arg_4_choice), (VOID *)&UsbControlTransfer_Arg_4_choice);
    switch(UsbControlTransfer_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UsbControlTransfer_Arg_4), (VOID *)UsbControlTransfer_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(UsbControlTransfer_Arg_4);
            UsbControlTransfer_Arg_4 = NULL;
            break;
        }
    }
    
    UINT8* UsbControlTransfer_Arg_5_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(UsbControlTransfer_Arg_5_choice), (VOID *)UsbControlTransfer_Arg_5_choice);
    switch(*UsbControlTransfer_Arg_5_choice % 5) {
        case 0:
        {
        // Constant Variable Initialization
        UsbControlTransfer_Arg_5 = kEmptyHashValue;
    
            break;
        }
        case 1:
        {
        // Constant Variable Initialization
        UsbControlTransfer_Arg_5 = _PCD_VALUE_PcdUsbExtendedDecode;
    
            break;
        }
        case 2:
        {
        // Constant Variable Initialization
        UsbControlTransfer_Arg_5 = kMatchMinLen;
    
            break;
        }
        case 3:
        {
        // Constant Variable Initialization
        UsbControlTransfer_Arg_5 = sizeof (EFI_USB_HID_DESCRIPTOR);
    
            break;
        }
        case 4:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(UsbControlTransfer_Arg_5), (VOID *)&UsbControlTransfer_Arg_5);
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 UsbControlTransfer_Arg_6_choice = 0;
    ReadBytes(Input, sizeof(UsbControlTransfer_Arg_6_choice), (VOID *)&UsbControlTransfer_Arg_6_choice);
    switch(UsbControlTransfer_Arg_6_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UsbControlTransfer_Arg_6), (VOID *)UsbControlTransfer_Arg_6);
            break;
        case 1:
        {
            gBS->FreePool(UsbControlTransfer_Arg_6);
            UsbControlTransfer_Arg_6 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->UsbControlTransfer(
        ProtocolVariable,
        UsbControlTransfer_Arg_1,
        UsbControlTransfer_Arg_2,
        UsbControlTransfer_Arg_3,
        (void *)UsbControlTransfer_Arg_4,
        UsbControlTransfer_Arg_5,
        UsbControlTransfer_Arg_6
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UsbSyncInterruptTransfer.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUsbSyncInterruptTransfer(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 UsbSyncInterruptTransfer_Arg_1 = 0;
    UINTN*  UsbSyncInterruptTransfer_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN * UsbSyncInterruptTransfer_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN UsbSyncInterruptTransfer_Arg_4 = 0;
    UINT32 * UsbSyncInterruptTransfer_Arg_5 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UsbSyncInterruptTransfer_Arg_1), (VOID *)&UsbSyncInterruptTransfer_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 UsbSyncInterruptTransfer_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(UsbSyncInterruptTransfer_Arg_2_choice), (VOID *)&UsbSyncInterruptTransfer_Arg_2_choice);
    switch(UsbSyncInterruptTransfer_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UsbSyncInterruptTransfer_Arg_2), (VOID *)UsbSyncInterruptTransfer_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(UsbSyncInterruptTransfer_Arg_2);
            UsbSyncInterruptTransfer_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 UsbSyncInterruptTransfer_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(UsbSyncInterruptTransfer_Arg_3_choice), (VOID *)&UsbSyncInterruptTransfer_Arg_3_choice);
    switch(UsbSyncInterruptTransfer_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UsbSyncInterruptTransfer_Arg_3), (VOID *)UsbSyncInterruptTransfer_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(UsbSyncInterruptTransfer_Arg_3);
            UsbSyncInterruptTransfer_Arg_3 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UsbSyncInterruptTransfer_Arg_4), (VOID *)&UsbSyncInterruptTransfer_Arg_4);
    
    // Fuzzable Variable Initialization
    UINT8 UsbSyncInterruptTransfer_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(UsbSyncInterruptTransfer_Arg_5_choice), (VOID *)&UsbSyncInterruptTransfer_Arg_5_choice);
    switch(UsbSyncInterruptTransfer_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UsbSyncInterruptTransfer_Arg_5), (VOID *)UsbSyncInterruptTransfer_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(UsbSyncInterruptTransfer_Arg_5);
            UsbSyncInterruptTransfer_Arg_5 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->UsbSyncInterruptTransfer(
        ProtocolVariable,
        UsbSyncInterruptTransfer_Arg_1,
        (void *)UsbSyncInterruptTransfer_Arg_2,
        UsbSyncInterruptTransfer_Arg_3,
        UsbSyncInterruptTransfer_Arg_4,
        UsbSyncInterruptTransfer_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UsbIsochronousTransfer.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUsbIsochronousTransfer(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 UsbIsochronousTransfer_Arg_1 = 0;
    UINTN UsbIsochronousTransfer_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UsbIsochronousTransfer_Arg_1), (VOID *)&UsbIsochronousTransfer_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UsbIsochronousTransfer_Arg_3), (VOID *)&UsbIsochronousTransfer_Arg_3);
    
    /*
        Output Variable(s)
    */
    UINT32 * UsbIsochronousTransfer_Arg_4 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT8* UsbIsochronousTransfer_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(UsbIsochronousTransfer_Arg_4_OutputChoice), (VOID *)UsbIsochronousTransfer_Arg_4_OutputChoice);
    if(*UsbIsochronousTransfer_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*UsbIsochronousTransfer_Arg_4), (VOID *)UsbIsochronousTransfer_Arg_4);
    }
    Status = ProtocolVariable->UsbIsochronousTransfer(
        ProtocolVariable,
        UsbIsochronousTransfer_Arg_1,
        NULL,
        UsbIsochronousTransfer_Arg_3,
        UsbIsochronousTransfer_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UsbAsyncIsochronousTransfer.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUsbAsyncIsochronousTransfer(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 UsbAsyncIsochronousTransfer_Arg_1 = 0;
    UINTN*  UsbAsyncIsochronousTransfer_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN UsbAsyncIsochronousTransfer_Arg_3 = 0;
    UINTN*  UsbAsyncIsochronousTransfer_Arg_5 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UsbAsyncIsochronousTransfer_Arg_1), (VOID *)&UsbAsyncIsochronousTransfer_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 UsbAsyncIsochronousTransfer_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(UsbAsyncIsochronousTransfer_Arg_2_choice), (VOID *)&UsbAsyncIsochronousTransfer_Arg_2_choice);
    switch(UsbAsyncIsochronousTransfer_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UsbAsyncIsochronousTransfer_Arg_2), (VOID *)UsbAsyncIsochronousTransfer_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(UsbAsyncIsochronousTransfer_Arg_2);
            UsbAsyncIsochronousTransfer_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UsbAsyncIsochronousTransfer_Arg_3), (VOID *)&UsbAsyncIsochronousTransfer_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 UsbAsyncIsochronousTransfer_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(UsbAsyncIsochronousTransfer_Arg_5_choice), (VOID *)&UsbAsyncIsochronousTransfer_Arg_5_choice);
    switch(UsbAsyncIsochronousTransfer_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UsbAsyncIsochronousTransfer_Arg_5), (VOID *)UsbAsyncIsochronousTransfer_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(UsbAsyncIsochronousTransfer_Arg_5);
            UsbAsyncIsochronousTransfer_Arg_5 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->UsbAsyncIsochronousTransfer(
        ProtocolVariable,
        UsbAsyncIsochronousTransfer_Arg_1,
        (void *)UsbAsyncIsochronousTransfer_Arg_2,
        UsbAsyncIsochronousTransfer_Arg_3,
        (EFI_ASYNC_USB_TRANSFER_CALLBACK){0},
        (void *)UsbAsyncIsochronousTransfer_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UsbGetConfigDescriptor.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUsbGetConfigDescriptor(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_USB_CONFIG_DESCRIPTOR * UsbGetConfigDescriptor_Arg_1 = (EFI_USB_CONFIG_DESCRIPTOR *)AllocateZeroPool(sizeof(EFI_USB_CONFIG_DESCRIPTOR));
    UINT8* UsbGetConfigDescriptor_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(UsbGetConfigDescriptor_Arg_1_OutputChoice), (VOID *)UsbGetConfigDescriptor_Arg_1_OutputChoice);
    if(*UsbGetConfigDescriptor_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*UsbGetConfigDescriptor_Arg_1), (VOID *)UsbGetConfigDescriptor_Arg_1);
    }
    Status = ProtocolVariable->UsbGetConfigDescriptor(
        ProtocolVariable,
        UsbGetConfigDescriptor_Arg_1
    );
    return Status;
}

