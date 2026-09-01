#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called GetRootHubPortNumber.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetRootHubPortNumber(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 * GetRootHubPortNumber_Arg_1 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    
    // Fuzzable Variable Initialization
    UINT8 GetRootHubPortNumber_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetRootHubPortNumber_Arg_1_choice), (VOID *)&GetRootHubPortNumber_Arg_1_choice);
    switch(GetRootHubPortNumber_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetRootHubPortNumber_Arg_1), (VOID *)GetRootHubPortNumber_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(GetRootHubPortNumber_Arg_1);
            GetRootHubPortNumber_Arg_1 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetRootHubPortNumber(
        ProtocolVariable,
        GetRootHubPortNumber_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetRootHubPortStatus.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetRootHubPortStatus(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 GetRootHubPortStatus_Arg_1 = 0;
    EFI_USB_PORT_STATUS * GetRootHubPortStatus_Arg_2 = (EFI_USB_PORT_STATUS *)AllocateZeroPool(sizeof(EFI_USB_PORT_STATUS));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetRootHubPortStatus_Arg_1), (VOID *)&GetRootHubPortStatus_Arg_1);
    
    // Generator Struct Variable Initialization
    {
        UINT16 Firness_PortStatus;
        ReadBytes(Input, sizeof(Firness_PortStatus), (VOID *)&Firness_PortStatus);
        GetRootHubPortStatus_Arg_2->PortStatus = Firness_PortStatus;
    }
    {
        UINT16 Firness_PortChangeStatus;
        ReadBytes(Input, sizeof(Firness_PortChangeStatus), (VOID *)&Firness_PortChangeStatus);
        GetRootHubPortStatus_Arg_2->PortChangeStatus = Firness_PortChangeStatus;
    }
    
    Status = ProtocolVariable->GetRootHubPortStatus(
        ProtocolVariable,
        GetRootHubPortStatus_Arg_1,
        GetRootHubPortStatus_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetRootHubPortFeature.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetRootHubPortFeature(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 SetRootHubPortFeature_Arg_1 = 0;
    EFI_USB_PORT_FEATURE SetRootHubPortFeature_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetRootHubPortFeature_Arg_1), (VOID *)&SetRootHubPortFeature_Arg_1);
    
    // Constant Variable Initialization
    UINT8* SetRootHubPortFeature_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SetRootHubPortFeature_Arg_2_choice), (VOID *)SetRootHubPortFeature_Arg_2_choice);
    switch(*SetRootHubPortFeature_Arg_2_choice % 11) {
        case 0:
            SetRootHubPortFeature_Arg_2 = EfiUsbPortConnectChange;
            break;
        case 1:
            SetRootHubPortFeature_Arg_2 = EfiUsbPortEnable;
            break;
        case 2:
            SetRootHubPortFeature_Arg_2 = EfiUsbPortEnableChange;
            break;
        case 3:
            SetRootHubPortFeature_Arg_2 = EfiUsbPortOverCurrentChange;
            break;
        case 4:
            SetRootHubPortFeature_Arg_2 = EfiUsbPortOwner;
            break;
        case 5:
            SetRootHubPortFeature_Arg_2 = EfiUsbPortPower;
            break;
        case 6:
            SetRootHubPortFeature_Arg_2 = EfiUsbPortReset;
            break;
        case 7:
            SetRootHubPortFeature_Arg_2 = EfiUsbPortResetChange;
            break;
        case 8:
            SetRootHubPortFeature_Arg_2 = EfiUsbPortSuspend;
            break;
        case 9:
            SetRootHubPortFeature_Arg_2 = EfiUsbPortSuspendChange;
            break;
        case 10:
            ReadBytes(Input, sizeof(SetRootHubPortFeature_Arg_2), (VOID *)&SetRootHubPortFeature_Arg_2);
            break;
    }
    
    Status = ProtocolVariable->SetRootHubPortFeature(
        ProtocolVariable,
        SetRootHubPortFeature_Arg_1,
        SetRootHubPortFeature_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ClearRootHubPortFeature.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzClearRootHubPortFeature(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 ClearRootHubPortFeature_Arg_1 = 0;
    EFI_USB_PORT_FEATURE ClearRootHubPortFeature_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ClearRootHubPortFeature_Arg_1), (VOID *)&ClearRootHubPortFeature_Arg_1);
    
    // Constant Variable Initialization
    UINT8* ClearRootHubPortFeature_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ClearRootHubPortFeature_Arg_2_choice), (VOID *)ClearRootHubPortFeature_Arg_2_choice);
    switch(*ClearRootHubPortFeature_Arg_2_choice % 11) {
        case 0:
            ClearRootHubPortFeature_Arg_2 = EfiUsbPortConnectChange;
            break;
        case 1:
            ClearRootHubPortFeature_Arg_2 = EfiUsbPortEnable;
            break;
        case 2:
            ClearRootHubPortFeature_Arg_2 = EfiUsbPortEnableChange;
            break;
        case 3:
            ClearRootHubPortFeature_Arg_2 = EfiUsbPortOverCurrentChange;
            break;
        case 4:
            ClearRootHubPortFeature_Arg_2 = EfiUsbPortOwner;
            break;
        case 5:
            ClearRootHubPortFeature_Arg_2 = EfiUsbPortPower;
            break;
        case 6:
            ClearRootHubPortFeature_Arg_2 = EfiUsbPortReset;
            break;
        case 7:
            ClearRootHubPortFeature_Arg_2 = EfiUsbPortResetChange;
            break;
        case 8:
            ClearRootHubPortFeature_Arg_2 = EfiUsbPortSuspend;
            break;
        case 9:
            ClearRootHubPortFeature_Arg_2 = EfiUsbPortSuspendChange;
            break;
        case 10:
            ReadBytes(Input, sizeof(ClearRootHubPortFeature_Arg_2), (VOID *)&ClearRootHubPortFeature_Arg_2);
            break;
    }
    
    Status = ProtocolVariable->ClearRootHubPortFeature(
        ProtocolVariable,
        ClearRootHubPortFeature_Arg_1,
        ClearRootHubPortFeature_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ControlTransfer.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzControlTransfer(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 ControlTransfer_Arg_1 = 0;
    BOOLEAN ControlTransfer_Arg_2 = FALSE;
    UINT8 ControlTransfer_Arg_3 = 0;
    EFI_USB_DEVICE_REQUEST * ControlTransfer_Arg_4 = (EFI_USB_DEVICE_REQUEST *)AllocateZeroPool(sizeof(EFI_USB_DEVICE_REQUEST));
    EFI_USB_DATA_DIRECTION ControlTransfer_Arg_5 = 0;
    UINTN*  ControlTransfer_Arg_6 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN * ControlTransfer_Arg_7 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN ControlTransfer_Arg_8 = 0;
    UINT32 * ControlTransfer_Arg_9 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ControlTransfer_Arg_1), (VOID *)&ControlTransfer_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ControlTransfer_Arg_2), (VOID *)&ControlTransfer_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ControlTransfer_Arg_3), (VOID *)&ControlTransfer_Arg_3);
    
    // Generator Struct Variable Initialization
    {
        UINT8 Firness_RequestType;
        ReadBytes(Input, sizeof(Firness_RequestType), (VOID *)&Firness_RequestType);
        ControlTransfer_Arg_4->RequestType = Firness_RequestType;
    }
    {
        UINT8 Firness_Request;
        ReadBytes(Input, sizeof(Firness_Request), (VOID *)&Firness_Request);
        ControlTransfer_Arg_4->Request = Firness_Request;
    }
    {
        UINT16 Firness_Value;
        ReadBytes(Input, sizeof(Firness_Value), (VOID *)&Firness_Value);
        ControlTransfer_Arg_4->Value = Firness_Value;
    }
    {
        UINT16 Firness_Index;
        ReadBytes(Input, sizeof(Firness_Index), (VOID *)&Firness_Index);
        ControlTransfer_Arg_4->Index = Firness_Index;
    }
    {
        UINT16 Firness_Length;
        ReadBytes(Input, sizeof(Firness_Length), (VOID *)&Firness_Length);
        ControlTransfer_Arg_4->Length = Firness_Length;
    }
    
    // Constant Variable Initialization
    UINT8* ControlTransfer_Arg_5_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ControlTransfer_Arg_5_choice), (VOID *)ControlTransfer_Arg_5_choice);
    switch(*ControlTransfer_Arg_5_choice % 4) {
        case 0:
            ControlTransfer_Arg_5 = EfiUsbDataIn;
            break;
        case 1:
            ControlTransfer_Arg_5 = EfiUsbDataOut;
            break;
        case 2:
            ControlTransfer_Arg_5 = EfiUsbNoData;
            break;
        case 3:
            ReadBytes(Input, sizeof(ControlTransfer_Arg_5), (VOID *)&ControlTransfer_Arg_5);
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 ControlTransfer_Arg_6_choice = 0;
    ReadBytes(Input, sizeof(ControlTransfer_Arg_6_choice), (VOID *)&ControlTransfer_Arg_6_choice);
    switch(ControlTransfer_Arg_6_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(ControlTransfer_Arg_6), (VOID *)ControlTransfer_Arg_6);
            break;
        case 1:
        {
            gBS->FreePool(ControlTransfer_Arg_6);
            ControlTransfer_Arg_6 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 ControlTransfer_Arg_7_choice = 0;
    ReadBytes(Input, sizeof(ControlTransfer_Arg_7_choice), (VOID *)&ControlTransfer_Arg_7_choice);
    switch(ControlTransfer_Arg_7_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(ControlTransfer_Arg_7), (VOID *)ControlTransfer_Arg_7);
            break;
        case 1:
        {
            gBS->FreePool(ControlTransfer_Arg_7);
            ControlTransfer_Arg_7 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ControlTransfer_Arg_8), (VOID *)&ControlTransfer_Arg_8);
    
    // Fuzzable Variable Initialization
    UINT8 ControlTransfer_Arg_9_choice = 0;
    ReadBytes(Input, sizeof(ControlTransfer_Arg_9_choice), (VOID *)&ControlTransfer_Arg_9_choice);
    switch(ControlTransfer_Arg_9_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(ControlTransfer_Arg_9), (VOID *)ControlTransfer_Arg_9);
            break;
        case 1:
        {
            gBS->FreePool(ControlTransfer_Arg_9);
            ControlTransfer_Arg_9 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->ControlTransfer(
        ProtocolVariable,
        ControlTransfer_Arg_1,
        ControlTransfer_Arg_2,
        ControlTransfer_Arg_3,
        ControlTransfer_Arg_4,
        ControlTransfer_Arg_5,
        (void *)ControlTransfer_Arg_6,
        ControlTransfer_Arg_7,
        ControlTransfer_Arg_8,
        ControlTransfer_Arg_9
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called BulkTransfer.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzBulkTransfer(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 BulkTransfer_Arg_1 = 0;
    UINT8 BulkTransfer_Arg_2 = 0;
    UINT8 BulkTransfer_Arg_3 = 0;
    UINTN*  BulkTransfer_Arg_4 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN * BulkTransfer_Arg_5 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8 * BulkTransfer_Arg_6 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINTN BulkTransfer_Arg_7 = 0;
    UINT32 * BulkTransfer_Arg_8 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(BulkTransfer_Arg_1), (VOID *)&BulkTransfer_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(BulkTransfer_Arg_2), (VOID *)&BulkTransfer_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(BulkTransfer_Arg_3), (VOID *)&BulkTransfer_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 BulkTransfer_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(BulkTransfer_Arg_4_choice), (VOID *)&BulkTransfer_Arg_4_choice);
    switch(BulkTransfer_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(BulkTransfer_Arg_4), (VOID *)BulkTransfer_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(BulkTransfer_Arg_4);
            BulkTransfer_Arg_4 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 BulkTransfer_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(BulkTransfer_Arg_5_choice), (VOID *)&BulkTransfer_Arg_5_choice);
    switch(BulkTransfer_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(BulkTransfer_Arg_5), (VOID *)BulkTransfer_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(BulkTransfer_Arg_5);
            BulkTransfer_Arg_5 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 BulkTransfer_Arg_6_choice = 0;
    ReadBytes(Input, sizeof(BulkTransfer_Arg_6_choice), (VOID *)&BulkTransfer_Arg_6_choice);
    switch(BulkTransfer_Arg_6_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(BulkTransfer_Arg_6), (VOID *)BulkTransfer_Arg_6);
            break;
        case 1:
        {
            gBS->FreePool(BulkTransfer_Arg_6);
            BulkTransfer_Arg_6 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(BulkTransfer_Arg_7), (VOID *)&BulkTransfer_Arg_7);
    
    // Fuzzable Variable Initialization
    UINT8 BulkTransfer_Arg_8_choice = 0;
    ReadBytes(Input, sizeof(BulkTransfer_Arg_8_choice), (VOID *)&BulkTransfer_Arg_8_choice);
    switch(BulkTransfer_Arg_8_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(BulkTransfer_Arg_8), (VOID *)BulkTransfer_Arg_8);
            break;
        case 1:
        {
            gBS->FreePool(BulkTransfer_Arg_8);
            BulkTransfer_Arg_8 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->BulkTransfer(
        ProtocolVariable,
        BulkTransfer_Arg_1,
        BulkTransfer_Arg_2,
        BulkTransfer_Arg_3,
        (void *)BulkTransfer_Arg_4,
        BulkTransfer_Arg_5,
        BulkTransfer_Arg_6,
        BulkTransfer_Arg_7,
        BulkTransfer_Arg_8
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called AsyncInterruptTransfer.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAsyncInterruptTransfer(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 AsyncInterruptTransfer_Arg_1 = 0;
    UINT8 AsyncInterruptTransfer_Arg_2 = 0;
    BOOLEAN AsyncInterruptTransfer_Arg_3 = FALSE;
    UINT8 AsyncInterruptTransfer_Arg_4 = 0;
    BOOLEAN AsyncInterruptTransfer_Arg_5 = FALSE;
    UINT8 * AsyncInterruptTransfer_Arg_6 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINTN AsyncInterruptTransfer_Arg_7 = 0;
    UINTN AsyncInterruptTransfer_Arg_8 = 0;
    UINTN*  AsyncInterruptTransfer_Arg_10 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AsyncInterruptTransfer_Arg_1), (VOID *)&AsyncInterruptTransfer_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AsyncInterruptTransfer_Arg_2), (VOID *)&AsyncInterruptTransfer_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AsyncInterruptTransfer_Arg_3), (VOID *)&AsyncInterruptTransfer_Arg_3);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AsyncInterruptTransfer_Arg_4), (VOID *)&AsyncInterruptTransfer_Arg_4);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AsyncInterruptTransfer_Arg_5), (VOID *)&AsyncInterruptTransfer_Arg_5);
    
    // Fuzzable Variable Initialization
    UINT8 AsyncInterruptTransfer_Arg_6_choice = 0;
    ReadBytes(Input, sizeof(AsyncInterruptTransfer_Arg_6_choice), (VOID *)&AsyncInterruptTransfer_Arg_6_choice);
    switch(AsyncInterruptTransfer_Arg_6_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(AsyncInterruptTransfer_Arg_6), (VOID *)AsyncInterruptTransfer_Arg_6);
            break;
        case 1:
        {
            gBS->FreePool(AsyncInterruptTransfer_Arg_6);
            AsyncInterruptTransfer_Arg_6 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AsyncInterruptTransfer_Arg_7), (VOID *)&AsyncInterruptTransfer_Arg_7);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AsyncInterruptTransfer_Arg_8), (VOID *)&AsyncInterruptTransfer_Arg_8);
    
    // Fuzzable Variable Initialization
    UINT8 AsyncInterruptTransfer_Arg_10_choice = 0;
    ReadBytes(Input, sizeof(AsyncInterruptTransfer_Arg_10_choice), (VOID *)&AsyncInterruptTransfer_Arg_10_choice);
    switch(AsyncInterruptTransfer_Arg_10_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(AsyncInterruptTransfer_Arg_10), (VOID *)AsyncInterruptTransfer_Arg_10);
            break;
        case 1:
        {
            gBS->FreePool(AsyncInterruptTransfer_Arg_10);
            AsyncInterruptTransfer_Arg_10 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->AsyncInterruptTransfer(
        ProtocolVariable,
        AsyncInterruptTransfer_Arg_1,
        AsyncInterruptTransfer_Arg_2,
        AsyncInterruptTransfer_Arg_3,
        AsyncInterruptTransfer_Arg_4,
        AsyncInterruptTransfer_Arg_5,
        AsyncInterruptTransfer_Arg_6,
        AsyncInterruptTransfer_Arg_7,
        AsyncInterruptTransfer_Arg_8,
        (EFI_ASYNC_USB_TRANSFER_CALLBACK){0},
        (void *)AsyncInterruptTransfer_Arg_10
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SyncInterruptTransfer.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSyncInterruptTransfer(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 SyncInterruptTransfer_Arg_1 = 0;
    UINT8 SyncInterruptTransfer_Arg_2 = 0;
    BOOLEAN SyncInterruptTransfer_Arg_3 = FALSE;
    UINT8 SyncInterruptTransfer_Arg_4 = 0;
    UINTN*  SyncInterruptTransfer_Arg_5 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN * SyncInterruptTransfer_Arg_6 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8 * SyncInterruptTransfer_Arg_7 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINTN SyncInterruptTransfer_Arg_8 = 0;
    UINT32 * SyncInterruptTransfer_Arg_9 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SyncInterruptTransfer_Arg_1), (VOID *)&SyncInterruptTransfer_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SyncInterruptTransfer_Arg_2), (VOID *)&SyncInterruptTransfer_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SyncInterruptTransfer_Arg_3), (VOID *)&SyncInterruptTransfer_Arg_3);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SyncInterruptTransfer_Arg_4), (VOID *)&SyncInterruptTransfer_Arg_4);
    
    // Fuzzable Variable Initialization
    UINT8 SyncInterruptTransfer_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(SyncInterruptTransfer_Arg_5_choice), (VOID *)&SyncInterruptTransfer_Arg_5_choice);
    switch(SyncInterruptTransfer_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SyncInterruptTransfer_Arg_5), (VOID *)SyncInterruptTransfer_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(SyncInterruptTransfer_Arg_5);
            SyncInterruptTransfer_Arg_5 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 SyncInterruptTransfer_Arg_6_choice = 0;
    ReadBytes(Input, sizeof(SyncInterruptTransfer_Arg_6_choice), (VOID *)&SyncInterruptTransfer_Arg_6_choice);
    switch(SyncInterruptTransfer_Arg_6_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SyncInterruptTransfer_Arg_6), (VOID *)SyncInterruptTransfer_Arg_6);
            break;
        case 1:
        {
            gBS->FreePool(SyncInterruptTransfer_Arg_6);
            SyncInterruptTransfer_Arg_6 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 SyncInterruptTransfer_Arg_7_choice = 0;
    ReadBytes(Input, sizeof(SyncInterruptTransfer_Arg_7_choice), (VOID *)&SyncInterruptTransfer_Arg_7_choice);
    switch(SyncInterruptTransfer_Arg_7_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SyncInterruptTransfer_Arg_7), (VOID *)SyncInterruptTransfer_Arg_7);
            break;
        case 1:
        {
            gBS->FreePool(SyncInterruptTransfer_Arg_7);
            SyncInterruptTransfer_Arg_7 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SyncInterruptTransfer_Arg_8), (VOID *)&SyncInterruptTransfer_Arg_8);
    
    // Fuzzable Variable Initialization
    UINT8 SyncInterruptTransfer_Arg_9_choice = 0;
    ReadBytes(Input, sizeof(SyncInterruptTransfer_Arg_9_choice), (VOID *)&SyncInterruptTransfer_Arg_9_choice);
    switch(SyncInterruptTransfer_Arg_9_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SyncInterruptTransfer_Arg_9), (VOID *)SyncInterruptTransfer_Arg_9);
            break;
        case 1:
        {
            gBS->FreePool(SyncInterruptTransfer_Arg_9);
            SyncInterruptTransfer_Arg_9 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->SyncInterruptTransfer(
        ProtocolVariable,
        SyncInterruptTransfer_Arg_1,
        SyncInterruptTransfer_Arg_2,
        SyncInterruptTransfer_Arg_3,
        SyncInterruptTransfer_Arg_4,
        (void *)SyncInterruptTransfer_Arg_5,
        SyncInterruptTransfer_Arg_6,
        SyncInterruptTransfer_Arg_7,
        SyncInterruptTransfer_Arg_8,
        SyncInterruptTransfer_Arg_9
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Reset.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzReset(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT16 Reset_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Reset_Arg_1), (VOID *)&Reset_Arg_1);
    
    Status = ProtocolVariable->Reset(
        ProtocolVariable,
        Reset_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetState.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetState(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_USB_HC_STATE * GetState_Arg_1 = (EFI_USB_HC_STATE *)AllocateZeroPool(sizeof(EFI_USB_HC_STATE));
    UINT8* GetState_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetState_Arg_1_OutputChoice), (VOID *)GetState_Arg_1_OutputChoice);
    if(*GetState_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetState_Arg_1), (VOID *)GetState_Arg_1);
    }
    Status = ProtocolVariable->GetState(
        ProtocolVariable,
        GetState_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetState.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetState(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->SetState(
        ProtocolVariable,
        (EFI_USB_HC_STATE){0}
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called IsochronousTransfer.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzIsochronousTransfer(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 IsochronousTransfer_Arg_1 = 0;
    UINT8 IsochronousTransfer_Arg_2 = 0;
    UINT8 IsochronousTransfer_Arg_3 = 0;
    UINTN*  IsochronousTransfer_Arg_4 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN IsochronousTransfer_Arg_5 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(IsochronousTransfer_Arg_1), (VOID *)&IsochronousTransfer_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(IsochronousTransfer_Arg_2), (VOID *)&IsochronousTransfer_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(IsochronousTransfer_Arg_3), (VOID *)&IsochronousTransfer_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 IsochronousTransfer_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(IsochronousTransfer_Arg_4_choice), (VOID *)&IsochronousTransfer_Arg_4_choice);
    switch(IsochronousTransfer_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(IsochronousTransfer_Arg_4), (VOID *)IsochronousTransfer_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(IsochronousTransfer_Arg_4);
            IsochronousTransfer_Arg_4 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(IsochronousTransfer_Arg_5), (VOID *)&IsochronousTransfer_Arg_5);
    
    /*
        Output Variable(s)
    */
    UINT32 * IsochronousTransfer_Arg_6 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT8* IsochronousTransfer_Arg_6_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(IsochronousTransfer_Arg_6_OutputChoice), (VOID *)IsochronousTransfer_Arg_6_OutputChoice);
    if(*IsochronousTransfer_Arg_6_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*IsochronousTransfer_Arg_6), (VOID *)IsochronousTransfer_Arg_6);
    }
    Status = ProtocolVariable->IsochronousTransfer(
        ProtocolVariable,
        IsochronousTransfer_Arg_1,
        IsochronousTransfer_Arg_2,
        IsochronousTransfer_Arg_3,
        (VOID *)IsochronousTransfer_Arg_4,
        IsochronousTransfer_Arg_5,
        IsochronousTransfer_Arg_6
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called AsyncIsochronousTransfer.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAsyncIsochronousTransfer(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_USB_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUsbHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 AsyncIsochronousTransfer_Arg_1 = 0;
    UINT8 AsyncIsochronousTransfer_Arg_2 = 0;
    UINT8 AsyncIsochronousTransfer_Arg_3 = 0;
    UINTN*  AsyncIsochronousTransfer_Arg_4 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN AsyncIsochronousTransfer_Arg_5 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AsyncIsochronousTransfer_Arg_1), (VOID *)&AsyncIsochronousTransfer_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AsyncIsochronousTransfer_Arg_2), (VOID *)&AsyncIsochronousTransfer_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AsyncIsochronousTransfer_Arg_3), (VOID *)&AsyncIsochronousTransfer_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 AsyncIsochronousTransfer_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(AsyncIsochronousTransfer_Arg_4_choice), (VOID *)&AsyncIsochronousTransfer_Arg_4_choice);
    switch(AsyncIsochronousTransfer_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(AsyncIsochronousTransfer_Arg_4), (VOID *)AsyncIsochronousTransfer_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(AsyncIsochronousTransfer_Arg_4);
            AsyncIsochronousTransfer_Arg_4 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AsyncIsochronousTransfer_Arg_5), (VOID *)&AsyncIsochronousTransfer_Arg_5);
    
    Status = ProtocolVariable->AsyncIsochronousTransfer(
        ProtocolVariable,
        AsyncIsochronousTransfer_Arg_1,
        AsyncIsochronousTransfer_Arg_2,
        AsyncIsochronousTransfer_Arg_3,
        (VOID *)AsyncIsochronousTransfer_Arg_4,
        AsyncIsochronousTransfer_Arg_5,
        (EFI_ASYNC_USB_TRANSFER_CALLBACK){0},
        NULL
    );
    return Status;
}

