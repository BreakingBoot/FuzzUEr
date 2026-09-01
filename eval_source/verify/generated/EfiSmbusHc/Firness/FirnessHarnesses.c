#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called Execute.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzExecute(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMBUS_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmbusHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_SMBUS_DEVICE_ADDRESS Execute_Arg_1 = {0};
    EFI_SMBUS_DEVICE_COMMAND Execute_Arg_2 = 0;
    BOOLEAN Execute_Arg_4 = FALSE;
    UINTN * Execute_Arg_5 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN*  Execute_Arg_6 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Generator Struct Variable Initialization
    {
        UINTN Firness_SmbusDeviceAddress;
        ReadBytes(Input, sizeof(Firness_SmbusDeviceAddress), (VOID *)&Firness_SmbusDeviceAddress);
        Execute_Arg_1.SmbusDeviceAddress = Firness_SmbusDeviceAddress;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Execute_Arg_2), (VOID *)&Execute_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Execute_Arg_4), (VOID *)&Execute_Arg_4);
    
    // Fuzzable Variable Initialization
    UINT8 Execute_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(Execute_Arg_5_choice), (VOID *)&Execute_Arg_5_choice);
    switch(Execute_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Execute_Arg_5), (VOID *)Execute_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(Execute_Arg_5);
            Execute_Arg_5 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 Execute_Arg_6_choice = 0;
    ReadBytes(Input, sizeof(Execute_Arg_6_choice), (VOID *)&Execute_Arg_6_choice);
    switch(Execute_Arg_6_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Execute_Arg_6), (VOID *)Execute_Arg_6);
            break;
        case 1:
        {
            gBS->FreePool(Execute_Arg_6);
            Execute_Arg_6 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->Execute(
        ProtocolVariable,
        Execute_Arg_1,
        Execute_Arg_2,
        (EFI_SMBUS_OPERATION){0},
        Execute_Arg_4,
        Execute_Arg_5,
        (VOID *)Execute_Arg_6
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ArpDevice.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzArpDevice(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMBUS_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmbusHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN ArpDevice_Arg_1 = FALSE;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ArpDevice_Arg_1), (VOID *)&ArpDevice_Arg_1);
    
    Status = ProtocolVariable->ArpDevice(
        ProtocolVariable,
        ArpDevice_Arg_1,
        NULL,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetArpMap.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetArpMap(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMBUS_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmbusHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * GetArpMap_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    EFI_SMBUS_DEVICE_MAP * * GetArpMap_Arg_2 = (EFI_SMBUS_DEVICE_MAP * *)AllocateZeroPool(sizeof(EFI_SMBUS_DEVICE_MAP));
    
    // Fuzzable Variable Initialization
    UINT8 GetArpMap_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetArpMap_Arg_1_choice), (VOID *)&GetArpMap_Arg_1_choice);
    switch(GetArpMap_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetArpMap_Arg_1), (VOID *)GetArpMap_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(GetArpMap_Arg_1);
            GetArpMap_Arg_1 = NULL;
            break;
        }
    }
    
    
    Status = ProtocolVariable->GetArpMap(
        ProtocolVariable,
        GetArpMap_Arg_1,
        &GetArpMap_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Notify.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzNotify(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMBUS_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmbusHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_SMBUS_DEVICE_ADDRESS Notify_Arg_1 = {0};
    UINTN Notify_Arg_2 = 0;
    
    // Generator Struct Variable Initialization
    {
        UINTN Firness_SmbusDeviceAddress;
        ReadBytes(Input, sizeof(Firness_SmbusDeviceAddress), (VOID *)&Firness_SmbusDeviceAddress);
        Notify_Arg_1.SmbusDeviceAddress = Firness_SmbusDeviceAddress;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Notify_Arg_2), (VOID *)&Notify_Arg_2);
    
    Status = ProtocolVariable->Notify(
        ProtocolVariable,
        Notify_Arg_1,
        Notify_Arg_2,
        (EFI_SMBUS_NOTIFY_FUNCTION){0}
    );
    return Status;
}

