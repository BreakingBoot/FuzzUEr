#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called RwUfsDescriptor.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRwUfsDescriptor(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_UFS_DEVICE_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUfsDeviceConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN RwUfsDescriptor_Arg_1 = FALSE;
    UINT8 RwUfsDescriptor_Arg_2 = 0;
    UINT8 RwUfsDescriptor_Arg_3 = 0;
    UINT8 RwUfsDescriptor_Arg_4 = 0;
    UINT8 * RwUfsDescriptor_Arg_5 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT32 * RwUfsDescriptor_Arg_6 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RwUfsDescriptor_Arg_1), (VOID *)&RwUfsDescriptor_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RwUfsDescriptor_Arg_2), (VOID *)&RwUfsDescriptor_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RwUfsDescriptor_Arg_3), (VOID *)&RwUfsDescriptor_Arg_3);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RwUfsDescriptor_Arg_4), (VOID *)&RwUfsDescriptor_Arg_4);
    
    // Fuzzable Variable Initialization
    UINT8 RwUfsDescriptor_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(RwUfsDescriptor_Arg_5_choice), (VOID *)&RwUfsDescriptor_Arg_5_choice);
    switch(RwUfsDescriptor_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(RwUfsDescriptor_Arg_5), (VOID *)RwUfsDescriptor_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(RwUfsDescriptor_Arg_5);
            RwUfsDescriptor_Arg_5 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 RwUfsDescriptor_Arg_6_choice = 0;
    ReadBytes(Input, sizeof(RwUfsDescriptor_Arg_6_choice), (VOID *)&RwUfsDescriptor_Arg_6_choice);
    switch(RwUfsDescriptor_Arg_6_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(RwUfsDescriptor_Arg_6), (VOID *)RwUfsDescriptor_Arg_6);
            break;
        case 1:
        {
            gBS->FreePool(RwUfsDescriptor_Arg_6);
            RwUfsDescriptor_Arg_6 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->RwUfsDescriptor(
        ProtocolVariable,
        RwUfsDescriptor_Arg_1,
        RwUfsDescriptor_Arg_2,
        RwUfsDescriptor_Arg_3,
        RwUfsDescriptor_Arg_4,
        RwUfsDescriptor_Arg_5,
        RwUfsDescriptor_Arg_6
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RwUfsFlag.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRwUfsFlag(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_UFS_DEVICE_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUfsDeviceConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN RwUfsFlag_Arg_1 = FALSE;
    UINT8 RwUfsFlag_Arg_2 = 0;
    UINT8 * RwUfsFlag_Arg_3 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RwUfsFlag_Arg_1), (VOID *)&RwUfsFlag_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RwUfsFlag_Arg_2), (VOID *)&RwUfsFlag_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 RwUfsFlag_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(RwUfsFlag_Arg_3_choice), (VOID *)&RwUfsFlag_Arg_3_choice);
    switch(RwUfsFlag_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(RwUfsFlag_Arg_3), (VOID *)RwUfsFlag_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(RwUfsFlag_Arg_3);
            RwUfsFlag_Arg_3 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->RwUfsFlag(
        ProtocolVariable,
        RwUfsFlag_Arg_1,
        RwUfsFlag_Arg_2,
        RwUfsFlag_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RwUfsAttribute.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRwUfsAttribute(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_UFS_DEVICE_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUfsDeviceConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN RwUfsAttribute_Arg_1 = FALSE;
    UINT8 RwUfsAttribute_Arg_2 = 0;
    UINT8 RwUfsAttribute_Arg_3 = 0;
    UINT8 RwUfsAttribute_Arg_4 = 0;
    UINT8 * RwUfsAttribute_Arg_5 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT32 * RwUfsAttribute_Arg_6 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RwUfsAttribute_Arg_1), (VOID *)&RwUfsAttribute_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RwUfsAttribute_Arg_2), (VOID *)&RwUfsAttribute_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RwUfsAttribute_Arg_3), (VOID *)&RwUfsAttribute_Arg_3);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RwUfsAttribute_Arg_4), (VOID *)&RwUfsAttribute_Arg_4);
    
    // Fuzzable Variable Initialization
    UINT8 RwUfsAttribute_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(RwUfsAttribute_Arg_5_choice), (VOID *)&RwUfsAttribute_Arg_5_choice);
    switch(RwUfsAttribute_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(RwUfsAttribute_Arg_5), (VOID *)RwUfsAttribute_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(RwUfsAttribute_Arg_5);
            RwUfsAttribute_Arg_5 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 RwUfsAttribute_Arg_6_choice = 0;
    ReadBytes(Input, sizeof(RwUfsAttribute_Arg_6_choice), (VOID *)&RwUfsAttribute_Arg_6_choice);
    switch(RwUfsAttribute_Arg_6_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(RwUfsAttribute_Arg_6), (VOID *)RwUfsAttribute_Arg_6);
            break;
        case 1:
        {
            gBS->FreePool(RwUfsAttribute_Arg_6);
            RwUfsAttribute_Arg_6 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->RwUfsAttribute(
        ProtocolVariable,
        RwUfsAttribute_Arg_1,
        RwUfsAttribute_Arg_2,
        RwUfsAttribute_Arg_3,
        RwUfsAttribute_Arg_4,
        RwUfsAttribute_Arg_5,
        RwUfsAttribute_Arg_6
    );
    return Status;
}

