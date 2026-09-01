#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called Supported.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSupported(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DRIVER_BINDING_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDriverBindingProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * Supported_Arg_2 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    
    // Generator Struct Variable Initialization
    {
        UINT8 Firness_Type;
        ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
        Supported_Arg_2->Type = Firness_Type;
    }
    {
        UINT8 Firness_SubType;
        ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
        Supported_Arg_2->SubType = Firness_SubType;
    }
    ReadBytes(Input, sizeof(Supported_Arg_2->Length), (VOID *)&(Supported_Arg_2->Length));
    
    Status = ProtocolVariable->Supported(
        ProtocolVariable,
        ImageHandle,
        Supported_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Start.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStart(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DRIVER_BINDING_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDriverBindingProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * Start_Arg_2 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    
    // Generator Struct Variable Initialization
    {
        UINT8 Firness_Type;
        ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
        Start_Arg_2->Type = Firness_Type;
    }
    {
        UINT8 Firness_SubType;
        ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
        Start_Arg_2->SubType = Firness_SubType;
    }
    ReadBytes(Input, sizeof(Start_Arg_2->Length), (VOID *)&(Start_Arg_2->Length));
    
    Status = ProtocolVariable->Start(
        ProtocolVariable,
        ImageHandle,
        Start_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Stop.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStop(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DRIVER_BINDING_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDriverBindingProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN Stop_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Stop_Arg_2), (VOID *)&Stop_Arg_2);
    
    Status = ProtocolVariable->Stop(
        ProtocolVariable,
        ImageHandle,
        Stop_Arg_2,
        ImageHandle
    );
    return Status;
}

