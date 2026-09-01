#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called CreateDevice.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzCreateDevice(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_UGA_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUgaIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  CreateDevice_Arg_3 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    UINT8 CreateDevice_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(CreateDevice_Arg_3_choice), (VOID *)&CreateDevice_Arg_3_choice);
    switch(CreateDevice_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(CreateDevice_Arg_3), (VOID *)CreateDevice_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(CreateDevice_Arg_3);
            CreateDevice_Arg_3 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    UGA_DEVICE * * CreateDevice_Arg_4 = (UGA_DEVICE * *)AllocateZeroPool(sizeof(UGA_DEVICE));
    UINT8* CreateDevice_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(CreateDevice_Arg_4_OutputChoice), (VOID *)CreateDevice_Arg_4_OutputChoice);
    if(*CreateDevice_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*CreateDevice_Arg_4), (VOID *)CreateDevice_Arg_4);
    }
    Status = ProtocolVariable->CreateDevice(
        ProtocolVariable,
        NULL,
        NULL,
        (VOID *)CreateDevice_Arg_3,
        &CreateDevice_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called DeleteDevice.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDeleteDevice(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_UGA_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUgaIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->DeleteDevice(
        ProtocolVariable,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called DispatchService.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDispatchService(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_UGA_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUgaIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    PUGA_IO_REQUEST DispatchService_Arg_1 = 0;
    
    
    ProtocolVariable->DispatchService(
        (PUGA_DEVICE){0},
        DispatchService_Arg_1
    );
    return Status;
}

