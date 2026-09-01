#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called Open.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzOpen(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MM_ACCESS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMmAccessProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Open(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Close.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzClose(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MM_ACCESS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMmAccessProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Close(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Lock.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzLock(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MM_ACCESS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMmAccessProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Lock(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetCapabilities.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetCapabilities(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MM_ACCESS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMmAccessProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * GetCapabilities_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    EFI_MMRAM_DESCRIPTOR * GetCapabilities_Arg_2 = (EFI_MMRAM_DESCRIPTOR *)AllocateZeroPool(sizeof(EFI_MMRAM_DESCRIPTOR));
    
    // Fuzzable Variable Initialization
    UINT8 GetCapabilities_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetCapabilities_Arg_1_choice), (VOID *)&GetCapabilities_Arg_1_choice);
    switch(GetCapabilities_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetCapabilities_Arg_1), (VOID *)GetCapabilities_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(GetCapabilities_Arg_1);
            GetCapabilities_Arg_1 = NULL;
            break;
        }
    }
    
    
    Status = ProtocolVariable->GetCapabilities(
        ProtocolVariable,
        GetCapabilities_Arg_1,
        GetCapabilities_Arg_2
    );
    return Status;
}

