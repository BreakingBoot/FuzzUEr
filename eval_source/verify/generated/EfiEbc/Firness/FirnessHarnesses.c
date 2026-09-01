#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called UnloadImage.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUnloadImage(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_EBC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiEbcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->UnloadImage(
        ProtocolVariable,
        ImageHandle
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called CreateThunk.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzCreateThunk(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_EBC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiEbcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  CreateThunk_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    UINT8 CreateThunk_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(CreateThunk_Arg_2_choice), (VOID *)&CreateThunk_Arg_2_choice);
    switch(CreateThunk_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(CreateThunk_Arg_2), (VOID *)CreateThunk_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(CreateThunk_Arg_2);
            CreateThunk_Arg_2 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    UINTN* CreateThunk_Arg_3 = (UINTN*)AllocateZeroPool(sizeof(UINTN));
    UINT8* CreateThunk_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(CreateThunk_Arg_3_OutputChoice), (VOID *)CreateThunk_Arg_3_OutputChoice);
    if(*CreateThunk_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*CreateThunk_Arg_3), (VOID *)CreateThunk_Arg_3);
    }
    Status = ProtocolVariable->CreateThunk(
        ProtocolVariable,
        ImageHandle,
        (void *)CreateThunk_Arg_2,
        (void **)&CreateThunk_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetVersion.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetVersion(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_EBC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiEbcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT64 * GetVersion_Arg_1 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    
    // Fuzzable Variable Initialization
    UINT8 GetVersion_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetVersion_Arg_1_choice), (VOID *)&GetVersion_Arg_1_choice);
    switch(GetVersion_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetVersion_Arg_1), (VOID *)GetVersion_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(GetVersion_Arg_1);
            GetVersion_Arg_1 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetVersion(
        ProtocolVariable,
        GetVersion_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RegisterICacheFlush.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterICacheFlush(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_EBC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiEbcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->RegisterICacheFlush(
        ProtocolVariable,
        (EBC_ICACHE_FLUSH){0}
    );
    return Status;
}

