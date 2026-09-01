#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called GetHashSize.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetHashSize(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HASH2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHash2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * GetHashSize_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        GetHashSize_Arg_1->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        GetHashSize_Arg_1->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        GetHashSize_Arg_1->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(GetHashSize_Arg_1->Data4), (VOID *)&(GetHashSize_Arg_1->Data4));
    
    /*
        Output Variable(s)
    */
    UINTN * GetHashSize_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetHashSize_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetHashSize_Arg_2_OutputChoice), (VOID *)GetHashSize_Arg_2_OutputChoice);
    if(*GetHashSize_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetHashSize_Arg_2), (VOID *)GetHashSize_Arg_2);
    }
    Status = ProtocolVariable->GetHashSize(
        ProtocolVariable,
        GetHashSize_Arg_1,
        GetHashSize_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Hash.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzHash(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HASH2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHash2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * Hash_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINT8 * Hash_Arg_2 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINTN Hash_Arg_3 = 0;
    EFI_HASH2_OUTPUT * Hash_Arg_4 = (EFI_HASH2_OUTPUT *)AllocateZeroPool(sizeof(EFI_HASH2_OUTPUT));
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        Hash_Arg_1->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        Hash_Arg_1->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        Hash_Arg_1->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(Hash_Arg_1->Data4), (VOID *)&(Hash_Arg_1->Data4));
    
    // Fuzzable Variable Initialization
    UINT8 Hash_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(Hash_Arg_2_choice), (VOID *)&Hash_Arg_2_choice);
    switch(Hash_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Hash_Arg_2), (VOID *)Hash_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(Hash_Arg_2);
            Hash_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Hash_Arg_3), (VOID *)&Hash_Arg_3);
    
    
    Status = ProtocolVariable->Hash(
        ProtocolVariable,
        Hash_Arg_1,
        Hash_Arg_2,
        Hash_Arg_3,
        Hash_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called HashInit.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzHashInit(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HASH2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHash2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * HashInit_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        HashInit_Arg_1->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        HashInit_Arg_1->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        HashInit_Arg_1->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(HashInit_Arg_1->Data4), (VOID *)&(HashInit_Arg_1->Data4));
    
    Status = ProtocolVariable->HashInit(
        ProtocolVariable,
        HashInit_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called HashUpdate.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzHashUpdate(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HASH2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHash2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 * HashUpdate_Arg_1 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINTN HashUpdate_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    UINT8 HashUpdate_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(HashUpdate_Arg_1_choice), (VOID *)&HashUpdate_Arg_1_choice);
    switch(HashUpdate_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(HashUpdate_Arg_1), (VOID *)HashUpdate_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(HashUpdate_Arg_1);
            HashUpdate_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(HashUpdate_Arg_2), (VOID *)&HashUpdate_Arg_2);
    
    Status = ProtocolVariable->HashUpdate(
        ProtocolVariable,
        HashUpdate_Arg_1,
        HashUpdate_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called HashFinal.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzHashFinal(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HASH2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHash2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HASH2_OUTPUT * HashFinal_Arg_1 = (EFI_HASH2_OUTPUT *)AllocateZeroPool(sizeof(EFI_HASH2_OUTPUT));
    
    
    Status = ProtocolVariable->HashFinal(
        ProtocolVariable,
        HashFinal_Arg_1
    );
    return Status;
}

