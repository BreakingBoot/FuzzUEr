#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called Decode.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDecode(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_LEGACY_REGION2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiLegacyRegion2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 Decode_Arg_1 = 0;
    UINT32 Decode_Arg_2 = 0;
    BOOLEAN * Decode_Arg_4 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Decode_Arg_1), (VOID *)&Decode_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Decode_Arg_2), (VOID *)&Decode_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 Decode_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(Decode_Arg_4_choice), (VOID *)&Decode_Arg_4_choice);
    switch(Decode_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Decode_Arg_4), (VOID *)Decode_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(Decode_Arg_4);
            Decode_Arg_4 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    UINT32 * Decode_Arg_3 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT8* Decode_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Decode_Arg_3_OutputChoice), (VOID *)Decode_Arg_3_OutputChoice);
    if(*Decode_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Decode_Arg_3), (VOID *)Decode_Arg_3);
    }
    Status = ProtocolVariable->Decode(
        ProtocolVariable,
        Decode_Arg_1,
        Decode_Arg_2,
        Decode_Arg_3,
        Decode_Arg_4
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
    EFI_LEGACY_REGION2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiLegacyRegion2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 Lock_Arg_1 = 0;
    UINT32 Lock_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Lock_Arg_1), (VOID *)&Lock_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Lock_Arg_2), (VOID *)&Lock_Arg_2);
    
    /*
        Output Variable(s)
    */
    UINT32 * Lock_Arg_3 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT8* Lock_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Lock_Arg_3_OutputChoice), (VOID *)Lock_Arg_3_OutputChoice);
    if(*Lock_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Lock_Arg_3), (VOID *)Lock_Arg_3);
    }
    Status = ProtocolVariable->Lock(
        ProtocolVariable,
        Lock_Arg_1,
        Lock_Arg_2,
        Lock_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called BootLock.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzBootLock(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_LEGACY_REGION2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiLegacyRegion2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 BootLock_Arg_1 = 0;
    UINT32 BootLock_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(BootLock_Arg_1), (VOID *)&BootLock_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(BootLock_Arg_2), (VOID *)&BootLock_Arg_2);
    
    Status = ProtocolVariable->BootLock(
        ProtocolVariable,
        BootLock_Arg_1,
        BootLock_Arg_2,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UnLock.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUnLock(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_LEGACY_REGION2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiLegacyRegion2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 UnLock_Arg_1 = 0;
    UINT32 UnLock_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UnLock_Arg_1), (VOID *)&UnLock_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UnLock_Arg_2), (VOID *)&UnLock_Arg_2);
    
    /*
        Output Variable(s)
    */
    UINT32 * UnLock_Arg_3 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT8* UnLock_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(UnLock_Arg_3_OutputChoice), (VOID *)UnLock_Arg_3_OutputChoice);
    if(*UnLock_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*UnLock_Arg_3), (VOID *)UnLock_Arg_3);
    }
    Status = ProtocolVariable->UnLock(
        ProtocolVariable,
        UnLock_Arg_1,
        UnLock_Arg_2,
        UnLock_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetInfo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_LEGACY_REGION2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiLegacyRegion2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINT32 * GetInfo_Arg_1 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT8* GetInfo_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetInfo_Arg_1_OutputChoice), (VOID *)GetInfo_Arg_1_OutputChoice);
    if(*GetInfo_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetInfo_Arg_1), (VOID *)GetInfo_Arg_1);
    }
    EFI_LEGACY_REGION_DESCRIPTOR * * GetInfo_Arg_2 = (EFI_LEGACY_REGION_DESCRIPTOR * *)AllocateZeroPool(sizeof(EFI_LEGACY_REGION_DESCRIPTOR));
    UINT8* GetInfo_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetInfo_Arg_2_OutputChoice), (VOID *)GetInfo_Arg_2_OutputChoice);
    if(*GetInfo_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetInfo_Arg_2), (VOID *)GetInfo_Arg_2);
    }
    Status = ProtocolVariable->GetInfo(
        ProtocolVariable,
        GetInfo_Arg_1,
        &GetInfo_Arg_2
    );
    return Status;
}

