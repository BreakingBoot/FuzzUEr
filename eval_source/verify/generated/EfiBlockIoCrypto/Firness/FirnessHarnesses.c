#include "FirnessHarnesses.h"

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
    EFI_BLOCK_IO_CRYPTO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBlockIoCryptoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN Reset_Arg_1 = FALSE;
    
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
    EFI_BLOCK_IO_CRYPTO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBlockIoCryptoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_BLOCK_IO_CRYPTO_CAPABILITIES * GetCapabilities_Arg_1 = (EFI_BLOCK_IO_CRYPTO_CAPABILITIES *)AllocateZeroPool(sizeof(EFI_BLOCK_IO_CRYPTO_CAPABILITIES));
    UINT8* GetCapabilities_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetCapabilities_Arg_1_OutputChoice), (VOID *)GetCapabilities_Arg_1_OutputChoice);
    if(*GetCapabilities_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetCapabilities_Arg_1), (VOID *)GetCapabilities_Arg_1);
    }
    Status = ProtocolVariable->GetCapabilities(
        ProtocolVariable,
        GetCapabilities_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetConfiguration.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetConfiguration(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLOCK_IO_CRYPTO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBlockIoCryptoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT64 SetConfiguration_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetConfiguration_Arg_1), (VOID *)&SetConfiguration_Arg_1);
    
    Status = ProtocolVariable->SetConfiguration(
        ProtocolVariable,
        SetConfiguration_Arg_1,
        NULL,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetConfiguration.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetConfiguration(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLOCK_IO_CRYPTO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBlockIoCryptoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT64 GetConfiguration_Arg_1 = 0;
    UINT64 GetConfiguration_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetConfiguration_Arg_1), (VOID *)&GetConfiguration_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetConfiguration_Arg_2), (VOID *)&GetConfiguration_Arg_2);
    
    /*
        Output Variable(s)
    */
    EFI_BLOCK_IO_CRYPTO_RESPONSE_CONFIGURATION_ENTRY * GetConfiguration_Arg_4 = (EFI_BLOCK_IO_CRYPTO_RESPONSE_CONFIGURATION_ENTRY *)AllocateZeroPool(sizeof(EFI_BLOCK_IO_CRYPTO_RESPONSE_CONFIGURATION_ENTRY));
    UINT8* GetConfiguration_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetConfiguration_Arg_4_OutputChoice), (VOID *)GetConfiguration_Arg_4_OutputChoice);
    if(*GetConfiguration_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetConfiguration_Arg_4), (VOID *)GetConfiguration_Arg_4);
    }
    Status = ProtocolVariable->GetConfiguration(
        ProtocolVariable,
        GetConfiguration_Arg_1,
        GetConfiguration_Arg_2,
        NULL,
        GetConfiguration_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ReadExtended.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzReadExtended(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLOCK_IO_CRYPTO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBlockIoCryptoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 ReadExtended_Arg_1 = 0;
    EFI_LBA ReadExtended_Arg_2 = 0;
    EFI_BLOCK_IO_CRYPTO_TOKEN * ReadExtended_Arg_3 = (EFI_BLOCK_IO_CRYPTO_TOKEN *)AllocateZeroPool(sizeof(EFI_BLOCK_IO_CRYPTO_TOKEN));
    UINT64 ReadExtended_Arg_4 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ReadExtended_Arg_1), (VOID *)&ReadExtended_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ReadExtended_Arg_2), (VOID *)&ReadExtended_Arg_2);
    
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ReadExtended_Arg_4), (VOID *)&ReadExtended_Arg_4);
    
    /*
        Output Variable(s)
    */
    UINTN*  ReadExtended_Arg_5 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT8* ReadExtended_Arg_5_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ReadExtended_Arg_5_OutputChoice), (VOID *)ReadExtended_Arg_5_OutputChoice);
    if(*ReadExtended_Arg_5_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ReadExtended_Arg_5), (VOID *)ReadExtended_Arg_5);
    }
    Status = ProtocolVariable->ReadExtended(
        ProtocolVariable,
        ReadExtended_Arg_1,
        ReadExtended_Arg_2,
        ReadExtended_Arg_3,
        ReadExtended_Arg_4,
        (VOID *)ReadExtended_Arg_5,
        NULL,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called WriteExtended.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzWriteExtended(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLOCK_IO_CRYPTO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBlockIoCryptoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 WriteExtended_Arg_1 = 0;
    EFI_LBA WriteExtended_Arg_2 = 0;
    EFI_BLOCK_IO_CRYPTO_TOKEN * WriteExtended_Arg_3 = (EFI_BLOCK_IO_CRYPTO_TOKEN *)AllocateZeroPool(sizeof(EFI_BLOCK_IO_CRYPTO_TOKEN));
    UINT64 WriteExtended_Arg_4 = 0;
    UINTN*  WriteExtended_Arg_5 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(WriteExtended_Arg_1), (VOID *)&WriteExtended_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(WriteExtended_Arg_2), (VOID *)&WriteExtended_Arg_2);
    
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(WriteExtended_Arg_4), (VOID *)&WriteExtended_Arg_4);
    
    // Fuzzable Variable Initialization
    UINT8 WriteExtended_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(WriteExtended_Arg_5_choice), (VOID *)&WriteExtended_Arg_5_choice);
    switch(WriteExtended_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(WriteExtended_Arg_5), (VOID *)WriteExtended_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(WriteExtended_Arg_5);
            WriteExtended_Arg_5 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->WriteExtended(
        ProtocolVariable,
        WriteExtended_Arg_1,
        WriteExtended_Arg_2,
        WriteExtended_Arg_3,
        WriteExtended_Arg_4,
        (VOID *)WriteExtended_Arg_5,
        NULL,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called FlushBlocks.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFlushBlocks(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLOCK_IO_CRYPTO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBlockIoCryptoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_BLOCK_IO_CRYPTO_TOKEN * FlushBlocks_Arg_1 = (EFI_BLOCK_IO_CRYPTO_TOKEN *)AllocateZeroPool(sizeof(EFI_BLOCK_IO_CRYPTO_TOKEN));
    
    
    Status = ProtocolVariable->FlushBlocks(
        ProtocolVariable,
        FlushBlocks_Arg_1
    );
    return Status;
}

