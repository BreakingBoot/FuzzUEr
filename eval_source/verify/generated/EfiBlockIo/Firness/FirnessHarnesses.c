#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called ReadBlocks.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzReadBlocks(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLOCK_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBlockIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 ReadBlocks_Arg_1 = 0;
    EFI_LBA ReadBlocks_Arg_2 = 0;
    UINTN ReadBlocks_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ReadBlocks_Arg_1), (VOID *)&ReadBlocks_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ReadBlocks_Arg_2), (VOID *)&ReadBlocks_Arg_2);
    
    UINT8* ReadBlocks_Arg_3_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ReadBlocks_Arg_3_choice), (VOID *)ReadBlocks_Arg_3_choice);
    switch(*ReadBlocks_Arg_3_choice % 6) {
        case 0:
        {
        // Constant Variable Initialization
        ReadBlocks_Arg_3 = kEmptyHashValue;
    
            break;
        }
        case 1:
        {
    
            break;
        }
        case 2:
        {
    
            break;
        }
        case 3:
        {
    
            break;
        }
        case 4:
        {
    
            break;
        }
        case 5:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(ReadBlocks_Arg_3), (VOID *)&ReadBlocks_Arg_3);
    
            break;
        }
    }
    /*
        Output Variable(s)
    */
    UINTN*  ReadBlocks_Arg_4 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT8* ReadBlocks_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ReadBlocks_Arg_4_OutputChoice), (VOID *)ReadBlocks_Arg_4_OutputChoice);
    if(*ReadBlocks_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ReadBlocks_Arg_4), (VOID *)ReadBlocks_Arg_4);
    }
    Status = ProtocolVariable->ReadBlocks(
        ProtocolVariable,
        ReadBlocks_Arg_1,
        ReadBlocks_Arg_2,
        ReadBlocks_Arg_3,
        (void *)ReadBlocks_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called WriteBlocks.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzWriteBlocks(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLOCK_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBlockIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 WriteBlocks_Arg_1 = 0;
    UINTN WriteBlocks_Arg_2 = 0;
    UINTN WriteBlocks_Arg_3 = 0;
    UINTN*  WriteBlocks_Arg_4 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(WriteBlocks_Arg_1), (VOID *)&WriteBlocks_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(WriteBlocks_Arg_2), (VOID *)&WriteBlocks_Arg_2);
    
    UINT8* WriteBlocks_Arg_3_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(WriteBlocks_Arg_3_choice), (VOID *)WriteBlocks_Arg_3_choice);
    switch(*WriteBlocks_Arg_3_choice % 5) {
        case 0:
        {
    
            break;
        }
        case 1:
        {
    
            break;
        }
        case 2:
        {
    
            break;
        }
        case 3:
        {
    
            break;
        }
        case 4:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(WriteBlocks_Arg_3), (VOID *)&WriteBlocks_Arg_3);
    
            break;
        }
    }
    UINT8* WriteBlocks_Arg_4_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(WriteBlocks_Arg_4_choice), (VOID *)WriteBlocks_Arg_4_choice);
    switch(*WriteBlocks_Arg_4_choice % 5) {
        case 0:
        {
    
            break;
        }
        case 1:
        {
    
            break;
        }
        case 2:
        {
    
            break;
        }
        case 3:
        {
    
            break;
        }
        case 4:
        {
        // Fuzzable Variable Initialization
        UINT8 WriteBlocks_Arg_4_choice = 0;
        ReadBytes(Input, sizeof(WriteBlocks_Arg_4_choice), (VOID *)&WriteBlocks_Arg_4_choice);
        switch(WriteBlocks_Arg_4_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(WriteBlocks_Arg_4), (VOID *)WriteBlocks_Arg_4);
                break;
            case 1:
            {
                gBS->FreePool(WriteBlocks_Arg_4);
                WriteBlocks_Arg_4 = NULL;
                break;
            }
        }
    
            break;
        }
    }
    Status = ProtocolVariable->WriteBlocks(
        ProtocolVariable,
        WriteBlocks_Arg_1,
        WriteBlocks_Arg_2,
        WriteBlocks_Arg_3,
        (void *)WriteBlocks_Arg_4
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
    EFI_BLOCK_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBlockIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->FlushBlocks(
        ProtocolVariable
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
    EFI_BLOCK_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBlockIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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

