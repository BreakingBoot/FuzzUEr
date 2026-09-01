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
    EFI_BLOCK_IO2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBlockIo2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    called WriteBlocksEx.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzWriteBlocksEx(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLOCK_IO2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBlockIo2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 WriteBlocksEx_Arg_1 = 0;
    UINT64 WriteBlocksEx_Arg_2 = 0;
    EFI_BLOCK_IO2_TOKEN * WriteBlocksEx_Arg_3 = (EFI_BLOCK_IO2_TOKEN *)AllocateZeroPool(sizeof(EFI_BLOCK_IO2_TOKEN));
    UINT64 WriteBlocksEx_Arg_4 = 0;
    UINTN*  WriteBlocksEx_Arg_5 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(WriteBlocksEx_Arg_1), (VOID *)&WriteBlocksEx_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(WriteBlocksEx_Arg_2), (VOID *)&WriteBlocksEx_Arg_2);
    
    
    UINT8* WriteBlocksEx_Arg_4_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(WriteBlocksEx_Arg_4_choice), (VOID *)WriteBlocksEx_Arg_4_choice);
    switch(*WriteBlocksEx_Arg_4_choice % 5) {
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
        ReadBytes(Input, sizeof(WriteBlocksEx_Arg_4), (VOID *)&WriteBlocksEx_Arg_4);
    
            break;
        }
    }
    UINT8* WriteBlocksEx_Arg_5_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(WriteBlocksEx_Arg_5_choice), (VOID *)WriteBlocksEx_Arg_5_choice);
    switch(*WriteBlocksEx_Arg_5_choice % 5) {
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
        UINT8 WriteBlocksEx_Arg_5_choice = 0;
        ReadBytes(Input, sizeof(WriteBlocksEx_Arg_5_choice), (VOID *)&WriteBlocksEx_Arg_5_choice);
        switch(WriteBlocksEx_Arg_5_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(WriteBlocksEx_Arg_5), (VOID *)WriteBlocksEx_Arg_5);
                break;
            case 1:
            {
                gBS->FreePool(WriteBlocksEx_Arg_5);
                WriteBlocksEx_Arg_5 = NULL;
                break;
            }
        }
    
            break;
        }
    }
    Status = ProtocolVariable->WriteBlocksEx(
        ProtocolVariable,
        WriteBlocksEx_Arg_1,
        WriteBlocksEx_Arg_2,
        WriteBlocksEx_Arg_3,
        WriteBlocksEx_Arg_4,
        (void *)WriteBlocksEx_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ReadBlocksEx.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzReadBlocksEx(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLOCK_IO2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBlockIo2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 ReadBlocksEx_Arg_1 = 0;
    UINT64 ReadBlocksEx_Arg_2 = 0;
    EFI_BLOCK_IO2_TOKEN * ReadBlocksEx_Arg_3 = (EFI_BLOCK_IO2_TOKEN *)AllocateZeroPool(sizeof(EFI_BLOCK_IO2_TOKEN));
    UINT64 ReadBlocksEx_Arg_4 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ReadBlocksEx_Arg_1), (VOID *)&ReadBlocksEx_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ReadBlocksEx_Arg_2), (VOID *)&ReadBlocksEx_Arg_2);
    
    
    UINT8* ReadBlocksEx_Arg_4_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ReadBlocksEx_Arg_4_choice), (VOID *)ReadBlocksEx_Arg_4_choice);
    switch(*ReadBlocksEx_Arg_4_choice % 5) {
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
        ReadBytes(Input, sizeof(ReadBlocksEx_Arg_4), (VOID *)&ReadBlocksEx_Arg_4);
    
            break;
        }
    }
    /*
        Output Variable(s)
    */
    UINTN*  ReadBlocksEx_Arg_5 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT8* ReadBlocksEx_Arg_5_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ReadBlocksEx_Arg_5_OutputChoice), (VOID *)ReadBlocksEx_Arg_5_OutputChoice);
    if(*ReadBlocksEx_Arg_5_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ReadBlocksEx_Arg_5), (VOID *)ReadBlocksEx_Arg_5);
    }
    Status = ProtocolVariable->ReadBlocksEx(
        ProtocolVariable,
        ReadBlocksEx_Arg_1,
        ReadBlocksEx_Arg_2,
        ReadBlocksEx_Arg_3,
        ReadBlocksEx_Arg_4,
        (void *)ReadBlocksEx_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called FlushBlocksEx.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFlushBlocksEx(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLOCK_IO2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiBlockIo2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_BLOCK_IO2_TOKEN * FlushBlocksEx_Arg_1 = (EFI_BLOCK_IO2_TOKEN *)AllocateZeroPool(sizeof(EFI_BLOCK_IO2_TOKEN));
    
    // Generator Struct Variable Initialization
    {
        EFI_EVENT Firness_Event;
        ReadBytes(Input, sizeof(Firness_Event), (VOID *)&Firness_Event);
        FlushBlocksEx_Arg_1->Event = Firness_Event;
    }
    {
        EFI_STATUS Firness_TransactionStatus;
        ReadBytes(Input, sizeof(Firness_TransactionStatus), (VOID *)&Firness_TransactionStatus);
        FlushBlocksEx_Arg_1->TransactionStatus = Firness_TransactionStatus;
    }
    
    Status = ProtocolVariable->FlushBlocksEx(
        ProtocolVariable,
        FlushBlocksEx_Arg_1
    );
    return Status;
}

