#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called TapeRead.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzTapeRead(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_TAPE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTapeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * TapeRead_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    UINT8 TapeRead_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(TapeRead_Arg_1_choice), (VOID *)&TapeRead_Arg_1_choice);
    switch(TapeRead_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(TapeRead_Arg_1), (VOID *)TapeRead_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(TapeRead_Arg_1);
            TapeRead_Arg_1 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    UINTN*  TapeRead_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT8* TapeRead_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(TapeRead_Arg_2_OutputChoice), (VOID *)TapeRead_Arg_2_OutputChoice);
    if(*TapeRead_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*TapeRead_Arg_2), (VOID *)TapeRead_Arg_2);
    }
    Status = ProtocolVariable->TapeRead(
        ProtocolVariable,
        TapeRead_Arg_1,
        (VOID *)TapeRead_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called TapeWrite.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzTapeWrite(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_TAPE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTapeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * TapeWrite_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN*  TapeWrite_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    UINT8 TapeWrite_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(TapeWrite_Arg_1_choice), (VOID *)&TapeWrite_Arg_1_choice);
    switch(TapeWrite_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(TapeWrite_Arg_1), (VOID *)TapeWrite_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(TapeWrite_Arg_1);
            TapeWrite_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 TapeWrite_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(TapeWrite_Arg_2_choice), (VOID *)&TapeWrite_Arg_2_choice);
    switch(TapeWrite_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(TapeWrite_Arg_2), (VOID *)TapeWrite_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(TapeWrite_Arg_2);
            TapeWrite_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->TapeWrite(
        ProtocolVariable,
        TapeWrite_Arg_1,
        (VOID *)TapeWrite_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called TapeRewind.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzTapeRewind(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_TAPE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTapeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->TapeRewind(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called TapeSpace.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzTapeSpace(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_TAPE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTapeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    INTN TapeSpace_Arg_1 = 0;
    UINTN TapeSpace_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(TapeSpace_Arg_1), (VOID *)&TapeSpace_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(TapeSpace_Arg_2), (VOID *)&TapeSpace_Arg_2);
    
    Status = ProtocolVariable->TapeSpace(
        ProtocolVariable,
        TapeSpace_Arg_1,
        TapeSpace_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called TapeWriteFM.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzTapeWriteFM(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_TAPE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTapeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN TapeWriteFM_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(TapeWriteFM_Arg_1), (VOID *)&TapeWriteFM_Arg_1);
    
    Status = ProtocolVariable->TapeWriteFM(
        ProtocolVariable,
        TapeWriteFM_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called TapeReset.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzTapeReset(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_TAPE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTapeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN TapeReset_Arg_1 = FALSE;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(TapeReset_Arg_1), (VOID *)&TapeReset_Arg_1);
    
    Status = ProtocolVariable->TapeReset(
        ProtocolVariable,
        TapeReset_Arg_1
    );
    return Status;
}

