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
    EFI_DEBUGPORT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDebugPortProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Reset(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Write.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzWrite(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DEBUGPORT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDebugPortProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 Write_Arg_1 = 0;
    UINTN * Write_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN*  Write_Arg_3 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Write_Arg_1), (VOID *)&Write_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 Write_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(Write_Arg_2_choice), (VOID *)&Write_Arg_2_choice);
    switch(Write_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Write_Arg_2), (VOID *)Write_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(Write_Arg_2);
            Write_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 Write_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(Write_Arg_3_choice), (VOID *)&Write_Arg_3_choice);
    switch(Write_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Write_Arg_3), (VOID *)Write_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(Write_Arg_3);
            Write_Arg_3 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->Write(
        ProtocolVariable,
        Write_Arg_1,
        Write_Arg_2,
        (VOID *)Write_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Read.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRead(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DEBUGPORT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDebugPortProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 Read_Arg_1 = 0;
    UINTN * Read_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Read_Arg_1), (VOID *)&Read_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 Read_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(Read_Arg_2_choice), (VOID *)&Read_Arg_2_choice);
    switch(Read_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Read_Arg_2), (VOID *)Read_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(Read_Arg_2);
            Read_Arg_2 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    UINTN*  Read_Arg_3 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT8* Read_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Read_Arg_3_OutputChoice), (VOID *)Read_Arg_3_OutputChoice);
    if(*Read_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Read_Arg_3), (VOID *)Read_Arg_3);
    }
    Status = ProtocolVariable->Read(
        ProtocolVariable,
        Read_Arg_1,
        Read_Arg_2,
        (VOID *)Read_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Poll.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzPoll(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DEBUGPORT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDebugPortProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Poll(
        ProtocolVariable
    );
    return Status;
}

