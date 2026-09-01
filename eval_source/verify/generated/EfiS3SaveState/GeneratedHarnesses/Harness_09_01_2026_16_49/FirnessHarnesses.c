#include "FirnessHarnesses.h"

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
    EFI_S3_SAVE_STATE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiS3SaveStateProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN Write_Arg_1 = 0;
    
    UINT8* Write_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Write_Arg_1_choice), (VOID *)Write_Arg_1_choice);
    switch(*Write_Arg_1_choice % 2) {
        case 0:
        {
        // Constant Variable Initialization
        Write_Arg_1 = EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE_OPCODE;
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(Write_Arg_1), (VOID *)&Write_Arg_1);
    
            break;
        }
    }
    Status = ProtocolVariable->Write(
        ProtocolVariable,
        Write_Arg_1,
        (INT32){0},
        (UINT64){0},
        NULL,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Label.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzLabel(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_S3_SAVE_STATE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiS3SaveStateProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN Label_Arg_1 = FALSE;
    BOOLEAN Label_Arg_2 = FALSE;
    EFI_S3_BOOT_SCRIPT_POSITION * Label_Arg_3 = (EFI_S3_BOOT_SCRIPT_POSITION *)AllocateZeroPool(sizeof(EFI_S3_BOOT_SCRIPT_POSITION));
    CHAR8 * Label_Arg_4 = (CHAR8 *)AllocateZeroPool(sizeof(CHAR8));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Label_Arg_1), (VOID *)&Label_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Label_Arg_2), (VOID *)&Label_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 Label_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(Label_Arg_3_choice), (VOID *)&Label_Arg_3_choice);
    switch(Label_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Label_Arg_3), (VOID *)Label_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(Label_Arg_3);
            Label_Arg_3 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 Label_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(Label_Arg_4_choice), (VOID *)&Label_Arg_4_choice);
    switch(Label_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Label_Arg_4), (VOID *)Label_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(Label_Arg_4);
            Label_Arg_4 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->Label(
        ProtocolVariable,
        Label_Arg_1,
        Label_Arg_2,
        Label_Arg_3,
        Label_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Compare.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzCompare(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_S3_SAVE_STATE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiS3SaveStateProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_S3_BOOT_SCRIPT_POSITION Compare_Arg_1 = 0;
    EFI_S3_BOOT_SCRIPT_POSITION Compare_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Compare_Arg_1), (VOID *)&Compare_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Compare_Arg_2), (VOID *)&Compare_Arg_2);
    
    /*
        Output Variable(s)
    */
    UINTN * Compare_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* Compare_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Compare_Arg_3_OutputChoice), (VOID *)Compare_Arg_3_OutputChoice);
    if(*Compare_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Compare_Arg_3), (VOID *)Compare_Arg_3);
    }
    Status = ProtocolVariable->Compare(
        ProtocolVariable,
        Compare_Arg_1,
        Compare_Arg_2,
        Compare_Arg_3
    );
    return Status;
}

