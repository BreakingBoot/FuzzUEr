#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called Execute.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzExecute(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_EBC_VM_TEST_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiEbcVmTestProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * Execute_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    UINT8 Execute_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(Execute_Arg_2_choice), (VOID *)&Execute_Arg_2_choice);
    switch(Execute_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Execute_Arg_2), (VOID *)Execute_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(Execute_Arg_2);
            Execute_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->Execute(
        ProtocolVariable,
        NULL,
        Execute_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Assemble.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAssemble(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_EBC_VM_TEST_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiEbcVmTestProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * Assemble_Arg_1 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    INT8 * Assemble_Arg_2 = (INT8 *)AllocateZeroPool(sizeof(INT8));
    UINTN * Assemble_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    UINT8 Assemble_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(Assemble_Arg_1_choice), (VOID *)&Assemble_Arg_1_choice);
    switch(Assemble_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Assemble_Arg_1), (VOID *)Assemble_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(Assemble_Arg_1);
            Assemble_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 Assemble_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(Assemble_Arg_2_choice), (VOID *)&Assemble_Arg_2_choice);
    switch(Assemble_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Assemble_Arg_2), (VOID *)Assemble_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(Assemble_Arg_2);
            Assemble_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 Assemble_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(Assemble_Arg_3_choice), (VOID *)&Assemble_Arg_3_choice);
    switch(Assemble_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Assemble_Arg_3), (VOID *)Assemble_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(Assemble_Arg_3);
            Assemble_Arg_3 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->Assemble(
        ProtocolVariable,
        Assemble_Arg_1,
        Assemble_Arg_2,
        Assemble_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Disassemble.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDisassemble(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_EBC_VM_TEST_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiEbcVmTestProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * Disassemble_Arg_1 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    INT8 * Disassemble_Arg_2 = (INT8 *)AllocateZeroPool(sizeof(INT8));
    UINTN * Disassemble_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    UINT8 Disassemble_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(Disassemble_Arg_1_choice), (VOID *)&Disassemble_Arg_1_choice);
    switch(Disassemble_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Disassemble_Arg_1), (VOID *)Disassemble_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(Disassemble_Arg_1);
            Disassemble_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 Disassemble_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(Disassemble_Arg_2_choice), (VOID *)&Disassemble_Arg_2_choice);
    switch(Disassemble_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Disassemble_Arg_2), (VOID *)Disassemble_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(Disassemble_Arg_2);
            Disassemble_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 Disassemble_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(Disassemble_Arg_3_choice), (VOID *)&Disassemble_Arg_3_choice);
    switch(Disassemble_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Disassemble_Arg_3), (VOID *)Disassemble_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(Disassemble_Arg_3);
            Disassemble_Arg_3 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->Disassemble(
        ProtocolVariable,
        Disassemble_Arg_1,
        Disassemble_Arg_2,
        Disassemble_Arg_3
    );
    return Status;
}

