#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called OutputString.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzOutputString(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleTextOutProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * OutputString_Arg_1 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    
    // Fuzzable Variable Initialization
    UINT8 OutputString_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(OutputString_Arg_1_choice), (VOID *)&OutputString_Arg_1_choice);
    switch(OutputString_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(OutputString_Arg_1), (VOID *)OutputString_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(OutputString_Arg_1);
            OutputString_Arg_1 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->OutputString(
        ProtocolVariable,
        OutputString_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called TestString.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzTestString(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleTextOutProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * TestString_Arg_1 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    
    // Fuzzable Variable Initialization
    UINT8 TestString_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(TestString_Arg_1_choice), (VOID *)&TestString_Arg_1_choice);
    switch(TestString_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(TestString_Arg_1), (VOID *)TestString_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(TestString_Arg_1);
            TestString_Arg_1 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->TestString(
        ProtocolVariable,
        TestString_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called QueryMode.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzQueryMode(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleTextOutProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN QueryMode_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(QueryMode_Arg_1), (VOID *)&QueryMode_Arg_1);
    
    /*
        Output Variable(s)
    */
    UINTN * QueryMode_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* QueryMode_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(QueryMode_Arg_2_OutputChoice), (VOID *)QueryMode_Arg_2_OutputChoice);
    if(*QueryMode_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*QueryMode_Arg_2), (VOID *)QueryMode_Arg_2);
    }
    UINTN * QueryMode_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* QueryMode_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(QueryMode_Arg_3_OutputChoice), (VOID *)QueryMode_Arg_3_OutputChoice);
    if(*QueryMode_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*QueryMode_Arg_3), (VOID *)QueryMode_Arg_3);
    }
    Status = ProtocolVariable->QueryMode(
        ProtocolVariable,
        QueryMode_Arg_1,
        QueryMode_Arg_2,
        QueryMode_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetMode.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetMode(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleTextOutProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN SetMode_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetMode_Arg_1), (VOID *)&SetMode_Arg_1);
    
    Status = ProtocolVariable->SetMode(
        ProtocolVariable,
        SetMode_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetAttribute.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetAttribute(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleTextOutProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN SetAttribute_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetAttribute_Arg_1), (VOID *)&SetAttribute_Arg_1);
    
    Status = ProtocolVariable->SetAttribute(
        ProtocolVariable,
        SetAttribute_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ClearScreen.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzClearScreen(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleTextOutProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->ClearScreen(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetCursorPosition.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetCursorPosition(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleTextOutProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN SetCursorPosition_Arg_1 = 0;
    UINTN SetCursorPosition_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetCursorPosition_Arg_1), (VOID *)&SetCursorPosition_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetCursorPosition_Arg_2), (VOID *)&SetCursorPosition_Arg_2);
    
    Status = ProtocolVariable->SetCursorPosition(
        ProtocolVariable,
        SetCursorPosition_Arg_1,
        SetCursorPosition_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called EnableCursor.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzEnableCursor(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleTextOutProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN EnableCursor_Arg_1 = FALSE;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(EnableCursor_Arg_1), (VOID *)&EnableCursor_Arg_1);
    
    Status = ProtocolVariable->EnableCursor(
        ProtocolVariable,
        EnableCursor_Arg_1
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
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleTextOutProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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

