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
    EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleTextInputExProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    called ReadKeyStrokeEx.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzReadKeyStrokeEx(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleTextInputExProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_KEY_DATA * ReadKeyStrokeEx_Arg_1 = (EFI_KEY_DATA *)AllocateZeroPool(sizeof(EFI_KEY_DATA));
    
    // Generator Struct Variable Initialization
    {
        EFI_INPUT_KEY Firness_Key;
        ReadBytes(Input, sizeof(Firness_Key), (VOID *)&Firness_Key);
        ReadKeyStrokeEx_Arg_1->Key = Firness_Key;
    }
    {
        EFI_KEY_STATE Firness_KeyState;
        ReadBytes(Input, sizeof(Firness_KeyState), (VOID *)&Firness_KeyState);
        ReadKeyStrokeEx_Arg_1->KeyState = Firness_KeyState;
    }
    
    Status = ProtocolVariable->ReadKeyStrokeEx(
        ProtocolVariable,
        ReadKeyStrokeEx_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetState.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetState(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleTextInputExProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_KEY_TOGGLE_STATE * SetState_Arg_1 = (EFI_KEY_TOGGLE_STATE *)AllocateZeroPool(sizeof(EFI_KEY_TOGGLE_STATE));
    
    // Fuzzable Variable Initialization
    UINT8 SetState_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(SetState_Arg_1_choice), (VOID *)&SetState_Arg_1_choice);
    switch(SetState_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetState_Arg_1), (VOID *)SetState_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(SetState_Arg_1);
            SetState_Arg_1 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->SetState(
        ProtocolVariable,
        SetState_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RegisterKeyNotify.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterKeyNotify(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleTextInputExProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_KEY_DATA * RegisterKeyNotify_Arg_1 = (EFI_KEY_DATA *)AllocateZeroPool(sizeof(EFI_KEY_DATA));
    UINTN* RegisterKeyNotify_Arg_3 = (UINTN*)AllocateZeroPool(sizeof(UINTN));
    
    // Generator Struct Variable Initialization
    {
        EFI_INPUT_KEY Firness_Key;
        ReadBytes(Input, sizeof(Firness_Key), (VOID *)&Firness_Key);
        RegisterKeyNotify_Arg_1->Key = Firness_Key;
    }
    {
        EFI_KEY_STATE Firness_KeyState;
        ReadBytes(Input, sizeof(Firness_KeyState), (VOID *)&Firness_KeyState);
        RegisterKeyNotify_Arg_1->KeyState = Firness_KeyState;
    }
    
    // Fuzzable Variable Initialization
    UINT8 RegisterKeyNotify_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(RegisterKeyNotify_Arg_3_choice), (VOID *)&RegisterKeyNotify_Arg_3_choice);
    switch(RegisterKeyNotify_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(RegisterKeyNotify_Arg_3), (VOID *)RegisterKeyNotify_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(RegisterKeyNotify_Arg_3);
            RegisterKeyNotify_Arg_3 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->RegisterKeyNotify(
        ProtocolVariable,
        RegisterKeyNotify_Arg_1,
        NULL,
        (void **)&RegisterKeyNotify_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UnregisterKeyNotify.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUnregisterKeyNotify(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleTextInputExProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  UnregisterKeyNotify_Arg_1 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    UINT8 UnregisterKeyNotify_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(UnregisterKeyNotify_Arg_1_choice), (VOID *)&UnregisterKeyNotify_Arg_1_choice);
    switch(UnregisterKeyNotify_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UnregisterKeyNotify_Arg_1), (VOID *)UnregisterKeyNotify_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(UnregisterKeyNotify_Arg_1);
            UnregisterKeyNotify_Arg_1 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->UnregisterKeyNotify(
        ProtocolVariable,
        (void *)UnregisterKeyNotify_Arg_1
    );
    return Status;
}

