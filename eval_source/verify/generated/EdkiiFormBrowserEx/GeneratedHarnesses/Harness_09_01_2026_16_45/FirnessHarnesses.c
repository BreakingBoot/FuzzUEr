#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the Protocols service
    called SetScope.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetScope(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_FORM_BROWSER_EXTENSION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiFormBrowserExProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->SetScope(
        (BROWSER_SETTING_SCOPE){0}
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called RegisterHotKey.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterHotKey(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_FORM_BROWSER_EXTENSION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiFormBrowserExProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_INPUT_KEY * RegisterHotKey_Arg_0 = (EFI_INPUT_KEY *)AllocateZeroPool(sizeof(EFI_INPUT_KEY));
    UINT32 RegisterHotKey_Arg_1 = 0;
    UINT16 RegisterHotKey_Arg_2 = 0;
    
    // Generator Struct Variable Initialization
    {
        UINT16 Firness_ScanCode;
        ReadBytes(Input, sizeof(Firness_ScanCode), (VOID *)&Firness_ScanCode);
        RegisterHotKey_Arg_0->ScanCode = Firness_ScanCode;
    }
    {
        CHAR16 Firness_UnicodeChar;
        ReadBytes(Input, sizeof(Firness_UnicodeChar), (VOID *)&Firness_UnicodeChar);
        RegisterHotKey_Arg_0->UnicodeChar = Firness_UnicodeChar;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RegisterHotKey_Arg_1), (VOID *)&RegisterHotKey_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RegisterHotKey_Arg_2), (VOID *)&RegisterHotKey_Arg_2);
    
    Status = ProtocolVariable->RegisterHotKey(
        RegisterHotKey_Arg_0,
        RegisterHotKey_Arg_1,
        RegisterHotKey_Arg_2,
        (EFI_STRING){0}
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called RegiserExitHandler.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegiserExitHandler(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_FORM_BROWSER_EXTENSION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiFormBrowserExProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    ProtocolVariable->RegiserExitHandler(
        (EXIT_HANDLER){0}
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called SaveReminder.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSaveReminder(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_FORM_BROWSER_EXTENSION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiFormBrowserExProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    ProtocolVariable->SaveReminder(
    );
    return Status;
}

