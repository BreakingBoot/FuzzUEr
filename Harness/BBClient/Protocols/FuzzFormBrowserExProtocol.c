#include "FuzzFormBrowserExProtocol.h"


EFI_STATUS
EFIAPI
FuzzFormBrowserExProtocol(
    IN INPUT_BUFFER* Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: FormBrowserExProtocol\n"));
    UINTN ProtocolChoice = 0;
    ReadInput(Input, 1, ProtocolChoice);
    switch(ProtocolChoice%4)
    {
        case SET_SCOPE:
            Status = FuzzSetScope(Input);
            break;
        case REGISTER_HOT_KEY:
            Status = FuzzRegisterHotKey(Input);
            break;
        case REGISTER_EXIT_HANDLER:
            Status = FuzzRegisterExitHandler(Input);
            break;
        case SAVE_REMINDER:
            Status = FuzzSaveReminder(Input);
            break;
    }

    return Status;
}

EFI_STATUS
EFIAPI
FuzzSetScope(
    IN INPUT_BUFFER* Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: SetScope\n"));
    EDKII_FORM_BROWSER_EXTENSION_PROTOCOL *FormBrowserExtensionProtocol;
    gBS->LocateProtocol(&gEdkiiFormBrowserExProtocolGuid, NULL, (VOID **)&FormBrowserExtensionProtocol);

    BROWSER_SETTING_SCOPE Scope;
    UINTN ScopeChoice = 0;
    ReadInput(Input, 1, &ScopeChoice);
    switch(ScopeChoice%4)
    {
        case 0:
            Scope = FormLevel;
            break;
        case 1:
            Scope = FormSetLevel;
            break;
        case 2:
            Scope = SystemLevel;
            break;
        case 3:
            Scope = MaxLevel;
            break;
    }

    Status = FormBrowserExtensionProtocol->SetScope(Scope);

    return Status;
}


EFI_STATUS
EFIAPI
FuzzRegisterHotKey(
    IN INPUT_BUFFER* Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: RegisterHotKey\n"));
    EDKII_FORM_BROWSER_EXTENSION_PROTOCOL *FormBrowserExtensionProtocol;
    gBS->LocateProtocol(&gEdkiiFormBrowserExProtocolGuid, NULL, (VOID **)&FormBrowserExtensionProtocol);
    EFI_INPUT_KEY HotKey;

    UINTN HotKeyChoice = 0;
    ReadInput(Input, 1, &HotKeyChoice);
    HotKey.UnicodeChar = ConvertKeyboardScanCodeToEfiKey[HotKeyChoice%(sizeof(ConvertKeyboardScanCodeToEfiKey)/sizeof(ConvertKeyboardScanCodeToEfiKey[0]))];
    HotKey.ScanCode = ConvertKeyboardScanCodeToEfiKey[HotKeyChoice%(sizeof(ConvertKeyboardScanCodeToEfiKey)/sizeof(ConvertKeyboardScanCodeToEfiKey[0]))];

    UINT32 Actions = 0;
    UINTN NumOfActions = 0;
    UINTN ActionChoice = 0;
    ReadInput(Input, 1, &NumOfActions);
    for(UINTN i = 0; i < NumOfActions; i++)
    {
        ReadInput(Input, 1, &ActionChoice);
        switch(ActionChoice%7)
        {
            case 0:
                Actions |= BROWSER_ACTION_UNREGISTER;
                break;
            case 1:
                Actions |= BROWSER_ACTION_DISCARD;
                break;
            case 2:
                Actions |= BROWSER_ACTION_DEFAULT;
                break;
            case 3:
                Actions |= BROWSER_ACTION_SUBMIT;
                break;
            case 4:
                Actions |= BROWSER_ACTION_RESET;
                break;
            case 5:
                Actions |= BROWSER_ACTION_EXIT;
                break;
            case 6:
                Actions |= BROWSER_ACTION_GOTO;
                break;
        }
        ActionChoice = 0;
    }
    

    UINT16 DefaultId = 0;
    ReadInput(Input, 1, &DefaultId);

    CHAR16 *HelpString = NULL;
    ReadInput(Input, 3, HelpString);


    Status = FormBrowserExtensionProtocol->RegisterHotKey(&HotKey, Actions, DefaultId, HelpString);

    return Status;
}

EFI_STATUS
EFIAPI
FuzzRegisterExitHandler(
    IN INPUT_BUFFER* Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: RegisterExitHandler\n"));
    EDKII_FORM_BROWSER_EXTENSION_PROTOCOL *FormBrowserExtensionProtocol;
    gBS->LocateProtocol(&gEdkiiFormBrowserExProtocolGuid, NULL, (VOID **)&FormBrowserExtensionProtocol);

    return Status;
}

EFI_STATUS
EFIAPI
FuzzSaveReminder(
    IN INPUT_BUFFER* Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: SaveReminder\n"));
    EDKII_FORM_BROWSER_EXTENSION_PROTOCOL *FormBrowserExtensionProtocol;
    gBS->LocateProtocol(&gEdkiiFormBrowserExProtocolGuid, NULL, (VOID **)&FormBrowserExtensionProtocol);
    Status = FormBrowserExtensionProtocol->SaveReminder();

    return Status;
}