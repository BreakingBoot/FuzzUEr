#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the Protocols service
    called IsBrowserDataModified.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzIsBrowserDataModified(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_FORM_BROWSER_EXTENSION2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiFormBrowserEx2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    ProtocolVariable->IsBrowserDataModified(
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called ExecuteAction.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzExecuteAction(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_FORM_BROWSER_EXTENSION2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiFormBrowserEx2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 ExecuteAction_Arg_0 = 0;
    UINT16 ExecuteAction_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ExecuteAction_Arg_0), (VOID *)&ExecuteAction_Arg_0);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ExecuteAction_Arg_1), (VOID *)&ExecuteAction_Arg_1);
    
    Status = ProtocolVariable->ExecuteAction(
        ExecuteAction_Arg_0,
        ExecuteAction_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called IsResetRequired.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzIsResetRequired(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_FORM_BROWSER_EXTENSION2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiFormBrowserEx2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    ProtocolVariable->IsResetRequired(
    );
    return Status;
}

