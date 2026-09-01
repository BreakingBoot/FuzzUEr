#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the Protocols service
    called FormDisplay.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFormDisplay(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_FORM_DISPLAY_ENGINE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiFormDisplayEngineProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    USER_INPUT * FormDisplay_Arg_1 = (USER_INPUT *)AllocateZeroPool(sizeof(USER_INPUT));
    UINT8* FormDisplay_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(FormDisplay_Arg_1_OutputChoice), (VOID *)FormDisplay_Arg_1_OutputChoice);
    if(*FormDisplay_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*FormDisplay_Arg_1), (VOID *)FormDisplay_Arg_1);
    }
    Status = ProtocolVariable->FormDisplay(
        NULL,
        FormDisplay_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called ExitDisplay.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzExitDisplay(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_FORM_DISPLAY_ENGINE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiFormDisplayEngineProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    ProtocolVariable->ExitDisplay(
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called ConfirmDataChange.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzConfirmDataChange(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_FORM_DISPLAY_ENGINE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiFormDisplayEngineProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    ProtocolVariable->ConfirmDataChange(
    );
    return Status;
}

