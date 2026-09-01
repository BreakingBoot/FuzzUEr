#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called SendReceive.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSendReceive(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_REST_EX_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiRestExProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_HTTP_MESSAGE * SendReceive_Arg_2 = (EFI_HTTP_MESSAGE *)AllocateZeroPool(sizeof(EFI_HTTP_MESSAGE));
    UINT8* SendReceive_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SendReceive_Arg_2_OutputChoice), (VOID *)SendReceive_Arg_2_OutputChoice);
    if(*SendReceive_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*SendReceive_Arg_2), (VOID *)SendReceive_Arg_2);
    }
    Status = ProtocolVariable->SendReceive(
        ProtocolVariable,
        NULL,
        SendReceive_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetServiceTime.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetServiceTime(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_REST_EX_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiRestExProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_TIME * GetServiceTime_Arg_1 = (EFI_TIME *)AllocateZeroPool(sizeof(EFI_TIME));
    UINT8* GetServiceTime_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetServiceTime_Arg_1_OutputChoice), (VOID *)GetServiceTime_Arg_1_OutputChoice);
    if(*GetServiceTime_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetServiceTime_Arg_1), (VOID *)GetServiceTime_Arg_1);
    }
    Status = ProtocolVariable->GetServiceTime(
        ProtocolVariable,
        GetServiceTime_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetService.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetService(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_REST_EX_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiRestExProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_REST_EX_SERVICE_INFO * * GetService_Arg_1 = (EFI_REST_EX_SERVICE_INFO * *)AllocateZeroPool(sizeof(EFI_REST_EX_SERVICE_INFO));
    UINT8* GetService_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetService_Arg_1_OutputChoice), (VOID *)GetService_Arg_1_OutputChoice);
    if(*GetService_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetService_Arg_1), (VOID *)GetService_Arg_1);
    }
    Status = ProtocolVariable->GetService(
        ProtocolVariable,
        &GetService_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetModeData.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetModeData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_REST_EX_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiRestExProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_REST_EX_CONFIG_DATA * GetModeData_Arg_1 = (EFI_REST_EX_CONFIG_DATA *)AllocateZeroPool(sizeof(EFI_REST_EX_CONFIG_DATA));
    UINT8* GetModeData_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetModeData_Arg_1_OutputChoice), (VOID *)GetModeData_Arg_1_OutputChoice);
    if(*GetModeData_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetModeData_Arg_1), (VOID *)GetModeData_Arg_1);
    }
    Status = ProtocolVariable->GetModeData(
        ProtocolVariable,
        GetModeData_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Configure.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzConfigure(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_REST_EX_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiRestExProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Configure(
        ProtocolVariable,
        (EFI_REST_EX_CONFIG_DATA){0}
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called AyncSendReceive.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAyncSendReceive(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_REST_EX_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiRestExProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->AyncSendReceive(
        ProtocolVariable,
        NULL,
        NULL,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called EventService.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzEventService(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_REST_EX_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiRestExProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->EventService(
        ProtocolVariable,
        NULL,
        NULL
    );
    return Status;
}

