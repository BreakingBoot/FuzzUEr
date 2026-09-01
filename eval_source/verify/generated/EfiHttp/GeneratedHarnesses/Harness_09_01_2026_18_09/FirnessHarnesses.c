#include "FirnessHarnesses.h"

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
    EFI_HTTP_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHttpProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HTTP_CONFIG_DATA * Configure_Arg_1 = (EFI_HTTP_CONFIG_DATA *)AllocateZeroPool(sizeof(EFI_HTTP_CONFIG_DATA));
    
    // Generator Struct Variable Initialization
    {
        EFI_HTTP_VERSION Firness_HttpVersion;
        ReadBytes(Input, sizeof(Firness_HttpVersion), (VOID *)&Firness_HttpVersion);
        Configure_Arg_1->HttpVersion = Firness_HttpVersion;
    }
    {
        UINT32 Firness_TimeOutMillisec;
        ReadBytes(Input, sizeof(Firness_TimeOutMillisec), (VOID *)&Firness_TimeOutMillisec);
        Configure_Arg_1->TimeOutMillisec = Firness_TimeOutMillisec;
    }
    {
        BOOLEAN Firness_LocalAddressIsIPv6;
        ReadBytes(Input, sizeof(Firness_LocalAddressIsIPv6), (VOID *)&Firness_LocalAddressIsIPv6);
        Configure_Arg_1->LocalAddressIsIPv6 = Firness_LocalAddressIsIPv6;
    }
    ReadBytes(Input, sizeof(Configure_Arg_1->AccessPoint), (VOID *)&(Configure_Arg_1->AccessPoint));
    
    Status = ProtocolVariable->Configure(
        ProtocolVariable,
        Configure_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Request.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRequest(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HTTP_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHttpProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Request(
        ProtocolVariable,
        NULL
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
    EFI_HTTP_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHttpProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Poll(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Response.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzResponse(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HTTP_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHttpProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Response(
        ProtocolVariable,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Cancel.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzCancel(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HTTP_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHttpProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Cancel(
        ProtocolVariable,
        NULL
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
    EFI_HTTP_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHttpProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_HTTP_CONFIG_DATA * GetModeData_Arg_1 = (EFI_HTTP_CONFIG_DATA *)AllocateZeroPool(sizeof(EFI_HTTP_CONFIG_DATA));
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

