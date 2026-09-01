#include "FirnessHarnesses.h"

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
    EFI_MTFTP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMtftp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_MTFTP4_MODE_DATA * GetModeData_Arg_1 = (EFI_MTFTP4_MODE_DATA *)AllocateZeroPool(sizeof(EFI_MTFTP4_MODE_DATA));
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
    EFI_MTFTP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMtftp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_MTFTP4_CONFIG_DATA * Configure_Arg_1 = (EFI_MTFTP4_CONFIG_DATA *)AllocateZeroPool(sizeof(EFI_MTFTP4_CONFIG_DATA));
    
    // Generator Struct Variable Initialization
    {
        BOOLEAN Firness_UseDefaultSetting;
        ReadBytes(Input, sizeof(Firness_UseDefaultSetting), (VOID *)&Firness_UseDefaultSetting);
        Configure_Arg_1->UseDefaultSetting = Firness_UseDefaultSetting;
    }
    {
        EFI_IPv4_ADDRESS Firness_StationIp;
        ReadBytes(Input, sizeof(Firness_StationIp), (VOID *)&Firness_StationIp);
        Configure_Arg_1->StationIp = Firness_StationIp;
    }
    {
        EFI_IPv4_ADDRESS Firness_SubnetMask;
        ReadBytes(Input, sizeof(Firness_SubnetMask), (VOID *)&Firness_SubnetMask);
        Configure_Arg_1->SubnetMask = Firness_SubnetMask;
    }
    {
        UINT16 Firness_LocalPort;
        ReadBytes(Input, sizeof(Firness_LocalPort), (VOID *)&Firness_LocalPort);
        Configure_Arg_1->LocalPort = Firness_LocalPort;
    }
    {
        EFI_IPv4_ADDRESS Firness_GatewayIp;
        ReadBytes(Input, sizeof(Firness_GatewayIp), (VOID *)&Firness_GatewayIp);
        Configure_Arg_1->GatewayIp = Firness_GatewayIp;
    }
    {
        EFI_IPv4_ADDRESS Firness_ServerIp;
        ReadBytes(Input, sizeof(Firness_ServerIp), (VOID *)&Firness_ServerIp);
        Configure_Arg_1->ServerIp = Firness_ServerIp;
    }
    {
        UINT16 Firness_InitialServerPort;
        ReadBytes(Input, sizeof(Firness_InitialServerPort), (VOID *)&Firness_InitialServerPort);
        Configure_Arg_1->InitialServerPort = Firness_InitialServerPort;
    }
    {
        UINT16 Firness_TryCount;
        ReadBytes(Input, sizeof(Firness_TryCount), (VOID *)&Firness_TryCount);
        Configure_Arg_1->TryCount = Firness_TryCount;
    }
    {
        UINT16 Firness_TimeoutValue;
        ReadBytes(Input, sizeof(Firness_TimeoutValue), (VOID *)&Firness_TimeoutValue);
        Configure_Arg_1->TimeoutValue = Firness_TimeoutValue;
    }
    
    Status = ProtocolVariable->Configure(
        ProtocolVariable,
        Configure_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetInfo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MTFTP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMtftp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_MTFTP4_OVERRIDE_DATA * GetInfo_Arg_1 = (EFI_MTFTP4_OVERRIDE_DATA *)AllocateZeroPool(sizeof(EFI_MTFTP4_OVERRIDE_DATA));
    UINT8 * GetInfo_Arg_2 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT8 * GetInfo_Arg_3 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT8 GetInfo_Arg_4 = 0;
    EFI_MTFTP4_OPTION * GetInfo_Arg_5 = (EFI_MTFTP4_OPTION *)AllocateZeroPool(sizeof(EFI_MTFTP4_OPTION));
    
    // Generator Struct Variable Initialization
    {
        EFI_IPv4_ADDRESS Firness_GatewayIp;
        ReadBytes(Input, sizeof(Firness_GatewayIp), (VOID *)&Firness_GatewayIp);
        GetInfo_Arg_1->GatewayIp = Firness_GatewayIp;
    }
    {
        EFI_IPv4_ADDRESS Firness_ServerIp;
        ReadBytes(Input, sizeof(Firness_ServerIp), (VOID *)&Firness_ServerIp);
        GetInfo_Arg_1->ServerIp = Firness_ServerIp;
    }
    {
        UINT16 Firness_ServerPort;
        ReadBytes(Input, sizeof(Firness_ServerPort), (VOID *)&Firness_ServerPort);
        GetInfo_Arg_1->ServerPort = Firness_ServerPort;
    }
    {
        UINT16 Firness_TryCount;
        ReadBytes(Input, sizeof(Firness_TryCount), (VOID *)&Firness_TryCount);
        GetInfo_Arg_1->TryCount = Firness_TryCount;
    }
    {
        UINT16 Firness_TimeoutValue;
        ReadBytes(Input, sizeof(Firness_TimeoutValue), (VOID *)&Firness_TimeoutValue);
        GetInfo_Arg_1->TimeoutValue = Firness_TimeoutValue;
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetInfo_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetInfo_Arg_2_choice), (VOID *)&GetInfo_Arg_2_choice);
    switch(GetInfo_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetInfo_Arg_2), (VOID *)GetInfo_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(GetInfo_Arg_2);
            GetInfo_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetInfo_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(GetInfo_Arg_3_choice), (VOID *)&GetInfo_Arg_3_choice);
    switch(GetInfo_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetInfo_Arg_3), (VOID *)GetInfo_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(GetInfo_Arg_3);
            GetInfo_Arg_3 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetInfo_Arg_4), (VOID *)&GetInfo_Arg_4);
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(GetInfo_Arg_5->OptionStr), (VOID *)(GetInfo_Arg_5->OptionStr));
    ReadBytes(Input, sizeof(GetInfo_Arg_5->ValueStr), (VOID *)(GetInfo_Arg_5->ValueStr));
    
    /*
        Output Variable(s)
    */
    UINT32 * GetInfo_Arg_6 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT8* GetInfo_Arg_6_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetInfo_Arg_6_OutputChoice), (VOID *)GetInfo_Arg_6_OutputChoice);
    if(*GetInfo_Arg_6_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetInfo_Arg_6), (VOID *)GetInfo_Arg_6);
    }
    EFI_MTFTP4_PACKET * GetInfo_Arg_7 = (EFI_MTFTP4_PACKET *)AllocateZeroPool(sizeof(EFI_MTFTP4_PACKET));
    UINT8* GetInfo_Arg_7_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetInfo_Arg_7_OutputChoice), (VOID *)GetInfo_Arg_7_OutputChoice);
    if(*GetInfo_Arg_7_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetInfo_Arg_7), (VOID *)GetInfo_Arg_7);
    }
    Status = ProtocolVariable->GetInfo(
        ProtocolVariable,
        GetInfo_Arg_1,
        GetInfo_Arg_2,
        GetInfo_Arg_3,
        GetInfo_Arg_4,
        GetInfo_Arg_5,
        GetInfo_Arg_6,
        (EFI_MTFTP4_PACKET **)&GetInfo_Arg_7
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ParseOptions.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzParseOptions(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MTFTP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMtftp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 ParseOptions_Arg_1 = 0;
    EFI_MTFTP4_PACKET * ParseOptions_Arg_2 = (EFI_MTFTP4_PACKET *)AllocateZeroPool(sizeof(EFI_MTFTP4_PACKET));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ParseOptions_Arg_1), (VOID *)&ParseOptions_Arg_1);
    
    // Generator Struct Variable Initialization
    {
        UINT16 Firness_OpCode;
        ReadBytes(Input, sizeof(Firness_OpCode), (VOID *)&Firness_OpCode);
        ParseOptions_Arg_2->OpCode = Firness_OpCode;
    }
    {
        EFI_MTFTP4_REQ_HEADER Firness_Rrq;
        ReadBytes(Input, sizeof(Firness_Rrq), (VOID *)&Firness_Rrq);
        ParseOptions_Arg_2->Rrq = Firness_Rrq;
    }
    {
        EFI_MTFTP4_REQ_HEADER Firness_Wrq;
        ReadBytes(Input, sizeof(Firness_Wrq), (VOID *)&Firness_Wrq);
        ParseOptions_Arg_2->Wrq = Firness_Wrq;
    }
    {
        EFI_MTFTP4_OACK_HEADER Firness_Oack;
        ReadBytes(Input, sizeof(Firness_Oack), (VOID *)&Firness_Oack);
        ParseOptions_Arg_2->Oack = Firness_Oack;
    }
    {
        EFI_MTFTP4_DATA_HEADER Firness_Data;
        ReadBytes(Input, sizeof(Firness_Data), (VOID *)&Firness_Data);
        ParseOptions_Arg_2->Data = Firness_Data;
    }
    {
        EFI_MTFTP4_ACK_HEADER Firness_Ack;
        ReadBytes(Input, sizeof(Firness_Ack), (VOID *)&Firness_Ack);
        ParseOptions_Arg_2->Ack = Firness_Ack;
    }
    {
        EFI_MTFTP4_DATA8_HEADER Firness_Data8;
        ReadBytes(Input, sizeof(Firness_Data8), (VOID *)&Firness_Data8);
        ParseOptions_Arg_2->Data8 = Firness_Data8;
    }
    {
        EFI_MTFTP4_ACK8_HEADER Firness_Ack8;
        ReadBytes(Input, sizeof(Firness_Ack8), (VOID *)&Firness_Ack8);
        ParseOptions_Arg_2->Ack8 = Firness_Ack8;
    }
    {
        EFI_MTFTP4_ERROR_HEADER Firness_Error;
        ReadBytes(Input, sizeof(Firness_Error), (VOID *)&Firness_Error);
        ParseOptions_Arg_2->Error = Firness_Error;
    }
    
    /*
        Output Variable(s)
    */
    UINT32 * ParseOptions_Arg_3 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT8* ParseOptions_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ParseOptions_Arg_3_OutputChoice), (VOID *)ParseOptions_Arg_3_OutputChoice);
    if(*ParseOptions_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ParseOptions_Arg_3), (VOID *)ParseOptions_Arg_3);
    }
    EFI_MTFTP4_OPTION * ParseOptions_Arg_4 = (EFI_MTFTP4_OPTION *)AllocateZeroPool(sizeof(EFI_MTFTP4_OPTION));
    UINT8* ParseOptions_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ParseOptions_Arg_4_OutputChoice), (VOID *)ParseOptions_Arg_4_OutputChoice);
    if(*ParseOptions_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ParseOptions_Arg_4), (VOID *)ParseOptions_Arg_4);
    }
    Status = ProtocolVariable->ParseOptions(
        ProtocolVariable,
        ParseOptions_Arg_1,
        ParseOptions_Arg_2,
        ParseOptions_Arg_3,
        (EFI_MTFTP4_OPTION **)&ParseOptions_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ReadFile.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzReadFile(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MTFTP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMtftp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->ReadFile(
        ProtocolVariable,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called WriteFile.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzWriteFile(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MTFTP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMtftp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->WriteFile(
        ProtocolVariable,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ReadDirectory.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzReadDirectory(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MTFTP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMtftp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->ReadDirectory(
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
    EFI_MTFTP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMtftp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Poll(
        ProtocolVariable
    );
    return Status;
}

