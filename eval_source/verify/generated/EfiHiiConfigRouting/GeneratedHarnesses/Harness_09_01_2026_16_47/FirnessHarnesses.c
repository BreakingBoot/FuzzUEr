#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called BlockToConfig.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzBlockToConfig(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_CONFIG_ROUTING_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiConfigRoutingProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_STRING BlockToConfig_Arg_1 = 0;
    UINT8 * BlockToConfig_Arg_2 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINTN BlockToConfig_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(BlockToConfig_Arg_1), (VOID *)&BlockToConfig_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 BlockToConfig_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(BlockToConfig_Arg_2_choice), (VOID *)&BlockToConfig_Arg_2_choice);
    switch(BlockToConfig_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(BlockToConfig_Arg_2), (VOID *)BlockToConfig_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(BlockToConfig_Arg_2);
            BlockToConfig_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(BlockToConfig_Arg_3), (VOID *)&BlockToConfig_Arg_3);
    
    /*
        Output Variable(s)
    */
    EFI_STRING * BlockToConfig_Arg_4 = (EFI_STRING *)AllocateZeroPool(sizeof(EFI_STRING));
    UINT8* BlockToConfig_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(BlockToConfig_Arg_4_OutputChoice), (VOID *)BlockToConfig_Arg_4_OutputChoice);
    if(*BlockToConfig_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*BlockToConfig_Arg_4), (VOID *)BlockToConfig_Arg_4);
    }
    EFI_STRING * BlockToConfig_Arg_5 = (EFI_STRING *)AllocateZeroPool(sizeof(EFI_STRING));
    UINT8* BlockToConfig_Arg_5_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(BlockToConfig_Arg_5_OutputChoice), (VOID *)BlockToConfig_Arg_5_OutputChoice);
    if(*BlockToConfig_Arg_5_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*BlockToConfig_Arg_5), (VOID *)BlockToConfig_Arg_5);
    }
    Status = ProtocolVariable->BlockToConfig(
        ProtocolVariable,
        BlockToConfig_Arg_1,
        BlockToConfig_Arg_2,
        BlockToConfig_Arg_3,
        BlockToConfig_Arg_4,
        BlockToConfig_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ConfigToBlock.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzConfigToBlock(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_CONFIG_ROUTING_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiConfigRoutingProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_STRING ConfigToBlock_Arg_1 = 0;
    UINT8 * ConfigToBlock_Arg_2 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINTN * ConfigToBlock_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ConfigToBlock_Arg_1), (VOID *)&ConfigToBlock_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 ConfigToBlock_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(ConfigToBlock_Arg_2_choice), (VOID *)&ConfigToBlock_Arg_2_choice);
    switch(ConfigToBlock_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(ConfigToBlock_Arg_2), (VOID *)ConfigToBlock_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(ConfigToBlock_Arg_2);
            ConfigToBlock_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 ConfigToBlock_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(ConfigToBlock_Arg_3_choice), (VOID *)&ConfigToBlock_Arg_3_choice);
    switch(ConfigToBlock_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(ConfigToBlock_Arg_3), (VOID *)ConfigToBlock_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(ConfigToBlock_Arg_3);
            ConfigToBlock_Arg_3 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_STRING * ConfigToBlock_Arg_4 = (EFI_STRING *)AllocateZeroPool(sizeof(EFI_STRING));
    UINT8* ConfigToBlock_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ConfigToBlock_Arg_4_OutputChoice), (VOID *)ConfigToBlock_Arg_4_OutputChoice);
    if(*ConfigToBlock_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ConfigToBlock_Arg_4), (VOID *)ConfigToBlock_Arg_4);
    }
    Status = ProtocolVariable->ConfigToBlock(
        ProtocolVariable,
        ConfigToBlock_Arg_1,
        ConfigToBlock_Arg_2,
        ConfigToBlock_Arg_3,
        ConfigToBlock_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RouteConfig.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRouteConfig(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_CONFIG_ROUTING_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiConfigRoutingProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * RouteConfig_Arg_1 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    CHAR16 * RouteConfig_Arg_2 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    
    // Fuzzable Variable Initialization
    UINT8 RouteConfig_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(RouteConfig_Arg_1_choice), (VOID *)&RouteConfig_Arg_1_choice);
    switch(RouteConfig_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(RouteConfig_Arg_1), (VOID *)RouteConfig_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(RouteConfig_Arg_1);
            RouteConfig_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 RouteConfig_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(RouteConfig_Arg_2_choice), (VOID *)&RouteConfig_Arg_2_choice);
    switch(RouteConfig_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(RouteConfig_Arg_2), (VOID *)RouteConfig_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(RouteConfig_Arg_2);
            RouteConfig_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->RouteConfig(
        ProtocolVariable,
        RouteConfig_Arg_1,
        (CHAR16 **)&RouteConfig_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ExtractConfig.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzExtractConfig(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_CONFIG_ROUTING_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiConfigRoutingProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_STRING ExtractConfig_Arg_1 = 0;
    EFI_STRING * ExtractConfig_Arg_2 = (EFI_STRING *)AllocateZeroPool(sizeof(EFI_STRING));
    EFI_STRING * ExtractConfig_Arg_3 = (EFI_STRING *)AllocateZeroPool(sizeof(EFI_STRING));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ExtractConfig_Arg_1), (VOID *)&ExtractConfig_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 ExtractConfig_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(ExtractConfig_Arg_2_choice), (VOID *)&ExtractConfig_Arg_2_choice);
    switch(ExtractConfig_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(ExtractConfig_Arg_2), (VOID *)ExtractConfig_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(ExtractConfig_Arg_2);
            ExtractConfig_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 ExtractConfig_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(ExtractConfig_Arg_3_choice), (VOID *)&ExtractConfig_Arg_3_choice);
    switch(ExtractConfig_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(ExtractConfig_Arg_3), (VOID *)ExtractConfig_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(ExtractConfig_Arg_3);
            ExtractConfig_Arg_3 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->ExtractConfig(
        ProtocolVariable,
        ExtractConfig_Arg_1,
        ExtractConfig_Arg_2,
        ExtractConfig_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ExportConfig.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzExportConfig(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_CONFIG_ROUTING_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiConfigRoutingProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_STRING * ExportConfig_Arg_1 = (EFI_STRING *)AllocateZeroPool(sizeof(EFI_STRING));
    UINT8* ExportConfig_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ExportConfig_Arg_1_OutputChoice), (VOID *)ExportConfig_Arg_1_OutputChoice);
    if(*ExportConfig_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ExportConfig_Arg_1), (VOID *)ExportConfig_Arg_1);
    }
    Status = ProtocolVariable->ExportConfig(
        ProtocolVariable,
        ExportConfig_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetAltConfig.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetAltConfig(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_CONFIG_ROUTING_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiConfigRoutingProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_STRING GetAltConfig_Arg_1 = 0;
    EFI_GUID * GetAltConfig_Arg_2 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    EFI_STRING GetAltConfig_Arg_3 = 0;
    EFI_DEVICE_PATH_PROTOCOL * GetAltConfig_Arg_4 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    UINT16 * GetAltConfig_Arg_5 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetAltConfig_Arg_1), (VOID *)&GetAltConfig_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 GetAltConfig_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetAltConfig_Arg_2_choice), (VOID *)&GetAltConfig_Arg_2_choice);
    switch(GetAltConfig_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetAltConfig_Arg_2), (VOID *)GetAltConfig_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(GetAltConfig_Arg_2);
            GetAltConfig_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetAltConfig_Arg_3), (VOID *)&GetAltConfig_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 GetAltConfig_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(GetAltConfig_Arg_4_choice), (VOID *)&GetAltConfig_Arg_4_choice);
    switch(GetAltConfig_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetAltConfig_Arg_4), (VOID *)GetAltConfig_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(GetAltConfig_Arg_4);
            GetAltConfig_Arg_4 = NULL;
            break;
        }
    }
    
    UINT8* GetAltConfig_Arg_5_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetAltConfig_Arg_5_choice), (VOID *)GetAltConfig_Arg_5_choice);
    switch(*GetAltConfig_Arg_5_choice % 4) {
        case 0:
        {
        // Constant Variable Initialization
        GetAltConfig_Arg_5 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    
            break;
        }
        case 1:
        {
        // Constant Variable Initialization
        GetAltConfig_Arg_5 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    
            break;
        }
        case 2:
        {
        // Constant Variable Initialization
        GetAltConfig_Arg_5 = NULL;
    
            break;
        }
        case 3:
        {
        // Fuzzable Variable Initialization
        UINT8 GetAltConfig_Arg_5_choice = 0;
        ReadBytes(Input, sizeof(GetAltConfig_Arg_5_choice), (VOID *)&GetAltConfig_Arg_5_choice);
        switch(GetAltConfig_Arg_5_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(GetAltConfig_Arg_5), (VOID *)GetAltConfig_Arg_5);
                break;
            case 1:
            {
                gBS->FreePool(GetAltConfig_Arg_5);
                GetAltConfig_Arg_5 = NULL;
                break;
            }
        }
    
            break;
        }
    }
    /*
        Output Variable(s)
    */
    EFI_STRING * GetAltConfig_Arg_6 = (EFI_STRING *)AllocateZeroPool(sizeof(EFI_STRING));
    UINT8* GetAltConfig_Arg_6_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetAltConfig_Arg_6_OutputChoice), (VOID *)GetAltConfig_Arg_6_OutputChoice);
    if(*GetAltConfig_Arg_6_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetAltConfig_Arg_6), (VOID *)GetAltConfig_Arg_6);
    }
    Status = ProtocolVariable->GetAltConfig(
        ProtocolVariable,
        GetAltConfig_Arg_1,
        GetAltConfig_Arg_2,
        GetAltConfig_Arg_3,
        GetAltConfig_Arg_4,
        GetAltConfig_Arg_5,
        GetAltConfig_Arg_6
    );
    return Status;
}

