#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called Callback.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzCallback(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_CONFIG_ACCESS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiConfigAccessProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_BROWSER_ACTION Callback_Arg_1 = 0;
    EFI_QUESTION_ID Callback_Arg_2 = 0;
    UINT8 Callback_Arg_3 = 0;
    EFI_IFR_TYPE_VALUE * Callback_Arg_4 = (EFI_IFR_TYPE_VALUE *)AllocateZeroPool(sizeof(EFI_IFR_TYPE_VALUE));
    EFI_BROWSER_ACTION_REQUEST * Callback_Arg_5 = (EFI_BROWSER_ACTION_REQUEST *)AllocateZeroPool(sizeof(EFI_BROWSER_ACTION_REQUEST));
    
    UINT8* Callback_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Callback_Arg_1_choice), (VOID *)Callback_Arg_1_choice);
    switch(*Callback_Arg_1_choice % 5) {
        case 0:
        {
        // Constant Variable Initialization
        Callback_Arg_1 = EFI_BROWSER_ACTION_RETRIEVE;
    
            break;
        }
        case 1:
        {
        // Constant Variable Initialization
        Callback_Arg_1 = EFI_BROWSER_ACTION_CHANGED;
    
            break;
        }
        case 2:
        {
        // Constant Variable Initialization
        Callback_Arg_1 = EFI_BROWSER_ACTION_SUBMITTED;
    
            break;
        }
        case 3:
        {
        // Constant Variable Initialization
        Callback_Arg_1 = EFI_BROWSER_ACTION_CHANGING;
    
            break;
        }
        case 4:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(Callback_Arg_1), (VOID *)&Callback_Arg_1);
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Callback_Arg_2), (VOID *)&Callback_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Callback_Arg_3), (VOID *)&Callback_Arg_3);
    
    
    // Fuzzable Variable Initialization
    UINT8 Callback_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(Callback_Arg_5_choice), (VOID *)&Callback_Arg_5_choice);
    switch(Callback_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Callback_Arg_5), (VOID *)Callback_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(Callback_Arg_5);
            Callback_Arg_5 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->Callback(
        ProtocolVariable,
        Callback_Arg_1,
        Callback_Arg_2,
        Callback_Arg_3,
        Callback_Arg_4,
        Callback_Arg_5
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
    EFI_HII_CONFIG_ACCESS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiConfigAccessProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_STRING ExtractConfig_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ExtractConfig_Arg_1), (VOID *)&ExtractConfig_Arg_1);
    
    /*
        Output Variable(s)
    */
    EFI_STRING * ExtractConfig_Arg_2 = (EFI_STRING *)AllocateZeroPool(sizeof(EFI_STRING));
    UINT8* ExtractConfig_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ExtractConfig_Arg_2_OutputChoice), (VOID *)ExtractConfig_Arg_2_OutputChoice);
    if(*ExtractConfig_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ExtractConfig_Arg_2), (VOID *)ExtractConfig_Arg_2);
    }
    EFI_STRING * ExtractConfig_Arg_3 = (EFI_STRING *)AllocateZeroPool(sizeof(EFI_STRING));
    UINT8* ExtractConfig_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ExtractConfig_Arg_3_OutputChoice), (VOID *)ExtractConfig_Arg_3_OutputChoice);
    if(*ExtractConfig_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ExtractConfig_Arg_3), (VOID *)ExtractConfig_Arg_3);
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
    EFI_HII_CONFIG_ACCESS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiConfigAccessProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_STRING RouteConfig_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RouteConfig_Arg_1), (VOID *)&RouteConfig_Arg_1);
    
    /*
        Output Variable(s)
    */
    EFI_STRING * RouteConfig_Arg_2 = (EFI_STRING *)AllocateZeroPool(sizeof(EFI_STRING));
    UINT8* RouteConfig_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(RouteConfig_Arg_2_OutputChoice), (VOID *)RouteConfig_Arg_2_OutputChoice);
    if(*RouteConfig_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*RouteConfig_Arg_2), (VOID *)RouteConfig_Arg_2);
    }
    Status = ProtocolVariable->RouteConfig(
        ProtocolVariable,
        RouteConfig_Arg_1,
        RouteConfig_Arg_2
    );
    return Status;
}

