#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called Build.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzBuild(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DHCP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDhcp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 Build_Arg_2 = 0;
    UINT8 * Build_Arg_3 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT32 Build_Arg_4 = 0;
    EFI_DHCP4_PACKET_OPTION * Build_Arg_5 = (EFI_DHCP4_PACKET_OPTION *)AllocateZeroPool(sizeof(EFI_DHCP4_PACKET_OPTION));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Build_Arg_2), (VOID *)&Build_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 Build_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(Build_Arg_3_choice), (VOID *)&Build_Arg_3_choice);
    switch(Build_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Build_Arg_3), (VOID *)Build_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(Build_Arg_3);
            Build_Arg_3 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Build_Arg_4), (VOID *)&Build_Arg_4);
    
    // Generator Struct Variable Initialization
    {
        UINT8 Firness_OpCode;
        ReadBytes(Input, sizeof(Firness_OpCode), (VOID *)&Firness_OpCode);
        Build_Arg_5->OpCode = Firness_OpCode;
    }
    {
        UINT8 Firness_Length;
        ReadBytes(Input, sizeof(Firness_Length), (VOID *)&Firness_Length);
        Build_Arg_5->Length = Firness_Length;
    }
    ReadBytes(Input, sizeof(Build_Arg_5->Data), (VOID *)&(Build_Arg_5->Data));
    
    /*
        Output Variable(s)
    */
    EFI_DHCP4_PACKET * Build_Arg_6 = (EFI_DHCP4_PACKET *)AllocateZeroPool(sizeof(EFI_DHCP4_PACKET));
    UINT8* Build_Arg_6_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Build_Arg_6_OutputChoice), (VOID *)Build_Arg_6_OutputChoice);
    if(*Build_Arg_6_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Build_Arg_6), (VOID *)Build_Arg_6);
    }
    Status = ProtocolVariable->Build(
        ProtocolVariable,
        NULL,
        Build_Arg_2,
        Build_Arg_3,
        Build_Arg_4,
        (EFI_DHCP4_PACKET_OPTION **)&Build_Arg_5,
        (EFI_DHCP4_PACKET **)&Build_Arg_6
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called TransmitReceive.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzTransmitReceive(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DHCP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDhcp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->TransmitReceive(
        ProtocolVariable,
        NULL
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
    EFI_DHCP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDhcp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DHCP4_CONFIG_DATA * Configure_Arg_1 = (EFI_DHCP4_CONFIG_DATA *)AllocateZeroPool(sizeof(EFI_DHCP4_CONFIG_DATA));
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_DiscoverTryCount;
        ReadBytes(Input, sizeof(Firness_DiscoverTryCount), (VOID *)&Firness_DiscoverTryCount);
        Configure_Arg_1->DiscoverTryCount = Firness_DiscoverTryCount;
    }
    ReadBytes(Input, sizeof(Configure_Arg_1->DiscoverTimeout), (VOID *)(Configure_Arg_1->DiscoverTimeout));
    {
        UINT32 Firness_RequestTryCount;
        ReadBytes(Input, sizeof(Firness_RequestTryCount), (VOID *)&Firness_RequestTryCount);
        Configure_Arg_1->RequestTryCount = Firness_RequestTryCount;
    }
    ReadBytes(Input, sizeof(Configure_Arg_1->RequestTimeout), (VOID *)(Configure_Arg_1->RequestTimeout));
    {
        EFI_IPv4_ADDRESS Firness_ClientAddress;
        ReadBytes(Input, sizeof(Firness_ClientAddress), (VOID *)&Firness_ClientAddress);
        Configure_Arg_1->ClientAddress = Firness_ClientAddress;
    }
    {
        EFI_DHCP4_CALLBACK Firness_Dhcp4Callback;
        ReadBytes(Input, sizeof(Firness_Dhcp4Callback), (VOID *)&Firness_Dhcp4Callback);
        Configure_Arg_1->Dhcp4Callback = Firness_Dhcp4Callback;
    }
    ReadBytes(Input, sizeof(Configure_Arg_1->CallbackContext), (VOID *)(Configure_Arg_1->CallbackContext));
    {
        UINT32 Firness_OptionCount;
        ReadBytes(Input, sizeof(Firness_OptionCount), (VOID *)&Firness_OptionCount);
        Configure_Arg_1->OptionCount = Firness_OptionCount;
    }
    ReadBytes(Input, sizeof(Configure_Arg_1->OptionList), (VOID *)(Configure_Arg_1->OptionList));
    
    Status = ProtocolVariable->Configure(
        ProtocolVariable,
        Configure_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Start.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStart(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DHCP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDhcp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  Start_Arg_1 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    UINT8* Start_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Start_Arg_1_choice), (VOID *)Start_Arg_1_choice);
    switch(*Start_Arg_1_choice % 6) {
        case 0:
        {
        // Fuzzable Variable Initialization
        UINT8 Start_Arg_1_choice = 0;
        ReadBytes(Input, sizeof(Start_Arg_1_choice), (VOID *)&Start_Arg_1_choice);
        switch(Start_Arg_1_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(Start_Arg_1), (VOID *)Start_Arg_1);
                break;
            case 1:
            {
                gBS->FreePool(Start_Arg_1);
                Start_Arg_1 = NULL;
                break;
            }
        }
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Output Variable(s)
            */
            EFI_EVENT * EfiCreateEventReadyToBoot_Arg_0 = (EFI_EVENT *)AllocateZeroPool(sizeof(EFI_EVENT));
            UINT8* EfiCreateEventReadyToBoot_Arg_0_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(EfiCreateEventReadyToBoot_Arg_0_OutputChoice), (VOID *)EfiCreateEventReadyToBoot_Arg_0_OutputChoice);
            if(*EfiCreateEventReadyToBoot_Arg_0_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*EfiCreateEventReadyToBoot_Arg_0), (VOID *)EfiCreateEventReadyToBoot_Arg_0);
            }
            Status = EfiCreateEventReadyToBoot(
                EfiCreateEventReadyToBoot_Arg_0
            );
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            /*
                Output Variable(s)
            */
            EFI_EVENT * EfiCreateEventLegacyBoot_Arg_0 = (EFI_EVENT *)AllocateZeroPool(sizeof(EFI_EVENT));
            UINT8* EfiCreateEventLegacyBoot_Arg_0_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(EfiCreateEventLegacyBoot_Arg_0_OutputChoice), (VOID *)EfiCreateEventLegacyBoot_Arg_0_OutputChoice);
            if(*EfiCreateEventLegacyBoot_Arg_0_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*EfiCreateEventLegacyBoot_Arg_0), (VOID *)EfiCreateEventLegacyBoot_Arg_0);
            }
            Status = EfiCreateEventLegacyBoot(
                EfiCreateEventLegacyBoot_Arg_0
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_TPL CreateBdsEvent_Arg_0 = 0;
            EFI_GUID * CreateBdsEvent_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(CreateBdsEvent_Arg_0), (VOID *)&CreateBdsEvent_Arg_0);
            
            UINT8* CreateBdsEvent_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(CreateBdsEvent_Arg_1_choice), (VOID *)CreateBdsEvent_Arg_1_choice);
            switch(*CreateBdsEvent_Arg_1_choice % 4) {
                case 0:
                {
                // EFI_GUID Variable Initialization
                CreateBdsEvent_Arg_1 = &gBdsEventBeforeConsoleAfterTrustedConsoleGuid;
            
                    break;
                }
                case 1:
                {
                // EFI_GUID Variable Initialization
                CreateBdsEvent_Arg_1 = &gBdsEventBeforeConsoleBeforeEndOfDxeGuid;
            
                    break;
                }
                case 2:
                {
                // EFI_GUID Variable Initialization
                CreateBdsEvent_Arg_1 = &gBdsEventAfterConsoleReadyBeforeBootOptionGuid;
            
                    break;
                }
                case 3:
                {
                // Generator Struct Variable Initialization
                {
                    UINT32 Firness_Data1;
                    ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
                    CreateBdsEvent_Arg_1->Data1 = Firness_Data1;
                }
                {
                    UINT16 Firness_Data2;
                    ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
                    CreateBdsEvent_Arg_1->Data2 = Firness_Data2;
                }
                {
                    UINT16 Firness_Data3;
                    ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
                    CreateBdsEvent_Arg_1->Data3 = Firness_Data3;
                }
                ReadBytes(Input, sizeof(CreateBdsEvent_Arg_1->Data4), (VOID *)&(CreateBdsEvent_Arg_1->Data4));
            
                    break;
                }
            }
            /*
                Output Variable(s)
            */
            EFI_EVENT * CreateBdsEvent_Arg_2 = (EFI_EVENT *)AllocateZeroPool(sizeof(EFI_EVENT));
            UINT8* CreateBdsEvent_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(CreateBdsEvent_Arg_2_OutputChoice), (VOID *)CreateBdsEvent_Arg_2_OutputChoice);
            if(*CreateBdsEvent_Arg_2_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*CreateBdsEvent_Arg_2), (VOID *)CreateBdsEvent_Arg_2);
            }
            Status = CreateBdsEvent(
                CreateBdsEvent_Arg_0,
                CreateBdsEvent_Arg_1,
                CreateBdsEvent_Arg_2
            );
    
            break;
        }
        case 4:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_TPL EfiCreateEventReadyToBootEx_Arg_0 = 0;
            UINTN*  EfiCreateEventReadyToBootEx_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
            
            UINT8* EfiCreateEventReadyToBootEx_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(EfiCreateEventReadyToBootEx_Arg_0_choice), (VOID *)EfiCreateEventReadyToBootEx_Arg_0_choice);
            switch(*EfiCreateEventReadyToBootEx_Arg_0_choice % 2) {
                case 0:
                {
                // Constant Variable Initialization
                EfiCreateEventReadyToBootEx_Arg_0 = TPL_CALLBACK;
            
                    break;
                }
                case 1:
                {
                // Fuzzable Variable Initialization
                ReadBytes(Input, sizeof(EfiCreateEventReadyToBootEx_Arg_0), (VOID *)&EfiCreateEventReadyToBootEx_Arg_0);
            
                    break;
                }
            }
            // Fuzzable Variable Initialization
            UINT8 EfiCreateEventReadyToBootEx_Arg_2_choice = 0;
            ReadBytes(Input, sizeof(EfiCreateEventReadyToBootEx_Arg_2_choice), (VOID *)&EfiCreateEventReadyToBootEx_Arg_2_choice);
            switch(EfiCreateEventReadyToBootEx_Arg_2_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(EfiCreateEventReadyToBootEx_Arg_2), (VOID *)EfiCreateEventReadyToBootEx_Arg_2);
                    break;
                case 1:
                {
                    gBS->FreePool(EfiCreateEventReadyToBootEx_Arg_2);
                    EfiCreateEventReadyToBootEx_Arg_2 = NULL;
                    break;
                }
            }
            
            /*
                Output Variable(s)
            */
            EFI_EVENT * EfiCreateEventReadyToBootEx_Arg_3 = (EFI_EVENT *)AllocateZeroPool(sizeof(EFI_EVENT));
            UINT8* EfiCreateEventReadyToBootEx_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(EfiCreateEventReadyToBootEx_Arg_3_OutputChoice), (VOID *)EfiCreateEventReadyToBootEx_Arg_3_OutputChoice);
            if(*EfiCreateEventReadyToBootEx_Arg_3_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*EfiCreateEventReadyToBootEx_Arg_3), (VOID *)EfiCreateEventReadyToBootEx_Arg_3);
            }
            Status = EfiCreateEventReadyToBootEx(
                EfiCreateEventReadyToBootEx_Arg_0,
                NULL,
                (void *)EfiCreateEventReadyToBootEx_Arg_2,
                EfiCreateEventReadyToBootEx_Arg_3
            );
    
            break;
        }
        case 5:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_TPL EfiCreateEventLegacyBootEx_Arg_0 = 0;
            UINTN*  EfiCreateEventLegacyBootEx_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiCreateEventLegacyBootEx_Arg_0), (VOID *)&EfiCreateEventLegacyBootEx_Arg_0);
            
            // Fuzzable Variable Initialization
            UINT8 EfiCreateEventLegacyBootEx_Arg_2_choice = 0;
            ReadBytes(Input, sizeof(EfiCreateEventLegacyBootEx_Arg_2_choice), (VOID *)&EfiCreateEventLegacyBootEx_Arg_2_choice);
            switch(EfiCreateEventLegacyBootEx_Arg_2_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(EfiCreateEventLegacyBootEx_Arg_2), (VOID *)EfiCreateEventLegacyBootEx_Arg_2);
                    break;
                case 1:
                {
                    gBS->FreePool(EfiCreateEventLegacyBootEx_Arg_2);
                    EfiCreateEventLegacyBootEx_Arg_2 = NULL;
                    break;
                }
            }
            
            /*
                Output Variable(s)
            */
            EFI_EVENT * EfiCreateEventLegacyBootEx_Arg_3 = (EFI_EVENT *)AllocateZeroPool(sizeof(EFI_EVENT));
            UINT8* EfiCreateEventLegacyBootEx_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(EfiCreateEventLegacyBootEx_Arg_3_OutputChoice), (VOID *)EfiCreateEventLegacyBootEx_Arg_3_OutputChoice);
            if(*EfiCreateEventLegacyBootEx_Arg_3_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*EfiCreateEventLegacyBootEx_Arg_3), (VOID *)EfiCreateEventLegacyBootEx_Arg_3);
            }
            Status = EfiCreateEventLegacyBootEx(
                EfiCreateEventLegacyBootEx_Arg_0,
                NULL,
                (void *)EfiCreateEventLegacyBootEx_Arg_2,
                EfiCreateEventLegacyBootEx_Arg_3
            );
    
            break;
        }
    }
    Status = ProtocolVariable->Start(
        ProtocolVariable,
        (void *)Start_Arg_1
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
    EFI_DHCP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDhcp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_DHCP4_MODE_DATA * GetModeData_Arg_1 = (EFI_DHCP4_MODE_DATA *)AllocateZeroPool(sizeof(EFI_DHCP4_MODE_DATA));
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
    called Stop.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStop(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DHCP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDhcp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Stop(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Parse.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzParse(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DHCP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDhcp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 * Parse_Arg_2 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    EFI_DHCP4_PACKET_OPTION * Parse_Arg_3 = (EFI_DHCP4_PACKET_OPTION *)AllocateZeroPool(sizeof(EFI_DHCP4_PACKET_OPTION));
    
    // Fuzzable Variable Initialization
    UINT8 Parse_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(Parse_Arg_2_choice), (VOID *)&Parse_Arg_2_choice);
    switch(Parse_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Parse_Arg_2), (VOID *)Parse_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(Parse_Arg_2);
            Parse_Arg_2 = NULL;
            break;
        }
    }
    
    // Generator Struct Variable Initialization
    {
        UINT8 Firness_OpCode;
        ReadBytes(Input, sizeof(Firness_OpCode), (VOID *)&Firness_OpCode);
        Parse_Arg_3->OpCode = Firness_OpCode;
    }
    {
        UINT8 Firness_Length;
        ReadBytes(Input, sizeof(Firness_Length), (VOID *)&Firness_Length);
        Parse_Arg_3->Length = Firness_Length;
    }
    ReadBytes(Input, sizeof(Parse_Arg_3->Data), (VOID *)&(Parse_Arg_3->Data));
    
    Status = ProtocolVariable->Parse(
        ProtocolVariable,
        NULL,
        Parse_Arg_2,
        (EFI_DHCP4_PACKET_OPTION **)&Parse_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RenewRebind.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRenewRebind(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DHCP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDhcp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN RenewRebind_Arg_1 = FALSE;
    EFI_EVENT RenewRebind_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RenewRebind_Arg_1), (VOID *)&RenewRebind_Arg_1);
    
    UINT8* RenewRebind_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(RenewRebind_Arg_2_choice), (VOID *)RenewRebind_Arg_2_choice);
    switch(*RenewRebind_Arg_2_choice % 6) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(RenewRebind_Arg_2), (VOID *)&RenewRebind_Arg_2);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            Status = EfiCreateEventReadyToBoot(
                &RenewRebind_Arg_2
            );
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            Status = EfiCreateEventLegacyBoot(
                &RenewRebind_Arg_2
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_TPL CreateBdsEvent_Arg_0 = 0;
            EFI_GUID * CreateBdsEvent_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(CreateBdsEvent_Arg_0), (VOID *)&CreateBdsEvent_Arg_0);
            
            UINT8* CreateBdsEvent_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(CreateBdsEvent_Arg_1_choice), (VOID *)CreateBdsEvent_Arg_1_choice);
            switch(*CreateBdsEvent_Arg_1_choice % 4) {
                case 0:
                {
                // EFI_GUID Variable Initialization
                CreateBdsEvent_Arg_1 = &gBdsEventBeforeConsoleAfterTrustedConsoleGuid;
            
                    break;
                }
                case 1:
                {
                // EFI_GUID Variable Initialization
                CreateBdsEvent_Arg_1 = &gBdsEventBeforeConsoleBeforeEndOfDxeGuid;
            
                    break;
                }
                case 2:
                {
                // EFI_GUID Variable Initialization
                CreateBdsEvent_Arg_1 = &gBdsEventAfterConsoleReadyBeforeBootOptionGuid;
            
                    break;
                }
                case 3:
                {
                // Generator Struct Variable Initialization
                {
                    UINT32 Firness_Data1;
                    ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
                    CreateBdsEvent_Arg_1->Data1 = Firness_Data1;
                }
                {
                    UINT16 Firness_Data2;
                    ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
                    CreateBdsEvent_Arg_1->Data2 = Firness_Data2;
                }
                {
                    UINT16 Firness_Data3;
                    ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
                    CreateBdsEvent_Arg_1->Data3 = Firness_Data3;
                }
                ReadBytes(Input, sizeof(CreateBdsEvent_Arg_1->Data4), (VOID *)&(CreateBdsEvent_Arg_1->Data4));
            
                    break;
                }
            }
            Status = CreateBdsEvent(
                CreateBdsEvent_Arg_0,
                CreateBdsEvent_Arg_1,
                &RenewRebind_Arg_2
            );
    
            break;
        }
        case 4:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_TPL EfiCreateEventReadyToBootEx_Arg_0 = 0;
            UINTN*  EfiCreateEventReadyToBootEx_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
            
            UINT8* EfiCreateEventReadyToBootEx_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(EfiCreateEventReadyToBootEx_Arg_0_choice), (VOID *)EfiCreateEventReadyToBootEx_Arg_0_choice);
            switch(*EfiCreateEventReadyToBootEx_Arg_0_choice % 2) {
                case 0:
                {
                // Constant Variable Initialization
                EfiCreateEventReadyToBootEx_Arg_0 = TPL_CALLBACK;
            
                    break;
                }
                case 1:
                {
                // Fuzzable Variable Initialization
                ReadBytes(Input, sizeof(EfiCreateEventReadyToBootEx_Arg_0), (VOID *)&EfiCreateEventReadyToBootEx_Arg_0);
            
                    break;
                }
            }
            // Fuzzable Variable Initialization
            UINT8 EfiCreateEventReadyToBootEx_Arg_2_choice = 0;
            ReadBytes(Input, sizeof(EfiCreateEventReadyToBootEx_Arg_2_choice), (VOID *)&EfiCreateEventReadyToBootEx_Arg_2_choice);
            switch(EfiCreateEventReadyToBootEx_Arg_2_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(EfiCreateEventReadyToBootEx_Arg_2), (VOID *)EfiCreateEventReadyToBootEx_Arg_2);
                    break;
                case 1:
                {
                    gBS->FreePool(EfiCreateEventReadyToBootEx_Arg_2);
                    EfiCreateEventReadyToBootEx_Arg_2 = NULL;
                    break;
                }
            }
            
            Status = EfiCreateEventReadyToBootEx(
                EfiCreateEventReadyToBootEx_Arg_0,
                NULL,
                (void *)EfiCreateEventReadyToBootEx_Arg_2,
                &RenewRebind_Arg_2
            );
    
            break;
        }
        case 5:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_TPL EfiCreateEventLegacyBootEx_Arg_0 = 0;
            UINTN*  EfiCreateEventLegacyBootEx_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiCreateEventLegacyBootEx_Arg_0), (VOID *)&EfiCreateEventLegacyBootEx_Arg_0);
            
            // Fuzzable Variable Initialization
            UINT8 EfiCreateEventLegacyBootEx_Arg_2_choice = 0;
            ReadBytes(Input, sizeof(EfiCreateEventLegacyBootEx_Arg_2_choice), (VOID *)&EfiCreateEventLegacyBootEx_Arg_2_choice);
            switch(EfiCreateEventLegacyBootEx_Arg_2_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(EfiCreateEventLegacyBootEx_Arg_2), (VOID *)EfiCreateEventLegacyBootEx_Arg_2);
                    break;
                case 1:
                {
                    gBS->FreePool(EfiCreateEventLegacyBootEx_Arg_2);
                    EfiCreateEventLegacyBootEx_Arg_2 = NULL;
                    break;
                }
            }
            
            Status = EfiCreateEventLegacyBootEx(
                EfiCreateEventLegacyBootEx_Arg_0,
                NULL,
                (void *)EfiCreateEventLegacyBootEx_Arg_2,
                &RenewRebind_Arg_2
            );
    
            break;
        }
    }
    Status = ProtocolVariable->RenewRebind(
        ProtocolVariable,
        RenewRebind_Arg_1,
        RenewRebind_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Release.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRelease(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DHCP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDhcp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Release(
        ProtocolVariable
    );
    return Status;
}

