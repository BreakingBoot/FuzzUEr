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
    EFI_DNS4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDns4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_DNS4_MODE_DATA * GetModeData_Arg_1 = (EFI_DNS4_MODE_DATA *)AllocateZeroPool(sizeof(EFI_DNS4_MODE_DATA));
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
    EFI_DNS4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDns4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DNS4_CONFIG_DATA * Configure_Arg_1 = (EFI_DNS4_CONFIG_DATA *)AllocateZeroPool(sizeof(EFI_DNS4_CONFIG_DATA));
    
    // Generator Struct Variable Initialization
    {
        UINTN Firness_DnsServerListCount;
        ReadBytes(Input, sizeof(Firness_DnsServerListCount), (VOID *)&Firness_DnsServerListCount);
        Configure_Arg_1->DnsServerListCount = Firness_DnsServerListCount;
    }
    ReadBytes(Input, sizeof(Configure_Arg_1->DnsServerList), (VOID *)(Configure_Arg_1->DnsServerList));
    {
        BOOLEAN Firness_UseDefaultSetting;
        ReadBytes(Input, sizeof(Firness_UseDefaultSetting), (VOID *)&Firness_UseDefaultSetting);
        Configure_Arg_1->UseDefaultSetting = Firness_UseDefaultSetting;
    }
    {
        BOOLEAN Firness_EnableDnsCache;
        ReadBytes(Input, sizeof(Firness_EnableDnsCache), (VOID *)&Firness_EnableDnsCache);
        Configure_Arg_1->EnableDnsCache = Firness_EnableDnsCache;
    }
    {
        UINT8 Firness_Protocol;
        ReadBytes(Input, sizeof(Firness_Protocol), (VOID *)&Firness_Protocol);
        Configure_Arg_1->Protocol = Firness_Protocol;
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
        UINT32 Firness_RetryCount;
        ReadBytes(Input, sizeof(Firness_RetryCount), (VOID *)&Firness_RetryCount);
        Configure_Arg_1->RetryCount = Firness_RetryCount;
    }
    {
        UINT32 Firness_RetryInterval;
        ReadBytes(Input, sizeof(Firness_RetryInterval), (VOID *)&Firness_RetryInterval);
        Configure_Arg_1->RetryInterval = Firness_RetryInterval;
    }
    
    Status = ProtocolVariable->Configure(
        ProtocolVariable,
        Configure_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called HostNameToIp.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzHostNameToIp(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DNS4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDns4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * HostNameToIp_Arg_1 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    
    // Fuzzable Variable Initialization
    UINT8 HostNameToIp_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(HostNameToIp_Arg_1_choice), (VOID *)&HostNameToIp_Arg_1_choice);
    switch(HostNameToIp_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(HostNameToIp_Arg_1), (VOID *)HostNameToIp_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(HostNameToIp_Arg_1);
            HostNameToIp_Arg_1 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->HostNameToIp(
        ProtocolVariable,
        HostNameToIp_Arg_1,
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
    EFI_DNS4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDns4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    called IpToHostName.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzIpToHostName(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DNS4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDns4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_IPv4_ADDRESS IpToHostName_Arg_1 = {0};
    
    UINT8* IpToHostName_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(IpToHostName_Arg_1_choice), (VOID *)IpToHostName_Arg_1_choice);
    switch(*IpToHostName_Arg_1_choice % 8) {
        case 0:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * NetLibStrToIp4_Arg_0 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 NetLibStrToIp4_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(NetLibStrToIp4_Arg_0_choice), (VOID *)&NetLibStrToIp4_Arg_0_choice);
            switch(NetLibStrToIp4_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(NetLibStrToIp4_Arg_0), (VOID *)NetLibStrToIp4_Arg_0);
                    break;
                case 1:
                {
                    gBS->FreePool(NetLibStrToIp4_Arg_0);
                    NetLibStrToIp4_Arg_0 = NULL;
                    break;
                }
            }
            
            Status = NetLibStrToIp4(
                NetLibStrToIp4_Arg_0,
                &IpToHostName_Arg_1
            );
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR8 * NetLibAsciiStrToIp4_Arg_0 = (CHAR8 *)AllocateZeroPool(sizeof(CHAR8));
            
            // Fuzzable Variable Initialization
            UINT8 NetLibAsciiStrToIp4_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(NetLibAsciiStrToIp4_Arg_0_choice), (VOID *)&NetLibAsciiStrToIp4_Arg_0_choice);
            switch(NetLibAsciiStrToIp4_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(NetLibAsciiStrToIp4_Arg_0), (VOID *)NetLibAsciiStrToIp4_Arg_0);
                    break;
                case 1:
                {
                    gBS->FreePool(NetLibAsciiStrToIp4_Arg_0);
                    NetLibAsciiStrToIp4_Arg_0 = NULL;
                    break;
                }
            }
            
            Status = NetLibAsciiStrToIp4(
                NetLibAsciiStrToIp4_Arg_0,
                &IpToHostName_Arg_1
            );
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * StrToIpv4Address_Arg_0 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 StrToIpv4Address_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(StrToIpv4Address_Arg_0_choice), (VOID *)&StrToIpv4Address_Arg_0_choice);
            switch(StrToIpv4Address_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(StrToIpv4Address_Arg_0), (VOID *)StrToIpv4Address_Arg_0);
                    break;
                case 1:
                {
                    gBS->FreePool(StrToIpv4Address_Arg_0);
                    StrToIpv4Address_Arg_0 = NULL;
                    break;
                }
            }
            
            /*
                Output Variable(s)
            */
            CHAR16 * StrToIpv4Address_Arg_1 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
            UINT8* StrToIpv4Address_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(StrToIpv4Address_Arg_1_OutputChoice), (VOID *)StrToIpv4Address_Arg_1_OutputChoice);
            if(*StrToIpv4Address_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*StrToIpv4Address_Arg_1), (VOID *)StrToIpv4Address_Arg_1);
            }
            UINT8 * StrToIpv4Address_Arg_3 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
            UINT8* StrToIpv4Address_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(StrToIpv4Address_Arg_3_OutputChoice), (VOID *)StrToIpv4Address_Arg_3_OutputChoice);
            if(*StrToIpv4Address_Arg_3_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*StrToIpv4Address_Arg_3), (VOID *)StrToIpv4Address_Arg_3);
            }
            StrToIpv4Address(
                StrToIpv4Address_Arg_0,
                (CHAR16 **)&StrToIpv4Address_Arg_1,
                &IpToHostName_Arg_1,
                StrToIpv4Address_Arg_3
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * StrToIpv6Address_Arg_0 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 StrToIpv6Address_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(StrToIpv6Address_Arg_0_choice), (VOID *)&StrToIpv6Address_Arg_0_choice);
            switch(StrToIpv6Address_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(StrToIpv6Address_Arg_0), (VOID *)StrToIpv6Address_Arg_0);
                    break;
                case 1:
                {
                    gBS->FreePool(StrToIpv6Address_Arg_0);
                    StrToIpv6Address_Arg_0 = NULL;
                    break;
                }
            }
            
            /*
                Output Variable(s)
            */
            CHAR16 * StrToIpv6Address_Arg_1 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
            UINT8* StrToIpv6Address_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(StrToIpv6Address_Arg_1_OutputChoice), (VOID *)StrToIpv6Address_Arg_1_OutputChoice);
            if(*StrToIpv6Address_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*StrToIpv6Address_Arg_1), (VOID *)StrToIpv6Address_Arg_1);
            }
            EFI_IPv6_ADDRESS * StrToIpv6Address_Arg_2 = (EFI_IPv6_ADDRESS *)AllocateZeroPool(sizeof(EFI_IPv6_ADDRESS));
            UINT8* StrToIpv6Address_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(StrToIpv6Address_Arg_2_OutputChoice), (VOID *)StrToIpv6Address_Arg_2_OutputChoice);
            if(*StrToIpv6Address_Arg_2_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*StrToIpv6Address_Arg_2), (VOID *)StrToIpv6Address_Arg_2);
            }
            UINT8 * StrToIpv6Address_Arg_3 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
            UINT8* StrToIpv6Address_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(StrToIpv6Address_Arg_3_OutputChoice), (VOID *)StrToIpv6Address_Arg_3_OutputChoice);
            if(*StrToIpv6Address_Arg_3_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*StrToIpv6Address_Arg_3), (VOID *)StrToIpv6Address_Arg_3);
            }
            StrToIpv6Address(
                StrToIpv6Address_Arg_0,
                (CHAR16 **)&StrToIpv6Address_Arg_1,
                StrToIpv6Address_Arg_2,
                StrToIpv6Address_Arg_3
            );
    
            break;
        }
        case 4:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * NetLibStrToIp6andPrefix_Arg_0 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 NetLibStrToIp6andPrefix_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(NetLibStrToIp6andPrefix_Arg_0_choice), (VOID *)&NetLibStrToIp6andPrefix_Arg_0_choice);
            switch(NetLibStrToIp6andPrefix_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(NetLibStrToIp6andPrefix_Arg_0), (VOID *)NetLibStrToIp6andPrefix_Arg_0);
                    break;
                case 1:
                {
                    gBS->FreePool(NetLibStrToIp6andPrefix_Arg_0);
                    NetLibStrToIp6andPrefix_Arg_0 = NULL;
                    break;
                }
            }
            
            /*
                Output Variable(s)
            */
            EFI_IPv6_ADDRESS * NetLibStrToIp6andPrefix_Arg_1 = (EFI_IPv6_ADDRESS *)AllocateZeroPool(sizeof(EFI_IPv6_ADDRESS));
            UINT8* NetLibStrToIp6andPrefix_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(NetLibStrToIp6andPrefix_Arg_1_OutputChoice), (VOID *)NetLibStrToIp6andPrefix_Arg_1_OutputChoice);
            if(*NetLibStrToIp6andPrefix_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*NetLibStrToIp6andPrefix_Arg_1), (VOID *)NetLibStrToIp6andPrefix_Arg_1);
            }
            UINT8 * NetLibStrToIp6andPrefix_Arg_2 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
            UINT8* NetLibStrToIp6andPrefix_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(NetLibStrToIp6andPrefix_Arg_2_OutputChoice), (VOID *)NetLibStrToIp6andPrefix_Arg_2_OutputChoice);
            if(*NetLibStrToIp6andPrefix_Arg_2_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*NetLibStrToIp6andPrefix_Arg_2), (VOID *)NetLibStrToIp6andPrefix_Arg_2);
            }
            Status = NetLibStrToIp6andPrefix(
                NetLibStrToIp6andPrefix_Arg_0,
                NetLibStrToIp6andPrefix_Arg_1,
                NetLibStrToIp6andPrefix_Arg_2
            );
    
            break;
        }
        case 5:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * NetLibStrToIp6_Arg_0 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 NetLibStrToIp6_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(NetLibStrToIp6_Arg_0_choice), (VOID *)&NetLibStrToIp6_Arg_0_choice);
            switch(NetLibStrToIp6_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(NetLibStrToIp6_Arg_0), (VOID *)NetLibStrToIp6_Arg_0);
                    break;
                case 1:
                {
                    gBS->FreePool(NetLibStrToIp6_Arg_0);
                    NetLibStrToIp6_Arg_0 = NULL;
                    break;
                }
            }
            
            /*
                Output Variable(s)
            */
            EFI_IPv6_ADDRESS * NetLibStrToIp6_Arg_1 = (EFI_IPv6_ADDRESS *)AllocateZeroPool(sizeof(EFI_IPv6_ADDRESS));
            UINT8* NetLibStrToIp6_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(NetLibStrToIp6_Arg_1_OutputChoice), (VOID *)NetLibStrToIp6_Arg_1_OutputChoice);
            if(*NetLibStrToIp6_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*NetLibStrToIp6_Arg_1), (VOID *)NetLibStrToIp6_Arg_1);
            }
            Status = NetLibStrToIp6(
                NetLibStrToIp6_Arg_0,
                NetLibStrToIp6_Arg_1
            );
    
            break;
        }
        case 6:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR8 * NetLibAsciiStrToIp6_Arg_0 = (CHAR8 *)AllocateZeroPool(sizeof(CHAR8));
            
            // Fuzzable Variable Initialization
            UINT8 NetLibAsciiStrToIp6_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(NetLibAsciiStrToIp6_Arg_0_choice), (VOID *)&NetLibAsciiStrToIp6_Arg_0_choice);
            switch(NetLibAsciiStrToIp6_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(NetLibAsciiStrToIp6_Arg_0), (VOID *)NetLibAsciiStrToIp6_Arg_0);
                    break;
                case 1:
                {
                    gBS->FreePool(NetLibAsciiStrToIp6_Arg_0);
                    NetLibAsciiStrToIp6_Arg_0 = NULL;
                    break;
                }
            }
            
            /*
                Output Variable(s)
            */
            EFI_IPv6_ADDRESS * NetLibAsciiStrToIp6_Arg_1 = (EFI_IPv6_ADDRESS *)AllocateZeroPool(sizeof(EFI_IPv6_ADDRESS));
            UINT8* NetLibAsciiStrToIp6_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(NetLibAsciiStrToIp6_Arg_1_OutputChoice), (VOID *)NetLibAsciiStrToIp6_Arg_1_OutputChoice);
            if(*NetLibAsciiStrToIp6_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*NetLibAsciiStrToIp6_Arg_1), (VOID *)NetLibAsciiStrToIp6_Arg_1);
            }
            Status = NetLibAsciiStrToIp6(
                NetLibAsciiStrToIp6_Arg_0,
                NetLibAsciiStrToIp6_Arg_1
            );
    
            break;
        }
        case 7:
        {
        // Generator Struct Variable Initialization
        ReadBytes(Input, sizeof(IpToHostName_Arg_1.Addr), (VOID *)&(IpToHostName_Arg_1.Addr));
    
            break;
        }
    }
    Status = ProtocolVariable->IpToHostName(
        ProtocolVariable,
        IpToHostName_Arg_1,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GeneralLookUp.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGeneralLookUp(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DNS4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDns4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR8 * GeneralLookUp_Arg_1 = (CHAR8 *)AllocateZeroPool(sizeof(CHAR8));
    UINT16 GeneralLookUp_Arg_2 = 0;
    UINT16 GeneralLookUp_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    UINT8 GeneralLookUp_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GeneralLookUp_Arg_1_choice), (VOID *)&GeneralLookUp_Arg_1_choice);
    switch(GeneralLookUp_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GeneralLookUp_Arg_1), (VOID *)GeneralLookUp_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(GeneralLookUp_Arg_1);
            GeneralLookUp_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GeneralLookUp_Arg_2), (VOID *)&GeneralLookUp_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GeneralLookUp_Arg_3), (VOID *)&GeneralLookUp_Arg_3);
    
    Status = ProtocolVariable->GeneralLookUp(
        ProtocolVariable,
        GeneralLookUp_Arg_1,
        GeneralLookUp_Arg_2,
        GeneralLookUp_Arg_3,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UpdateDnsCache.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUpdateDnsCache(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DNS4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDns4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN UpdateDnsCache_Arg_1 = FALSE;
    BOOLEAN UpdateDnsCache_Arg_2 = FALSE;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UpdateDnsCache_Arg_1), (VOID *)&UpdateDnsCache_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UpdateDnsCache_Arg_2), (VOID *)&UpdateDnsCache_Arg_2);
    
    Status = ProtocolVariable->UpdateDnsCache(
        ProtocolVariable,
        UpdateDnsCache_Arg_1,
        UpdateDnsCache_Arg_2,
        (EFI_DNS4_CACHE_ENTRY){0}
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
    EFI_DNS4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDns4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Cancel(
        ProtocolVariable,
        NULL
    );
    return Status;
}

