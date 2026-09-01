#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called Receive.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzReceive(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_IP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Receive(
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
    EFI_IP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_IP4_CONFIG_DATA * Configure_Arg_1 = (EFI_IP4_CONFIG_DATA *)AllocateZeroPool(sizeof(EFI_IP4_CONFIG_DATA));
    
    // Generator Struct Variable Initialization
    {
        UINT8 Firness_DefaultProtocol;
        ReadBytes(Input, sizeof(Firness_DefaultProtocol), (VOID *)&Firness_DefaultProtocol);
        Configure_Arg_1->DefaultProtocol = Firness_DefaultProtocol;
    }
    {
        BOOLEAN Firness_AcceptAnyProtocol;
        ReadBytes(Input, sizeof(Firness_AcceptAnyProtocol), (VOID *)&Firness_AcceptAnyProtocol);
        Configure_Arg_1->AcceptAnyProtocol = Firness_AcceptAnyProtocol;
    }
    {
        BOOLEAN Firness_AcceptIcmpErrors;
        ReadBytes(Input, sizeof(Firness_AcceptIcmpErrors), (VOID *)&Firness_AcceptIcmpErrors);
        Configure_Arg_1->AcceptIcmpErrors = Firness_AcceptIcmpErrors;
    }
    {
        BOOLEAN Firness_AcceptBroadcast;
        ReadBytes(Input, sizeof(Firness_AcceptBroadcast), (VOID *)&Firness_AcceptBroadcast);
        Configure_Arg_1->AcceptBroadcast = Firness_AcceptBroadcast;
    }
    {
        BOOLEAN Firness_AcceptPromiscuous;
        ReadBytes(Input, sizeof(Firness_AcceptPromiscuous), (VOID *)&Firness_AcceptPromiscuous);
        Configure_Arg_1->AcceptPromiscuous = Firness_AcceptPromiscuous;
    }
    {
        BOOLEAN Firness_UseDefaultAddress;
        ReadBytes(Input, sizeof(Firness_UseDefaultAddress), (VOID *)&Firness_UseDefaultAddress);
        Configure_Arg_1->UseDefaultAddress = Firness_UseDefaultAddress;
    }
    {
        EFI_IPv4_ADDRESS Firness_StationAddress;
        ReadBytes(Input, sizeof(Firness_StationAddress), (VOID *)&Firness_StationAddress);
        Configure_Arg_1->StationAddress = Firness_StationAddress;
    }
    {
        EFI_IPv4_ADDRESS Firness_SubnetMask;
        ReadBytes(Input, sizeof(Firness_SubnetMask), (VOID *)&Firness_SubnetMask);
        Configure_Arg_1->SubnetMask = Firness_SubnetMask;
    }
    {
        UINT8 Firness_TypeOfService;
        ReadBytes(Input, sizeof(Firness_TypeOfService), (VOID *)&Firness_TypeOfService);
        Configure_Arg_1->TypeOfService = Firness_TypeOfService;
    }
    {
        UINT8 Firness_TimeToLive;
        ReadBytes(Input, sizeof(Firness_TimeToLive), (VOID *)&Firness_TimeToLive);
        Configure_Arg_1->TimeToLive = Firness_TimeToLive;
    }
    {
        BOOLEAN Firness_DoNotFragment;
        ReadBytes(Input, sizeof(Firness_DoNotFragment), (VOID *)&Firness_DoNotFragment);
        Configure_Arg_1->DoNotFragment = Firness_DoNotFragment;
    }
    {
        BOOLEAN Firness_RawData;
        ReadBytes(Input, sizeof(Firness_RawData), (VOID *)&Firness_RawData);
        Configure_Arg_1->RawData = Firness_RawData;
    }
    {
        UINT32 Firness_ReceiveTimeout;
        ReadBytes(Input, sizeof(Firness_ReceiveTimeout), (VOID *)&Firness_ReceiveTimeout);
        Configure_Arg_1->ReceiveTimeout = Firness_ReceiveTimeout;
    }
    {
        UINT32 Firness_TransmitTimeout;
        ReadBytes(Input, sizeof(Firness_TransmitTimeout), (VOID *)&Firness_TransmitTimeout);
        Configure_Arg_1->TransmitTimeout = Firness_TransmitTimeout;
    }
    
    Status = ProtocolVariable->Configure(
        ProtocolVariable,
        Configure_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Routes.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRoutes(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_IP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN Routes_Arg_1 = FALSE;
    EFI_IPv4_ADDRESS * Routes_Arg_2 = (EFI_IPv4_ADDRESS *)AllocateZeroPool(sizeof(EFI_IPv4_ADDRESS));
    EFI_IPv4_ADDRESS * Routes_Arg_3 = (EFI_IPv4_ADDRESS *)AllocateZeroPool(sizeof(EFI_IPv4_ADDRESS));
    EFI_IPv4_ADDRESS * Routes_Arg_4 = (EFI_IPv4_ADDRESS *)AllocateZeroPool(sizeof(EFI_IPv4_ADDRESS));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Routes_Arg_1), (VOID *)&Routes_Arg_1);
    
    UINT8* Routes_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Routes_Arg_2_choice), (VOID *)Routes_Arg_2_choice);
    switch(*Routes_Arg_2_choice % 10) {
        case 0:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR8 * HttpUrlGetIp6_Arg_0 = (CHAR8 *)AllocateZeroPool(sizeof(CHAR8));
            UINTN*  HttpUrlGetIp6_Arg_1 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
            
            // Fuzzable Variable Initialization
            UINT8 HttpUrlGetIp6_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(HttpUrlGetIp6_Arg_0_choice), (VOID *)&HttpUrlGetIp6_Arg_0_choice);
            switch(HttpUrlGetIp6_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(HttpUrlGetIp6_Arg_0), (VOID *)HttpUrlGetIp6_Arg_0);
                    break;
                case 1:
                {
                    gBS->FreePool(HttpUrlGetIp6_Arg_0);
                    HttpUrlGetIp6_Arg_0 = NULL;
                    break;
                }
            }
            
            // Fuzzable Variable Initialization
            UINT8 HttpUrlGetIp6_Arg_1_choice = 0;
            ReadBytes(Input, sizeof(HttpUrlGetIp6_Arg_1_choice), (VOID *)&HttpUrlGetIp6_Arg_1_choice);
            switch(HttpUrlGetIp6_Arg_1_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(HttpUrlGetIp6_Arg_1), (VOID *)HttpUrlGetIp6_Arg_1);
                    break;
                case 1:
                {
                    gBS->FreePool(HttpUrlGetIp6_Arg_1);
                    HttpUrlGetIp6_Arg_1 = NULL;
                    break;
                }
            }
            
            /*
                Output Variable(s)
            */
            EFI_IPv6_ADDRESS * HttpUrlGetIp6_Arg_2 = (EFI_IPv6_ADDRESS *)AllocateZeroPool(sizeof(EFI_IPv6_ADDRESS));
            UINT8* HttpUrlGetIp6_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(HttpUrlGetIp6_Arg_2_OutputChoice), (VOID *)HttpUrlGetIp6_Arg_2_OutputChoice);
            if(*HttpUrlGetIp6_Arg_2_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*HttpUrlGetIp6_Arg_2), (VOID *)HttpUrlGetIp6_Arg_2);
            }
            Status = HttpUrlGetIp6(
                HttpUrlGetIp6_Arg_0,
                (void *)HttpUrlGetIp6_Arg_1,
                HttpUrlGetIp6_Arg_2
            );
    
            break;
        }
        case 1:
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
                Routes_Arg_2
            );
    
            break;
        }
        case 2:
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
                Routes_Arg_2
            );
    
            break;
        }
        case 3:
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
                Routes_Arg_2,
                StrToIpv4Address_Arg_3
            );
    
            break;
        }
        case 4:
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
        case 5:
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
        case 6:
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
        case 7:
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
        case 8:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR8 * HttpUrlGetIp4_Arg_0 = (CHAR8 *)AllocateZeroPool(sizeof(CHAR8));
            UINTN*  HttpUrlGetIp4_Arg_1 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
            
            // Fuzzable Variable Initialization
            UINT8 HttpUrlGetIp4_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(HttpUrlGetIp4_Arg_0_choice), (VOID *)&HttpUrlGetIp4_Arg_0_choice);
            switch(HttpUrlGetIp4_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(HttpUrlGetIp4_Arg_0), (VOID *)HttpUrlGetIp4_Arg_0);
                    break;
                case 1:
                {
                    gBS->FreePool(HttpUrlGetIp4_Arg_0);
                    HttpUrlGetIp4_Arg_0 = NULL;
                    break;
                }
            }
            
            // Fuzzable Variable Initialization
            UINT8 HttpUrlGetIp4_Arg_1_choice = 0;
            ReadBytes(Input, sizeof(HttpUrlGetIp4_Arg_1_choice), (VOID *)&HttpUrlGetIp4_Arg_1_choice);
            switch(HttpUrlGetIp4_Arg_1_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(HttpUrlGetIp4_Arg_1), (VOID *)HttpUrlGetIp4_Arg_1);
                    break;
                case 1:
                {
                    gBS->FreePool(HttpUrlGetIp4_Arg_1);
                    HttpUrlGetIp4_Arg_1 = NULL;
                    break;
                }
            }
            
            Status = HttpUrlGetIp4(
                HttpUrlGetIp4_Arg_0,
                (void *)HttpUrlGetIp4_Arg_1,
                Routes_Arg_2
            );
    
            break;
        }
        case 9:
        {
        // Generator Struct Variable Initialization
        ReadBytes(Input, sizeof(Routes_Arg_2->Addr), (VOID *)&(Routes_Arg_2->Addr));
    
            break;
        }
    }
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(Routes_Arg_3->Addr), (VOID *)&(Routes_Arg_3->Addr));
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(Routes_Arg_4->Addr), (VOID *)&(Routes_Arg_4->Addr));
    
    Status = ProtocolVariable->Routes(
        ProtocolVariable,
        Routes_Arg_1,
        Routes_Arg_2,
        Routes_Arg_3,
        Routes_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Transmit.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzTransmit(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_IP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Transmit(
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
    EFI_IP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    EFI_IP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_MANAGED_NETWORK_CONFIG_DATA * GetModeData_Arg_2 = (EFI_MANAGED_NETWORK_CONFIG_DATA *)AllocateZeroPool(sizeof(EFI_MANAGED_NETWORK_CONFIG_DATA));
    EFI_SIMPLE_NETWORK_MODE * GetModeData_Arg_3 = (EFI_SIMPLE_NETWORK_MODE *)AllocateZeroPool(sizeof(EFI_SIMPLE_NETWORK_MODE));
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_ReceivedQueueTimeoutValue;
        ReadBytes(Input, sizeof(Firness_ReceivedQueueTimeoutValue), (VOID *)&Firness_ReceivedQueueTimeoutValue);
        GetModeData_Arg_2->ReceivedQueueTimeoutValue = Firness_ReceivedQueueTimeoutValue;
    }
    {
        UINT32 Firness_TransmitQueueTimeoutValue;
        ReadBytes(Input, sizeof(Firness_TransmitQueueTimeoutValue), (VOID *)&Firness_TransmitQueueTimeoutValue);
        GetModeData_Arg_2->TransmitQueueTimeoutValue = Firness_TransmitQueueTimeoutValue;
    }
    {
        UINT16 Firness_ProtocolTypeFilter;
        ReadBytes(Input, sizeof(Firness_ProtocolTypeFilter), (VOID *)&Firness_ProtocolTypeFilter);
        GetModeData_Arg_2->ProtocolTypeFilter = Firness_ProtocolTypeFilter;
    }
    {
        BOOLEAN Firness_EnableUnicastReceive;
        ReadBytes(Input, sizeof(Firness_EnableUnicastReceive), (VOID *)&Firness_EnableUnicastReceive);
        GetModeData_Arg_2->EnableUnicastReceive = Firness_EnableUnicastReceive;
    }
    {
        BOOLEAN Firness_EnableMulticastReceive;
        ReadBytes(Input, sizeof(Firness_EnableMulticastReceive), (VOID *)&Firness_EnableMulticastReceive);
        GetModeData_Arg_2->EnableMulticastReceive = Firness_EnableMulticastReceive;
    }
    {
        BOOLEAN Firness_EnableBroadcastReceive;
        ReadBytes(Input, sizeof(Firness_EnableBroadcastReceive), (VOID *)&Firness_EnableBroadcastReceive);
        GetModeData_Arg_2->EnableBroadcastReceive = Firness_EnableBroadcastReceive;
    }
    {
        BOOLEAN Firness_EnablePromiscuousReceive;
        ReadBytes(Input, sizeof(Firness_EnablePromiscuousReceive), (VOID *)&Firness_EnablePromiscuousReceive);
        GetModeData_Arg_2->EnablePromiscuousReceive = Firness_EnablePromiscuousReceive;
    }
    {
        BOOLEAN Firness_FlushQueuesOnReset;
        ReadBytes(Input, sizeof(Firness_FlushQueuesOnReset), (VOID *)&Firness_FlushQueuesOnReset);
        GetModeData_Arg_2->FlushQueuesOnReset = Firness_FlushQueuesOnReset;
    }
    {
        BOOLEAN Firness_EnableReceiveTimestamps;
        ReadBytes(Input, sizeof(Firness_EnableReceiveTimestamps), (VOID *)&Firness_EnableReceiveTimestamps);
        GetModeData_Arg_2->EnableReceiveTimestamps = Firness_EnableReceiveTimestamps;
    }
    {
        BOOLEAN Firness_DisableBackgroundPolling;
        ReadBytes(Input, sizeof(Firness_DisableBackgroundPolling), (VOID *)&Firness_DisableBackgroundPolling);
        GetModeData_Arg_2->DisableBackgroundPolling = Firness_DisableBackgroundPolling;
    }
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_State;
        ReadBytes(Input, sizeof(Firness_State), (VOID *)&Firness_State);
        GetModeData_Arg_3->State = Firness_State;
    }
    {
        UINT32 Firness_HwAddressSize;
        ReadBytes(Input, sizeof(Firness_HwAddressSize), (VOID *)&Firness_HwAddressSize);
        GetModeData_Arg_3->HwAddressSize = Firness_HwAddressSize;
    }
    {
        UINT32 Firness_MediaHeaderSize;
        ReadBytes(Input, sizeof(Firness_MediaHeaderSize), (VOID *)&Firness_MediaHeaderSize);
        GetModeData_Arg_3->MediaHeaderSize = Firness_MediaHeaderSize;
    }
    {
        UINT32 Firness_MaxPacketSize;
        ReadBytes(Input, sizeof(Firness_MaxPacketSize), (VOID *)&Firness_MaxPacketSize);
        GetModeData_Arg_3->MaxPacketSize = Firness_MaxPacketSize;
    }
    {
        UINT32 Firness_NvRamSize;
        ReadBytes(Input, sizeof(Firness_NvRamSize), (VOID *)&Firness_NvRamSize);
        GetModeData_Arg_3->NvRamSize = Firness_NvRamSize;
    }
    {
        UINT32 Firness_NvRamAccessSize;
        ReadBytes(Input, sizeof(Firness_NvRamAccessSize), (VOID *)&Firness_NvRamAccessSize);
        GetModeData_Arg_3->NvRamAccessSize = Firness_NvRamAccessSize;
    }
    {
        UINT32 Firness_ReceiveFilterMask;
        ReadBytes(Input, sizeof(Firness_ReceiveFilterMask), (VOID *)&Firness_ReceiveFilterMask);
        GetModeData_Arg_3->ReceiveFilterMask = Firness_ReceiveFilterMask;
    }
    {
        UINT32 Firness_ReceiveFilterSetting;
        ReadBytes(Input, sizeof(Firness_ReceiveFilterSetting), (VOID *)&Firness_ReceiveFilterSetting);
        GetModeData_Arg_3->ReceiveFilterSetting = Firness_ReceiveFilterSetting;
    }
    {
        UINT32 Firness_MaxMCastFilterCount;
        ReadBytes(Input, sizeof(Firness_MaxMCastFilterCount), (VOID *)&Firness_MaxMCastFilterCount);
        GetModeData_Arg_3->MaxMCastFilterCount = Firness_MaxMCastFilterCount;
    }
    {
        UINT32 Firness_MCastFilterCount;
        ReadBytes(Input, sizeof(Firness_MCastFilterCount), (VOID *)&Firness_MCastFilterCount);
        GetModeData_Arg_3->MCastFilterCount = Firness_MCastFilterCount;
    }
    ReadBytes(Input, sizeof(GetModeData_Arg_3->MCastFilter), (VOID *)&(GetModeData_Arg_3->MCastFilter));
    {
        EFI_MAC_ADDRESS Firness_CurrentAddress;
        ReadBytes(Input, sizeof(Firness_CurrentAddress), (VOID *)&Firness_CurrentAddress);
        GetModeData_Arg_3->CurrentAddress = Firness_CurrentAddress;
    }
    {
        EFI_MAC_ADDRESS Firness_BroadcastAddress;
        ReadBytes(Input, sizeof(Firness_BroadcastAddress), (VOID *)&Firness_BroadcastAddress);
        GetModeData_Arg_3->BroadcastAddress = Firness_BroadcastAddress;
    }
    {
        EFI_MAC_ADDRESS Firness_PermanentAddress;
        ReadBytes(Input, sizeof(Firness_PermanentAddress), (VOID *)&Firness_PermanentAddress);
        GetModeData_Arg_3->PermanentAddress = Firness_PermanentAddress;
    }
    {
        UINT8 Firness_IfType;
        ReadBytes(Input, sizeof(Firness_IfType), (VOID *)&Firness_IfType);
        GetModeData_Arg_3->IfType = Firness_IfType;
    }
    {
        BOOLEAN Firness_MacAddressChangeable;
        ReadBytes(Input, sizeof(Firness_MacAddressChangeable), (VOID *)&Firness_MacAddressChangeable);
        GetModeData_Arg_3->MacAddressChangeable = Firness_MacAddressChangeable;
    }
    {
        BOOLEAN Firness_MultipleTxSupported;
        ReadBytes(Input, sizeof(Firness_MultipleTxSupported), (VOID *)&Firness_MultipleTxSupported);
        GetModeData_Arg_3->MultipleTxSupported = Firness_MultipleTxSupported;
    }
    {
        BOOLEAN Firness_MediaPresentSupported;
        ReadBytes(Input, sizeof(Firness_MediaPresentSupported), (VOID *)&Firness_MediaPresentSupported);
        GetModeData_Arg_3->MediaPresentSupported = Firness_MediaPresentSupported;
    }
    {
        BOOLEAN Firness_MediaPresent;
        ReadBytes(Input, sizeof(Firness_MediaPresent), (VOID *)&Firness_MediaPresent);
        GetModeData_Arg_3->MediaPresent = Firness_MediaPresent;
    }
    
    Status = ProtocolVariable->GetModeData(
        ProtocolVariable,
        NULL,
        GetModeData_Arg_2,
        GetModeData_Arg_3
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
    EFI_IP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    called Groups.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGroups(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_IP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN Groups_Arg_1 = FALSE;
    EFI_IPv4_ADDRESS * Groups_Arg_2 = (EFI_IPv4_ADDRESS *)AllocateZeroPool(sizeof(EFI_IPv4_ADDRESS));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Groups_Arg_1), (VOID *)&Groups_Arg_1);
    
    UINT8* Groups_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Groups_Arg_2_choice), (VOID *)Groups_Arg_2_choice);
    switch(*Groups_Arg_2_choice % 10) {
        case 0:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR8 * HttpUrlGetIp6_Arg_0 = (CHAR8 *)AllocateZeroPool(sizeof(CHAR8));
            UINTN*  HttpUrlGetIp6_Arg_1 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
            
            // Fuzzable Variable Initialization
            UINT8 HttpUrlGetIp6_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(HttpUrlGetIp6_Arg_0_choice), (VOID *)&HttpUrlGetIp6_Arg_0_choice);
            switch(HttpUrlGetIp6_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(HttpUrlGetIp6_Arg_0), (VOID *)HttpUrlGetIp6_Arg_0);
                    break;
                case 1:
                {
                    gBS->FreePool(HttpUrlGetIp6_Arg_0);
                    HttpUrlGetIp6_Arg_0 = NULL;
                    break;
                }
            }
            
            // Fuzzable Variable Initialization
            UINT8 HttpUrlGetIp6_Arg_1_choice = 0;
            ReadBytes(Input, sizeof(HttpUrlGetIp6_Arg_1_choice), (VOID *)&HttpUrlGetIp6_Arg_1_choice);
            switch(HttpUrlGetIp6_Arg_1_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(HttpUrlGetIp6_Arg_1), (VOID *)HttpUrlGetIp6_Arg_1);
                    break;
                case 1:
                {
                    gBS->FreePool(HttpUrlGetIp6_Arg_1);
                    HttpUrlGetIp6_Arg_1 = NULL;
                    break;
                }
            }
            
            /*
                Output Variable(s)
            */
            EFI_IPv6_ADDRESS * HttpUrlGetIp6_Arg_2 = (EFI_IPv6_ADDRESS *)AllocateZeroPool(sizeof(EFI_IPv6_ADDRESS));
            UINT8* HttpUrlGetIp6_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(HttpUrlGetIp6_Arg_2_OutputChoice), (VOID *)HttpUrlGetIp6_Arg_2_OutputChoice);
            if(*HttpUrlGetIp6_Arg_2_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*HttpUrlGetIp6_Arg_2), (VOID *)HttpUrlGetIp6_Arg_2);
            }
            Status = HttpUrlGetIp6(
                HttpUrlGetIp6_Arg_0,
                (void *)HttpUrlGetIp6_Arg_1,
                HttpUrlGetIp6_Arg_2
            );
    
            break;
        }
        case 1:
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
                Groups_Arg_2
            );
    
            break;
        }
        case 2:
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
                Groups_Arg_2
            );
    
            break;
        }
        case 3:
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
                Groups_Arg_2,
                StrToIpv4Address_Arg_3
            );
    
            break;
        }
        case 4:
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
        case 5:
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
        case 6:
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
        case 7:
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
        case 8:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR8 * HttpUrlGetIp4_Arg_0 = (CHAR8 *)AllocateZeroPool(sizeof(CHAR8));
            UINTN*  HttpUrlGetIp4_Arg_1 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
            
            // Fuzzable Variable Initialization
            UINT8 HttpUrlGetIp4_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(HttpUrlGetIp4_Arg_0_choice), (VOID *)&HttpUrlGetIp4_Arg_0_choice);
            switch(HttpUrlGetIp4_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(HttpUrlGetIp4_Arg_0), (VOID *)HttpUrlGetIp4_Arg_0);
                    break;
                case 1:
                {
                    gBS->FreePool(HttpUrlGetIp4_Arg_0);
                    HttpUrlGetIp4_Arg_0 = NULL;
                    break;
                }
            }
            
            // Fuzzable Variable Initialization
            UINT8 HttpUrlGetIp4_Arg_1_choice = 0;
            ReadBytes(Input, sizeof(HttpUrlGetIp4_Arg_1_choice), (VOID *)&HttpUrlGetIp4_Arg_1_choice);
            switch(HttpUrlGetIp4_Arg_1_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(HttpUrlGetIp4_Arg_1), (VOID *)HttpUrlGetIp4_Arg_1);
                    break;
                case 1:
                {
                    gBS->FreePool(HttpUrlGetIp4_Arg_1);
                    HttpUrlGetIp4_Arg_1 = NULL;
                    break;
                }
            }
            
            Status = HttpUrlGetIp4(
                HttpUrlGetIp4_Arg_0,
                (void *)HttpUrlGetIp4_Arg_1,
                Groups_Arg_2
            );
    
            break;
        }
        case 9:
        {
        // Generator Struct Variable Initialization
        ReadBytes(Input, sizeof(Groups_Arg_2->Addr), (VOID *)&(Groups_Arg_2->Addr));
    
            break;
        }
    }
    Status = ProtocolVariable->Groups(
        ProtocolVariable,
        Groups_Arg_1,
        Groups_Arg_2
    );
    return Status;
}

