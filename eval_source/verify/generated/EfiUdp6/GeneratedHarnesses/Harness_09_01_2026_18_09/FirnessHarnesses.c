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
    EFI_UDP6_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUdp6ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_UDP6_CONFIG_DATA * Configure_Arg_1 = (EFI_UDP6_CONFIG_DATA *)AllocateZeroPool(sizeof(EFI_UDP6_CONFIG_DATA));
    
    // Generator Struct Variable Initialization
    {
        BOOLEAN Firness_AcceptPromiscuous;
        ReadBytes(Input, sizeof(Firness_AcceptPromiscuous), (VOID *)&Firness_AcceptPromiscuous);
        Configure_Arg_1->AcceptPromiscuous = Firness_AcceptPromiscuous;
    }
    {
        BOOLEAN Firness_AcceptAnyPort;
        ReadBytes(Input, sizeof(Firness_AcceptAnyPort), (VOID *)&Firness_AcceptAnyPort);
        Configure_Arg_1->AcceptAnyPort = Firness_AcceptAnyPort;
    }
    {
        BOOLEAN Firness_AllowDuplicatePort;
        ReadBytes(Input, sizeof(Firness_AllowDuplicatePort), (VOID *)&Firness_AllowDuplicatePort);
        Configure_Arg_1->AllowDuplicatePort = Firness_AllowDuplicatePort;
    }
    {
        UINT8 Firness_TrafficClass;
        ReadBytes(Input, sizeof(Firness_TrafficClass), (VOID *)&Firness_TrafficClass);
        Configure_Arg_1->TrafficClass = Firness_TrafficClass;
    }
    {
        UINT8 Firness_HopLimit;
        ReadBytes(Input, sizeof(Firness_HopLimit), (VOID *)&Firness_HopLimit);
        Configure_Arg_1->HopLimit = Firness_HopLimit;
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
    {
        EFI_IPv6_ADDRESS Firness_StationAddress;
        ReadBytes(Input, sizeof(Firness_StationAddress), (VOID *)&Firness_StationAddress);
        Configure_Arg_1->StationAddress = Firness_StationAddress;
    }
    {
        UINT16 Firness_StationPort;
        ReadBytes(Input, sizeof(Firness_StationPort), (VOID *)&Firness_StationPort);
        Configure_Arg_1->StationPort = Firness_StationPort;
    }
    {
        EFI_IPv6_ADDRESS Firness_RemoteAddress;
        ReadBytes(Input, sizeof(Firness_RemoteAddress), (VOID *)&Firness_RemoteAddress);
        Configure_Arg_1->RemoteAddress = Firness_RemoteAddress;
    }
    {
        UINT16 Firness_RemotePort;
        ReadBytes(Input, sizeof(Firness_RemotePort), (VOID *)&Firness_RemotePort);
        Configure_Arg_1->RemotePort = Firness_RemotePort;
    }
    
    Status = ProtocolVariable->Configure(
        ProtocolVariable,
        Configure_Arg_1
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
    EFI_UDP6_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUdp6ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    EFI_UDP6_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUdp6ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_UDP6_CONFIG_DATA * GetModeData_Arg_1 = (EFI_UDP6_CONFIG_DATA *)AllocateZeroPool(sizeof(EFI_UDP6_CONFIG_DATA));
    EFI_IP6_MODE_DATA * GetModeData_Arg_2 = (EFI_IP6_MODE_DATA *)AllocateZeroPool(sizeof(EFI_IP6_MODE_DATA));
    EFI_MANAGED_NETWORK_CONFIG_DATA * GetModeData_Arg_3 = (EFI_MANAGED_NETWORK_CONFIG_DATA *)AllocateZeroPool(sizeof(EFI_MANAGED_NETWORK_CONFIG_DATA));
    
    // Generator Struct Variable Initialization
    {
        BOOLEAN Firness_AcceptPromiscuous;
        ReadBytes(Input, sizeof(Firness_AcceptPromiscuous), (VOID *)&Firness_AcceptPromiscuous);
        GetModeData_Arg_1->AcceptPromiscuous = Firness_AcceptPromiscuous;
    }
    {
        BOOLEAN Firness_AcceptAnyPort;
        ReadBytes(Input, sizeof(Firness_AcceptAnyPort), (VOID *)&Firness_AcceptAnyPort);
        GetModeData_Arg_1->AcceptAnyPort = Firness_AcceptAnyPort;
    }
    {
        BOOLEAN Firness_AllowDuplicatePort;
        ReadBytes(Input, sizeof(Firness_AllowDuplicatePort), (VOID *)&Firness_AllowDuplicatePort);
        GetModeData_Arg_1->AllowDuplicatePort = Firness_AllowDuplicatePort;
    }
    {
        UINT8 Firness_TrafficClass;
        ReadBytes(Input, sizeof(Firness_TrafficClass), (VOID *)&Firness_TrafficClass);
        GetModeData_Arg_1->TrafficClass = Firness_TrafficClass;
    }
    {
        UINT8 Firness_HopLimit;
        ReadBytes(Input, sizeof(Firness_HopLimit), (VOID *)&Firness_HopLimit);
        GetModeData_Arg_1->HopLimit = Firness_HopLimit;
    }
    {
        UINT32 Firness_ReceiveTimeout;
        ReadBytes(Input, sizeof(Firness_ReceiveTimeout), (VOID *)&Firness_ReceiveTimeout);
        GetModeData_Arg_1->ReceiveTimeout = Firness_ReceiveTimeout;
    }
    {
        UINT32 Firness_TransmitTimeout;
        ReadBytes(Input, sizeof(Firness_TransmitTimeout), (VOID *)&Firness_TransmitTimeout);
        GetModeData_Arg_1->TransmitTimeout = Firness_TransmitTimeout;
    }
    {
        EFI_IPv6_ADDRESS Firness_StationAddress;
        ReadBytes(Input, sizeof(Firness_StationAddress), (VOID *)&Firness_StationAddress);
        GetModeData_Arg_1->StationAddress = Firness_StationAddress;
    }
    {
        UINT16 Firness_StationPort;
        ReadBytes(Input, sizeof(Firness_StationPort), (VOID *)&Firness_StationPort);
        GetModeData_Arg_1->StationPort = Firness_StationPort;
    }
    {
        EFI_IPv6_ADDRESS Firness_RemoteAddress;
        ReadBytes(Input, sizeof(Firness_RemoteAddress), (VOID *)&Firness_RemoteAddress);
        GetModeData_Arg_1->RemoteAddress = Firness_RemoteAddress;
    }
    {
        UINT16 Firness_RemotePort;
        ReadBytes(Input, sizeof(Firness_RemotePort), (VOID *)&Firness_RemotePort);
        GetModeData_Arg_1->RemotePort = Firness_RemotePort;
    }
    
    // Generator Struct Variable Initialization
    {
        BOOLEAN Firness_IsStarted;
        ReadBytes(Input, sizeof(Firness_IsStarted), (VOID *)&Firness_IsStarted);
        GetModeData_Arg_2->IsStarted = Firness_IsStarted;
    }
    {
        UINT32 Firness_MaxPacketSize;
        ReadBytes(Input, sizeof(Firness_MaxPacketSize), (VOID *)&Firness_MaxPacketSize);
        GetModeData_Arg_2->MaxPacketSize = Firness_MaxPacketSize;
    }
    {
        EFI_IP6_CONFIG_DATA Firness_ConfigData;
        ReadBytes(Input, sizeof(Firness_ConfigData), (VOID *)&Firness_ConfigData);
        GetModeData_Arg_2->ConfigData = Firness_ConfigData;
    }
    {
        BOOLEAN Firness_IsConfigured;
        ReadBytes(Input, sizeof(Firness_IsConfigured), (VOID *)&Firness_IsConfigured);
        GetModeData_Arg_2->IsConfigured = Firness_IsConfigured;
    }
    {
        UINT32 Firness_AddressCount;
        ReadBytes(Input, sizeof(Firness_AddressCount), (VOID *)&Firness_AddressCount);
        GetModeData_Arg_2->AddressCount = Firness_AddressCount;
    }
    ReadBytes(Input, sizeof(GetModeData_Arg_2->AddressList), (VOID *)&(GetModeData_Arg_2->AddressList));
    {
        UINT32 Firness_GroupCount;
        ReadBytes(Input, sizeof(Firness_GroupCount), (VOID *)&Firness_GroupCount);
        GetModeData_Arg_2->GroupCount = Firness_GroupCount;
    }
    ReadBytes(Input, sizeof(GetModeData_Arg_2->GroupTable), (VOID *)&(GetModeData_Arg_2->GroupTable));
    {
        UINT32 Firness_RouteCount;
        ReadBytes(Input, sizeof(Firness_RouteCount), (VOID *)&Firness_RouteCount);
        GetModeData_Arg_2->RouteCount = Firness_RouteCount;
    }
    ReadBytes(Input, sizeof(GetModeData_Arg_2->RouteTable), (VOID *)&(GetModeData_Arg_2->RouteTable));
    {
        UINT32 Firness_NeighborCount;
        ReadBytes(Input, sizeof(Firness_NeighborCount), (VOID *)&Firness_NeighborCount);
        GetModeData_Arg_2->NeighborCount = Firness_NeighborCount;
    }
    ReadBytes(Input, sizeof(GetModeData_Arg_2->NeighborCache), (VOID *)&(GetModeData_Arg_2->NeighborCache));
    {
        UINT32 Firness_PrefixCount;
        ReadBytes(Input, sizeof(Firness_PrefixCount), (VOID *)&Firness_PrefixCount);
        GetModeData_Arg_2->PrefixCount = Firness_PrefixCount;
    }
    ReadBytes(Input, sizeof(GetModeData_Arg_2->PrefixTable), (VOID *)&(GetModeData_Arg_2->PrefixTable));
    {
        UINT32 Firness_IcmpTypeCount;
        ReadBytes(Input, sizeof(Firness_IcmpTypeCount), (VOID *)&Firness_IcmpTypeCount);
        GetModeData_Arg_2->IcmpTypeCount = Firness_IcmpTypeCount;
    }
    ReadBytes(Input, sizeof(GetModeData_Arg_2->IcmpTypeList), (VOID *)&(GetModeData_Arg_2->IcmpTypeList));
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_ReceivedQueueTimeoutValue;
        ReadBytes(Input, sizeof(Firness_ReceivedQueueTimeoutValue), (VOID *)&Firness_ReceivedQueueTimeoutValue);
        GetModeData_Arg_3->ReceivedQueueTimeoutValue = Firness_ReceivedQueueTimeoutValue;
    }
    {
        UINT32 Firness_TransmitQueueTimeoutValue;
        ReadBytes(Input, sizeof(Firness_TransmitQueueTimeoutValue), (VOID *)&Firness_TransmitQueueTimeoutValue);
        GetModeData_Arg_3->TransmitQueueTimeoutValue = Firness_TransmitQueueTimeoutValue;
    }
    {
        UINT16 Firness_ProtocolTypeFilter;
        ReadBytes(Input, sizeof(Firness_ProtocolTypeFilter), (VOID *)&Firness_ProtocolTypeFilter);
        GetModeData_Arg_3->ProtocolTypeFilter = Firness_ProtocolTypeFilter;
    }
    {
        BOOLEAN Firness_EnableUnicastReceive;
        ReadBytes(Input, sizeof(Firness_EnableUnicastReceive), (VOID *)&Firness_EnableUnicastReceive);
        GetModeData_Arg_3->EnableUnicastReceive = Firness_EnableUnicastReceive;
    }
    {
        BOOLEAN Firness_EnableMulticastReceive;
        ReadBytes(Input, sizeof(Firness_EnableMulticastReceive), (VOID *)&Firness_EnableMulticastReceive);
        GetModeData_Arg_3->EnableMulticastReceive = Firness_EnableMulticastReceive;
    }
    {
        BOOLEAN Firness_EnableBroadcastReceive;
        ReadBytes(Input, sizeof(Firness_EnableBroadcastReceive), (VOID *)&Firness_EnableBroadcastReceive);
        GetModeData_Arg_3->EnableBroadcastReceive = Firness_EnableBroadcastReceive;
    }
    {
        BOOLEAN Firness_EnablePromiscuousReceive;
        ReadBytes(Input, sizeof(Firness_EnablePromiscuousReceive), (VOID *)&Firness_EnablePromiscuousReceive);
        GetModeData_Arg_3->EnablePromiscuousReceive = Firness_EnablePromiscuousReceive;
    }
    {
        BOOLEAN Firness_FlushQueuesOnReset;
        ReadBytes(Input, sizeof(Firness_FlushQueuesOnReset), (VOID *)&Firness_FlushQueuesOnReset);
        GetModeData_Arg_3->FlushQueuesOnReset = Firness_FlushQueuesOnReset;
    }
    {
        BOOLEAN Firness_EnableReceiveTimestamps;
        ReadBytes(Input, sizeof(Firness_EnableReceiveTimestamps), (VOID *)&Firness_EnableReceiveTimestamps);
        GetModeData_Arg_3->EnableReceiveTimestamps = Firness_EnableReceiveTimestamps;
    }
    {
        BOOLEAN Firness_DisableBackgroundPolling;
        ReadBytes(Input, sizeof(Firness_DisableBackgroundPolling), (VOID *)&Firness_DisableBackgroundPolling);
        GetModeData_Arg_3->DisableBackgroundPolling = Firness_DisableBackgroundPolling;
    }
    
    /*
        Output Variable(s)
    */
    EFI_SIMPLE_NETWORK_MODE * GetModeData_Arg_4 = (EFI_SIMPLE_NETWORK_MODE *)AllocateZeroPool(sizeof(EFI_SIMPLE_NETWORK_MODE));
    UINT8* GetModeData_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetModeData_Arg_4_OutputChoice), (VOID *)GetModeData_Arg_4_OutputChoice);
    if(*GetModeData_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetModeData_Arg_4), (VOID *)GetModeData_Arg_4);
    }
    Status = ProtocolVariable->GetModeData(
        ProtocolVariable,
        GetModeData_Arg_1,
        GetModeData_Arg_2,
        GetModeData_Arg_3,
        GetModeData_Arg_4
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
    EFI_UDP6_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUdp6ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    EFI_UDP6_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUdp6ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    EFI_UDP6_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUdp6ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_UDP6_COMPLETION_TOKEN * Cancel_Arg_1 = (EFI_UDP6_COMPLETION_TOKEN *)AllocateZeroPool(sizeof(EFI_UDP6_COMPLETION_TOKEN));
    
    // Generator Struct Variable Initialization
    {
        EFI_EVENT Firness_Event;
        ReadBytes(Input, sizeof(Firness_Event), (VOID *)&Firness_Event);
        Cancel_Arg_1->Event = Firness_Event;
    }
    {
        EFI_STATUS Firness_Status;
        ReadBytes(Input, sizeof(Firness_Status), (VOID *)&Firness_Status);
        Cancel_Arg_1->Status = Firness_Status;
    }
    ReadBytes(Input, sizeof(Cancel_Arg_1->Packet), (VOID *)&(Cancel_Arg_1->Packet));
    
    Status = ProtocolVariable->Cancel(
        ProtocolVariable,
        Cancel_Arg_1
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
    EFI_UDP6_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUdp6ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN Groups_Arg_1 = FALSE;
    EFI_IPv6_ADDRESS * Groups_Arg_2 = (EFI_IPv6_ADDRESS *)AllocateZeroPool(sizeof(EFI_IPv6_ADDRESS));
    
    UINT8* Groups_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Groups_Arg_1_choice), (VOID *)Groups_Arg_1_choice);
    switch(*Groups_Arg_1_choice % 2) {
        case 0:
        {
        // Constant Variable Initialization
        Groups_Arg_1 = SATA_ENUMER_ALL;
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(Groups_Arg_1), (VOID *)&Groups_Arg_1);
    
            break;
        }
    }
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
            
            Status = HttpUrlGetIp6(
                HttpUrlGetIp6_Arg_0,
                (void *)HttpUrlGetIp6_Arg_1,
                Groups_Arg_2
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
            
            /*
                Output Variable(s)
            */
            EFI_IPv4_ADDRESS * NetLibStrToIp4_Arg_1 = (EFI_IPv4_ADDRESS *)AllocateZeroPool(sizeof(EFI_IPv4_ADDRESS));
            UINT8* NetLibStrToIp4_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(NetLibStrToIp4_Arg_1_OutputChoice), (VOID *)NetLibStrToIp4_Arg_1_OutputChoice);
            if(*NetLibStrToIp4_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*NetLibStrToIp4_Arg_1), (VOID *)NetLibStrToIp4_Arg_1);
            }
            Status = NetLibStrToIp4(
                NetLibStrToIp4_Arg_0,
                NetLibStrToIp4_Arg_1
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
            
            /*
                Output Variable(s)
            */
            EFI_IPv4_ADDRESS * NetLibAsciiStrToIp4_Arg_1 = (EFI_IPv4_ADDRESS *)AllocateZeroPool(sizeof(EFI_IPv4_ADDRESS));
            UINT8* NetLibAsciiStrToIp4_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(NetLibAsciiStrToIp4_Arg_1_OutputChoice), (VOID *)NetLibAsciiStrToIp4_Arg_1_OutputChoice);
            if(*NetLibAsciiStrToIp4_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*NetLibAsciiStrToIp4_Arg_1), (VOID *)NetLibAsciiStrToIp4_Arg_1);
            }
            Status = NetLibAsciiStrToIp4(
                NetLibAsciiStrToIp4_Arg_0,
                NetLibAsciiStrToIp4_Arg_1
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
            EFI_IPv4_ADDRESS * StrToIpv4Address_Arg_2 = (EFI_IPv4_ADDRESS *)AllocateZeroPool(sizeof(EFI_IPv4_ADDRESS));
            UINT8* StrToIpv4Address_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(StrToIpv4Address_Arg_2_OutputChoice), (VOID *)StrToIpv4Address_Arg_2_OutputChoice);
            if(*StrToIpv4Address_Arg_2_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*StrToIpv4Address_Arg_2), (VOID *)StrToIpv4Address_Arg_2);
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
                StrToIpv4Address_Arg_2,
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
                Groups_Arg_2,
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
            UINT8 * NetLibStrToIp6andPrefix_Arg_2 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
            UINT8* NetLibStrToIp6andPrefix_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(NetLibStrToIp6andPrefix_Arg_2_OutputChoice), (VOID *)NetLibStrToIp6andPrefix_Arg_2_OutputChoice);
            if(*NetLibStrToIp6andPrefix_Arg_2_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*NetLibStrToIp6andPrefix_Arg_2), (VOID *)NetLibStrToIp6andPrefix_Arg_2);
            }
            Status = NetLibStrToIp6andPrefix(
                NetLibStrToIp6andPrefix_Arg_0,
                Groups_Arg_2,
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
            
            Status = NetLibStrToIp6(
                NetLibStrToIp6_Arg_0,
                Groups_Arg_2
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
            
            Status = NetLibAsciiStrToIp6(
                NetLibAsciiStrToIp6_Arg_0,
                Groups_Arg_2
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
            
            /*
                Output Variable(s)
            */
            EFI_IPv4_ADDRESS * HttpUrlGetIp4_Arg_2 = (EFI_IPv4_ADDRESS *)AllocateZeroPool(sizeof(EFI_IPv4_ADDRESS));
            UINT8* HttpUrlGetIp4_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(HttpUrlGetIp4_Arg_2_OutputChoice), (VOID *)HttpUrlGetIp4_Arg_2_OutputChoice);
            if(*HttpUrlGetIp4_Arg_2_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*HttpUrlGetIp4_Arg_2), (VOID *)HttpUrlGetIp4_Arg_2);
            }
            Status = HttpUrlGetIp4(
                HttpUrlGetIp4_Arg_0,
                (void *)HttpUrlGetIp4_Arg_1,
                HttpUrlGetIp4_Arg_2
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

