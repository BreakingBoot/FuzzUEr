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
    EFI_MANAGED_NETWORK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiManagedNetworkProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_MANAGED_NETWORK_CONFIG_DATA * GetModeData_Arg_1 = (EFI_MANAGED_NETWORK_CONFIG_DATA *)AllocateZeroPool(sizeof(EFI_MANAGED_NETWORK_CONFIG_DATA));
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_ReceivedQueueTimeoutValue;
        ReadBytes(Input, sizeof(Firness_ReceivedQueueTimeoutValue), (VOID *)&Firness_ReceivedQueueTimeoutValue);
        GetModeData_Arg_1->ReceivedQueueTimeoutValue = Firness_ReceivedQueueTimeoutValue;
    }
    {
        UINT32 Firness_TransmitQueueTimeoutValue;
        ReadBytes(Input, sizeof(Firness_TransmitQueueTimeoutValue), (VOID *)&Firness_TransmitQueueTimeoutValue);
        GetModeData_Arg_1->TransmitQueueTimeoutValue = Firness_TransmitQueueTimeoutValue;
    }
    {
        UINT16 Firness_ProtocolTypeFilter;
        ReadBytes(Input, sizeof(Firness_ProtocolTypeFilter), (VOID *)&Firness_ProtocolTypeFilter);
        GetModeData_Arg_1->ProtocolTypeFilter = Firness_ProtocolTypeFilter;
    }
    {
        BOOLEAN Firness_EnableUnicastReceive;
        ReadBytes(Input, sizeof(Firness_EnableUnicastReceive), (VOID *)&Firness_EnableUnicastReceive);
        GetModeData_Arg_1->EnableUnicastReceive = Firness_EnableUnicastReceive;
    }
    {
        BOOLEAN Firness_EnableMulticastReceive;
        ReadBytes(Input, sizeof(Firness_EnableMulticastReceive), (VOID *)&Firness_EnableMulticastReceive);
        GetModeData_Arg_1->EnableMulticastReceive = Firness_EnableMulticastReceive;
    }
    {
        BOOLEAN Firness_EnableBroadcastReceive;
        ReadBytes(Input, sizeof(Firness_EnableBroadcastReceive), (VOID *)&Firness_EnableBroadcastReceive);
        GetModeData_Arg_1->EnableBroadcastReceive = Firness_EnableBroadcastReceive;
    }
    {
        BOOLEAN Firness_EnablePromiscuousReceive;
        ReadBytes(Input, sizeof(Firness_EnablePromiscuousReceive), (VOID *)&Firness_EnablePromiscuousReceive);
        GetModeData_Arg_1->EnablePromiscuousReceive = Firness_EnablePromiscuousReceive;
    }
    {
        BOOLEAN Firness_FlushQueuesOnReset;
        ReadBytes(Input, sizeof(Firness_FlushQueuesOnReset), (VOID *)&Firness_FlushQueuesOnReset);
        GetModeData_Arg_1->FlushQueuesOnReset = Firness_FlushQueuesOnReset;
    }
    {
        BOOLEAN Firness_EnableReceiveTimestamps;
        ReadBytes(Input, sizeof(Firness_EnableReceiveTimestamps), (VOID *)&Firness_EnableReceiveTimestamps);
        GetModeData_Arg_1->EnableReceiveTimestamps = Firness_EnableReceiveTimestamps;
    }
    {
        BOOLEAN Firness_DisableBackgroundPolling;
        ReadBytes(Input, sizeof(Firness_DisableBackgroundPolling), (VOID *)&Firness_DisableBackgroundPolling);
        GetModeData_Arg_1->DisableBackgroundPolling = Firness_DisableBackgroundPolling;
    }
    
    Status = ProtocolVariable->GetModeData(
        ProtocolVariable,
        GetModeData_Arg_1,
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
    EFI_MANAGED_NETWORK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiManagedNetworkProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_MANAGED_NETWORK_CONFIG_DATA * Configure_Arg_1 = (EFI_MANAGED_NETWORK_CONFIG_DATA *)AllocateZeroPool(sizeof(EFI_MANAGED_NETWORK_CONFIG_DATA));
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_ReceivedQueueTimeoutValue;
        ReadBytes(Input, sizeof(Firness_ReceivedQueueTimeoutValue), (VOID *)&Firness_ReceivedQueueTimeoutValue);
        Configure_Arg_1->ReceivedQueueTimeoutValue = Firness_ReceivedQueueTimeoutValue;
    }
    {
        UINT32 Firness_TransmitQueueTimeoutValue;
        ReadBytes(Input, sizeof(Firness_TransmitQueueTimeoutValue), (VOID *)&Firness_TransmitQueueTimeoutValue);
        Configure_Arg_1->TransmitQueueTimeoutValue = Firness_TransmitQueueTimeoutValue;
    }
    {
        UINT16 Firness_ProtocolTypeFilter;
        ReadBytes(Input, sizeof(Firness_ProtocolTypeFilter), (VOID *)&Firness_ProtocolTypeFilter);
        Configure_Arg_1->ProtocolTypeFilter = Firness_ProtocolTypeFilter;
    }
    {
        BOOLEAN Firness_EnableUnicastReceive;
        ReadBytes(Input, sizeof(Firness_EnableUnicastReceive), (VOID *)&Firness_EnableUnicastReceive);
        Configure_Arg_1->EnableUnicastReceive = Firness_EnableUnicastReceive;
    }
    {
        BOOLEAN Firness_EnableMulticastReceive;
        ReadBytes(Input, sizeof(Firness_EnableMulticastReceive), (VOID *)&Firness_EnableMulticastReceive);
        Configure_Arg_1->EnableMulticastReceive = Firness_EnableMulticastReceive;
    }
    {
        BOOLEAN Firness_EnableBroadcastReceive;
        ReadBytes(Input, sizeof(Firness_EnableBroadcastReceive), (VOID *)&Firness_EnableBroadcastReceive);
        Configure_Arg_1->EnableBroadcastReceive = Firness_EnableBroadcastReceive;
    }
    {
        BOOLEAN Firness_EnablePromiscuousReceive;
        ReadBytes(Input, sizeof(Firness_EnablePromiscuousReceive), (VOID *)&Firness_EnablePromiscuousReceive);
        Configure_Arg_1->EnablePromiscuousReceive = Firness_EnablePromiscuousReceive;
    }
    {
        BOOLEAN Firness_FlushQueuesOnReset;
        ReadBytes(Input, sizeof(Firness_FlushQueuesOnReset), (VOID *)&Firness_FlushQueuesOnReset);
        Configure_Arg_1->FlushQueuesOnReset = Firness_FlushQueuesOnReset;
    }
    {
        BOOLEAN Firness_EnableReceiveTimestamps;
        ReadBytes(Input, sizeof(Firness_EnableReceiveTimestamps), (VOID *)&Firness_EnableReceiveTimestamps);
        Configure_Arg_1->EnableReceiveTimestamps = Firness_EnableReceiveTimestamps;
    }
    {
        BOOLEAN Firness_DisableBackgroundPolling;
        ReadBytes(Input, sizeof(Firness_DisableBackgroundPolling), (VOID *)&Firness_DisableBackgroundPolling);
        Configure_Arg_1->DisableBackgroundPolling = Firness_DisableBackgroundPolling;
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
    EFI_MANAGED_NETWORK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiManagedNetworkProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    EFI_MANAGED_NETWORK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiManagedNetworkProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_MANAGED_NETWORK_COMPLETION_TOKEN * Cancel_Arg_1 = (EFI_MANAGED_NETWORK_COMPLETION_TOKEN *)AllocateZeroPool(sizeof(EFI_MANAGED_NETWORK_COMPLETION_TOKEN));
    
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
    EFI_MANAGED_NETWORK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiManagedNetworkProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN Groups_Arg_1 = FALSE;
    EFI_MAC_ADDRESS * Groups_Arg_2 = (EFI_MAC_ADDRESS *)AllocateZeroPool(sizeof(EFI_MAC_ADDRESS));
    
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
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(Groups_Arg_2->Addr), (VOID *)&(Groups_Arg_2->Addr));
    
    Status = ProtocolVariable->Groups(
        ProtocolVariable,
        Groups_Arg_1,
        Groups_Arg_2
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
    EFI_MANAGED_NETWORK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiManagedNetworkProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    EFI_MANAGED_NETWORK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiManagedNetworkProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    called McastIpToMac.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzMcastIpToMac(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MANAGED_NETWORK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiManagedNetworkProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN McastIpToMac_Arg_1 = FALSE;
    EFI_IP_ADDRESS * McastIpToMac_Arg_2 = (EFI_IP_ADDRESS *)AllocateZeroPool(sizeof(EFI_IP_ADDRESS));
    EFI_MAC_ADDRESS * McastIpToMac_Arg_3 = (EFI_MAC_ADDRESS *)AllocateZeroPool(sizeof(EFI_MAC_ADDRESS));
    
    UINT8* McastIpToMac_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(McastIpToMac_Arg_1_choice), (VOID *)McastIpToMac_Arg_1_choice);
    switch(*McastIpToMac_Arg_1_choice % 2) {
        case 0:
        {
        // Constant Variable Initialization
        McastIpToMac_Arg_1 = MEMORY_PROFILE_RECORDING_ENABLE;
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(McastIpToMac_Arg_1), (VOID *)&McastIpToMac_Arg_1);
    
            break;
        }
    }
    UINT8* McastIpToMac_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(McastIpToMac_Arg_2_choice), (VOID *)McastIpToMac_Arg_2_choice);
    switch(*McastIpToMac_Arg_2_choice % 5) {
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
        case 3:
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
        case 4:
        {
        // Generator Struct Variable Initialization
        ReadBytes(Input, sizeof(McastIpToMac_Arg_2->Addr), (VOID *)&(McastIpToMac_Arg_2->Addr));
        {
            EFI_IPv4_ADDRESS Firness_v4;
            ReadBytes(Input, sizeof(Firness_v4), (VOID *)&Firness_v4);
            McastIpToMac_Arg_2->v4 = Firness_v4;
        }
        {
            EFI_IPv6_ADDRESS Firness_v6;
            ReadBytes(Input, sizeof(Firness_v6), (VOID *)&Firness_v6);
            McastIpToMac_Arg_2->v6 = Firness_v6;
        }
    
            break;
        }
    }
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(McastIpToMac_Arg_3->Addr), (VOID *)&(McastIpToMac_Arg_3->Addr));
    
    Status = ProtocolVariable->McastIpToMac(
        ProtocolVariable,
        McastIpToMac_Arg_1,
        McastIpToMac_Arg_2,
        McastIpToMac_Arg_3
    );
    return Status;
}

