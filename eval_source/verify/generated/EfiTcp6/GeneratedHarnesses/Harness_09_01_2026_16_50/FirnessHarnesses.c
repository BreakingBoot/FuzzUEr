#include "FirnessHarnesses.h"

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
    EFI_TCP6_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTcp6ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    EFI_TCP6_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTcp6ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    called Connect.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzConnect(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_TCP6_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTcp6ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Connect(
        ProtocolVariable,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Close.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzClose(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_TCP6_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTcp6ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Close(
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
    EFI_TCP6_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTcp6ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_TCP6_CONFIG_DATA * Configure_Arg_1 = (EFI_TCP6_CONFIG_DATA *)AllocateZeroPool(sizeof(EFI_TCP6_CONFIG_DATA));
    
    // Generator Struct Variable Initialization
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
        EFI_TCP6_ACCESS_POINT Firness_AccessPoint;
        ReadBytes(Input, sizeof(Firness_AccessPoint), (VOID *)&Firness_AccessPoint);
        Configure_Arg_1->AccessPoint = Firness_AccessPoint;
    }
    ReadBytes(Input, sizeof(Configure_Arg_1->ControlOption), (VOID *)(Configure_Arg_1->ControlOption));
    
    Status = ProtocolVariable->Configure(
        ProtocolVariable,
        Configure_Arg_1
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
    EFI_TCP6_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTcp6ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_TCP6_CONNECTION_STATE * GetModeData_Arg_1 = (EFI_TCP6_CONNECTION_STATE *)AllocateZeroPool(sizeof(EFI_TCP6_CONNECTION_STATE));
    EFI_TCP6_CONFIG_DATA * GetModeData_Arg_2 = (EFI_TCP6_CONFIG_DATA *)AllocateZeroPool(sizeof(EFI_TCP6_CONFIG_DATA));
    EFI_IP6_MODE_DATA * GetModeData_Arg_3 = (EFI_IP6_MODE_DATA *)AllocateZeroPool(sizeof(EFI_IP6_MODE_DATA));
    EFI_MANAGED_NETWORK_CONFIG_DATA * GetModeData_Arg_4 = (EFI_MANAGED_NETWORK_CONFIG_DATA *)AllocateZeroPool(sizeof(EFI_MANAGED_NETWORK_CONFIG_DATA));
    EFI_SIMPLE_NETWORK_MODE * GetModeData_Arg_5 = (EFI_SIMPLE_NETWORK_MODE *)AllocateZeroPool(sizeof(EFI_SIMPLE_NETWORK_MODE));
    
    // Constant Variable Initialization
    UINT8* GetModeData_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetModeData_Arg_1_choice), (VOID *)GetModeData_Arg_1_choice);
    switch(*GetModeData_Arg_1_choice % 12) {
        case 0:
            GetModeData_Arg_1 = Tcp6StateCloseWait;
            break;
        case 1:
            GetModeData_Arg_1 = Tcp6StateClosed;
            break;
        case 2:
            GetModeData_Arg_1 = Tcp6StateClosing;
            break;
        case 3:
            GetModeData_Arg_1 = Tcp6StateEstablished;
            break;
        case 4:
            GetModeData_Arg_1 = Tcp6StateFinWait1;
            break;
        case 5:
            GetModeData_Arg_1 = Tcp6StateFinWait2;
            break;
        case 6:
            GetModeData_Arg_1 = Tcp6StateLastAck;
            break;
        case 7:
            GetModeData_Arg_1 = Tcp6StateListen;
            break;
        case 8:
            GetModeData_Arg_1 = Tcp6StateSynReceived;
            break;
        case 9:
            GetModeData_Arg_1 = Tcp6StateSynSent;
            break;
        case 10:
            GetModeData_Arg_1 = Tcp6StateTimeWait;
            break;
        case 11:
            ReadBytes(Input, sizeof(GetModeData_Arg_1), (VOID *)GetModeData_Arg_1);
            break;
    }
    
    // Generator Struct Variable Initialization
    {
        UINT8 Firness_TrafficClass;
        ReadBytes(Input, sizeof(Firness_TrafficClass), (VOID *)&Firness_TrafficClass);
        GetModeData_Arg_2->TrafficClass = Firness_TrafficClass;
    }
    {
        UINT8 Firness_HopLimit;
        ReadBytes(Input, sizeof(Firness_HopLimit), (VOID *)&Firness_HopLimit);
        GetModeData_Arg_2->HopLimit = Firness_HopLimit;
    }
    {
        EFI_TCP6_ACCESS_POINT Firness_AccessPoint;
        ReadBytes(Input, sizeof(Firness_AccessPoint), (VOID *)&Firness_AccessPoint);
        GetModeData_Arg_2->AccessPoint = Firness_AccessPoint;
    }
    ReadBytes(Input, sizeof(GetModeData_Arg_2->ControlOption), (VOID *)(GetModeData_Arg_2->ControlOption));
    
    // Generator Struct Variable Initialization
    {
        BOOLEAN Firness_IsStarted;
        ReadBytes(Input, sizeof(Firness_IsStarted), (VOID *)&Firness_IsStarted);
        GetModeData_Arg_3->IsStarted = Firness_IsStarted;
    }
    {
        UINT32 Firness_MaxPacketSize;
        ReadBytes(Input, sizeof(Firness_MaxPacketSize), (VOID *)&Firness_MaxPacketSize);
        GetModeData_Arg_3->MaxPacketSize = Firness_MaxPacketSize;
    }
    {
        EFI_IP6_CONFIG_DATA Firness_ConfigData;
        ReadBytes(Input, sizeof(Firness_ConfigData), (VOID *)&Firness_ConfigData);
        GetModeData_Arg_3->ConfigData = Firness_ConfigData;
    }
    {
        BOOLEAN Firness_IsConfigured;
        ReadBytes(Input, sizeof(Firness_IsConfigured), (VOID *)&Firness_IsConfigured);
        GetModeData_Arg_3->IsConfigured = Firness_IsConfigured;
    }
    {
        UINT32 Firness_AddressCount;
        ReadBytes(Input, sizeof(Firness_AddressCount), (VOID *)&Firness_AddressCount);
        GetModeData_Arg_3->AddressCount = Firness_AddressCount;
    }
    ReadBytes(Input, sizeof(GetModeData_Arg_3->AddressList), (VOID *)(GetModeData_Arg_3->AddressList));
    {
        UINT32 Firness_GroupCount;
        ReadBytes(Input, sizeof(Firness_GroupCount), (VOID *)&Firness_GroupCount);
        GetModeData_Arg_3->GroupCount = Firness_GroupCount;
    }
    ReadBytes(Input, sizeof(GetModeData_Arg_3->GroupTable), (VOID *)(GetModeData_Arg_3->GroupTable));
    {
        UINT32 Firness_RouteCount;
        ReadBytes(Input, sizeof(Firness_RouteCount), (VOID *)&Firness_RouteCount);
        GetModeData_Arg_3->RouteCount = Firness_RouteCount;
    }
    ReadBytes(Input, sizeof(GetModeData_Arg_3->RouteTable), (VOID *)(GetModeData_Arg_3->RouteTable));
    {
        UINT32 Firness_NeighborCount;
        ReadBytes(Input, sizeof(Firness_NeighborCount), (VOID *)&Firness_NeighborCount);
        GetModeData_Arg_3->NeighborCount = Firness_NeighborCount;
    }
    ReadBytes(Input, sizeof(GetModeData_Arg_3->NeighborCache), (VOID *)(GetModeData_Arg_3->NeighborCache));
    {
        UINT32 Firness_PrefixCount;
        ReadBytes(Input, sizeof(Firness_PrefixCount), (VOID *)&Firness_PrefixCount);
        GetModeData_Arg_3->PrefixCount = Firness_PrefixCount;
    }
    ReadBytes(Input, sizeof(GetModeData_Arg_3->PrefixTable), (VOID *)(GetModeData_Arg_3->PrefixTable));
    {
        UINT32 Firness_IcmpTypeCount;
        ReadBytes(Input, sizeof(Firness_IcmpTypeCount), (VOID *)&Firness_IcmpTypeCount);
        GetModeData_Arg_3->IcmpTypeCount = Firness_IcmpTypeCount;
    }
    ReadBytes(Input, sizeof(GetModeData_Arg_3->IcmpTypeList), (VOID *)(GetModeData_Arg_3->IcmpTypeList));
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_ReceivedQueueTimeoutValue;
        ReadBytes(Input, sizeof(Firness_ReceivedQueueTimeoutValue), (VOID *)&Firness_ReceivedQueueTimeoutValue);
        GetModeData_Arg_4->ReceivedQueueTimeoutValue = Firness_ReceivedQueueTimeoutValue;
    }
    {
        UINT32 Firness_TransmitQueueTimeoutValue;
        ReadBytes(Input, sizeof(Firness_TransmitQueueTimeoutValue), (VOID *)&Firness_TransmitQueueTimeoutValue);
        GetModeData_Arg_4->TransmitQueueTimeoutValue = Firness_TransmitQueueTimeoutValue;
    }
    {
        UINT16 Firness_ProtocolTypeFilter;
        ReadBytes(Input, sizeof(Firness_ProtocolTypeFilter), (VOID *)&Firness_ProtocolTypeFilter);
        GetModeData_Arg_4->ProtocolTypeFilter = Firness_ProtocolTypeFilter;
    }
    {
        BOOLEAN Firness_EnableUnicastReceive;
        ReadBytes(Input, sizeof(Firness_EnableUnicastReceive), (VOID *)&Firness_EnableUnicastReceive);
        GetModeData_Arg_4->EnableUnicastReceive = Firness_EnableUnicastReceive;
    }
    {
        BOOLEAN Firness_EnableMulticastReceive;
        ReadBytes(Input, sizeof(Firness_EnableMulticastReceive), (VOID *)&Firness_EnableMulticastReceive);
        GetModeData_Arg_4->EnableMulticastReceive = Firness_EnableMulticastReceive;
    }
    {
        BOOLEAN Firness_EnableBroadcastReceive;
        ReadBytes(Input, sizeof(Firness_EnableBroadcastReceive), (VOID *)&Firness_EnableBroadcastReceive);
        GetModeData_Arg_4->EnableBroadcastReceive = Firness_EnableBroadcastReceive;
    }
    {
        BOOLEAN Firness_EnablePromiscuousReceive;
        ReadBytes(Input, sizeof(Firness_EnablePromiscuousReceive), (VOID *)&Firness_EnablePromiscuousReceive);
        GetModeData_Arg_4->EnablePromiscuousReceive = Firness_EnablePromiscuousReceive;
    }
    {
        BOOLEAN Firness_FlushQueuesOnReset;
        ReadBytes(Input, sizeof(Firness_FlushQueuesOnReset), (VOID *)&Firness_FlushQueuesOnReset);
        GetModeData_Arg_4->FlushQueuesOnReset = Firness_FlushQueuesOnReset;
    }
    {
        BOOLEAN Firness_EnableReceiveTimestamps;
        ReadBytes(Input, sizeof(Firness_EnableReceiveTimestamps), (VOID *)&Firness_EnableReceiveTimestamps);
        GetModeData_Arg_4->EnableReceiveTimestamps = Firness_EnableReceiveTimestamps;
    }
    {
        BOOLEAN Firness_DisableBackgroundPolling;
        ReadBytes(Input, sizeof(Firness_DisableBackgroundPolling), (VOID *)&Firness_DisableBackgroundPolling);
        GetModeData_Arg_4->DisableBackgroundPolling = Firness_DisableBackgroundPolling;
    }
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_State;
        ReadBytes(Input, sizeof(Firness_State), (VOID *)&Firness_State);
        GetModeData_Arg_5->State = Firness_State;
    }
    {
        UINT32 Firness_HwAddressSize;
        ReadBytes(Input, sizeof(Firness_HwAddressSize), (VOID *)&Firness_HwAddressSize);
        GetModeData_Arg_5->HwAddressSize = Firness_HwAddressSize;
    }
    {
        UINT32 Firness_MediaHeaderSize;
        ReadBytes(Input, sizeof(Firness_MediaHeaderSize), (VOID *)&Firness_MediaHeaderSize);
        GetModeData_Arg_5->MediaHeaderSize = Firness_MediaHeaderSize;
    }
    {
        UINT32 Firness_MaxPacketSize;
        ReadBytes(Input, sizeof(Firness_MaxPacketSize), (VOID *)&Firness_MaxPacketSize);
        GetModeData_Arg_5->MaxPacketSize = Firness_MaxPacketSize;
    }
    {
        UINT32 Firness_NvRamSize;
        ReadBytes(Input, sizeof(Firness_NvRamSize), (VOID *)&Firness_NvRamSize);
        GetModeData_Arg_5->NvRamSize = Firness_NvRamSize;
    }
    {
        UINT32 Firness_NvRamAccessSize;
        ReadBytes(Input, sizeof(Firness_NvRamAccessSize), (VOID *)&Firness_NvRamAccessSize);
        GetModeData_Arg_5->NvRamAccessSize = Firness_NvRamAccessSize;
    }
    {
        UINT32 Firness_ReceiveFilterMask;
        ReadBytes(Input, sizeof(Firness_ReceiveFilterMask), (VOID *)&Firness_ReceiveFilterMask);
        GetModeData_Arg_5->ReceiveFilterMask = Firness_ReceiveFilterMask;
    }
    {
        UINT32 Firness_ReceiveFilterSetting;
        ReadBytes(Input, sizeof(Firness_ReceiveFilterSetting), (VOID *)&Firness_ReceiveFilterSetting);
        GetModeData_Arg_5->ReceiveFilterSetting = Firness_ReceiveFilterSetting;
    }
    {
        UINT32 Firness_MaxMCastFilterCount;
        ReadBytes(Input, sizeof(Firness_MaxMCastFilterCount), (VOID *)&Firness_MaxMCastFilterCount);
        GetModeData_Arg_5->MaxMCastFilterCount = Firness_MaxMCastFilterCount;
    }
    {
        UINT32 Firness_MCastFilterCount;
        ReadBytes(Input, sizeof(Firness_MCastFilterCount), (VOID *)&Firness_MCastFilterCount);
        GetModeData_Arg_5->MCastFilterCount = Firness_MCastFilterCount;
    }
    ReadBytes(Input, sizeof(GetModeData_Arg_5->MCastFilter), (VOID *)&(GetModeData_Arg_5->MCastFilter));
    {
        EFI_MAC_ADDRESS Firness_CurrentAddress;
        ReadBytes(Input, sizeof(Firness_CurrentAddress), (VOID *)&Firness_CurrentAddress);
        GetModeData_Arg_5->CurrentAddress = Firness_CurrentAddress;
    }
    {
        EFI_MAC_ADDRESS Firness_BroadcastAddress;
        ReadBytes(Input, sizeof(Firness_BroadcastAddress), (VOID *)&Firness_BroadcastAddress);
        GetModeData_Arg_5->BroadcastAddress = Firness_BroadcastAddress;
    }
    {
        EFI_MAC_ADDRESS Firness_PermanentAddress;
        ReadBytes(Input, sizeof(Firness_PermanentAddress), (VOID *)&Firness_PermanentAddress);
        GetModeData_Arg_5->PermanentAddress = Firness_PermanentAddress;
    }
    {
        UINT8 Firness_IfType;
        ReadBytes(Input, sizeof(Firness_IfType), (VOID *)&Firness_IfType);
        GetModeData_Arg_5->IfType = Firness_IfType;
    }
    {
        BOOLEAN Firness_MacAddressChangeable;
        ReadBytes(Input, sizeof(Firness_MacAddressChangeable), (VOID *)&Firness_MacAddressChangeable);
        GetModeData_Arg_5->MacAddressChangeable = Firness_MacAddressChangeable;
    }
    {
        BOOLEAN Firness_MultipleTxSupported;
        ReadBytes(Input, sizeof(Firness_MultipleTxSupported), (VOID *)&Firness_MultipleTxSupported);
        GetModeData_Arg_5->MultipleTxSupported = Firness_MultipleTxSupported;
    }
    {
        BOOLEAN Firness_MediaPresentSupported;
        ReadBytes(Input, sizeof(Firness_MediaPresentSupported), (VOID *)&Firness_MediaPresentSupported);
        GetModeData_Arg_5->MediaPresentSupported = Firness_MediaPresentSupported;
    }
    {
        BOOLEAN Firness_MediaPresent;
        ReadBytes(Input, sizeof(Firness_MediaPresent), (VOID *)&Firness_MediaPresent);
        GetModeData_Arg_5->MediaPresent = Firness_MediaPresent;
    }
    
    Status = ProtocolVariable->GetModeData(
        ProtocolVariable,
        GetModeData_Arg_1,
        GetModeData_Arg_2,
        GetModeData_Arg_3,
        GetModeData_Arg_4,
        GetModeData_Arg_5
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
    EFI_TCP6_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTcp6ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    EFI_TCP6_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTcp6ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    called Accept.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAccept(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_TCP6_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTcp6ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Accept(
        ProtocolVariable,
        NULL
    );
    return Status;
}

