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
    EFI_TCP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTcp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Cancel(
        ProtocolVariable,
        NULL
    );
    FirnessSanitizer(FALSE);
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
    EFI_TCP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTcp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Poll(
        ProtocolVariable
    );
    FirnessSanitizer(FALSE);
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
    EFI_TCP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTcp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Connect(
        ProtocolVariable,
        NULL
    );
    FirnessSanitizer(FALSE);
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
    EFI_TCP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTcp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Close(
        ProtocolVariable,
        NULL
    );
    FirnessSanitizer(FALSE);
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
    EFI_TCP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTcp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_TCP4_CONFIG_DATA * Configure_Arg_1 = (EFI_TCP4_CONFIG_DATA *)AllocateZeroPool(sizeof(EFI_TCP4_CONFIG_DATA));
    
    // Generator Struct Variable Initialization
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
    ReadBytes(Input, sizeof(Configure_Arg_1->AccessPoint), (VOID *)&(Configure_Arg_1->AccessPoint));
    Configure_Arg_1->ControlOption = (EFI_TCP4_OPTION *)AllocateZeroPool(sizeof(*Configure_Arg_1->ControlOption));
    if (Configure_Arg_1->ControlOption != NULL) {
        ReadBytes(Input, sizeof(*Configure_Arg_1->ControlOption), (VOID *)(Configure_Arg_1->ControlOption));
    }
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Configure(
        ProtocolVariable,
        Configure_Arg_1
    );
    FirnessSanitizer(FALSE);
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
    EFI_TCP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTcp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_TCP4_CONNECTION_STATE * GetModeData_Arg_1 = (EFI_TCP4_CONNECTION_STATE *)AllocateZeroPool(sizeof(EFI_TCP4_CONNECTION_STATE));
    EFI_TCP4_CONFIG_DATA * GetModeData_Arg_2 = (EFI_TCP4_CONFIG_DATA *)AllocateZeroPool(sizeof(EFI_TCP4_CONFIG_DATA));
    EFI_IP4_MODE_DATA * GetModeData_Arg_3 = (EFI_IP4_MODE_DATA *)AllocateZeroPool(sizeof(EFI_IP4_MODE_DATA));
    EFI_MANAGED_NETWORK_CONFIG_DATA * GetModeData_Arg_4 = (EFI_MANAGED_NETWORK_CONFIG_DATA *)AllocateZeroPool(sizeof(EFI_MANAGED_NETWORK_CONFIG_DATA));
    EFI_SIMPLE_NETWORK_MODE * GetModeData_Arg_5 = (EFI_SIMPLE_NETWORK_MODE *)AllocateZeroPool(sizeof(EFI_SIMPLE_NETWORK_MODE));
    
    // Constant Variable Initialization
    UINT8* GetModeData_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetModeData_Arg_1_choice), (VOID *)GetModeData_Arg_1_choice);
    switch(*GetModeData_Arg_1_choice % 12) {
        case 0:
            *GetModeData_Arg_1 = Tcp4StateCloseWait;
            break;
        case 1:
            *GetModeData_Arg_1 = Tcp4StateClosed;
            break;
        case 2:
            *GetModeData_Arg_1 = Tcp4StateClosing;
            break;
        case 3:
            *GetModeData_Arg_1 = Tcp4StateEstablished;
            break;
        case 4:
            *GetModeData_Arg_1 = Tcp4StateFinWait1;
            break;
        case 5:
            *GetModeData_Arg_1 = Tcp4StateFinWait2;
            break;
        case 6:
            *GetModeData_Arg_1 = Tcp4StateLastAck;
            break;
        case 7:
            *GetModeData_Arg_1 = Tcp4StateListen;
            break;
        case 8:
            *GetModeData_Arg_1 = Tcp4StateSynReceived;
            break;
        case 9:
            *GetModeData_Arg_1 = Tcp4StateSynSent;
            break;
        case 10:
            *GetModeData_Arg_1 = Tcp4StateTimeWait;
            break;
        case 11:
            ReadBytes(Input, sizeof(*GetModeData_Arg_1), (VOID *)GetModeData_Arg_1);
            break;
    }
    
    // Generator Struct Variable Initialization
    {
        UINT8 Firness_TypeOfService;
        ReadBytes(Input, sizeof(Firness_TypeOfService), (VOID *)&Firness_TypeOfService);
        GetModeData_Arg_2->TypeOfService = Firness_TypeOfService;
    }
    {
        UINT8 Firness_TimeToLive;
        ReadBytes(Input, sizeof(Firness_TimeToLive), (VOID *)&Firness_TimeToLive);
        GetModeData_Arg_2->TimeToLive = Firness_TimeToLive;
    }
    ReadBytes(Input, sizeof(GetModeData_Arg_2->AccessPoint), (VOID *)&(GetModeData_Arg_2->AccessPoint));
    GetModeData_Arg_2->ControlOption = (EFI_TCP4_OPTION *)AllocateZeroPool(sizeof(*GetModeData_Arg_2->ControlOption));
    if (GetModeData_Arg_2->ControlOption != NULL) {
        ReadBytes(Input, sizeof(*GetModeData_Arg_2->ControlOption), (VOID *)(GetModeData_Arg_2->ControlOption));
    }
    
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
    ReadBytes(Input, sizeof(GetModeData_Arg_3->ConfigData), (VOID *)&(GetModeData_Arg_3->ConfigData));
    {
        BOOLEAN Firness_IsConfigured;
        ReadBytes(Input, sizeof(Firness_IsConfigured), (VOID *)&Firness_IsConfigured);
        GetModeData_Arg_3->IsConfigured = Firness_IsConfigured;
    }
    {
        UINT32 Firness_GroupCount;
        ReadBytes(Input, sizeof(Firness_GroupCount), (VOID *)&Firness_GroupCount);
        GetModeData_Arg_3->GroupCount = Firness_GroupCount;
    }
    GetModeData_Arg_3->GroupTable = (EFI_IPv4_ADDRESS *)AllocateZeroPool((4 * sizeof(*GetModeData_Arg_3->GroupTable)));
    if (GetModeData_Arg_3->GroupTable != NULL) {
        ReadBytes(Input, (4 * sizeof(*GetModeData_Arg_3->GroupTable)), (VOID *)(GetModeData_Arg_3->GroupTable));
    }
    GetModeData_Arg_3->GroupCount = GetModeData_Arg_3->GroupCount % (4 + 1);
    {
        UINT32 Firness_RouteCount;
        ReadBytes(Input, sizeof(Firness_RouteCount), (VOID *)&Firness_RouteCount);
        GetModeData_Arg_3->RouteCount = Firness_RouteCount;
    }
    GetModeData_Arg_3->RouteTable = (EFI_IP4_ROUTE_TABLE *)AllocateZeroPool((4 * sizeof(*GetModeData_Arg_3->RouteTable)));
    if (GetModeData_Arg_3->RouteTable != NULL) {
        ReadBytes(Input, (4 * sizeof(*GetModeData_Arg_3->RouteTable)), (VOID *)(GetModeData_Arg_3->RouteTable));
    }
    GetModeData_Arg_3->RouteCount = GetModeData_Arg_3->RouteCount % (4 + 1);
    {
        UINT32 Firness_IcmpTypeCount;
        ReadBytes(Input, sizeof(Firness_IcmpTypeCount), (VOID *)&Firness_IcmpTypeCount);
        GetModeData_Arg_3->IcmpTypeCount = Firness_IcmpTypeCount;
    }
    GetModeData_Arg_3->IcmpTypeList = (EFI_IP4_ICMP_TYPE *)AllocateZeroPool((4 * sizeof(*GetModeData_Arg_3->IcmpTypeList)));
    if (GetModeData_Arg_3->IcmpTypeList != NULL) {
        ReadBytes(Input, (4 * sizeof(*GetModeData_Arg_3->IcmpTypeList)), (VOID *)(GetModeData_Arg_3->IcmpTypeList));
    }
    GetModeData_Arg_3->IcmpTypeCount = GetModeData_Arg_3->IcmpTypeCount % (4 + 1);
    
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
    GetModeData_Arg_5->HwAddressSize = sizeof(EFI_SIMPLE_NETWORK_MODE);
    GetModeData_Arg_5->MediaHeaderSize = sizeof(EFI_SIMPLE_NETWORK_MODE);
    GetModeData_Arg_5->MaxPacketSize = sizeof(EFI_SIMPLE_NETWORK_MODE);
    GetModeData_Arg_5->NvRamSize = sizeof(EFI_SIMPLE_NETWORK_MODE);
    GetModeData_Arg_5->NvRamAccessSize = sizeof(EFI_SIMPLE_NETWORK_MODE);
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
    ReadBytes(Input, sizeof(GetModeData_Arg_5->CurrentAddress), (VOID *)&(GetModeData_Arg_5->CurrentAddress));
    ReadBytes(Input, sizeof(GetModeData_Arg_5->BroadcastAddress), (VOID *)&(GetModeData_Arg_5->BroadcastAddress));
    ReadBytes(Input, sizeof(GetModeData_Arg_5->PermanentAddress), (VOID *)&(GetModeData_Arg_5->PermanentAddress));
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
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetModeData(
        ProtocolVariable,
        GetModeData_Arg_1,
        GetModeData_Arg_2,
        GetModeData_Arg_3,
        GetModeData_Arg_4,
        GetModeData_Arg_5
    );
    FirnessSanitizer(FALSE);
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
    EFI_TCP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTcp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Transmit(
        ProtocolVariable,
        NULL
    );
    FirnessSanitizer(FALSE);
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
    EFI_TCP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTcp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Receive(
        ProtocolVariable,
        NULL
    );
    FirnessSanitizer(FALSE);
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
    EFI_TCP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTcp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN Routes_Arg_1 = {0};
    EFI_IPv4_ADDRESS * Routes_Arg_2 = (EFI_IPv4_ADDRESS *)AllocateZeroPool(sizeof(EFI_IPv4_ADDRESS));
    EFI_IPv4_ADDRESS * Routes_Arg_3 = (EFI_IPv4_ADDRESS *)AllocateZeroPool(sizeof(EFI_IPv4_ADDRESS));
    EFI_IPv4_ADDRESS * Routes_Arg_4 = (EFI_IPv4_ADDRESS *)AllocateZeroPool(sizeof(EFI_IPv4_ADDRESS));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Routes_Arg_1), (VOID *)&Routes_Arg_1);
    
    UINT8* Routes_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*Routes_Arg_2_choice), (VOID *)Routes_Arg_2_choice);
    switch(*Routes_Arg_2_choice % 10) {
        case 0:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR8 * HttpUrlGetIp6_Arg_0 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
            UINTN*  HttpUrlGetIp6_Arg_1 = (UINTN* )AllocateZeroPool(4096);
            
            // Fuzzable Variable Initialization
            UINT8 HttpUrlGetIp6_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(HttpUrlGetIp6_Arg_0_choice), (VOID *)&HttpUrlGetIp6_Arg_0_choice);
            switch(HttpUrlGetIp6_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*HttpUrlGetIp6_Arg_0), (VOID *)HttpUrlGetIp6_Arg_0);
                    HttpUrlGetIp6_Arg_0[31] = 0;
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
                    ReadBytes(Input, sizeof(*HttpUrlGetIp6_Arg_1), (VOID *)HttpUrlGetIp6_Arg_1);
                    *HttpUrlGetIp6_Arg_1 = *HttpUrlGetIp6_Arg_1 % (4096 + 1);
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
            ReadBytes(Input, sizeof(*HttpUrlGetIp6_Arg_2_OutputChoice), (VOID *)HttpUrlGetIp6_Arg_2_OutputChoice);
            if(*HttpUrlGetIp6_Arg_2_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*HttpUrlGetIp6_Arg_2), (VOID *)HttpUrlGetIp6_Arg_2);
            }
            FirnessSanitizer(TRUE);
            Status = HttpUrlGetIp6(
                HttpUrlGetIp6_Arg_0,
                (void *)HttpUrlGetIp6_Arg_1,
                HttpUrlGetIp6_Arg_2
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * NetLibStrToIp4_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 NetLibStrToIp4_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(NetLibStrToIp4_Arg_0_choice), (VOID *)&NetLibStrToIp4_Arg_0_choice);
            switch(NetLibStrToIp4_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*NetLibStrToIp4_Arg_0), (VOID *)NetLibStrToIp4_Arg_0);
                    NetLibStrToIp4_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(NetLibStrToIp4_Arg_0);
                    NetLibStrToIp4_Arg_0 = NULL;
                    break;
                }
            }
            
            FirnessSanitizer(TRUE);
            Status = NetLibStrToIp4(
                NetLibStrToIp4_Arg_0,
                Routes_Arg_2
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR8 * NetLibAsciiStrToIp4_Arg_0 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
            
            // Fuzzable Variable Initialization
            UINT8 NetLibAsciiStrToIp4_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(NetLibAsciiStrToIp4_Arg_0_choice), (VOID *)&NetLibAsciiStrToIp4_Arg_0_choice);
            switch(NetLibAsciiStrToIp4_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*NetLibAsciiStrToIp4_Arg_0), (VOID *)NetLibAsciiStrToIp4_Arg_0);
                    NetLibAsciiStrToIp4_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(NetLibAsciiStrToIp4_Arg_0);
                    NetLibAsciiStrToIp4_Arg_0 = NULL;
                    break;
                }
            }
            
            FirnessSanitizer(TRUE);
            Status = NetLibAsciiStrToIp4(
                NetLibAsciiStrToIp4_Arg_0,
                Routes_Arg_2
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * StrToIpv4Address_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 StrToIpv4Address_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(StrToIpv4Address_Arg_0_choice), (VOID *)&StrToIpv4Address_Arg_0_choice);
            switch(StrToIpv4Address_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*StrToIpv4Address_Arg_0), (VOID *)StrToIpv4Address_Arg_0);
                    StrToIpv4Address_Arg_0[31] = 0;
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
            CHAR16 * StrToIpv4Address_Arg_1 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            UINT8* StrToIpv4Address_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*StrToIpv4Address_Arg_1_OutputChoice), (VOID *)StrToIpv4Address_Arg_1_OutputChoice);
            if(*StrToIpv4Address_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*StrToIpv4Address_Arg_1), (VOID *)StrToIpv4Address_Arg_1);
            }
            UINT8 * StrToIpv4Address_Arg_3 = (UINT8 *)AllocateZeroPool(4096);
            UINT8* StrToIpv4Address_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*StrToIpv4Address_Arg_3_OutputChoice), (VOID *)StrToIpv4Address_Arg_3_OutputChoice);
            if(*StrToIpv4Address_Arg_3_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*StrToIpv4Address_Arg_3), (VOID *)StrToIpv4Address_Arg_3);
            }
            FirnessSanitizer(TRUE);
            StrToIpv4Address(
                StrToIpv4Address_Arg_0,
                (CHAR16 **)&StrToIpv4Address_Arg_1,
                Routes_Arg_2,
                StrToIpv4Address_Arg_3
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 4:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * StrToIpv6Address_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 StrToIpv6Address_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(StrToIpv6Address_Arg_0_choice), (VOID *)&StrToIpv6Address_Arg_0_choice);
            switch(StrToIpv6Address_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*StrToIpv6Address_Arg_0), (VOID *)StrToIpv6Address_Arg_0);
                    StrToIpv6Address_Arg_0[31] = 0;
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
            CHAR16 * StrToIpv6Address_Arg_1 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            UINT8* StrToIpv6Address_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*StrToIpv6Address_Arg_1_OutputChoice), (VOID *)StrToIpv6Address_Arg_1_OutputChoice);
            if(*StrToIpv6Address_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*StrToIpv6Address_Arg_1), (VOID *)StrToIpv6Address_Arg_1);
            }
            EFI_IPv6_ADDRESS * StrToIpv6Address_Arg_2 = (EFI_IPv6_ADDRESS *)AllocateZeroPool(sizeof(EFI_IPv6_ADDRESS));
            UINT8* StrToIpv6Address_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*StrToIpv6Address_Arg_2_OutputChoice), (VOID *)StrToIpv6Address_Arg_2_OutputChoice);
            if(*StrToIpv6Address_Arg_2_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*StrToIpv6Address_Arg_2), (VOID *)StrToIpv6Address_Arg_2);
            }
            UINT8 * StrToIpv6Address_Arg_3 = (UINT8 *)AllocateZeroPool(4096);
            UINT8* StrToIpv6Address_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*StrToIpv6Address_Arg_3_OutputChoice), (VOID *)StrToIpv6Address_Arg_3_OutputChoice);
            if(*StrToIpv6Address_Arg_3_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*StrToIpv6Address_Arg_3), (VOID *)StrToIpv6Address_Arg_3);
            }
            FirnessSanitizer(TRUE);
            StrToIpv6Address(
                StrToIpv6Address_Arg_0,
                (CHAR16 **)&StrToIpv6Address_Arg_1,
                StrToIpv6Address_Arg_2,
                StrToIpv6Address_Arg_3
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 5:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * NetLibStrToIp6andPrefix_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 NetLibStrToIp6andPrefix_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(NetLibStrToIp6andPrefix_Arg_0_choice), (VOID *)&NetLibStrToIp6andPrefix_Arg_0_choice);
            switch(NetLibStrToIp6andPrefix_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*NetLibStrToIp6andPrefix_Arg_0), (VOID *)NetLibStrToIp6andPrefix_Arg_0);
                    NetLibStrToIp6andPrefix_Arg_0[31] = 0;
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
            ReadBytes(Input, sizeof(*NetLibStrToIp6andPrefix_Arg_1_OutputChoice), (VOID *)NetLibStrToIp6andPrefix_Arg_1_OutputChoice);
            if(*NetLibStrToIp6andPrefix_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*NetLibStrToIp6andPrefix_Arg_1), (VOID *)NetLibStrToIp6andPrefix_Arg_1);
            }
            UINT8 * NetLibStrToIp6andPrefix_Arg_2 = (UINT8 *)AllocateZeroPool(4096);
            UINT8* NetLibStrToIp6andPrefix_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*NetLibStrToIp6andPrefix_Arg_2_OutputChoice), (VOID *)NetLibStrToIp6andPrefix_Arg_2_OutputChoice);
            if(*NetLibStrToIp6andPrefix_Arg_2_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*NetLibStrToIp6andPrefix_Arg_2), (VOID *)NetLibStrToIp6andPrefix_Arg_2);
            }
            FirnessSanitizer(TRUE);
            Status = NetLibStrToIp6andPrefix(
                NetLibStrToIp6andPrefix_Arg_0,
                NetLibStrToIp6andPrefix_Arg_1,
                NetLibStrToIp6andPrefix_Arg_2
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 6:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * NetLibStrToIp6_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 NetLibStrToIp6_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(NetLibStrToIp6_Arg_0_choice), (VOID *)&NetLibStrToIp6_Arg_0_choice);
            switch(NetLibStrToIp6_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*NetLibStrToIp6_Arg_0), (VOID *)NetLibStrToIp6_Arg_0);
                    NetLibStrToIp6_Arg_0[31] = 0;
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
            ReadBytes(Input, sizeof(*NetLibStrToIp6_Arg_1_OutputChoice), (VOID *)NetLibStrToIp6_Arg_1_OutputChoice);
            if(*NetLibStrToIp6_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*NetLibStrToIp6_Arg_1), (VOID *)NetLibStrToIp6_Arg_1);
            }
            FirnessSanitizer(TRUE);
            Status = NetLibStrToIp6(
                NetLibStrToIp6_Arg_0,
                NetLibStrToIp6_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 7:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR8 * NetLibAsciiStrToIp6_Arg_0 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
            
            // Fuzzable Variable Initialization
            UINT8 NetLibAsciiStrToIp6_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(NetLibAsciiStrToIp6_Arg_0_choice), (VOID *)&NetLibAsciiStrToIp6_Arg_0_choice);
            switch(NetLibAsciiStrToIp6_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*NetLibAsciiStrToIp6_Arg_0), (VOID *)NetLibAsciiStrToIp6_Arg_0);
                    NetLibAsciiStrToIp6_Arg_0[31] = 0;
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
            ReadBytes(Input, sizeof(*NetLibAsciiStrToIp6_Arg_1_OutputChoice), (VOID *)NetLibAsciiStrToIp6_Arg_1_OutputChoice);
            if(*NetLibAsciiStrToIp6_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*NetLibAsciiStrToIp6_Arg_1), (VOID *)NetLibAsciiStrToIp6_Arg_1);
            }
            FirnessSanitizer(TRUE);
            Status = NetLibAsciiStrToIp6(
                NetLibAsciiStrToIp6_Arg_0,
                NetLibAsciiStrToIp6_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 8:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR8 * HttpUrlGetIp4_Arg_0 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
            UINTN*  HttpUrlGetIp4_Arg_1 = (UINTN* )AllocateZeroPool(4096);
            
            // Fuzzable Variable Initialization
            UINT8 HttpUrlGetIp4_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(HttpUrlGetIp4_Arg_0_choice), (VOID *)&HttpUrlGetIp4_Arg_0_choice);
            switch(HttpUrlGetIp4_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*HttpUrlGetIp4_Arg_0), (VOID *)HttpUrlGetIp4_Arg_0);
                    HttpUrlGetIp4_Arg_0[31] = 0;
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
                    ReadBytes(Input, sizeof(*HttpUrlGetIp4_Arg_1), (VOID *)HttpUrlGetIp4_Arg_1);
                    *HttpUrlGetIp4_Arg_1 = *HttpUrlGetIp4_Arg_1 % (4096 + 1);
                    break;
                case 1:
                {
                    gBS->FreePool(HttpUrlGetIp4_Arg_1);
                    HttpUrlGetIp4_Arg_1 = NULL;
                    break;
                }
            }
            
            FirnessSanitizer(TRUE);
            Status = HttpUrlGetIp4(
                HttpUrlGetIp4_Arg_0,
                (void *)HttpUrlGetIp4_Arg_1,
                Routes_Arg_2
            );
            FirnessSanitizer(FALSE);
    
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
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Routes(
        ProtocolVariable,
        Routes_Arg_1,
        Routes_Arg_2,
        Routes_Arg_3,
        Routes_Arg_4
    );
    FirnessSanitizer(FALSE);
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
    EFI_TCP4_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTcp4ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Accept(
        ProtocolVariable,
        NULL
    );
    FirnessSanitizer(FALSE);
    return Status;
}

