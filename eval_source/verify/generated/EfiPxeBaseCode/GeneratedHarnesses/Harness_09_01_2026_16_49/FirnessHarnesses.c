#include "FirnessHarnesses.h"

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
    EFI_PXE_BASE_CODE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPxeBaseCodeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    called Mtftp.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzMtftp(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PXE_BASE_CODE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPxeBaseCodeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PXE_BASE_CODE_TFTP_OPCODE Mtftp_Arg_1 = 0;
    UINTN*  Mtftp_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    BOOLEAN Mtftp_Arg_3 = FALSE;
    UINT64 * Mtftp_Arg_4 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    UINTN * Mtftp_Arg_5 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    EFI_IP_ADDRESS * Mtftp_Arg_6 = (EFI_IP_ADDRESS *)AllocateZeroPool(sizeof(EFI_IP_ADDRESS));
    UINT8 * Mtftp_Arg_7 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    EFI_PXE_BASE_CODE_MTFTP_INFO * Mtftp_Arg_8 = (EFI_PXE_BASE_CODE_MTFTP_INFO *)AllocateZeroPool(sizeof(EFI_PXE_BASE_CODE_MTFTP_INFO));
    BOOLEAN Mtftp_Arg_9 = FALSE;
    
    // Constant Variable Initialization
    UINT8* Mtftp_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Mtftp_Arg_1_choice), (VOID *)Mtftp_Arg_1_choice);
    switch(*Mtftp_Arg_1_choice % 10) {
        case 0:
            Mtftp_Arg_1 = EFI_PXE_BASE_CODE_MTFTP_GET_FILE_SIZE;
            break;
        case 1:
            Mtftp_Arg_1 = EFI_PXE_BASE_CODE_MTFTP_LAST;
            break;
        case 2:
            Mtftp_Arg_1 = EFI_PXE_BASE_CODE_MTFTP_READ_DIRECTORY;
            break;
        case 3:
            Mtftp_Arg_1 = EFI_PXE_BASE_CODE_MTFTP_READ_FILE;
            break;
        case 4:
            Mtftp_Arg_1 = EFI_PXE_BASE_CODE_TFTP_FIRST;
            break;
        case 5:
            Mtftp_Arg_1 = EFI_PXE_BASE_CODE_TFTP_GET_FILE_SIZE;
            break;
        case 6:
            Mtftp_Arg_1 = EFI_PXE_BASE_CODE_TFTP_READ_DIRECTORY;
            break;
        case 7:
            Mtftp_Arg_1 = EFI_PXE_BASE_CODE_TFTP_READ_FILE;
            break;
        case 8:
            Mtftp_Arg_1 = EFI_PXE_BASE_CODE_TFTP_WRITE_FILE;
            break;
        case 9:
            ReadBytes(Input, sizeof(Mtftp_Arg_1), (VOID *)&Mtftp_Arg_1);
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 Mtftp_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(Mtftp_Arg_2_choice), (VOID *)&Mtftp_Arg_2_choice);
    switch(Mtftp_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Mtftp_Arg_2), (VOID *)Mtftp_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(Mtftp_Arg_2);
            Mtftp_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Mtftp_Arg_3), (VOID *)&Mtftp_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 Mtftp_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(Mtftp_Arg_4_choice), (VOID *)&Mtftp_Arg_4_choice);
    switch(Mtftp_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Mtftp_Arg_4), (VOID *)Mtftp_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(Mtftp_Arg_4);
            Mtftp_Arg_4 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 Mtftp_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(Mtftp_Arg_5_choice), (VOID *)&Mtftp_Arg_5_choice);
    switch(Mtftp_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Mtftp_Arg_5), (VOID *)Mtftp_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(Mtftp_Arg_5);
            Mtftp_Arg_5 = NULL;
            break;
        }
    }
    
    UINT8* Mtftp_Arg_6_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Mtftp_Arg_6_choice), (VOID *)Mtftp_Arg_6_choice);
    switch(*Mtftp_Arg_6_choice % 4) {
        case 0:
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
        ReadBytes(Input, sizeof(Mtftp_Arg_6->Addr), (VOID *)&(Mtftp_Arg_6->Addr));
        {
            EFI_IPv4_ADDRESS Firness_v4;
            ReadBytes(Input, sizeof(Firness_v4), (VOID *)&Firness_v4);
            Mtftp_Arg_6->v4 = Firness_v4;
        }
        {
            EFI_IPv6_ADDRESS Firness_v6;
            ReadBytes(Input, sizeof(Firness_v6), (VOID *)&Firness_v6);
            Mtftp_Arg_6->v6 = Firness_v6;
        }
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 Mtftp_Arg_7_choice = 0;
    ReadBytes(Input, sizeof(Mtftp_Arg_7_choice), (VOID *)&Mtftp_Arg_7_choice);
    switch(Mtftp_Arg_7_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Mtftp_Arg_7), (VOID *)Mtftp_Arg_7);
            break;
        case 1:
        {
            gBS->FreePool(Mtftp_Arg_7);
            Mtftp_Arg_7 = NULL;
            break;
        }
    }
    
    // Generator Struct Variable Initialization
    {
        EFI_IP_ADDRESS Firness_MCastIp;
        ReadBytes(Input, sizeof(Firness_MCastIp), (VOID *)&Firness_MCastIp);
        Mtftp_Arg_8->MCastIp = Firness_MCastIp;
    }
    {
        EFI_PXE_BASE_CODE_UDP_PORT Firness_CPort;
        ReadBytes(Input, sizeof(Firness_CPort), (VOID *)&Firness_CPort);
        Mtftp_Arg_8->CPort = Firness_CPort;
    }
    {
        EFI_PXE_BASE_CODE_UDP_PORT Firness_SPort;
        ReadBytes(Input, sizeof(Firness_SPort), (VOID *)&Firness_SPort);
        Mtftp_Arg_8->SPort = Firness_SPort;
    }
    {
        UINT16 Firness_ListenTimeout;
        ReadBytes(Input, sizeof(Firness_ListenTimeout), (VOID *)&Firness_ListenTimeout);
        Mtftp_Arg_8->ListenTimeout = Firness_ListenTimeout;
    }
    {
        UINT16 Firness_TransmitTimeout;
        ReadBytes(Input, sizeof(Firness_TransmitTimeout), (VOID *)&Firness_TransmitTimeout);
        Mtftp_Arg_8->TransmitTimeout = Firness_TransmitTimeout;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Mtftp_Arg_9), (VOID *)&Mtftp_Arg_9);
    
    Status = ProtocolVariable->Mtftp(
        ProtocolVariable,
        Mtftp_Arg_1,
        (void *)Mtftp_Arg_2,
        Mtftp_Arg_3,
        Mtftp_Arg_4,
        Mtftp_Arg_5,
        Mtftp_Arg_6,
        Mtftp_Arg_7,
        Mtftp_Arg_8,
        Mtftp_Arg_9
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Dhcp.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDhcp(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PXE_BASE_CODE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPxeBaseCodeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN Dhcp_Arg_1 = FALSE;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Dhcp_Arg_1), (VOID *)&Dhcp_Arg_1);
    
    Status = ProtocolVariable->Dhcp(
        ProtocolVariable,
        Dhcp_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Discover.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDiscover(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PXE_BASE_CODE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPxeBaseCodeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT16 Discover_Arg_1 = 0;
    UINT16 * Discover_Arg_2 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    BOOLEAN Discover_Arg_3 = FALSE;
    EFI_PXE_BASE_CODE_DISCOVER_INFO * Discover_Arg_4 = (EFI_PXE_BASE_CODE_DISCOVER_INFO *)AllocateZeroPool(sizeof(EFI_PXE_BASE_CODE_DISCOVER_INFO));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Discover_Arg_1), (VOID *)&Discover_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 Discover_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(Discover_Arg_2_choice), (VOID *)&Discover_Arg_2_choice);
    switch(Discover_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Discover_Arg_2), (VOID *)Discover_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(Discover_Arg_2);
            Discover_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Discover_Arg_3), (VOID *)&Discover_Arg_3);
    
    // Generator Struct Variable Initialization
    {
        BOOLEAN Firness_UseMCast;
        ReadBytes(Input, sizeof(Firness_UseMCast), (VOID *)&Firness_UseMCast);
        Discover_Arg_4->UseMCast = Firness_UseMCast;
    }
    {
        BOOLEAN Firness_UseBCast;
        ReadBytes(Input, sizeof(Firness_UseBCast), (VOID *)&Firness_UseBCast);
        Discover_Arg_4->UseBCast = Firness_UseBCast;
    }
    {
        BOOLEAN Firness_UseUCast;
        ReadBytes(Input, sizeof(Firness_UseUCast), (VOID *)&Firness_UseUCast);
        Discover_Arg_4->UseUCast = Firness_UseUCast;
    }
    {
        BOOLEAN Firness_MustUseList;
        ReadBytes(Input, sizeof(Firness_MustUseList), (VOID *)&Firness_MustUseList);
        Discover_Arg_4->MustUseList = Firness_MustUseList;
    }
    {
        EFI_IP_ADDRESS Firness_ServerMCastIp;
        ReadBytes(Input, sizeof(Firness_ServerMCastIp), (VOID *)&Firness_ServerMCastIp);
        Discover_Arg_4->ServerMCastIp = Firness_ServerMCastIp;
    }
    {
        UINT16 Firness_IpCnt;
        ReadBytes(Input, sizeof(Firness_IpCnt), (VOID *)&Firness_IpCnt);
        Discover_Arg_4->IpCnt = Firness_IpCnt;
    }
    ReadBytes(Input, sizeof(Discover_Arg_4->SrvList), (VOID *)&(Discover_Arg_4->SrvList));
    
    Status = ProtocolVariable->Discover(
        ProtocolVariable,
        Discover_Arg_1,
        Discover_Arg_2,
        Discover_Arg_3,
        Discover_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetParameters.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetParameters(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PXE_BASE_CODE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPxeBaseCodeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN * SetParameters_Arg_1 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
    BOOLEAN * SetParameters_Arg_2 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
    UINT8 * SetParameters_Arg_3 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT8 * SetParameters_Arg_4 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    BOOLEAN * SetParameters_Arg_5 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
    
    // Fuzzable Variable Initialization
    UINT8 SetParameters_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(SetParameters_Arg_1_choice), (VOID *)&SetParameters_Arg_1_choice);
    switch(SetParameters_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetParameters_Arg_1), (VOID *)SetParameters_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(SetParameters_Arg_1);
            SetParameters_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 SetParameters_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(SetParameters_Arg_2_choice), (VOID *)&SetParameters_Arg_2_choice);
    switch(SetParameters_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetParameters_Arg_2), (VOID *)SetParameters_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(SetParameters_Arg_2);
            SetParameters_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 SetParameters_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(SetParameters_Arg_3_choice), (VOID *)&SetParameters_Arg_3_choice);
    switch(SetParameters_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetParameters_Arg_3), (VOID *)SetParameters_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(SetParameters_Arg_3);
            SetParameters_Arg_3 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 SetParameters_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(SetParameters_Arg_4_choice), (VOID *)&SetParameters_Arg_4_choice);
    switch(SetParameters_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetParameters_Arg_4), (VOID *)SetParameters_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(SetParameters_Arg_4);
            SetParameters_Arg_4 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 SetParameters_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(SetParameters_Arg_5_choice), (VOID *)&SetParameters_Arg_5_choice);
    switch(SetParameters_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetParameters_Arg_5), (VOID *)SetParameters_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(SetParameters_Arg_5);
            SetParameters_Arg_5 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->SetParameters(
        ProtocolVariable,
        SetParameters_Arg_1,
        SetParameters_Arg_2,
        SetParameters_Arg_3,
        SetParameters_Arg_4,
        SetParameters_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UdpWrite.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUdpWrite(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PXE_BASE_CODE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPxeBaseCodeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT16 UdpWrite_Arg_1 = 0;
    EFI_IP_ADDRESS * UdpWrite_Arg_2 = (EFI_IP_ADDRESS *)AllocateZeroPool(sizeof(EFI_IP_ADDRESS));
    EFI_PXE_BASE_CODE_UDP_PORT * UdpWrite_Arg_3 = (EFI_PXE_BASE_CODE_UDP_PORT *)AllocateZeroPool(sizeof(EFI_PXE_BASE_CODE_UDP_PORT));
    EFI_IP_ADDRESS * UdpWrite_Arg_4 = (EFI_IP_ADDRESS *)AllocateZeroPool(sizeof(EFI_IP_ADDRESS));
    EFI_IP_ADDRESS * UdpWrite_Arg_5 = (EFI_IP_ADDRESS *)AllocateZeroPool(sizeof(EFI_IP_ADDRESS));
    EFI_PXE_BASE_CODE_UDP_PORT * UdpWrite_Arg_6 = (EFI_PXE_BASE_CODE_UDP_PORT *)AllocateZeroPool(sizeof(EFI_PXE_BASE_CODE_UDP_PORT));
    UINTN * UdpWrite_Arg_7 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN*  UdpWrite_Arg_8 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN * UdpWrite_Arg_9 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN*  UdpWrite_Arg_10 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UdpWrite_Arg_1), (VOID *)&UdpWrite_Arg_1);
    
    UINT8* UdpWrite_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(UdpWrite_Arg_2_choice), (VOID *)UdpWrite_Arg_2_choice);
    switch(*UdpWrite_Arg_2_choice % 5) {
        case 0:
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
        case 1:
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
        case 2:
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
        case 3:
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
        case 4:
        {
        // Generator Struct Variable Initialization
        ReadBytes(Input, sizeof(UdpWrite_Arg_2->Addr), (VOID *)&(UdpWrite_Arg_2->Addr));
        {
            EFI_IPv4_ADDRESS Firness_v4;
            ReadBytes(Input, sizeof(Firness_v4), (VOID *)&Firness_v4);
            UdpWrite_Arg_2->v4 = Firness_v4;
        }
        {
            EFI_IPv6_ADDRESS Firness_v6;
            ReadBytes(Input, sizeof(Firness_v6), (VOID *)&Firness_v6);
            UdpWrite_Arg_2->v6 = Firness_v6;
        }
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 UdpWrite_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(UdpWrite_Arg_3_choice), (VOID *)&UdpWrite_Arg_3_choice);
    switch(UdpWrite_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UdpWrite_Arg_3), (VOID *)UdpWrite_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(UdpWrite_Arg_3);
            UdpWrite_Arg_3 = NULL;
            break;
        }
    }
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(UdpWrite_Arg_4->Addr), (VOID *)&(UdpWrite_Arg_4->Addr));
    {
        EFI_IPv4_ADDRESS Firness_v4;
        ReadBytes(Input, sizeof(Firness_v4), (VOID *)&Firness_v4);
        UdpWrite_Arg_4->v4 = Firness_v4;
    }
    {
        EFI_IPv6_ADDRESS Firness_v6;
        ReadBytes(Input, sizeof(Firness_v6), (VOID *)&Firness_v6);
        UdpWrite_Arg_4->v6 = Firness_v6;
    }
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(UdpWrite_Arg_5->Addr), (VOID *)&(UdpWrite_Arg_5->Addr));
    {
        EFI_IPv4_ADDRESS Firness_v4;
        ReadBytes(Input, sizeof(Firness_v4), (VOID *)&Firness_v4);
        UdpWrite_Arg_5->v4 = Firness_v4;
    }
    {
        EFI_IPv6_ADDRESS Firness_v6;
        ReadBytes(Input, sizeof(Firness_v6), (VOID *)&Firness_v6);
        UdpWrite_Arg_5->v6 = Firness_v6;
    }
    
    // Fuzzable Variable Initialization
    UINT8 UdpWrite_Arg_6_choice = 0;
    ReadBytes(Input, sizeof(UdpWrite_Arg_6_choice), (VOID *)&UdpWrite_Arg_6_choice);
    switch(UdpWrite_Arg_6_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UdpWrite_Arg_6), (VOID *)UdpWrite_Arg_6);
            break;
        case 1:
        {
            gBS->FreePool(UdpWrite_Arg_6);
            UdpWrite_Arg_6 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 UdpWrite_Arg_7_choice = 0;
    ReadBytes(Input, sizeof(UdpWrite_Arg_7_choice), (VOID *)&UdpWrite_Arg_7_choice);
    switch(UdpWrite_Arg_7_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UdpWrite_Arg_7), (VOID *)UdpWrite_Arg_7);
            break;
        case 1:
        {
            gBS->FreePool(UdpWrite_Arg_7);
            UdpWrite_Arg_7 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 UdpWrite_Arg_8_choice = 0;
    ReadBytes(Input, sizeof(UdpWrite_Arg_8_choice), (VOID *)&UdpWrite_Arg_8_choice);
    switch(UdpWrite_Arg_8_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UdpWrite_Arg_8), (VOID *)UdpWrite_Arg_8);
            break;
        case 1:
        {
            gBS->FreePool(UdpWrite_Arg_8);
            UdpWrite_Arg_8 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 UdpWrite_Arg_9_choice = 0;
    ReadBytes(Input, sizeof(UdpWrite_Arg_9_choice), (VOID *)&UdpWrite_Arg_9_choice);
    switch(UdpWrite_Arg_9_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UdpWrite_Arg_9), (VOID *)UdpWrite_Arg_9);
            break;
        case 1:
        {
            gBS->FreePool(UdpWrite_Arg_9);
            UdpWrite_Arg_9 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 UdpWrite_Arg_10_choice = 0;
    ReadBytes(Input, sizeof(UdpWrite_Arg_10_choice), (VOID *)&UdpWrite_Arg_10_choice);
    switch(UdpWrite_Arg_10_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UdpWrite_Arg_10), (VOID *)UdpWrite_Arg_10);
            break;
        case 1:
        {
            gBS->FreePool(UdpWrite_Arg_10);
            UdpWrite_Arg_10 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->UdpWrite(
        ProtocolVariable,
        UdpWrite_Arg_1,
        UdpWrite_Arg_2,
        UdpWrite_Arg_3,
        UdpWrite_Arg_4,
        UdpWrite_Arg_5,
        UdpWrite_Arg_6,
        UdpWrite_Arg_7,
        (void *)UdpWrite_Arg_8,
        UdpWrite_Arg_9,
        (void *)UdpWrite_Arg_10
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UdpRead.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUdpRead(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PXE_BASE_CODE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPxeBaseCodeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT16 UdpRead_Arg_1 = 0;
    EFI_IP_ADDRESS * UdpRead_Arg_2 = (EFI_IP_ADDRESS *)AllocateZeroPool(sizeof(EFI_IP_ADDRESS));
    EFI_PXE_BASE_CODE_UDP_PORT * UdpRead_Arg_3 = (EFI_PXE_BASE_CODE_UDP_PORT *)AllocateZeroPool(sizeof(EFI_PXE_BASE_CODE_UDP_PORT));
    EFI_IP_ADDRESS * UdpRead_Arg_4 = (EFI_IP_ADDRESS *)AllocateZeroPool(sizeof(EFI_IP_ADDRESS));
    EFI_PXE_BASE_CODE_UDP_PORT * UdpRead_Arg_5 = (EFI_PXE_BASE_CODE_UDP_PORT *)AllocateZeroPool(sizeof(EFI_PXE_BASE_CODE_UDP_PORT));
    UINTN * UdpRead_Arg_6 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN*  UdpRead_Arg_7 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN * UdpRead_Arg_8 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN*  UdpRead_Arg_9 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    UINT8* UdpRead_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(UdpRead_Arg_1_choice), (VOID *)UdpRead_Arg_1_choice);
    switch(*UdpRead_Arg_1_choice % 2) {
        case 0:
        {
        // Constant Variable Initialization
        UdpRead_Arg_1 = EFI_PXE_BASE_CODE_UDP_OPFLAGS_ANY_DEST_IP;
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(UdpRead_Arg_1), (VOID *)&UdpRead_Arg_1);
    
            break;
        }
    }
    // Constant Variable Initialization
    UdpRead_Arg_2 = NULL;
    
    // Fuzzable Variable Initialization
    UINT8 UdpRead_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(UdpRead_Arg_3_choice), (VOID *)&UdpRead_Arg_3_choice);
    switch(UdpRead_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UdpRead_Arg_3), (VOID *)UdpRead_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(UdpRead_Arg_3);
            UdpRead_Arg_3 = NULL;
            break;
        }
    }
    
    
    // Fuzzable Variable Initialization
    UINT8 UdpRead_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(UdpRead_Arg_5_choice), (VOID *)&UdpRead_Arg_5_choice);
    switch(UdpRead_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UdpRead_Arg_5), (VOID *)UdpRead_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(UdpRead_Arg_5);
            UdpRead_Arg_5 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 UdpRead_Arg_6_choice = 0;
    ReadBytes(Input, sizeof(UdpRead_Arg_6_choice), (VOID *)&UdpRead_Arg_6_choice);
    switch(UdpRead_Arg_6_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UdpRead_Arg_6), (VOID *)UdpRead_Arg_6);
            break;
        case 1:
        {
            gBS->FreePool(UdpRead_Arg_6);
            UdpRead_Arg_6 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 UdpRead_Arg_7_choice = 0;
    ReadBytes(Input, sizeof(UdpRead_Arg_7_choice), (VOID *)&UdpRead_Arg_7_choice);
    switch(UdpRead_Arg_7_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UdpRead_Arg_7), (VOID *)UdpRead_Arg_7);
            break;
        case 1:
        {
            gBS->FreePool(UdpRead_Arg_7);
            UdpRead_Arg_7 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 UdpRead_Arg_8_choice = 0;
    ReadBytes(Input, sizeof(UdpRead_Arg_8_choice), (VOID *)&UdpRead_Arg_8_choice);
    switch(UdpRead_Arg_8_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UdpRead_Arg_8), (VOID *)UdpRead_Arg_8);
            break;
        case 1:
        {
            gBS->FreePool(UdpRead_Arg_8);
            UdpRead_Arg_8 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 UdpRead_Arg_9_choice = 0;
    ReadBytes(Input, sizeof(UdpRead_Arg_9_choice), (VOID *)&UdpRead_Arg_9_choice);
    switch(UdpRead_Arg_9_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UdpRead_Arg_9), (VOID *)UdpRead_Arg_9);
            break;
        case 1:
        {
            gBS->FreePool(UdpRead_Arg_9);
            UdpRead_Arg_9 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->UdpRead(
        ProtocolVariable,
        UdpRead_Arg_1,
        UdpRead_Arg_2,
        UdpRead_Arg_3,
        UdpRead_Arg_4,
        UdpRead_Arg_5,
        UdpRead_Arg_6,
        (void *)UdpRead_Arg_7,
        UdpRead_Arg_8,
        (void *)UdpRead_Arg_9
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetIpFilter.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetIpFilter(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PXE_BASE_CODE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPxeBaseCodeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->SetIpFilter(
        ProtocolVariable,
        NULL
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
    EFI_PXE_BASE_CODE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPxeBaseCodeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN Start_Arg_1 = FALSE;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Start_Arg_1), (VOID *)&Start_Arg_1);
    
    Status = ProtocolVariable->Start(
        ProtocolVariable,
        Start_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Arp.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzArp(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PXE_BASE_CODE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPxeBaseCodeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_IP_ADDRESS * Arp_Arg_1 = (EFI_IP_ADDRESS *)AllocateZeroPool(sizeof(EFI_IP_ADDRESS));
    EFI_MAC_ADDRESS * Arp_Arg_2 = (EFI_MAC_ADDRESS *)AllocateZeroPool(sizeof(EFI_MAC_ADDRESS));
    
    UINT8* Arp_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Arp_Arg_1_choice), (VOID *)Arp_Arg_1_choice);
    switch(*Arp_Arg_1_choice % 4) {
        case 0:
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
        ReadBytes(Input, sizeof(Arp_Arg_1->Addr), (VOID *)&(Arp_Arg_1->Addr));
        {
            EFI_IPv4_ADDRESS Firness_v4;
            ReadBytes(Input, sizeof(Firness_v4), (VOID *)&Firness_v4);
            Arp_Arg_1->v4 = Firness_v4;
        }
        {
            EFI_IPv6_ADDRESS Firness_v6;
            ReadBytes(Input, sizeof(Firness_v6), (VOID *)&Firness_v6);
            Arp_Arg_1->v6 = Firness_v6;
        }
    
            break;
        }
    }
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(Arp_Arg_2->Addr), (VOID *)&(Arp_Arg_2->Addr));
    
    Status = ProtocolVariable->Arp(
        ProtocolVariable,
        Arp_Arg_1,
        Arp_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetStationIp.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetStationIp(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PXE_BASE_CODE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPxeBaseCodeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_IP_ADDRESS * SetStationIp_Arg_1 = (EFI_IP_ADDRESS *)AllocateZeroPool(sizeof(EFI_IP_ADDRESS));
    EFI_IP_ADDRESS * SetStationIp_Arg_2 = (EFI_IP_ADDRESS *)AllocateZeroPool(sizeof(EFI_IP_ADDRESS));
    
    UINT8* SetStationIp_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SetStationIp_Arg_1_choice), (VOID *)SetStationIp_Arg_1_choice);
    switch(*SetStationIp_Arg_1_choice % 4) {
        case 0:
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
        ReadBytes(Input, sizeof(SetStationIp_Arg_1->Addr), (VOID *)&(SetStationIp_Arg_1->Addr));
        {
            EFI_IPv4_ADDRESS Firness_v4;
            ReadBytes(Input, sizeof(Firness_v4), (VOID *)&Firness_v4);
            SetStationIp_Arg_1->v4 = Firness_v4;
        }
        {
            EFI_IPv6_ADDRESS Firness_v6;
            ReadBytes(Input, sizeof(Firness_v6), (VOID *)&Firness_v6);
            SetStationIp_Arg_1->v6 = Firness_v6;
        }
    
            break;
        }
    }
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(SetStationIp_Arg_2->Addr), (VOID *)&(SetStationIp_Arg_2->Addr));
    {
        EFI_IPv4_ADDRESS Firness_v4;
        ReadBytes(Input, sizeof(Firness_v4), (VOID *)&Firness_v4);
        SetStationIp_Arg_2->v4 = Firness_v4;
    }
    {
        EFI_IPv6_ADDRESS Firness_v6;
        ReadBytes(Input, sizeof(Firness_v6), (VOID *)&Firness_v6);
        SetStationIp_Arg_2->v6 = Firness_v6;
    }
    
    Status = ProtocolVariable->SetStationIp(
        ProtocolVariable,
        SetStationIp_Arg_1,
        SetStationIp_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetPackets.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetPackets(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PXE_BASE_CODE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPxeBaseCodeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN * SetPackets_Arg_1 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
    BOOLEAN * SetPackets_Arg_2 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
    BOOLEAN * SetPackets_Arg_3 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
    BOOLEAN * SetPackets_Arg_4 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
    BOOLEAN * SetPackets_Arg_5 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
    BOOLEAN * SetPackets_Arg_6 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
    EFI_PXE_BASE_CODE_PACKET * SetPackets_Arg_7 = (EFI_PXE_BASE_CODE_PACKET *)AllocateZeroPool(sizeof(EFI_PXE_BASE_CODE_PACKET));
    EFI_PXE_BASE_CODE_PACKET * SetPackets_Arg_8 = (EFI_PXE_BASE_CODE_PACKET *)AllocateZeroPool(sizeof(EFI_PXE_BASE_CODE_PACKET));
    EFI_PXE_BASE_CODE_PACKET * SetPackets_Arg_9 = (EFI_PXE_BASE_CODE_PACKET *)AllocateZeroPool(sizeof(EFI_PXE_BASE_CODE_PACKET));
    EFI_PXE_BASE_CODE_PACKET * SetPackets_Arg_10 = (EFI_PXE_BASE_CODE_PACKET *)AllocateZeroPool(sizeof(EFI_PXE_BASE_CODE_PACKET));
    EFI_PXE_BASE_CODE_PACKET * SetPackets_Arg_11 = (EFI_PXE_BASE_CODE_PACKET *)AllocateZeroPool(sizeof(EFI_PXE_BASE_CODE_PACKET));
    EFI_PXE_BASE_CODE_PACKET * SetPackets_Arg_12 = (EFI_PXE_BASE_CODE_PACKET *)AllocateZeroPool(sizeof(EFI_PXE_BASE_CODE_PACKET));
    
    // Fuzzable Variable Initialization
    UINT8 SetPackets_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(SetPackets_Arg_1_choice), (VOID *)&SetPackets_Arg_1_choice);
    switch(SetPackets_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetPackets_Arg_1), (VOID *)SetPackets_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(SetPackets_Arg_1);
            SetPackets_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 SetPackets_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(SetPackets_Arg_2_choice), (VOID *)&SetPackets_Arg_2_choice);
    switch(SetPackets_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetPackets_Arg_2), (VOID *)SetPackets_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(SetPackets_Arg_2);
            SetPackets_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 SetPackets_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(SetPackets_Arg_3_choice), (VOID *)&SetPackets_Arg_3_choice);
    switch(SetPackets_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetPackets_Arg_3), (VOID *)SetPackets_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(SetPackets_Arg_3);
            SetPackets_Arg_3 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 SetPackets_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(SetPackets_Arg_4_choice), (VOID *)&SetPackets_Arg_4_choice);
    switch(SetPackets_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetPackets_Arg_4), (VOID *)SetPackets_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(SetPackets_Arg_4);
            SetPackets_Arg_4 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 SetPackets_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(SetPackets_Arg_5_choice), (VOID *)&SetPackets_Arg_5_choice);
    switch(SetPackets_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetPackets_Arg_5), (VOID *)SetPackets_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(SetPackets_Arg_5);
            SetPackets_Arg_5 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 SetPackets_Arg_6_choice = 0;
    ReadBytes(Input, sizeof(SetPackets_Arg_6_choice), (VOID *)&SetPackets_Arg_6_choice);
    switch(SetPackets_Arg_6_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetPackets_Arg_6), (VOID *)SetPackets_Arg_6);
            break;
        case 1:
        {
            gBS->FreePool(SetPackets_Arg_6);
            SetPackets_Arg_6 = NULL;
            break;
        }
    }
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(SetPackets_Arg_7->Raw), (VOID *)&(SetPackets_Arg_7->Raw));
    {
        EFI_PXE_BASE_CODE_DHCPV4_PACKET Firness_Dhcpv4;
        ReadBytes(Input, sizeof(Firness_Dhcpv4), (VOID *)&Firness_Dhcpv4);
        SetPackets_Arg_7->Dhcpv4 = Firness_Dhcpv4;
    }
    {
        EFI_PXE_BASE_CODE_DHCPV6_PACKET Firness_Dhcpv6;
        ReadBytes(Input, sizeof(Firness_Dhcpv6), (VOID *)&Firness_Dhcpv6);
        SetPackets_Arg_7->Dhcpv6 = Firness_Dhcpv6;
    }
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(SetPackets_Arg_8->Raw), (VOID *)&(SetPackets_Arg_8->Raw));
    {
        EFI_PXE_BASE_CODE_DHCPV4_PACKET Firness_Dhcpv4;
        ReadBytes(Input, sizeof(Firness_Dhcpv4), (VOID *)&Firness_Dhcpv4);
        SetPackets_Arg_8->Dhcpv4 = Firness_Dhcpv4;
    }
    {
        EFI_PXE_BASE_CODE_DHCPV6_PACKET Firness_Dhcpv6;
        ReadBytes(Input, sizeof(Firness_Dhcpv6), (VOID *)&Firness_Dhcpv6);
        SetPackets_Arg_8->Dhcpv6 = Firness_Dhcpv6;
    }
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(SetPackets_Arg_9->Raw), (VOID *)&(SetPackets_Arg_9->Raw));
    {
        EFI_PXE_BASE_CODE_DHCPV4_PACKET Firness_Dhcpv4;
        ReadBytes(Input, sizeof(Firness_Dhcpv4), (VOID *)&Firness_Dhcpv4);
        SetPackets_Arg_9->Dhcpv4 = Firness_Dhcpv4;
    }
    {
        EFI_PXE_BASE_CODE_DHCPV6_PACKET Firness_Dhcpv6;
        ReadBytes(Input, sizeof(Firness_Dhcpv6), (VOID *)&Firness_Dhcpv6);
        SetPackets_Arg_9->Dhcpv6 = Firness_Dhcpv6;
    }
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(SetPackets_Arg_10->Raw), (VOID *)&(SetPackets_Arg_10->Raw));
    {
        EFI_PXE_BASE_CODE_DHCPV4_PACKET Firness_Dhcpv4;
        ReadBytes(Input, sizeof(Firness_Dhcpv4), (VOID *)&Firness_Dhcpv4);
        SetPackets_Arg_10->Dhcpv4 = Firness_Dhcpv4;
    }
    {
        EFI_PXE_BASE_CODE_DHCPV6_PACKET Firness_Dhcpv6;
        ReadBytes(Input, sizeof(Firness_Dhcpv6), (VOID *)&Firness_Dhcpv6);
        SetPackets_Arg_10->Dhcpv6 = Firness_Dhcpv6;
    }
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(SetPackets_Arg_11->Raw), (VOID *)&(SetPackets_Arg_11->Raw));
    {
        EFI_PXE_BASE_CODE_DHCPV4_PACKET Firness_Dhcpv4;
        ReadBytes(Input, sizeof(Firness_Dhcpv4), (VOID *)&Firness_Dhcpv4);
        SetPackets_Arg_11->Dhcpv4 = Firness_Dhcpv4;
    }
    {
        EFI_PXE_BASE_CODE_DHCPV6_PACKET Firness_Dhcpv6;
        ReadBytes(Input, sizeof(Firness_Dhcpv6), (VOID *)&Firness_Dhcpv6);
        SetPackets_Arg_11->Dhcpv6 = Firness_Dhcpv6;
    }
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(SetPackets_Arg_12->Raw), (VOID *)&(SetPackets_Arg_12->Raw));
    {
        EFI_PXE_BASE_CODE_DHCPV4_PACKET Firness_Dhcpv4;
        ReadBytes(Input, sizeof(Firness_Dhcpv4), (VOID *)&Firness_Dhcpv4);
        SetPackets_Arg_12->Dhcpv4 = Firness_Dhcpv4;
    }
    {
        EFI_PXE_BASE_CODE_DHCPV6_PACKET Firness_Dhcpv6;
        ReadBytes(Input, sizeof(Firness_Dhcpv6), (VOID *)&Firness_Dhcpv6);
        SetPackets_Arg_12->Dhcpv6 = Firness_Dhcpv6;
    }
    
    Status = ProtocolVariable->SetPackets(
        ProtocolVariable,
        SetPackets_Arg_1,
        SetPackets_Arg_2,
        SetPackets_Arg_3,
        SetPackets_Arg_4,
        SetPackets_Arg_5,
        SetPackets_Arg_6,
        SetPackets_Arg_7,
        SetPackets_Arg_8,
        SetPackets_Arg_9,
        SetPackets_Arg_10,
        SetPackets_Arg_11,
        SetPackets_Arg_12
    );
    return Status;
}

