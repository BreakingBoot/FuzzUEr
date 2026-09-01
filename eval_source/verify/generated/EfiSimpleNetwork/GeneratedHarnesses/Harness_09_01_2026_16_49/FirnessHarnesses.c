#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called GetStatus.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetStatus(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIMPLE_NETWORK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleNetworkProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINT32 * GetStatus_Arg_1 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT8* GetStatus_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetStatus_Arg_1_OutputChoice), (VOID *)GetStatus_Arg_1_OutputChoice);
    if(*GetStatus_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetStatus_Arg_1), (VOID *)GetStatus_Arg_1);
    }
    UINTN* GetStatus_Arg_2 = (UINTN*)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetStatus_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetStatus_Arg_2_OutputChoice), (VOID *)GetStatus_Arg_2_OutputChoice);
    if(*GetStatus_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetStatus_Arg_2), (VOID *)GetStatus_Arg_2);
    }
    Status = ProtocolVariable->GetStatus(
        ProtocolVariable,
        GetStatus_Arg_1,
        (void **)&GetStatus_Arg_2
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
    EFI_SIMPLE_NETWORK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleNetworkProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Start(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Initialize.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzInitialize(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIMPLE_NETWORK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleNetworkProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN Initialize_Arg_1 = 0;
    UINTN Initialize_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Initialize_Arg_1), (VOID *)&Initialize_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Initialize_Arg_2), (VOID *)&Initialize_Arg_2);
    
    Status = ProtocolVariable->Initialize(
        ProtocolVariable,
        Initialize_Arg_1,
        Initialize_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Shutdown.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzShutdown(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIMPLE_NETWORK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleNetworkProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Shutdown(
        ProtocolVariable
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
    EFI_SIMPLE_NETWORK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleNetworkProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    called ReceiveFilters.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzReceiveFilters(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIMPLE_NETWORK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleNetworkProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 ReceiveFilters_Arg_1 = 0;
    UINT32 ReceiveFilters_Arg_2 = 0;
    BOOLEAN ReceiveFilters_Arg_3 = FALSE;
    UINTN ReceiveFilters_Arg_4 = 0;
    EFI_MAC_ADDRESS * ReceiveFilters_Arg_5 = (EFI_MAC_ADDRESS *)AllocateZeroPool(sizeof(EFI_MAC_ADDRESS));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ReceiveFilters_Arg_1), (VOID *)&ReceiveFilters_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ReceiveFilters_Arg_2), (VOID *)&ReceiveFilters_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ReceiveFilters_Arg_3), (VOID *)&ReceiveFilters_Arg_3);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ReceiveFilters_Arg_4), (VOID *)&ReceiveFilters_Arg_4);
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(ReceiveFilters_Arg_5->Addr), (VOID *)&(ReceiveFilters_Arg_5->Addr));
    
    Status = ProtocolVariable->ReceiveFilters(
        ProtocolVariable,
        ReceiveFilters_Arg_1,
        ReceiveFilters_Arg_2,
        ReceiveFilters_Arg_3,
        ReceiveFilters_Arg_4,
        ReceiveFilters_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called MCastIpToMac.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzMCastIpToMac(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIMPLE_NETWORK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleNetworkProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN MCastIpToMac_Arg_1 = FALSE;
    EFI_IP_ADDRESS * MCastIpToMac_Arg_2 = (EFI_IP_ADDRESS *)AllocateZeroPool(sizeof(EFI_IP_ADDRESS));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(MCastIpToMac_Arg_1), (VOID *)&MCastIpToMac_Arg_1);
    
    UINT8* MCastIpToMac_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(MCastIpToMac_Arg_2_choice), (VOID *)MCastIpToMac_Arg_2_choice);
    switch(*MCastIpToMac_Arg_2_choice % 5) {
        case 0:
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
        ReadBytes(Input, sizeof(MCastIpToMac_Arg_2->Addr), (VOID *)&(MCastIpToMac_Arg_2->Addr));
        {
            EFI_IPv4_ADDRESS Firness_v4;
            ReadBytes(Input, sizeof(Firness_v4), (VOID *)&Firness_v4);
            MCastIpToMac_Arg_2->v4 = Firness_v4;
        }
        {
            EFI_IPv6_ADDRESS Firness_v6;
            ReadBytes(Input, sizeof(Firness_v6), (VOID *)&Firness_v6);
            MCastIpToMac_Arg_2->v6 = Firness_v6;
        }
    
            break;
        }
    }
    /*
        Output Variable(s)
    */
    EFI_MAC_ADDRESS * MCastIpToMac_Arg_3 = (EFI_MAC_ADDRESS *)AllocateZeroPool(sizeof(EFI_MAC_ADDRESS));
    UINT8* MCastIpToMac_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(MCastIpToMac_Arg_3_OutputChoice), (VOID *)MCastIpToMac_Arg_3_OutputChoice);
    if(*MCastIpToMac_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*MCastIpToMac_Arg_3), (VOID *)MCastIpToMac_Arg_3);
    }
    Status = ProtocolVariable->MCastIpToMac(
        ProtocolVariable,
        MCastIpToMac_Arg_1,
        MCastIpToMac_Arg_2,
        MCastIpToMac_Arg_3
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
    EFI_SIMPLE_NETWORK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleNetworkProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN Transmit_Arg_1 = 0;
    UINTN Transmit_Arg_2 = 0;
    UINTN*  Transmit_Arg_3 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    EFI_MAC_ADDRESS * Transmit_Arg_4 = (EFI_MAC_ADDRESS *)AllocateZeroPool(sizeof(EFI_MAC_ADDRESS));
    EFI_MAC_ADDRESS * Transmit_Arg_5 = (EFI_MAC_ADDRESS *)AllocateZeroPool(sizeof(EFI_MAC_ADDRESS));
    UINT16 * Transmit_Arg_6 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Transmit_Arg_1), (VOID *)&Transmit_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Transmit_Arg_2), (VOID *)&Transmit_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 Transmit_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(Transmit_Arg_3_choice), (VOID *)&Transmit_Arg_3_choice);
    switch(Transmit_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Transmit_Arg_3), (VOID *)Transmit_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(Transmit_Arg_3);
            Transmit_Arg_3 = NULL;
            break;
        }
    }
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(Transmit_Arg_4->Addr), (VOID *)&(Transmit_Arg_4->Addr));
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(Transmit_Arg_5->Addr), (VOID *)&(Transmit_Arg_5->Addr));
    
    // Fuzzable Variable Initialization
    UINT8 Transmit_Arg_6_choice = 0;
    ReadBytes(Input, sizeof(Transmit_Arg_6_choice), (VOID *)&Transmit_Arg_6_choice);
    switch(Transmit_Arg_6_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Transmit_Arg_6), (VOID *)Transmit_Arg_6);
            break;
        case 1:
        {
            gBS->FreePool(Transmit_Arg_6);
            Transmit_Arg_6 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->Transmit(
        ProtocolVariable,
        Transmit_Arg_1,
        Transmit_Arg_2,
        (void *)Transmit_Arg_3,
        Transmit_Arg_4,
        Transmit_Arg_5,
        Transmit_Arg_6
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
    EFI_SIMPLE_NETWORK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleNetworkProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * Receive_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    UINT8 Receive_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(Receive_Arg_2_choice), (VOID *)&Receive_Arg_2_choice);
    switch(Receive_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Receive_Arg_2), (VOID *)Receive_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(Receive_Arg_2);
            Receive_Arg_2 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    UINTN * Receive_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* Receive_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Receive_Arg_1_OutputChoice), (VOID *)Receive_Arg_1_OutputChoice);
    if(*Receive_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Receive_Arg_1), (VOID *)Receive_Arg_1);
    }
    UINTN*  Receive_Arg_3 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT8* Receive_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Receive_Arg_3_OutputChoice), (VOID *)Receive_Arg_3_OutputChoice);
    if(*Receive_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Receive_Arg_3), (VOID *)Receive_Arg_3);
    }
    EFI_MAC_ADDRESS * Receive_Arg_4 = (EFI_MAC_ADDRESS *)AllocateZeroPool(sizeof(EFI_MAC_ADDRESS));
    UINT8* Receive_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Receive_Arg_4_OutputChoice), (VOID *)Receive_Arg_4_OutputChoice);
    if(*Receive_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Receive_Arg_4), (VOID *)Receive_Arg_4);
    }
    EFI_MAC_ADDRESS * Receive_Arg_5 = (EFI_MAC_ADDRESS *)AllocateZeroPool(sizeof(EFI_MAC_ADDRESS));
    UINT8* Receive_Arg_5_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Receive_Arg_5_OutputChoice), (VOID *)Receive_Arg_5_OutputChoice);
    if(*Receive_Arg_5_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Receive_Arg_5), (VOID *)Receive_Arg_5);
    }
    UINT16 * Receive_Arg_6 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    UINT8* Receive_Arg_6_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Receive_Arg_6_OutputChoice), (VOID *)Receive_Arg_6_OutputChoice);
    if(*Receive_Arg_6_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Receive_Arg_6), (VOID *)Receive_Arg_6);
    }
    Status = ProtocolVariable->Receive(
        ProtocolVariable,
        Receive_Arg_1,
        Receive_Arg_2,
        (void *)Receive_Arg_3,
        Receive_Arg_4,
        Receive_Arg_5,
        Receive_Arg_6
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called StationAddress.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStationAddress(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIMPLE_NETWORK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleNetworkProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN StationAddress_Arg_1 = FALSE;
    EFI_MAC_ADDRESS * StationAddress_Arg_2 = (EFI_MAC_ADDRESS *)AllocateZeroPool(sizeof(EFI_MAC_ADDRESS));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StationAddress_Arg_1), (VOID *)&StationAddress_Arg_1);
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(StationAddress_Arg_2->Addr), (VOID *)&(StationAddress_Arg_2->Addr));
    
    Status = ProtocolVariable->StationAddress(
        ProtocolVariable,
        StationAddress_Arg_1,
        StationAddress_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Statistics.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStatistics(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIMPLE_NETWORK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleNetworkProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN Statistics_Arg_1 = FALSE;
    UINTN * Statistics_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    EFI_NETWORK_STATISTICS * Statistics_Arg_3 = (EFI_NETWORK_STATISTICS *)AllocateZeroPool(sizeof(EFI_NETWORK_STATISTICS));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Statistics_Arg_1), (VOID *)&Statistics_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 Statistics_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(Statistics_Arg_2_choice), (VOID *)&Statistics_Arg_2_choice);
    switch(Statistics_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Statistics_Arg_2), (VOID *)Statistics_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(Statistics_Arg_2);
            Statistics_Arg_2 = NULL;
            break;
        }
    }
    
    
    Status = ProtocolVariable->Statistics(
        ProtocolVariable,
        Statistics_Arg_1,
        Statistics_Arg_2,
        Statistics_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called NvData.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzNvData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIMPLE_NETWORK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleNetworkProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN NvData_Arg_1 = FALSE;
    UINTN NvData_Arg_2 = 0;
    UINTN NvData_Arg_3 = 0;
    UINTN*  NvData_Arg_4 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(NvData_Arg_1), (VOID *)&NvData_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(NvData_Arg_2), (VOID *)&NvData_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(NvData_Arg_3), (VOID *)&NvData_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 NvData_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(NvData_Arg_4_choice), (VOID *)&NvData_Arg_4_choice);
    switch(NvData_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(NvData_Arg_4), (VOID *)NvData_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(NvData_Arg_4);
            NvData_Arg_4 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->NvData(
        ProtocolVariable,
        NvData_Arg_1,
        NvData_Arg_2,
        NvData_Arg_3,
        (void *)NvData_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Reset.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzReset(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIMPLE_NETWORK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSimpleNetworkProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN Reset_Arg_1 = FALSE;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Reset_Arg_1), (VOID *)&Reset_Arg_1);
    
    Status = ProtocolVariable->Reset(
        ProtocolVariable,
        Reset_Arg_1
    );
    return Status;
}

