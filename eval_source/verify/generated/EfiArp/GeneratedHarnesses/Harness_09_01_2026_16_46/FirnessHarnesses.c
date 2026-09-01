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
    EFI_ARP_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiArpProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  Cancel_Arg_1 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    EFI_EVENT Cancel_Arg_2 = 0;
    
    UINT8* Cancel_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Cancel_Arg_1_choice), (VOID *)Cancel_Arg_1_choice);
    switch(*Cancel_Arg_1_choice % 5) {
        case 0:
        {
        // Fuzzable Variable Initialization
        UINT8 Cancel_Arg_1_choice = 0;
        ReadBytes(Input, sizeof(Cancel_Arg_1_choice), (VOID *)&Cancel_Arg_1_choice);
        switch(Cancel_Arg_1_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(Cancel_Arg_1), (VOID *)Cancel_Arg_1);
                break;
            case 1:
            {
                gBS->FreePool(Cancel_Arg_1);
                Cancel_Arg_1 = NULL;
                break;
            }
        }
    
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
    }
    UINT8* Cancel_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Cancel_Arg_2_choice), (VOID *)Cancel_Arg_2_choice);
    switch(*Cancel_Arg_2_choice % 3) {
        case 0:
        {
        // Generator Struct Variable Initialization
            Status = EfiCreateEventReadyToBoot(
                &Cancel_Arg_2
            );
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            Status = EfiCreateEventLegacyBoot(
                &Cancel_Arg_2
            );
    
            break;
        }
        case 2:
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
                &Cancel_Arg_2
            );
    
            break;
        }
    }
    Status = ProtocolVariable->Cancel(
        ProtocolVariable,
        (void *)Cancel_Arg_1,
        Cancel_Arg_2
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
    EFI_ARP_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiArpProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_ARP_CONFIG_DATA * Configure_Arg_1 = (EFI_ARP_CONFIG_DATA *)AllocateZeroPool(sizeof(EFI_ARP_CONFIG_DATA));
    
    // Generator Struct Variable Initialization
    {
        UINT16 Firness_SwAddressType;
        ReadBytes(Input, sizeof(Firness_SwAddressType), (VOID *)&Firness_SwAddressType);
        Configure_Arg_1->SwAddressType = Firness_SwAddressType;
    }
    {
        UINT8 Firness_SwAddressLength;
        ReadBytes(Input, sizeof(Firness_SwAddressLength), (VOID *)&Firness_SwAddressLength);
        Configure_Arg_1->SwAddressLength = Firness_SwAddressLength;
    }
    ReadBytes(Input, sizeof(Configure_Arg_1->StationAddress), (VOID *)(Configure_Arg_1->StationAddress));
    {
        UINT32 Firness_EntryTimeOut;
        ReadBytes(Input, sizeof(Firness_EntryTimeOut), (VOID *)&Firness_EntryTimeOut);
        Configure_Arg_1->EntryTimeOut = Firness_EntryTimeOut;
    }
    {
        UINT32 Firness_RetryCount;
        ReadBytes(Input, sizeof(Firness_RetryCount), (VOID *)&Firness_RetryCount);
        Configure_Arg_1->RetryCount = Firness_RetryCount;
    }
    {
        UINT32 Firness_RetryTimeOut;
        ReadBytes(Input, sizeof(Firness_RetryTimeOut), (VOID *)&Firness_RetryTimeOut);
        Configure_Arg_1->RetryTimeOut = Firness_RetryTimeOut;
    }
    
    Status = ProtocolVariable->Configure(
        ProtocolVariable,
        Configure_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Request.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRequest(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ARP_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiArpProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  Request_Arg_1 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN*  Request_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN*  Request_Arg_3 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    UINT8* Request_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Request_Arg_1_choice), (VOID *)Request_Arg_1_choice);
    switch(*Request_Arg_1_choice % 10) {
        case 0:
        {
        // Fuzzable Variable Initialization
        UINT8 Request_Arg_1_choice = 0;
        ReadBytes(Input, sizeof(Request_Arg_1_choice), (VOID *)&Request_Arg_1_choice);
        switch(Request_Arg_1_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(Request_Arg_1), (VOID *)Request_Arg_1);
                break;
            case 1:
            {
                gBS->FreePool(Request_Arg_1);
                Request_Arg_1 = NULL;
                break;
            }
        }
    
            break;
        }
        case 1:
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
        case 2:
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
        case 5:
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
        case 6:
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
        case 7:
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
        case 8:
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
        case 9:
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
    }
    UINT8* Request_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Request_Arg_2_choice), (VOID *)Request_Arg_2_choice);
    switch(*Request_Arg_2_choice % 6) {
        case 0:
        {
        // Fuzzable Variable Initialization
        UINT8 Request_Arg_2_choice = 0;
        ReadBytes(Input, sizeof(Request_Arg_2_choice), (VOID *)&Request_Arg_2_choice);
        switch(Request_Arg_2_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(Request_Arg_2), (VOID *)Request_Arg_2);
                break;
            case 1:
            {
                gBS->FreePool(Request_Arg_2);
                Request_Arg_2 = NULL;
                break;
            }
        }
    
            break;
        }
        case 1:
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
        case 2:
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
        case 3:
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
        case 4:
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
        case 5:
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
    }
    // Fuzzable Variable Initialization
    UINT8 Request_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(Request_Arg_3_choice), (VOID *)&Request_Arg_3_choice);
    switch(Request_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Request_Arg_3), (VOID *)Request_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(Request_Arg_3);
            Request_Arg_3 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->Request(
        ProtocolVariable,
        (void *)Request_Arg_1,
        (void *)Request_Arg_2,
        (void *)Request_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Find.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFind(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ARP_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiArpProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN Find_Arg_1 = FALSE;
    UINTN*  Find_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT32 * Find_Arg_3 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT32 * Find_Arg_4 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    EFI_ARP_FIND_DATA * Find_Arg_5 = (EFI_ARP_FIND_DATA *)AllocateZeroPool(sizeof(EFI_ARP_FIND_DATA));
    BOOLEAN Find_Arg_6 = FALSE;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Find_Arg_1), (VOID *)&Find_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 Find_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(Find_Arg_2_choice), (VOID *)&Find_Arg_2_choice);
    switch(Find_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Find_Arg_2), (VOID *)Find_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(Find_Arg_2);
            Find_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 Find_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(Find_Arg_3_choice), (VOID *)&Find_Arg_3_choice);
    switch(Find_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Find_Arg_3), (VOID *)Find_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(Find_Arg_3);
            Find_Arg_3 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 Find_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(Find_Arg_4_choice), (VOID *)&Find_Arg_4_choice);
    switch(Find_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Find_Arg_4), (VOID *)Find_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(Find_Arg_4);
            Find_Arg_4 = NULL;
            break;
        }
    }
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Size;
        ReadBytes(Input, sizeof(Firness_Size), (VOID *)&Firness_Size);
        Find_Arg_5->Size = Firness_Size;
    }
    {
        BOOLEAN Firness_DenyFlag;
        ReadBytes(Input, sizeof(Firness_DenyFlag), (VOID *)&Firness_DenyFlag);
        Find_Arg_5->DenyFlag = Firness_DenyFlag;
    }
    {
        BOOLEAN Firness_StaticFlag;
        ReadBytes(Input, sizeof(Firness_StaticFlag), (VOID *)&Firness_StaticFlag);
        Find_Arg_5->StaticFlag = Firness_StaticFlag;
    }
    {
        UINT16 Firness_HwAddressType;
        ReadBytes(Input, sizeof(Firness_HwAddressType), (VOID *)&Firness_HwAddressType);
        Find_Arg_5->HwAddressType = Firness_HwAddressType;
    }
    {
        UINT16 Firness_SwAddressType;
        ReadBytes(Input, sizeof(Firness_SwAddressType), (VOID *)&Firness_SwAddressType);
        Find_Arg_5->SwAddressType = Firness_SwAddressType;
    }
    {
        UINT8 Firness_HwAddressLength;
        ReadBytes(Input, sizeof(Firness_HwAddressLength), (VOID *)&Firness_HwAddressLength);
        Find_Arg_5->HwAddressLength = Firness_HwAddressLength;
    }
    {
        UINT8 Firness_SwAddressLength;
        ReadBytes(Input, sizeof(Firness_SwAddressLength), (VOID *)&Firness_SwAddressLength);
        Find_Arg_5->SwAddressLength = Firness_SwAddressLength;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Find_Arg_6), (VOID *)&Find_Arg_6);
    
    Status = ProtocolVariable->Find(
        ProtocolVariable,
        Find_Arg_1,
        (void *)Find_Arg_2,
        Find_Arg_3,
        Find_Arg_4,
        (EFI_ARP_FIND_DATA **)&Find_Arg_5,
        Find_Arg_6
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Add.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAdd(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ARP_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiArpProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN Add_Arg_1 = FALSE;
    UINTN*  Add_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN*  Add_Arg_3 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT32 Add_Arg_4 = 0;
    BOOLEAN Add_Arg_5 = FALSE;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Add_Arg_1), (VOID *)&Add_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 Add_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(Add_Arg_2_choice), (VOID *)&Add_Arg_2_choice);
    switch(Add_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Add_Arg_2), (VOID *)Add_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(Add_Arg_2);
            Add_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 Add_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(Add_Arg_3_choice), (VOID *)&Add_Arg_3_choice);
    switch(Add_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Add_Arg_3), (VOID *)Add_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(Add_Arg_3);
            Add_Arg_3 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Add_Arg_4), (VOID *)&Add_Arg_4);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Add_Arg_5), (VOID *)&Add_Arg_5);
    
    Status = ProtocolVariable->Add(
        ProtocolVariable,
        Add_Arg_1,
        (void *)Add_Arg_2,
        (void *)Add_Arg_3,
        Add_Arg_4,
        Add_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Delete.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDelete(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ARP_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiArpProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN Delete_Arg_1 = FALSE;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Delete_Arg_1), (VOID *)&Delete_Arg_1);
    
    Status = ProtocolVariable->Delete(
        ProtocolVariable,
        Delete_Arg_1,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Flush.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFlush(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ARP_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiArpProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Flush(
        ProtocolVariable
    );
    return Status;
}

