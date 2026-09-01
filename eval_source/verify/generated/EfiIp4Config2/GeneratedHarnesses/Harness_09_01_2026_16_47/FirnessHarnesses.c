#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called SetData.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_IP4_CONFIG2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIp4Config2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_IP4_CONFIG2_DATA_TYPE SetData_Arg_1 = 0;
    UINTN SetData_Arg_2 = 0;
    UINTN*  SetData_Arg_3 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Constant Variable Initialization
    UINT8* SetData_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SetData_Arg_1_choice), (VOID *)SetData_Arg_1_choice);
    switch(*SetData_Arg_1_choice % 7) {
        case 0:
            SetData_Arg_1 = Ip4Config2DataTypeDnsServer;
            break;
        case 1:
            SetData_Arg_1 = Ip4Config2DataTypeGateway;
            break;
        case 2:
            SetData_Arg_1 = Ip4Config2DataTypeInterfaceInfo;
            break;
        case 3:
            SetData_Arg_1 = Ip4Config2DataTypeManualAddress;
            break;
        case 4:
            SetData_Arg_1 = Ip4Config2DataTypeMaximum;
            break;
        case 5:
            SetData_Arg_1 = Ip4Config2DataTypePolicy;
            break;
        case 6:
            ReadBytes(Input, sizeof(SetData_Arg_1), (VOID *)&SetData_Arg_1);
            break;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetData_Arg_2), (VOID *)&SetData_Arg_2);
    
    UINT8* SetData_Arg_3_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SetData_Arg_3_choice), (VOID *)SetData_Arg_3_choice);
    switch(*SetData_Arg_3_choice % 3) {
        case 0:
        {
        // Constant Variable Initialization
        UINT8* SetData_Arg_3_choice = AllocateZeroPool(sizeof(UINT8));
        ReadBytes(Input, sizeof(SetData_Arg_3_choice), (VOID *)SetData_Arg_3_choice);
        switch(*SetData_Arg_3_choice % 4) {
            case 0:
                SetData_Arg_3 = Ip4Config2PolicyDhcp;
                break;
            case 1:
                SetData_Arg_3 = Ip4Config2PolicyMax;
                break;
            case 2:
                SetData_Arg_3 = Ip4Config2PolicyStatic;
                break;
            case 3:
                ReadBytes(Input, sizeof(SetData_Arg_3), (VOID *)SetData_Arg_3);
                break;
        }
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        UINT8 SetData_Arg_3_choice = 0;
        ReadBytes(Input, sizeof(SetData_Arg_3_choice), (VOID *)&SetData_Arg_3_choice);
        switch(SetData_Arg_3_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(SetData_Arg_3), (VOID *)SetData_Arg_3);
                break;
            case 1:
            {
                gBS->FreePool(SetData_Arg_3);
                SetData_Arg_3 = NULL;
                break;
            }
        }
    
            break;
        }
        case 2:
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
    Status = ProtocolVariable->SetData(
        ProtocolVariable,
        SetData_Arg_1,
        SetData_Arg_2,
        (void *)SetData_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetData.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_IP4_CONFIG2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIp4Config2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_IP4_CONFIG2_DATA_TYPE GetData_Arg_1 = 0;
    UINTN * GetData_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN*  GetData_Arg_3 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Constant Variable Initialization
    UINT8* GetData_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetData_Arg_1_choice), (VOID *)GetData_Arg_1_choice);
    switch(*GetData_Arg_1_choice % 7) {
        case 0:
            GetData_Arg_1 = Ip4Config2DataTypeDnsServer;
            break;
        case 1:
            GetData_Arg_1 = Ip4Config2DataTypeGateway;
            break;
        case 2:
            GetData_Arg_1 = Ip4Config2DataTypeInterfaceInfo;
            break;
        case 3:
            GetData_Arg_1 = Ip4Config2DataTypeManualAddress;
            break;
        case 4:
            GetData_Arg_1 = Ip4Config2DataTypeMaximum;
            break;
        case 5:
            GetData_Arg_1 = Ip4Config2DataTypePolicy;
            break;
        case 6:
            ReadBytes(Input, sizeof(GetData_Arg_1), (VOID *)&GetData_Arg_1);
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetData_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetData_Arg_2_choice), (VOID *)&GetData_Arg_2_choice);
    switch(GetData_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetData_Arg_2), (VOID *)GetData_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(GetData_Arg_2);
            GetData_Arg_2 = NULL;
            break;
        }
    }
    
    UINT8* GetData_Arg_3_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetData_Arg_3_choice), (VOID *)GetData_Arg_3_choice);
    switch(*GetData_Arg_3_choice % 3) {
        case 0:
        {
        // Constant Variable Initialization
        UINT8* GetData_Arg_3_choice = AllocateZeroPool(sizeof(UINT8));
        ReadBytes(Input, sizeof(GetData_Arg_3_choice), (VOID *)GetData_Arg_3_choice);
        switch(*GetData_Arg_3_choice % 4) {
            case 0:
                GetData_Arg_3 = Ip4Config2PolicyDhcp;
                break;
            case 1:
                GetData_Arg_3 = Ip4Config2PolicyMax;
                break;
            case 2:
                GetData_Arg_3 = Ip4Config2PolicyStatic;
                break;
            case 3:
                ReadBytes(Input, sizeof(GetData_Arg_3), (VOID *)GetData_Arg_3);
                break;
        }
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        UINT8 GetData_Arg_3_choice = 0;
        ReadBytes(Input, sizeof(GetData_Arg_3_choice), (VOID *)&GetData_Arg_3_choice);
        switch(GetData_Arg_3_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(GetData_Arg_3), (VOID *)GetData_Arg_3);
                break;
            case 1:
            {
                gBS->FreePool(GetData_Arg_3);
                GetData_Arg_3 = NULL;
                break;
            }
        }
    
            break;
        }
        case 2:
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
    Status = ProtocolVariable->GetData(
        ProtocolVariable,
        GetData_Arg_1,
        GetData_Arg_2,
        (void *)GetData_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RegisterDataNotify.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterDataNotify(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_IP4_CONFIG2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIp4Config2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_IP4_CONFIG2_DATA_TYPE RegisterDataNotify_Arg_1 = 0;
    
    // Constant Variable Initialization
    UINT8* RegisterDataNotify_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(RegisterDataNotify_Arg_1_choice), (VOID *)RegisterDataNotify_Arg_1_choice);
    switch(*RegisterDataNotify_Arg_1_choice % 7) {
        case 0:
            RegisterDataNotify_Arg_1 = Ip4Config2DataTypeDnsServer;
            break;
        case 1:
            RegisterDataNotify_Arg_1 = Ip4Config2DataTypeGateway;
            break;
        case 2:
            RegisterDataNotify_Arg_1 = Ip4Config2DataTypeInterfaceInfo;
            break;
        case 3:
            RegisterDataNotify_Arg_1 = Ip4Config2DataTypeManualAddress;
            break;
        case 4:
            RegisterDataNotify_Arg_1 = Ip4Config2DataTypeMaximum;
            break;
        case 5:
            RegisterDataNotify_Arg_1 = Ip4Config2DataTypePolicy;
            break;
        case 6:
            ReadBytes(Input, sizeof(RegisterDataNotify_Arg_1), (VOID *)&RegisterDataNotify_Arg_1);
            break;
    }
    
    Status = ProtocolVariable->RegisterDataNotify(
        ProtocolVariable,
        RegisterDataNotify_Arg_1,
        (EFI_EVENT){0}
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UnregisterDataNotify.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUnregisterDataNotify(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_IP4_CONFIG2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIp4Config2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_IP4_CONFIG2_DATA_TYPE UnregisterDataNotify_Arg_1 = 0;
    
    // Constant Variable Initialization
    UINT8* UnregisterDataNotify_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(UnregisterDataNotify_Arg_1_choice), (VOID *)UnregisterDataNotify_Arg_1_choice);
    switch(*UnregisterDataNotify_Arg_1_choice % 7) {
        case 0:
            UnregisterDataNotify_Arg_1 = Ip4Config2DataTypeDnsServer;
            break;
        case 1:
            UnregisterDataNotify_Arg_1 = Ip4Config2DataTypeGateway;
            break;
        case 2:
            UnregisterDataNotify_Arg_1 = Ip4Config2DataTypeInterfaceInfo;
            break;
        case 3:
            UnregisterDataNotify_Arg_1 = Ip4Config2DataTypeManualAddress;
            break;
        case 4:
            UnregisterDataNotify_Arg_1 = Ip4Config2DataTypeMaximum;
            break;
        case 5:
            UnregisterDataNotify_Arg_1 = Ip4Config2DataTypePolicy;
            break;
        case 6:
            ReadBytes(Input, sizeof(UnregisterDataNotify_Arg_1), (VOID *)&UnregisterDataNotify_Arg_1);
            break;
    }
    
    Status = ProtocolVariable->UnregisterDataNotify(
        ProtocolVariable,
        UnregisterDataNotify_Arg_1,
        (EFI_EVENT){0}
    );
    return Status;
}

