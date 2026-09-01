#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the Protocols service
    called GetSku.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetSku(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    GET_PCD_INFO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gGetPcdInfoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    ProtocolVariable->GetSku(
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetInfo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    GET_PCD_INFO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gGetPcdInfoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN GetInfo_Arg_0 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetInfo_Arg_0), (VOID *)&GetInfo_Arg_0);
    
    /*
        Output Variable(s)
    */
    EFI_PCD_INFO * GetInfo_Arg_1 = (EFI_PCD_INFO *)AllocateZeroPool(sizeof(EFI_PCD_INFO));
    UINT8* GetInfo_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetInfo_Arg_1_OutputChoice), (VOID *)GetInfo_Arg_1_OutputChoice);
    if(*GetInfo_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetInfo_Arg_1), (VOID *)GetInfo_Arg_1);
    }
    Status = ProtocolVariable->GetInfo(
        GetInfo_Arg_0,
        GetInfo_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetInfoEx.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetInfoEx(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    GET_PCD_INFO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gGetPcdInfoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * GetInfoEx_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINTN GetInfoEx_Arg_1 = 0;
    
    UINT8* GetInfoEx_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetInfoEx_Arg_0_choice), (VOID *)GetInfoEx_Arg_0_choice);
    switch(*GetInfoEx_Arg_0_choice % 7) {
        case 0:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            GUID * CopyGuid_Arg_1 = (GUID *)AllocateZeroPool(sizeof(GUID));
            
            UINT8* CopyGuid_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(CopyGuid_Arg_1_choice), (VOID *)CopyGuid_Arg_1_choice);
            switch(*CopyGuid_Arg_1_choice % 27) {
                case 0:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEdkiiDeviceIdentifierTypePciGuid;
            
                    break;
                }
                case 1:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVariableGuid;
            
                    break;
                }
                case 2:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiAuthenticatedVariableGuid;
            
                    break;
                }
                case 3:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiFirmwareFileSystem2Guid;
            
                    break;
                }
                case 4:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gVarCheckPolicyLibMmiHandlerGuid;
            
                    break;
                }
                case 5:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiGlobalVariableGuid;
            
                    break;
                }
                case 6:
                {
                // Constant Variable Initialization
                UINT8* CopyGuid_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
                ReadBytes(Input, sizeof(CopyGuid_Arg_1_choice), (VOID *)CopyGuid_Arg_1_choice);
                switch(*CopyGuid_Arg_1_choice % 1) {
                    case 0:
                        ReadBytes(Input, sizeof(CopyGuid_Arg_1), (VOID *)CopyGuid_Arg_1);
                        break;
                }
            
                    break;
                }
                case 7:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiCallerIdGuid;
            
                    break;
                }
                case 8:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gZeroGuid;
            
                    break;
                }
                case 9:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPcAnsiGuid;
            
                    break;
                }
                case 10:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100Guid;
            
                    break;
                }
                case 11:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100PlusGuid;
            
                    break;
                }
                case 12:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVTUTF8Guid;
            
                    break;
                }
                case 13:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiUartDevicePathGuid;
            
                    break;
                }
                case 14:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSasDevicePathGuid;
            
                    break;
                }
                case 15:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDebugPortProtocolGuid;
            
                    break;
                }
                case 16:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualDiskGuid;
            
                    break;
                }
                case 17:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualCdGuid;
            
                    break;
                }
                case 18:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualDiskGuid;
            
                    break;
                }
                case 19:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualCdGuid;
            
                    break;
                }
                case 20:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoAhciInterfaceGuid;
            
                    break;
                }
                case 21:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocModuleGuid;
            
                    break;
                }
                case 22:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocStackGuid;
            
                    break;
                }
                case 23:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocBspStoreGuid;
            
                    break;
                }
                case 24:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmmVariableProtocolGuid;
            
                    break;
                }
                case 25:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoIdeInterfaceGuid;
            
                    break;
                }
                case 26:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoUfsInterfaceGuid;
            
                    break;
                }
            }
            CopyGuid(
                GetInfoEx_Arg_0,
                CopyGuid_Arg_1
            );
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            Status = NetLibGetSystemGuid(
                GetInfoEx_Arg_0
            );
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * StrToGuid_Arg_0 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 StrToGuid_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(StrToGuid_Arg_0_choice), (VOID *)&StrToGuid_Arg_0_choice);
            switch(StrToGuid_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(StrToGuid_Arg_0), (VOID *)StrToGuid_Arg_0);
                    break;
                case 1:
                {
                    gBS->FreePool(StrToGuid_Arg_0);
                    StrToGuid_Arg_0 = NULL;
                    break;
                }
            }
            
            StrToGuid(
                StrToGuid_Arg_0,
                GetInfoEx_Arg_0
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            ExtractGuidedSectionGetGuidList(
                &GetInfoEx_Arg_0
            );
    
            break;
        }
        case 4:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * GetGuidFromStringName_Arg_0 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
            CHAR8 * GetGuidFromStringName_Arg_1 = (CHAR8 *)AllocateZeroPool(sizeof(CHAR8));
            
            // Fuzzable Variable Initialization
            UINT8 GetGuidFromStringName_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(GetGuidFromStringName_Arg_0_choice), (VOID *)&GetGuidFromStringName_Arg_0_choice);
            switch(GetGuidFromStringName_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(GetGuidFromStringName_Arg_0), (VOID *)GetGuidFromStringName_Arg_0);
                    break;
                case 1:
                {
                    gBS->FreePool(GetGuidFromStringName_Arg_0);
                    GetGuidFromStringName_Arg_0 = NULL;
                    break;
                }
            }
            
            // Fuzzable Variable Initialization
            UINT8 GetGuidFromStringName_Arg_1_choice = 0;
            ReadBytes(Input, sizeof(GetGuidFromStringName_Arg_1_choice), (VOID *)&GetGuidFromStringName_Arg_1_choice);
            switch(GetGuidFromStringName_Arg_1_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(GetGuidFromStringName_Arg_1), (VOID *)GetGuidFromStringName_Arg_1);
                    break;
                case 1:
                {
                    gBS->FreePool(GetGuidFromStringName_Arg_1);
                    GetGuidFromStringName_Arg_1 = NULL;
                    break;
                }
            }
            
            Status = GetGuidFromStringName(
                GetGuidFromStringName_Arg_0,
                GetGuidFromStringName_Arg_1,
                &GetInfoEx_Arg_0
            );
    
            break;
        }
        case 5:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * ConvertStrToGuid_Arg_0 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 ConvertStrToGuid_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(ConvertStrToGuid_Arg_0_choice), (VOID *)&ConvertStrToGuid_Arg_0_choice);
            switch(ConvertStrToGuid_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(ConvertStrToGuid_Arg_0), (VOID *)ConvertStrToGuid_Arg_0);
                    break;
                case 1:
                {
                    gBS->FreePool(ConvertStrToGuid_Arg_0);
                    ConvertStrToGuid_Arg_0 = NULL;
                    break;
                }
            }
            
            Status = ConvertStrToGuid(
                ConvertStrToGuid_Arg_0,
                GetInfoEx_Arg_0
            );
    
            break;
        }
        case 6:
        {
        // Generator Struct Variable Initialization
        {
            UINT32 Firness_Data1;
            ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
            GetInfoEx_Arg_0->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            GetInfoEx_Arg_0->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            GetInfoEx_Arg_0->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(GetInfoEx_Arg_0->Data4), (VOID *)&(GetInfoEx_Arg_0->Data4));
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetInfoEx_Arg_1), (VOID *)&GetInfoEx_Arg_1);
    
    /*
        Output Variable(s)
    */
    EFI_PCD_INFO * GetInfoEx_Arg_2 = (EFI_PCD_INFO *)AllocateZeroPool(sizeof(EFI_PCD_INFO));
    UINT8* GetInfoEx_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetInfoEx_Arg_2_OutputChoice), (VOID *)GetInfoEx_Arg_2_OutputChoice);
    if(*GetInfoEx_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetInfoEx_Arg_2), (VOID *)GetInfoEx_Arg_2);
    }
    Status = ProtocolVariable->GetInfoEx(
        GetInfoEx_Arg_0,
        GetInfoEx_Arg_1,
        GetInfoEx_Arg_2
    );
    return Status;
}

