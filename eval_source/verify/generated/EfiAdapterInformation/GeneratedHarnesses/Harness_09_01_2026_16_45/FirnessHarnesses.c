#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called GetSupportedTypes.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetSupportedTypes(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ADAPTER_INFORMATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAdapterInformationProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_GUID * GetSupportedTypes_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINT8* GetSupportedTypes_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetSupportedTypes_Arg_1_OutputChoice), (VOID *)GetSupportedTypes_Arg_1_OutputChoice);
    if(*GetSupportedTypes_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetSupportedTypes_Arg_1), (VOID *)GetSupportedTypes_Arg_1);
    }
    UINTN * GetSupportedTypes_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetSupportedTypes_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetSupportedTypes_Arg_2_OutputChoice), (VOID *)GetSupportedTypes_Arg_2_OutputChoice);
    if(*GetSupportedTypes_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetSupportedTypes_Arg_2), (VOID *)GetSupportedTypes_Arg_2);
    }
    Status = ProtocolVariable->GetSupportedTypes(
        ProtocolVariable,
        (EFI_GUID **)&GetSupportedTypes_Arg_1,
        GetSupportedTypes_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetInformation.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetInformation(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ADAPTER_INFORMATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAdapterInformationProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * GetInformation_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
    UINT8* GetInformation_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetInformation_Arg_1_choice), (VOID *)GetInformation_Arg_1_choice);
    switch(*GetInformation_Arg_1_choice % 9) {
        case 0:
        {
        // EFI_GUID Variable Initialization
        GetInformation_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
            break;
        }
        case 1:
        {
        // EFI_GUID Variable Initialization
        GetInformation_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
            break;
        }
        case 2:
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
                CopyGuid_Arg_1 = &gVarCheckPolicyLibMmiHandlerGuid;
            
                    break;
                }
                case 1:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiGlobalVariableGuid;
            
                    break;
                }
                case 2:
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
                case 3:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiAuthenticatedVariableGuid;
            
                    break;
                }
                case 4:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiCallerIdGuid;
            
                    break;
                }
                case 5:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gZeroGuid;
            
                    break;
                }
                case 6:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPcAnsiGuid;
            
                    break;
                }
                case 7:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100Guid;
            
                    break;
                }
                case 8:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100PlusGuid;
            
                    break;
                }
                case 9:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVTUTF8Guid;
            
                    break;
                }
                case 10:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiUartDevicePathGuid;
            
                    break;
                }
                case 11:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSasDevicePathGuid;
            
                    break;
                }
                case 12:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDebugPortProtocolGuid;
            
                    break;
                }
                case 13:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualDiskGuid;
            
                    break;
                }
                case 14:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualCdGuid;
            
                    break;
                }
                case 15:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualDiskGuid;
            
                    break;
                }
                case 16:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualCdGuid;
            
                    break;
                }
                case 17:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoAhciInterfaceGuid;
            
                    break;
                }
                case 18:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocModuleGuid;
            
                    break;
                }
                case 19:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocStackGuid;
            
                    break;
                }
                case 20:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocBspStoreGuid;
            
                    break;
                }
                case 21:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmmVariableProtocolGuid;
            
                    break;
                }
                case 22:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoIdeInterfaceGuid;
            
                    break;
                }
                case 23:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoUfsInterfaceGuid;
            
                    break;
                }
                case 24:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEdkiiDeviceIdentifierTypePciGuid;
            
                    break;
                }
                case 25:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVariableGuid;
            
                    break;
                }
                case 26:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiFirmwareFileSystem2Guid;
            
                    break;
                }
            }
            CopyGuid(
                GetInformation_Arg_1,
                CopyGuid_Arg_1
            );
    
            break;
        }
        case 3:
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
                GetInformation_Arg_1
            );
    
            break;
        }
        case 4:
        {
        // Generator Struct Variable Initialization
            Status = NetLibGetSystemGuid(
                GetInformation_Arg_1
            );
    
            break;
        }
        case 5:
        {
        // Generator Struct Variable Initialization
            ExtractGuidedSectionGetGuidList(
                &GetInformation_Arg_1
            );
    
            break;
        }
        case 6:
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
                &GetInformation_Arg_1
            );
    
            break;
        }
        case 7:
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
                GetInformation_Arg_1
            );
    
            break;
        }
        case 8:
        {
        // Generator Struct Variable Initialization
        {
            UINT32 Firness_Data1;
            ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
            GetInformation_Arg_1->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            GetInformation_Arg_1->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            GetInformation_Arg_1->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(GetInformation_Arg_1->Data4), (VOID *)&(GetInformation_Arg_1->Data4));
    
            break;
        }
    }
    /*
        Output Variable(s)
    */
    UINTN* GetInformation_Arg_2 = (UINTN*)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetInformation_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetInformation_Arg_2_OutputChoice), (VOID *)GetInformation_Arg_2_OutputChoice);
    if(*GetInformation_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetInformation_Arg_2), (VOID *)GetInformation_Arg_2);
    }
    UINTN * GetInformation_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetInformation_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetInformation_Arg_3_OutputChoice), (VOID *)GetInformation_Arg_3_OutputChoice);
    if(*GetInformation_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetInformation_Arg_3), (VOID *)GetInformation_Arg_3);
    }
    Status = ProtocolVariable->GetInformation(
        ProtocolVariable,
        GetInformation_Arg_1,
        (void **)&GetInformation_Arg_2,
        GetInformation_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetInformation.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetInformation(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ADAPTER_INFORMATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAdapterInformationProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * SetInformation_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINTN*  SetInformation_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN SetInformation_Arg_3 = 0;
    
    UINT8* SetInformation_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SetInformation_Arg_1_choice), (VOID *)SetInformation_Arg_1_choice);
    switch(*SetInformation_Arg_1_choice % 7) {
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
                CopyGuid_Arg_1 = &gVarCheckPolicyLibMmiHandlerGuid;
            
                    break;
                }
                case 1:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiGlobalVariableGuid;
            
                    break;
                }
                case 2:
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
                case 3:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiAuthenticatedVariableGuid;
            
                    break;
                }
                case 4:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiCallerIdGuid;
            
                    break;
                }
                case 5:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gZeroGuid;
            
                    break;
                }
                case 6:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPcAnsiGuid;
            
                    break;
                }
                case 7:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100Guid;
            
                    break;
                }
                case 8:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100PlusGuid;
            
                    break;
                }
                case 9:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVTUTF8Guid;
            
                    break;
                }
                case 10:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiUartDevicePathGuid;
            
                    break;
                }
                case 11:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSasDevicePathGuid;
            
                    break;
                }
                case 12:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDebugPortProtocolGuid;
            
                    break;
                }
                case 13:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualDiskGuid;
            
                    break;
                }
                case 14:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualCdGuid;
            
                    break;
                }
                case 15:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualDiskGuid;
            
                    break;
                }
                case 16:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualCdGuid;
            
                    break;
                }
                case 17:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoAhciInterfaceGuid;
            
                    break;
                }
                case 18:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocModuleGuid;
            
                    break;
                }
                case 19:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocStackGuid;
            
                    break;
                }
                case 20:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocBspStoreGuid;
            
                    break;
                }
                case 21:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmmVariableProtocolGuid;
            
                    break;
                }
                case 22:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoIdeInterfaceGuid;
            
                    break;
                }
                case 23:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoUfsInterfaceGuid;
            
                    break;
                }
                case 24:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEdkiiDeviceIdentifierTypePciGuid;
            
                    break;
                }
                case 25:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVariableGuid;
            
                    break;
                }
                case 26:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiFirmwareFileSystem2Guid;
            
                    break;
                }
            }
            CopyGuid(
                SetInformation_Arg_1,
                CopyGuid_Arg_1
            );
    
            break;
        }
        case 1:
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
                SetInformation_Arg_1
            );
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            Status = NetLibGetSystemGuid(
                SetInformation_Arg_1
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            ExtractGuidedSectionGetGuidList(
                &SetInformation_Arg_1
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
                &SetInformation_Arg_1
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
                SetInformation_Arg_1
            );
    
            break;
        }
        case 6:
        {
        // Generator Struct Variable Initialization
        {
            UINT32 Firness_Data1;
            ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
            SetInformation_Arg_1->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            SetInformation_Arg_1->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            SetInformation_Arg_1->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(SetInformation_Arg_1->Data4), (VOID *)&(SetInformation_Arg_1->Data4));
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 SetInformation_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(SetInformation_Arg_2_choice), (VOID *)&SetInformation_Arg_2_choice);
    switch(SetInformation_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetInformation_Arg_2), (VOID *)SetInformation_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(SetInformation_Arg_2);
            SetInformation_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetInformation_Arg_3), (VOID *)&SetInformation_Arg_3);
    
    Status = ProtocolVariable->SetInformation(
        ProtocolVariable,
        SetInformation_Arg_1,
        (VOID *)SetInformation_Arg_2,
        SetInformation_Arg_3
    );
    return Status;
}

