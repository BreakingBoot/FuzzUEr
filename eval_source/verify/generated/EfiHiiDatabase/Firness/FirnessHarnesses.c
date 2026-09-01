#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called ExportPackageLists.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzExportPackageLists(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE ExportPackageLists_Arg_1 = 0;
    UINTN * ExportPackageLists_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Generator Struct Variable Initialization
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * FindHiiHandleViaDevPath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    
    // Generator Struct Variable Initialization
    {
        UINT8 Firness_Type;
        ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
        FindHiiHandleViaDevPath_Arg_0->Type = Firness_Type;
    }
    {
        UINT8 Firness_SubType;
        ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
        FindHiiHandleViaDevPath_Arg_0->SubType = Firness_SubType;
    }
    ReadBytes(Input, sizeof(FindHiiHandleViaDevPath_Arg_0->Length), (VOID *)&(FindHiiHandleViaDevPath_Arg_0->Length));
    
    Status = FindHiiHandleViaDevPath(
        FindHiiHandleViaDevPath_Arg_0,
        &ExportPackageLists_Arg_1,
        NULL
    );
    
    // Fuzzable Variable Initialization
    UINT8 ExportPackageLists_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(ExportPackageLists_Arg_2_choice), (VOID *)&ExportPackageLists_Arg_2_choice);
    switch(ExportPackageLists_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(ExportPackageLists_Arg_2), (VOID *)ExportPackageLists_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(ExportPackageLists_Arg_2);
            ExportPackageLists_Arg_2 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_HII_PACKAGE_LIST_HEADER * ExportPackageLists_Arg_3 = (EFI_HII_PACKAGE_LIST_HEADER *)AllocateZeroPool(sizeof(EFI_HII_PACKAGE_LIST_HEADER));
    UINT8* ExportPackageLists_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ExportPackageLists_Arg_3_OutputChoice), (VOID *)ExportPackageLists_Arg_3_OutputChoice);
    if(*ExportPackageLists_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ExportPackageLists_Arg_3), (VOID *)ExportPackageLists_Arg_3);
    }
    Status = ProtocolVariable->ExportPackageLists(
        ProtocolVariable,
        ExportPackageLists_Arg_1,
        ExportPackageLists_Arg_2,
        ExportPackageLists_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetPackageListHandle.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetPackageListHandle(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE GetPackageListHandle_Arg_1 = 0;
    
    // Generator Struct Variable Initialization
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * FindHiiHandleViaDevPath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    
    // Generator Struct Variable Initialization
    {
        UINT8 Firness_Type;
        ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
        FindHiiHandleViaDevPath_Arg_0->Type = Firness_Type;
    }
    {
        UINT8 Firness_SubType;
        ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
        FindHiiHandleViaDevPath_Arg_0->SubType = Firness_SubType;
    }
    ReadBytes(Input, sizeof(FindHiiHandleViaDevPath_Arg_0->Length), (VOID *)&(FindHiiHandleViaDevPath_Arg_0->Length));
    
    Status = FindHiiHandleViaDevPath(
        FindHiiHandleViaDevPath_Arg_0,
        &GetPackageListHandle_Arg_1,
        NULL
    );
    
    /*
        Output Variable(s)
    */
    EFI_HANDLE * GetPackageListHandle_Arg_2 = (EFI_HANDLE *)AllocateZeroPool(sizeof(EFI_HANDLE));
    UINT8* GetPackageListHandle_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetPackageListHandle_Arg_2_OutputChoice), (VOID *)GetPackageListHandle_Arg_2_OutputChoice);
    if(*GetPackageListHandle_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetPackageListHandle_Arg_2), (VOID *)GetPackageListHandle_Arg_2);
    }
    Status = ProtocolVariable->GetPackageListHandle(
        ProtocolVariable,
        GetPackageListHandle_Arg_1,
        GetPackageListHandle_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RegisterPackageNotify.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterPackageNotify(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 RegisterPackageNotify_Arg_1 = 0;
    EFI_GUID * RegisterPackageNotify_Arg_2 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    EFI_HII_DATABASE_NOTIFY_TYPE RegisterPackageNotify_Arg_4 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RegisterPackageNotify_Arg_1), (VOID *)&RegisterPackageNotify_Arg_1);
    
    UINT8* RegisterPackageNotify_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(RegisterPackageNotify_Arg_2_choice), (VOID *)RegisterPackageNotify_Arg_2_choice);
    switch(*RegisterPackageNotify_Arg_2_choice % 7) {
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
                CopyGuid_Arg_1 = &gEfiPcAnsiGuid;
            
                    break;
                }
                case 1:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100Guid;
            
                    break;
                }
                case 2:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100PlusGuid;
            
                    break;
                }
                case 3:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVTUTF8Guid;
            
                    break;
                }
                case 4:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiUartDevicePathGuid;
            
                    break;
                }
                case 5:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSasDevicePathGuid;
            
                    break;
                }
                case 6:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDebugPortProtocolGuid;
            
                    break;
                }
                case 7:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualDiskGuid;
            
                    break;
                }
                case 8:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualCdGuid;
            
                    break;
                }
                case 9:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualDiskGuid;
            
                    break;
                }
                case 10:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualCdGuid;
            
                    break;
                }
                case 11:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiCallerIdGuid;
            
                    break;
                }
                case 12:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoAhciInterfaceGuid;
            
                    break;
                }
                case 13:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocModuleGuid;
            
                    break;
                }
                case 14:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocStackGuid;
            
                    break;
                }
                case 15:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocBspStoreGuid;
            
                    break;
                }
                case 16:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiAuthenticatedVariableGuid;
            
                    break;
                }
                case 17:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmmVariableProtocolGuid;
            
                    break;
                }
                case 18:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoIdeInterfaceGuid;
            
                    break;
                }
                case 19:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoUfsInterfaceGuid;
            
                    break;
                }
                case 20:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEdkiiDeviceIdentifierTypePciGuid;
            
                    break;
                }
                case 21:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVariableGuid;
            
                    break;
                }
                case 22:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiFirmwareFileSystem2Guid;
            
                    break;
                }
                case 23:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gVarCheckPolicyLibMmiHandlerGuid;
            
                    break;
                }
                case 24:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiGlobalVariableGuid;
            
                    break;
                }
                case 25:
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
                case 26:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gZeroGuid;
            
                    break;
                }
            }
            CopyGuid(
                RegisterPackageNotify_Arg_2,
                CopyGuid_Arg_1
            );
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            ExtractGuidedSectionGetGuidList(
                &RegisterPackageNotify_Arg_2
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
                RegisterPackageNotify_Arg_2
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            Status = NetLibGetSystemGuid(
                RegisterPackageNotify_Arg_2
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
                &RegisterPackageNotify_Arg_2
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
                RegisterPackageNotify_Arg_2
            );
    
            break;
        }
        case 6:
        {
        // Generator Struct Variable Initialization
        {
            UINT32 Firness_Data1;
            ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
            RegisterPackageNotify_Arg_2->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            RegisterPackageNotify_Arg_2->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            RegisterPackageNotify_Arg_2->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(RegisterPackageNotify_Arg_2->Data4), (VOID *)&(RegisterPackageNotify_Arg_2->Data4));
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RegisterPackageNotify_Arg_4), (VOID *)&RegisterPackageNotify_Arg_4);
    
    /*
        Output Variable(s)
    */
    EFI_HANDLE * RegisterPackageNotify_Arg_5 = (EFI_HANDLE *)AllocateZeroPool(sizeof(EFI_HANDLE));
    UINT8* RegisterPackageNotify_Arg_5_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(RegisterPackageNotify_Arg_5_OutputChoice), (VOID *)RegisterPackageNotify_Arg_5_OutputChoice);
    if(*RegisterPackageNotify_Arg_5_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*RegisterPackageNotify_Arg_5), (VOID *)RegisterPackageNotify_Arg_5);
    }
    Status = ProtocolVariable->RegisterPackageNotify(
        ProtocolVariable,
        RegisterPackageNotify_Arg_1,
        RegisterPackageNotify_Arg_2,
        NULL,
        RegisterPackageNotify_Arg_4,
        RegisterPackageNotify_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UnregisterPackageNotify.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUnregisterPackageNotify(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->UnregisterPackageNotify(
        ProtocolVariable,
        ImageHandle
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetKeyboardLayout.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetKeyboardLayout(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * SetKeyboardLayout_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
    UINT8* SetKeyboardLayout_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SetKeyboardLayout_Arg_1_choice), (VOID *)SetKeyboardLayout_Arg_1_choice);
    switch(*SetKeyboardLayout_Arg_1_choice % 8) {
        case 0:
        {
        // EFI_GUID Variable Initialization
        SetKeyboardLayout_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
            break;
        }
        case 1:
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
                CopyGuid_Arg_1 = &gEfiPcAnsiGuid;
            
                    break;
                }
                case 1:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100Guid;
            
                    break;
                }
                case 2:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100PlusGuid;
            
                    break;
                }
                case 3:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVTUTF8Guid;
            
                    break;
                }
                case 4:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiUartDevicePathGuid;
            
                    break;
                }
                case 5:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSasDevicePathGuid;
            
                    break;
                }
                case 6:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDebugPortProtocolGuid;
            
                    break;
                }
                case 7:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualDiskGuid;
            
                    break;
                }
                case 8:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualCdGuid;
            
                    break;
                }
                case 9:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualDiskGuid;
            
                    break;
                }
                case 10:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualCdGuid;
            
                    break;
                }
                case 11:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiCallerIdGuid;
            
                    break;
                }
                case 12:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoAhciInterfaceGuid;
            
                    break;
                }
                case 13:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocModuleGuid;
            
                    break;
                }
                case 14:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocStackGuid;
            
                    break;
                }
                case 15:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocBspStoreGuid;
            
                    break;
                }
                case 16:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiAuthenticatedVariableGuid;
            
                    break;
                }
                case 17:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmmVariableProtocolGuid;
            
                    break;
                }
                case 18:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoIdeInterfaceGuid;
            
                    break;
                }
                case 19:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoUfsInterfaceGuid;
            
                    break;
                }
                case 20:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEdkiiDeviceIdentifierTypePciGuid;
            
                    break;
                }
                case 21:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVariableGuid;
            
                    break;
                }
                case 22:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiFirmwareFileSystem2Guid;
            
                    break;
                }
                case 23:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gVarCheckPolicyLibMmiHandlerGuid;
            
                    break;
                }
                case 24:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiGlobalVariableGuid;
            
                    break;
                }
                case 25:
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
                case 26:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gZeroGuid;
            
                    break;
                }
            }
            CopyGuid(
                SetKeyboardLayout_Arg_1,
                CopyGuid_Arg_1
            );
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            ExtractGuidedSectionGetGuidList(
                &SetKeyboardLayout_Arg_1
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
                SetKeyboardLayout_Arg_1
            );
    
            break;
        }
        case 4:
        {
        // Generator Struct Variable Initialization
            Status = NetLibGetSystemGuid(
                SetKeyboardLayout_Arg_1
            );
    
            break;
        }
        case 5:
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
                &SetKeyboardLayout_Arg_1
            );
    
            break;
        }
        case 6:
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
                SetKeyboardLayout_Arg_1
            );
    
            break;
        }
        case 7:
        {
        // Generator Struct Variable Initialization
        {
            UINT32 Firness_Data1;
            ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
            SetKeyboardLayout_Arg_1->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            SetKeyboardLayout_Arg_1->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            SetKeyboardLayout_Arg_1->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(SetKeyboardLayout_Arg_1->Data4), (VOID *)&(SetKeyboardLayout_Arg_1->Data4));
    
            break;
        }
    }
    Status = ProtocolVariable->SetKeyboardLayout(
        ProtocolVariable,
        SetKeyboardLayout_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetKeyboardLayout.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetKeyboardLayout(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * GetKeyboardLayout_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINT16 * GetKeyboardLayout_Arg_2 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    
    UINT8* GetKeyboardLayout_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetKeyboardLayout_Arg_1_choice), (VOID *)GetKeyboardLayout_Arg_1_choice);
    switch(*GetKeyboardLayout_Arg_1_choice % 7) {
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
                CopyGuid_Arg_1 = &gEfiPcAnsiGuid;
            
                    break;
                }
                case 1:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100Guid;
            
                    break;
                }
                case 2:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100PlusGuid;
            
                    break;
                }
                case 3:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVTUTF8Guid;
            
                    break;
                }
                case 4:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiUartDevicePathGuid;
            
                    break;
                }
                case 5:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSasDevicePathGuid;
            
                    break;
                }
                case 6:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDebugPortProtocolGuid;
            
                    break;
                }
                case 7:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualDiskGuid;
            
                    break;
                }
                case 8:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualCdGuid;
            
                    break;
                }
                case 9:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualDiskGuid;
            
                    break;
                }
                case 10:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualCdGuid;
            
                    break;
                }
                case 11:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiCallerIdGuid;
            
                    break;
                }
                case 12:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoAhciInterfaceGuid;
            
                    break;
                }
                case 13:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocModuleGuid;
            
                    break;
                }
                case 14:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocStackGuid;
            
                    break;
                }
                case 15:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocBspStoreGuid;
            
                    break;
                }
                case 16:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiAuthenticatedVariableGuid;
            
                    break;
                }
                case 17:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmmVariableProtocolGuid;
            
                    break;
                }
                case 18:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoIdeInterfaceGuid;
            
                    break;
                }
                case 19:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoUfsInterfaceGuid;
            
                    break;
                }
                case 20:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEdkiiDeviceIdentifierTypePciGuid;
            
                    break;
                }
                case 21:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVariableGuid;
            
                    break;
                }
                case 22:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiFirmwareFileSystem2Guid;
            
                    break;
                }
                case 23:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gVarCheckPolicyLibMmiHandlerGuid;
            
                    break;
                }
                case 24:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiGlobalVariableGuid;
            
                    break;
                }
                case 25:
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
                case 26:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gZeroGuid;
            
                    break;
                }
            }
            CopyGuid(
                GetKeyboardLayout_Arg_1,
                CopyGuid_Arg_1
            );
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            ExtractGuidedSectionGetGuidList(
                &GetKeyboardLayout_Arg_1
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
                GetKeyboardLayout_Arg_1
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            Status = NetLibGetSystemGuid(
                GetKeyboardLayout_Arg_1
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
                &GetKeyboardLayout_Arg_1
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
                GetKeyboardLayout_Arg_1
            );
    
            break;
        }
        case 6:
        {
        // Generator Struct Variable Initialization
        {
            UINT32 Firness_Data1;
            ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
            GetKeyboardLayout_Arg_1->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            GetKeyboardLayout_Arg_1->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            GetKeyboardLayout_Arg_1->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(GetKeyboardLayout_Arg_1->Data4), (VOID *)&(GetKeyboardLayout_Arg_1->Data4));
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 GetKeyboardLayout_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetKeyboardLayout_Arg_2_choice), (VOID *)&GetKeyboardLayout_Arg_2_choice);
    switch(GetKeyboardLayout_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetKeyboardLayout_Arg_2), (VOID *)GetKeyboardLayout_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(GetKeyboardLayout_Arg_2);
            GetKeyboardLayout_Arg_2 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_HII_KEYBOARD_LAYOUT * GetKeyboardLayout_Arg_3 = (EFI_HII_KEYBOARD_LAYOUT *)AllocateZeroPool(sizeof(EFI_HII_KEYBOARD_LAYOUT));
    UINT8* GetKeyboardLayout_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetKeyboardLayout_Arg_3_OutputChoice), (VOID *)GetKeyboardLayout_Arg_3_OutputChoice);
    if(*GetKeyboardLayout_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetKeyboardLayout_Arg_3), (VOID *)GetKeyboardLayout_Arg_3);
    }
    Status = ProtocolVariable->GetKeyboardLayout(
        ProtocolVariable,
        GetKeyboardLayout_Arg_1,
        GetKeyboardLayout_Arg_2,
        GetKeyboardLayout_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called NewPackageList.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzNewPackageList(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_PACKAGE_LIST_HEADER * NewPackageList_Arg_1 = (EFI_HII_PACKAGE_LIST_HEADER *)AllocateZeroPool(sizeof(EFI_HII_PACKAGE_LIST_HEADER));
    
    // Generator Struct Variable Initialization
    {
        EFI_GUID Firness_PackageListGuid;
        ReadBytes(Input, sizeof(Firness_PackageListGuid), (VOID *)&Firness_PackageListGuid);
        NewPackageList_Arg_1->PackageListGuid = Firness_PackageListGuid;
    }
    {
        UINT32 Firness_PackageLength;
        ReadBytes(Input, sizeof(Firness_PackageLength), (VOID *)&Firness_PackageLength);
        NewPackageList_Arg_1->PackageLength = Firness_PackageLength;
    }
    
    /*
        Output Variable(s)
    */
    EFI_HII_HANDLE * NewPackageList_Arg_3 = (EFI_HII_HANDLE *)AllocateZeroPool(sizeof(EFI_HII_HANDLE));
    UINT8* NewPackageList_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(NewPackageList_Arg_3_OutputChoice), (VOID *)NewPackageList_Arg_3_OutputChoice);
    if(*NewPackageList_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*NewPackageList_Arg_3), (VOID *)NewPackageList_Arg_3);
    }
    Status = ProtocolVariable->NewPackageList(
        ProtocolVariable,
        NewPackageList_Arg_1,
        ImageHandle,
        NewPackageList_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RemovePackageList.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRemovePackageList(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE RemovePackageList_Arg_1 = 0;
    
    // Generator Struct Variable Initialization
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * FindHiiHandleViaDevPath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    
    // Generator Struct Variable Initialization
    {
        UINT8 Firness_Type;
        ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
        FindHiiHandleViaDevPath_Arg_0->Type = Firness_Type;
    }
    {
        UINT8 Firness_SubType;
        ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
        FindHiiHandleViaDevPath_Arg_0->SubType = Firness_SubType;
    }
    ReadBytes(Input, sizeof(FindHiiHandleViaDevPath_Arg_0->Length), (VOID *)&(FindHiiHandleViaDevPath_Arg_0->Length));
    
    Status = FindHiiHandleViaDevPath(
        FindHiiHandleViaDevPath_Arg_0,
        &RemovePackageList_Arg_1,
        NULL
    );
    
    Status = ProtocolVariable->RemovePackageList(
        ProtocolVariable,
        RemovePackageList_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ListPackageLists.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzListPackageLists(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 ListPackageLists_Arg_1 = 0;
    EFI_GUID * ListPackageLists_Arg_2 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINTN * ListPackageLists_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    UINT8* ListPackageLists_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ListPackageLists_Arg_1_choice), (VOID *)ListPackageLists_Arg_1_choice);
    switch(*ListPackageLists_Arg_1_choice % 2) {
        case 0:
        {
        // Constant Variable Initialization
        ListPackageLists_Arg_1 = EFI_HII_PACKAGE_DEVICE_PATH;
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(ListPackageLists_Arg_1), (VOID *)&ListPackageLists_Arg_1);
    
            break;
        }
    }
    UINT8* ListPackageLists_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ListPackageLists_Arg_2_choice), (VOID *)ListPackageLists_Arg_2_choice);
    switch(*ListPackageLists_Arg_2_choice % 7) {
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
                CopyGuid_Arg_1 = &gEfiPcAnsiGuid;
            
                    break;
                }
                case 1:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100Guid;
            
                    break;
                }
                case 2:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100PlusGuid;
            
                    break;
                }
                case 3:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVTUTF8Guid;
            
                    break;
                }
                case 4:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiUartDevicePathGuid;
            
                    break;
                }
                case 5:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSasDevicePathGuid;
            
                    break;
                }
                case 6:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDebugPortProtocolGuid;
            
                    break;
                }
                case 7:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualDiskGuid;
            
                    break;
                }
                case 8:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualCdGuid;
            
                    break;
                }
                case 9:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualDiskGuid;
            
                    break;
                }
                case 10:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualCdGuid;
            
                    break;
                }
                case 11:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiCallerIdGuid;
            
                    break;
                }
                case 12:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoAhciInterfaceGuid;
            
                    break;
                }
                case 13:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocModuleGuid;
            
                    break;
                }
                case 14:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocStackGuid;
            
                    break;
                }
                case 15:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocBspStoreGuid;
            
                    break;
                }
                case 16:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiAuthenticatedVariableGuid;
            
                    break;
                }
                case 17:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmmVariableProtocolGuid;
            
                    break;
                }
                case 18:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoIdeInterfaceGuid;
            
                    break;
                }
                case 19:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoUfsInterfaceGuid;
            
                    break;
                }
                case 20:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEdkiiDeviceIdentifierTypePciGuid;
            
                    break;
                }
                case 21:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVariableGuid;
            
                    break;
                }
                case 22:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiFirmwareFileSystem2Guid;
            
                    break;
                }
                case 23:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gVarCheckPolicyLibMmiHandlerGuid;
            
                    break;
                }
                case 24:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiGlobalVariableGuid;
            
                    break;
                }
                case 25:
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
                case 26:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gZeroGuid;
            
                    break;
                }
            }
            CopyGuid(
                ListPackageLists_Arg_2,
                CopyGuid_Arg_1
            );
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            ExtractGuidedSectionGetGuidList(
                &ListPackageLists_Arg_2
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
                ListPackageLists_Arg_2
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            Status = NetLibGetSystemGuid(
                ListPackageLists_Arg_2
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
                &ListPackageLists_Arg_2
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
                ListPackageLists_Arg_2
            );
    
            break;
        }
        case 6:
        {
        // Generator Struct Variable Initialization
        {
            UINT32 Firness_Data1;
            ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
            ListPackageLists_Arg_2->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            ListPackageLists_Arg_2->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            ListPackageLists_Arg_2->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(ListPackageLists_Arg_2->Data4), (VOID *)&(ListPackageLists_Arg_2->Data4));
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 ListPackageLists_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(ListPackageLists_Arg_3_choice), (VOID *)&ListPackageLists_Arg_3_choice);
    switch(ListPackageLists_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(ListPackageLists_Arg_3), (VOID *)ListPackageLists_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(ListPackageLists_Arg_3);
            ListPackageLists_Arg_3 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_HII_HANDLE * ListPackageLists_Arg_4 = (EFI_HII_HANDLE *)AllocateZeroPool(sizeof(EFI_HII_HANDLE));
    UINT8* ListPackageLists_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ListPackageLists_Arg_4_OutputChoice), (VOID *)ListPackageLists_Arg_4_OutputChoice);
    if(*ListPackageLists_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ListPackageLists_Arg_4), (VOID *)ListPackageLists_Arg_4);
    }
    Status = ProtocolVariable->ListPackageLists(
        ProtocolVariable,
        ListPackageLists_Arg_1,
        ListPackageLists_Arg_2,
        ListPackageLists_Arg_3,
        ListPackageLists_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UpdatePackageList.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUpdatePackageList(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE UpdatePackageList_Arg_1 = 0;
    EFI_HII_PACKAGE_LIST_HEADER * UpdatePackageList_Arg_2 = (EFI_HII_PACKAGE_LIST_HEADER *)AllocateZeroPool(sizeof(EFI_HII_PACKAGE_LIST_HEADER));
    
    UINT8* UpdatePackageList_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(UpdatePackageList_Arg_1_choice), (VOID *)UpdatePackageList_Arg_1_choice);
    switch(*UpdatePackageList_Arg_1_choice % 2) {
        case 0:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * FindHiiHandleViaDevPath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            
            // Generator Struct Variable Initialization
            {
                UINT8 Firness_Type;
                ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
                FindHiiHandleViaDevPath_Arg_0->Type = Firness_Type;
            }
            {
                UINT8 Firness_SubType;
                ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
                FindHiiHandleViaDevPath_Arg_0->SubType = Firness_SubType;
            }
            ReadBytes(Input, sizeof(FindHiiHandleViaDevPath_Arg_0->Length), (VOID *)&(FindHiiHandleViaDevPath_Arg_0->Length));
            
            Status = FindHiiHandleViaDevPath(
                FindHiiHandleViaDevPath_Arg_0,
                &UpdatePackageList_Arg_1,
                NULL
            );
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            Status = ConvertHandleToHiiHandle(
                ImageHandle,
                &UpdatePackageList_Arg_1,
                NULL
            );
    
            break;
        }
    }
    // Generator Struct Variable Initialization
    {
        EFI_GUID Firness_PackageListGuid;
        ReadBytes(Input, sizeof(Firness_PackageListGuid), (VOID *)&Firness_PackageListGuid);
        UpdatePackageList_Arg_2->PackageListGuid = Firness_PackageListGuid;
    }
    {
        UINT32 Firness_PackageLength;
        ReadBytes(Input, sizeof(Firness_PackageLength), (VOID *)&Firness_PackageLength);
        UpdatePackageList_Arg_2->PackageLength = Firness_PackageLength;
    }
    
    Status = ProtocolVariable->UpdatePackageList(
        ProtocolVariable,
        UpdatePackageList_Arg_1,
        UpdatePackageList_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called FindKeyboardLayouts.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFindKeyboardLayouts(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_GUID * FindKeyboardLayouts_Arg_2 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINT8* FindKeyboardLayouts_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(FindKeyboardLayouts_Arg_2_OutputChoice), (VOID *)FindKeyboardLayouts_Arg_2_OutputChoice);
    if(*FindKeyboardLayouts_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*FindKeyboardLayouts_Arg_2), (VOID *)FindKeyboardLayouts_Arg_2);
    }
    Status = ProtocolVariable->FindKeyboardLayouts(
        ProtocolVariable,
        NULL,
        FindKeyboardLayouts_Arg_2
    );
    return Status;
}

