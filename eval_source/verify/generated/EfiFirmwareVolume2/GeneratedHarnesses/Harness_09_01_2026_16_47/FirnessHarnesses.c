#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called ReadSection.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzReadSection(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FIRMWARE_VOLUME2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFirmwareVolume2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * ReadSection_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    EFI_SECTION_TYPE ReadSection_Arg_2 = 0;
    UINTN ReadSection_Arg_3 = 0;
    UINTN* ReadSection_Arg_4 = (UINTN*)AllocateZeroPool(sizeof(UINTN));
    UINTN * ReadSection_Arg_5 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    UINT8* ReadSection_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ReadSection_Arg_1_choice), (VOID *)ReadSection_Arg_1_choice);
    switch(*ReadSection_Arg_1_choice % 8) {
        case 0:
        {
        // EFI_GUID Variable Initialization
        ReadSection_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
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
                CopyGuid_Arg_1 = &gEfiCallerIdGuid;
            
                    break;
                }
                case 1:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoAhciInterfaceGuid;
            
                    break;
                }
                case 2:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocModuleGuid;
            
                    break;
                }
                case 3:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocStackGuid;
            
                    break;
                }
                case 4:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocBspStoreGuid;
            
                    break;
                }
                case 5:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiAuthenticatedVariableGuid;
            
                    break;
                }
                case 6:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmmVariableProtocolGuid;
            
                    break;
                }
                case 7:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoIdeInterfaceGuid;
            
                    break;
                }
                case 8:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoUfsInterfaceGuid;
            
                    break;
                }
                case 9:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEdkiiDeviceIdentifierTypePciGuid;
            
                    break;
                }
                case 10:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVariableGuid;
            
                    break;
                }
                case 11:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiFirmwareFileSystem2Guid;
            
                    break;
                }
                case 12:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gVarCheckPolicyLibMmiHandlerGuid;
            
                    break;
                }
                case 13:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiGlobalVariableGuid;
            
                    break;
                }
                case 14:
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
                case 15:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gZeroGuid;
            
                    break;
                }
                case 16:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPcAnsiGuid;
            
                    break;
                }
                case 17:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100Guid;
            
                    break;
                }
                case 18:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100PlusGuid;
            
                    break;
                }
                case 19:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVTUTF8Guid;
            
                    break;
                }
                case 20:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiUartDevicePathGuid;
            
                    break;
                }
                case 21:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSasDevicePathGuid;
            
                    break;
                }
                case 22:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDebugPortProtocolGuid;
            
                    break;
                }
                case 23:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualDiskGuid;
            
                    break;
                }
                case 24:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualCdGuid;
            
                    break;
                }
                case 25:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualDiskGuid;
            
                    break;
                }
                case 26:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualCdGuid;
            
                    break;
                }
            }
            CopyGuid(
                ReadSection_Arg_1,
                CopyGuid_Arg_1
            );
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            ExtractGuidedSectionGetGuidList(
                &ReadSection_Arg_1
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
                ReadSection_Arg_1
            );
    
            break;
        }
        case 4:
        {
        // Generator Struct Variable Initialization
            Status = NetLibGetSystemGuid(
                ReadSection_Arg_1
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
                &ReadSection_Arg_1
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
                ReadSection_Arg_1
            );
    
            break;
        }
        case 7:
        {
        // Generator Struct Variable Initialization
        {
            UINT32 Firness_Data1;
            ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
            ReadSection_Arg_1->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            ReadSection_Arg_1->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            ReadSection_Arg_1->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(ReadSection_Arg_1->Data4), (VOID *)&(ReadSection_Arg_1->Data4));
    
            break;
        }
    }
    UINT8* ReadSection_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ReadSection_Arg_2_choice), (VOID *)ReadSection_Arg_2_choice);
    switch(*ReadSection_Arg_2_choice % 7) {
        case 0:
        {
        // Constant Variable Initialization
        ReadSection_Arg_2 = EFI_SECTION_PE32;
    
            break;
        }
        case 1:
        {
        // Constant Variable Initialization
        ReadSection_Arg_2 = EFI_SECTION_TE;
    
            break;
        }
        case 2:
        {
        // Constant Variable Initialization
        ReadSection_Arg_2 = EFI_SECTION_RAW;
    
            break;
        }
        case 3:
        {
        // Constant Variable Initialization
        ReadSection_Arg_2 = EFI_SECTION_SMM_DEPEX;
    
            break;
        }
        case 4:
        {
        // Constant Variable Initialization
        ReadSection_Arg_2 = EFI_SECTION_DXE_DEPEX;
    
            break;
        }
        case 5:
        {
        // Constant Variable Initialization
        ReadSection_Arg_2 = EFI_SECTION_USER_INTERFACE;
    
            break;
        }
        case 6:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(ReadSection_Arg_2), (VOID *)&ReadSection_Arg_2);
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ReadSection_Arg_3), (VOID *)&ReadSection_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 ReadSection_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(ReadSection_Arg_4_choice), (VOID *)&ReadSection_Arg_4_choice);
    switch(ReadSection_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(ReadSection_Arg_4), (VOID *)ReadSection_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(ReadSection_Arg_4);
            ReadSection_Arg_4 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 ReadSection_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(ReadSection_Arg_5_choice), (VOID *)&ReadSection_Arg_5_choice);
    switch(ReadSection_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(ReadSection_Arg_5), (VOID *)ReadSection_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(ReadSection_Arg_5);
            ReadSection_Arg_5 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    UINT32 * ReadSection_Arg_6 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT8* ReadSection_Arg_6_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ReadSection_Arg_6_OutputChoice), (VOID *)ReadSection_Arg_6_OutputChoice);
    if(*ReadSection_Arg_6_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ReadSection_Arg_6), (VOID *)ReadSection_Arg_6);
    }
    Status = ProtocolVariable->ReadSection(
        ProtocolVariable,
        ReadSection_Arg_1,
        ReadSection_Arg_2,
        ReadSection_Arg_3,
        (void **)&ReadSection_Arg_4,
        ReadSection_Arg_5,
        ReadSection_Arg_6
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetNextFile.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetNextFile(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FIRMWARE_VOLUME2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFirmwareVolume2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  GetNextFile_Arg_1 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    EFI_FV_FILETYPE * GetNextFile_Arg_2 = (EFI_FV_FILETYPE *)AllocateZeroPool(sizeof(EFI_FV_FILETYPE));
    
    // Fuzzable Variable Initialization
    UINT8 GetNextFile_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetNextFile_Arg_1_choice), (VOID *)&GetNextFile_Arg_1_choice);
    switch(GetNextFile_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetNextFile_Arg_1), (VOID *)GetNextFile_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(GetNextFile_Arg_1);
            GetNextFile_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetNextFile_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetNextFile_Arg_2_choice), (VOID *)&GetNextFile_Arg_2_choice);
    switch(GetNextFile_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetNextFile_Arg_2), (VOID *)GetNextFile_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(GetNextFile_Arg_2);
            GetNextFile_Arg_2 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_GUID * GetNextFile_Arg_3 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINT8* GetNextFile_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetNextFile_Arg_3_OutputChoice), (VOID *)GetNextFile_Arg_3_OutputChoice);
    if(*GetNextFile_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetNextFile_Arg_3), (VOID *)GetNextFile_Arg_3);
    }
    EFI_FV_FILE_ATTRIBUTES * GetNextFile_Arg_4 = (EFI_FV_FILE_ATTRIBUTES *)AllocateZeroPool(sizeof(EFI_FV_FILE_ATTRIBUTES));
    UINT8* GetNextFile_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetNextFile_Arg_4_OutputChoice), (VOID *)GetNextFile_Arg_4_OutputChoice);
    if(*GetNextFile_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetNextFile_Arg_4), (VOID *)GetNextFile_Arg_4);
    }
    UINTN * GetNextFile_Arg_5 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetNextFile_Arg_5_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetNextFile_Arg_5_OutputChoice), (VOID *)GetNextFile_Arg_5_OutputChoice);
    if(*GetNextFile_Arg_5_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetNextFile_Arg_5), (VOID *)GetNextFile_Arg_5);
    }
    Status = ProtocolVariable->GetNextFile(
        ProtocolVariable,
        (void *)GetNextFile_Arg_1,
        GetNextFile_Arg_2,
        GetNextFile_Arg_3,
        GetNextFile_Arg_4,
        GetNextFile_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ReadFile.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzReadFile(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FIRMWARE_VOLUME2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFirmwareVolume2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * ReadFile_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINTN* ReadFile_Arg_2 = (UINTN*)AllocateZeroPool(sizeof(UINTN));
    UINTN * ReadFile_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    UINT8* ReadFile_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ReadFile_Arg_1_choice), (VOID *)ReadFile_Arg_1_choice);
    switch(*ReadFile_Arg_1_choice % 7) {
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
                CopyGuid_Arg_1 = &gEfiCallerIdGuid;
            
                    break;
                }
                case 1:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoAhciInterfaceGuid;
            
                    break;
                }
                case 2:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocModuleGuid;
            
                    break;
                }
                case 3:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocStackGuid;
            
                    break;
                }
                case 4:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocBspStoreGuid;
            
                    break;
                }
                case 5:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiAuthenticatedVariableGuid;
            
                    break;
                }
                case 6:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmmVariableProtocolGuid;
            
                    break;
                }
                case 7:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoIdeInterfaceGuid;
            
                    break;
                }
                case 8:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoUfsInterfaceGuid;
            
                    break;
                }
                case 9:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEdkiiDeviceIdentifierTypePciGuid;
            
                    break;
                }
                case 10:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVariableGuid;
            
                    break;
                }
                case 11:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiFirmwareFileSystem2Guid;
            
                    break;
                }
                case 12:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gVarCheckPolicyLibMmiHandlerGuid;
            
                    break;
                }
                case 13:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiGlobalVariableGuid;
            
                    break;
                }
                case 14:
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
                case 15:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gZeroGuid;
            
                    break;
                }
                case 16:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPcAnsiGuid;
            
                    break;
                }
                case 17:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100Guid;
            
                    break;
                }
                case 18:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100PlusGuid;
            
                    break;
                }
                case 19:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVTUTF8Guid;
            
                    break;
                }
                case 20:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiUartDevicePathGuid;
            
                    break;
                }
                case 21:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSasDevicePathGuid;
            
                    break;
                }
                case 22:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDebugPortProtocolGuid;
            
                    break;
                }
                case 23:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualDiskGuid;
            
                    break;
                }
                case 24:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualCdGuid;
            
                    break;
                }
                case 25:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualDiskGuid;
            
                    break;
                }
                case 26:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualCdGuid;
            
                    break;
                }
            }
            CopyGuid(
                ReadFile_Arg_1,
                CopyGuid_Arg_1
            );
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            ExtractGuidedSectionGetGuidList(
                &ReadFile_Arg_1
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
                ReadFile_Arg_1
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            Status = NetLibGetSystemGuid(
                ReadFile_Arg_1
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
                &ReadFile_Arg_1
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
                ReadFile_Arg_1
            );
    
            break;
        }
        case 6:
        {
        // Generator Struct Variable Initialization
        {
            UINT32 Firness_Data1;
            ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
            ReadFile_Arg_1->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            ReadFile_Arg_1->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            ReadFile_Arg_1->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(ReadFile_Arg_1->Data4), (VOID *)&(ReadFile_Arg_1->Data4));
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 ReadFile_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(ReadFile_Arg_2_choice), (VOID *)&ReadFile_Arg_2_choice);
    switch(ReadFile_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(ReadFile_Arg_2), (VOID *)ReadFile_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(ReadFile_Arg_2);
            ReadFile_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 ReadFile_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(ReadFile_Arg_3_choice), (VOID *)&ReadFile_Arg_3_choice);
    switch(ReadFile_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(ReadFile_Arg_3), (VOID *)ReadFile_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(ReadFile_Arg_3);
            ReadFile_Arg_3 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_FV_FILETYPE * ReadFile_Arg_4 = (EFI_FV_FILETYPE *)AllocateZeroPool(sizeof(EFI_FV_FILETYPE));
    UINT8* ReadFile_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ReadFile_Arg_4_OutputChoice), (VOID *)ReadFile_Arg_4_OutputChoice);
    if(*ReadFile_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ReadFile_Arg_4), (VOID *)ReadFile_Arg_4);
    }
    EFI_FV_FILE_ATTRIBUTES * ReadFile_Arg_5 = (EFI_FV_FILE_ATTRIBUTES *)AllocateZeroPool(sizeof(EFI_FV_FILE_ATTRIBUTES));
    UINT8* ReadFile_Arg_5_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ReadFile_Arg_5_OutputChoice), (VOID *)ReadFile_Arg_5_OutputChoice);
    if(*ReadFile_Arg_5_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ReadFile_Arg_5), (VOID *)ReadFile_Arg_5);
    }
    UINT32 * ReadFile_Arg_6 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT8* ReadFile_Arg_6_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ReadFile_Arg_6_OutputChoice), (VOID *)ReadFile_Arg_6_OutputChoice);
    if(*ReadFile_Arg_6_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ReadFile_Arg_6), (VOID *)ReadFile_Arg_6);
    }
    Status = ProtocolVariable->ReadFile(
        ProtocolVariable,
        ReadFile_Arg_1,
        (void **)&ReadFile_Arg_2,
        ReadFile_Arg_3,
        ReadFile_Arg_4,
        ReadFile_Arg_5,
        ReadFile_Arg_6
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetVolumeAttributes.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetVolumeAttributes(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FIRMWARE_VOLUME2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFirmwareVolume2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_FV_ATTRIBUTES * SetVolumeAttributes_Arg_1 = (EFI_FV_ATTRIBUTES *)AllocateZeroPool(sizeof(EFI_FV_ATTRIBUTES));
    UINT8* SetVolumeAttributes_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SetVolumeAttributes_Arg_1_OutputChoice), (VOID *)SetVolumeAttributes_Arg_1_OutputChoice);
    if(*SetVolumeAttributes_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*SetVolumeAttributes_Arg_1), (VOID *)SetVolumeAttributes_Arg_1);
    }
    Status = ProtocolVariable->SetVolumeAttributes(
        ProtocolVariable,
        SetVolumeAttributes_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called WriteFile.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzWriteFile(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FIRMWARE_VOLUME2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFirmwareVolume2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 WriteFile_Arg_1 = 0;
    EFI_FV_WRITE_POLICY WriteFile_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(WriteFile_Arg_1), (VOID *)&WriteFile_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(WriteFile_Arg_2), (VOID *)&WriteFile_Arg_2);
    
    Status = ProtocolVariable->WriteFile(
        ProtocolVariable,
        WriteFile_Arg_1,
        WriteFile_Arg_2,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
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
    EFI_FIRMWARE_VOLUME2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFirmwareVolume2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * GetInfo_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINTN * GetInfo_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    UINT8* GetInfo_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetInfo_Arg_1_choice), (VOID *)GetInfo_Arg_1_choice);
    switch(*GetInfo_Arg_1_choice % 7) {
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
                CopyGuid_Arg_1 = &gEfiCallerIdGuid;
            
                    break;
                }
                case 1:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoAhciInterfaceGuid;
            
                    break;
                }
                case 2:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocModuleGuid;
            
                    break;
                }
                case 3:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocStackGuid;
            
                    break;
                }
                case 4:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocBspStoreGuid;
            
                    break;
                }
                case 5:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiAuthenticatedVariableGuid;
            
                    break;
                }
                case 6:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmmVariableProtocolGuid;
            
                    break;
                }
                case 7:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoIdeInterfaceGuid;
            
                    break;
                }
                case 8:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoUfsInterfaceGuid;
            
                    break;
                }
                case 9:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEdkiiDeviceIdentifierTypePciGuid;
            
                    break;
                }
                case 10:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVariableGuid;
            
                    break;
                }
                case 11:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiFirmwareFileSystem2Guid;
            
                    break;
                }
                case 12:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gVarCheckPolicyLibMmiHandlerGuid;
            
                    break;
                }
                case 13:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiGlobalVariableGuid;
            
                    break;
                }
                case 14:
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
                case 15:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gZeroGuid;
            
                    break;
                }
                case 16:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPcAnsiGuid;
            
                    break;
                }
                case 17:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100Guid;
            
                    break;
                }
                case 18:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100PlusGuid;
            
                    break;
                }
                case 19:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVTUTF8Guid;
            
                    break;
                }
                case 20:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiUartDevicePathGuid;
            
                    break;
                }
                case 21:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSasDevicePathGuid;
            
                    break;
                }
                case 22:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDebugPortProtocolGuid;
            
                    break;
                }
                case 23:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualDiskGuid;
            
                    break;
                }
                case 24:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualCdGuid;
            
                    break;
                }
                case 25:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualDiskGuid;
            
                    break;
                }
                case 26:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualCdGuid;
            
                    break;
                }
            }
            CopyGuid(
                GetInfo_Arg_1,
                CopyGuid_Arg_1
            );
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            ExtractGuidedSectionGetGuidList(
                &GetInfo_Arg_1
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
                GetInfo_Arg_1
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            Status = NetLibGetSystemGuid(
                GetInfo_Arg_1
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
                &GetInfo_Arg_1
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
                GetInfo_Arg_1
            );
    
            break;
        }
        case 6:
        {
        // Generator Struct Variable Initialization
        {
            UINT32 Firness_Data1;
            ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
            GetInfo_Arg_1->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            GetInfo_Arg_1->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            GetInfo_Arg_1->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(GetInfo_Arg_1->Data4), (VOID *)&(GetInfo_Arg_1->Data4));
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 GetInfo_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetInfo_Arg_2_choice), (VOID *)&GetInfo_Arg_2_choice);
    switch(GetInfo_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetInfo_Arg_2), (VOID *)GetInfo_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(GetInfo_Arg_2);
            GetInfo_Arg_2 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    UINTN*  GetInfo_Arg_3 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT8* GetInfo_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetInfo_Arg_3_OutputChoice), (VOID *)GetInfo_Arg_3_OutputChoice);
    if(*GetInfo_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetInfo_Arg_3), (VOID *)GetInfo_Arg_3);
    }
    Status = ProtocolVariable->GetInfo(
        ProtocolVariable,
        GetInfo_Arg_1,
        GetInfo_Arg_2,
        (void *)GetInfo_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetInfo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FIRMWARE_VOLUME2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFirmwareVolume2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * SetInfo_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINTN SetInfo_Arg_2 = 0;
    UINTN*  SetInfo_Arg_3 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    UINT8* SetInfo_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SetInfo_Arg_1_choice), (VOID *)SetInfo_Arg_1_choice);
    switch(*SetInfo_Arg_1_choice % 7) {
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
                CopyGuid_Arg_1 = &gEfiCallerIdGuid;
            
                    break;
                }
                case 1:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoAhciInterfaceGuid;
            
                    break;
                }
                case 2:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocModuleGuid;
            
                    break;
                }
                case 3:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocStackGuid;
            
                    break;
                }
                case 4:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocBspStoreGuid;
            
                    break;
                }
                case 5:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiAuthenticatedVariableGuid;
            
                    break;
                }
                case 6:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmmVariableProtocolGuid;
            
                    break;
                }
                case 7:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoIdeInterfaceGuid;
            
                    break;
                }
                case 8:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoUfsInterfaceGuid;
            
                    break;
                }
                case 9:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEdkiiDeviceIdentifierTypePciGuid;
            
                    break;
                }
                case 10:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVariableGuid;
            
                    break;
                }
                case 11:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiFirmwareFileSystem2Guid;
            
                    break;
                }
                case 12:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gVarCheckPolicyLibMmiHandlerGuid;
            
                    break;
                }
                case 13:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiGlobalVariableGuid;
            
                    break;
                }
                case 14:
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
                case 15:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gZeroGuid;
            
                    break;
                }
                case 16:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPcAnsiGuid;
            
                    break;
                }
                case 17:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100Guid;
            
                    break;
                }
                case 18:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100PlusGuid;
            
                    break;
                }
                case 19:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVTUTF8Guid;
            
                    break;
                }
                case 20:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiUartDevicePathGuid;
            
                    break;
                }
                case 21:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSasDevicePathGuid;
            
                    break;
                }
                case 22:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDebugPortProtocolGuid;
            
                    break;
                }
                case 23:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualDiskGuid;
            
                    break;
                }
                case 24:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualCdGuid;
            
                    break;
                }
                case 25:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualDiskGuid;
            
                    break;
                }
                case 26:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualCdGuid;
            
                    break;
                }
            }
            CopyGuid(
                SetInfo_Arg_1,
                CopyGuid_Arg_1
            );
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            ExtractGuidedSectionGetGuidList(
                &SetInfo_Arg_1
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
                SetInfo_Arg_1
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            Status = NetLibGetSystemGuid(
                SetInfo_Arg_1
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
                &SetInfo_Arg_1
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
                SetInfo_Arg_1
            );
    
            break;
        }
        case 6:
        {
        // Generator Struct Variable Initialization
        {
            UINT32 Firness_Data1;
            ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
            SetInfo_Arg_1->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            SetInfo_Arg_1->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            SetInfo_Arg_1->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(SetInfo_Arg_1->Data4), (VOID *)&(SetInfo_Arg_1->Data4));
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetInfo_Arg_2), (VOID *)&SetInfo_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 SetInfo_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(SetInfo_Arg_3_choice), (VOID *)&SetInfo_Arg_3_choice);
    switch(SetInfo_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetInfo_Arg_3), (VOID *)SetInfo_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(SetInfo_Arg_3);
            SetInfo_Arg_3 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->SetInfo(
        ProtocolVariable,
        SetInfo_Arg_1,
        SetInfo_Arg_2,
        (void *)SetInfo_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetVolumeAttributes.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetVolumeAttributes(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FIRMWARE_VOLUME2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFirmwareVolume2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_FV_ATTRIBUTES * GetVolumeAttributes_Arg_1 = (EFI_FV_ATTRIBUTES *)AllocateZeroPool(sizeof(EFI_FV_ATTRIBUTES));
    UINT8* GetVolumeAttributes_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetVolumeAttributes_Arg_1_OutputChoice), (VOID *)GetVolumeAttributes_Arg_1_OutputChoice);
    if(*GetVolumeAttributes_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetVolumeAttributes_Arg_1), (VOID *)GetVolumeAttributes_Arg_1);
    }
    Status = ProtocolVariable->GetVolumeAttributes(
        ProtocolVariable,
        GetVolumeAttributes_Arg_1
    );
    return Status;
}

