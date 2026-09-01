#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called GetRootHpcList.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetRootHpcList(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_HOT_PLUG_INIT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciHotPlugInitProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINTN * GetRootHpcList_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetRootHpcList_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetRootHpcList_Arg_1_OutputChoice), (VOID *)GetRootHpcList_Arg_1_OutputChoice);
    if(*GetRootHpcList_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetRootHpcList_Arg_1), (VOID *)GetRootHpcList_Arg_1);
    }
    EFI_HPC_LOCATION * GetRootHpcList_Arg_2 = (EFI_HPC_LOCATION *)AllocateZeroPool(sizeof(EFI_HPC_LOCATION));
    UINT8* GetRootHpcList_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetRootHpcList_Arg_2_OutputChoice), (VOID *)GetRootHpcList_Arg_2_OutputChoice);
    if(*GetRootHpcList_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetRootHpcList_Arg_2), (VOID *)GetRootHpcList_Arg_2);
    }
    Status = ProtocolVariable->GetRootHpcList(
        ProtocolVariable,
        GetRootHpcList_Arg_1,
        (EFI_HPC_LOCATION **)&GetRootHpcList_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetResourcePadding.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetResourcePadding(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_HOT_PLUG_INIT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciHotPlugInitProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * GetResourcePadding_Arg_1 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    UINT64 GetResourcePadding_Arg_2 = 0;
    
    UINT8* GetResourcePadding_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetResourcePadding_Arg_1_choice), (VOID *)GetResourcePadding_Arg_1_choice);
    switch(*GetResourcePadding_Arg_1_choice % 4) {
        case 0:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * ChooseFile_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            unsigned short * ChooseFile_Arg_1 = (unsigned short *)AllocateZeroPool(sizeof(unsigned short));
            
            // Generator Struct Variable Initialization
            {
                UINT8 Firness_Type;
                ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
                ChooseFile_Arg_0->Type = Firness_Type;
            }
            {
                UINT8 Firness_SubType;
                ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
                ChooseFile_Arg_0->SubType = Firness_SubType;
            }
            ReadBytes(Input, sizeof(ChooseFile_Arg_0->Length), (VOID *)&(ChooseFile_Arg_0->Length));
            
            // Fuzzable Variable Initialization
            UINT8 ChooseFile_Arg_1_choice = 0;
            ReadBytes(Input, sizeof(ChooseFile_Arg_1_choice), (VOID *)&ChooseFile_Arg_1_choice);
            switch(ChooseFile_Arg_1_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(ChooseFile_Arg_1), (VOID *)ChooseFile_Arg_1);
                    break;
                case 1:
                {
                    gBS->FreePool(ChooseFile_Arg_1);
                    ChooseFile_Arg_1 = NULL;
                    break;
                }
            }
            
            Status = ChooseFile(
                ChooseFile_Arg_0,
                ChooseFile_Arg_1,
                NULL,
                &GetResourcePadding_Arg_1
            );
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * GetGopDevicePath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            
            // Generator Struct Variable Initialization
            {
                UINT8 Firness_Type;
                ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
                GetGopDevicePath_Arg_0->Type = Firness_Type;
            }
            {
                UINT8 Firness_SubType;
                ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
                GetGopDevicePath_Arg_0->SubType = Firness_SubType;
            }
            ReadBytes(Input, sizeof(GetGopDevicePath_Arg_0->Length), (VOID *)&(GetGopDevicePath_Arg_0->Length));
            
            Status = GetGopDevicePath(
                GetGopDevicePath_Arg_0,
                &GetResourcePadding_Arg_1
            );
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_GUID * GetFileDevicePathFromAnyFv_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
            EFI_SECTION_TYPE GetFileDevicePathFromAnyFv_Arg_1 = 0;
            UINTN GetFileDevicePathFromAnyFv_Arg_2 = 0;
            
            // Generator Struct Variable Initialization
            {
                UINT32 Firness_Data1;
                ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
                GetFileDevicePathFromAnyFv_Arg_0->Data1 = Firness_Data1;
            }
            {
                UINT16 Firness_Data2;
                ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
                GetFileDevicePathFromAnyFv_Arg_0->Data2 = Firness_Data2;
            }
            {
                UINT16 Firness_Data3;
                ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
                GetFileDevicePathFromAnyFv_Arg_0->Data3 = Firness_Data3;
            }
            ReadBytes(Input, sizeof(GetFileDevicePathFromAnyFv_Arg_0->Data4), (VOID *)&(GetFileDevicePathFromAnyFv_Arg_0->Data4));
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(GetFileDevicePathFromAnyFv_Arg_1), (VOID *)&GetFileDevicePathFromAnyFv_Arg_1);
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(GetFileDevicePathFromAnyFv_Arg_2), (VOID *)&GetFileDevicePathFromAnyFv_Arg_2);
            
            Status = GetFileDevicePathFromAnyFv(
                GetFileDevicePathFromAnyFv_Arg_0,
                GetFileDevicePathFromAnyFv_Arg_1,
                GetFileDevicePathFromAnyFv_Arg_2,
                &GetResourcePadding_Arg_1
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
        {
            UINT8 Firness_Type;
            ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
            GetResourcePadding_Arg_1->Type = Firness_Type;
        }
        {
            UINT8 Firness_SubType;
            ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
            GetResourcePadding_Arg_1->SubType = Firness_SubType;
        }
        ReadBytes(Input, sizeof(GetResourcePadding_Arg_1->Length), (VOID *)&(GetResourcePadding_Arg_1->Length));
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetResourcePadding_Arg_2), (VOID *)&GetResourcePadding_Arg_2);
    
    /*
        Output Variable(s)
    */
    EFI_HPC_STATE * GetResourcePadding_Arg_3 = (EFI_HPC_STATE *)AllocateZeroPool(sizeof(EFI_HPC_STATE));
    UINT8* GetResourcePadding_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetResourcePadding_Arg_3_OutputChoice), (VOID *)GetResourcePadding_Arg_3_OutputChoice);
    if(*GetResourcePadding_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetResourcePadding_Arg_3), (VOID *)GetResourcePadding_Arg_3);
    }
    UINTN* GetResourcePadding_Arg_4 = (UINTN*)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetResourcePadding_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetResourcePadding_Arg_4_OutputChoice), (VOID *)GetResourcePadding_Arg_4_OutputChoice);
    if(*GetResourcePadding_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetResourcePadding_Arg_4), (VOID *)GetResourcePadding_Arg_4);
    }
    EFI_HPC_PADDING_ATTRIBUTES * GetResourcePadding_Arg_5 = (EFI_HPC_PADDING_ATTRIBUTES *)AllocateZeroPool(sizeof(EFI_HPC_PADDING_ATTRIBUTES));
    UINT8* GetResourcePadding_Arg_5_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetResourcePadding_Arg_5_OutputChoice), (VOID *)GetResourcePadding_Arg_5_OutputChoice);
    if(*GetResourcePadding_Arg_5_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetResourcePadding_Arg_5), (VOID *)GetResourcePadding_Arg_5);
    }
    Status = ProtocolVariable->GetResourcePadding(
        ProtocolVariable,
        GetResourcePadding_Arg_1,
        GetResourcePadding_Arg_2,
        GetResourcePadding_Arg_3,
        (void **)&GetResourcePadding_Arg_4,
        GetResourcePadding_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called InitializeRootHpc.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzInitializeRootHpc(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_HOT_PLUG_INIT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciHotPlugInitProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * InitializeRootHpc_Arg_1 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    UINT64 InitializeRootHpc_Arg_2 = 0;
    EFI_EVENT InitializeRootHpc_Arg_3 = 0;
    
    UINT8* InitializeRootHpc_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(InitializeRootHpc_Arg_1_choice), (VOID *)InitializeRootHpc_Arg_1_choice);
    switch(*InitializeRootHpc_Arg_1_choice % 4) {
        case 0:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * ChooseFile_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            unsigned short * ChooseFile_Arg_1 = (unsigned short *)AllocateZeroPool(sizeof(unsigned short));
            
            // Generator Struct Variable Initialization
            {
                UINT8 Firness_Type;
                ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
                ChooseFile_Arg_0->Type = Firness_Type;
            }
            {
                UINT8 Firness_SubType;
                ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
                ChooseFile_Arg_0->SubType = Firness_SubType;
            }
            ReadBytes(Input, sizeof(ChooseFile_Arg_0->Length), (VOID *)&(ChooseFile_Arg_0->Length));
            
            // Fuzzable Variable Initialization
            UINT8 ChooseFile_Arg_1_choice = 0;
            ReadBytes(Input, sizeof(ChooseFile_Arg_1_choice), (VOID *)&ChooseFile_Arg_1_choice);
            switch(ChooseFile_Arg_1_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(ChooseFile_Arg_1), (VOID *)ChooseFile_Arg_1);
                    break;
                case 1:
                {
                    gBS->FreePool(ChooseFile_Arg_1);
                    ChooseFile_Arg_1 = NULL;
                    break;
                }
            }
            
            Status = ChooseFile(
                ChooseFile_Arg_0,
                ChooseFile_Arg_1,
                NULL,
                &InitializeRootHpc_Arg_1
            );
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * GetGopDevicePath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            
            // Generator Struct Variable Initialization
            {
                UINT8 Firness_Type;
                ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
                GetGopDevicePath_Arg_0->Type = Firness_Type;
            }
            {
                UINT8 Firness_SubType;
                ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
                GetGopDevicePath_Arg_0->SubType = Firness_SubType;
            }
            ReadBytes(Input, sizeof(GetGopDevicePath_Arg_0->Length), (VOID *)&(GetGopDevicePath_Arg_0->Length));
            
            Status = GetGopDevicePath(
                GetGopDevicePath_Arg_0,
                &InitializeRootHpc_Arg_1
            );
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_GUID * GetFileDevicePathFromAnyFv_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
            EFI_SECTION_TYPE GetFileDevicePathFromAnyFv_Arg_1 = 0;
            UINTN GetFileDevicePathFromAnyFv_Arg_2 = 0;
            
            // Generator Struct Variable Initialization
            {
                UINT32 Firness_Data1;
                ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
                GetFileDevicePathFromAnyFv_Arg_0->Data1 = Firness_Data1;
            }
            {
                UINT16 Firness_Data2;
                ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
                GetFileDevicePathFromAnyFv_Arg_0->Data2 = Firness_Data2;
            }
            {
                UINT16 Firness_Data3;
                ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
                GetFileDevicePathFromAnyFv_Arg_0->Data3 = Firness_Data3;
            }
            ReadBytes(Input, sizeof(GetFileDevicePathFromAnyFv_Arg_0->Data4), (VOID *)&(GetFileDevicePathFromAnyFv_Arg_0->Data4));
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(GetFileDevicePathFromAnyFv_Arg_1), (VOID *)&GetFileDevicePathFromAnyFv_Arg_1);
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(GetFileDevicePathFromAnyFv_Arg_2), (VOID *)&GetFileDevicePathFromAnyFv_Arg_2);
            
            Status = GetFileDevicePathFromAnyFv(
                GetFileDevicePathFromAnyFv_Arg_0,
                GetFileDevicePathFromAnyFv_Arg_1,
                GetFileDevicePathFromAnyFv_Arg_2,
                &InitializeRootHpc_Arg_1
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
        {
            UINT8 Firness_Type;
            ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
            InitializeRootHpc_Arg_1->Type = Firness_Type;
        }
        {
            UINT8 Firness_SubType;
            ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
            InitializeRootHpc_Arg_1->SubType = Firness_SubType;
        }
        ReadBytes(Input, sizeof(InitializeRootHpc_Arg_1->Length), (VOID *)&(InitializeRootHpc_Arg_1->Length));
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(InitializeRootHpc_Arg_2), (VOID *)&InitializeRootHpc_Arg_2);
    
    UINT8* InitializeRootHpc_Arg_3_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(InitializeRootHpc_Arg_3_choice), (VOID *)InitializeRootHpc_Arg_3_choice);
    switch(*InitializeRootHpc_Arg_3_choice % 3) {
        case 0:
        {
        // Generator Struct Variable Initialization
            Status = EfiCreateEventReadyToBoot(
                &InitializeRootHpc_Arg_3
            );
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            Status = EfiCreateEventLegacyBoot(
                &InitializeRootHpc_Arg_3
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
                &InitializeRootHpc_Arg_3
            );
    
            break;
        }
    }
    /*
        Output Variable(s)
    */
    EFI_HPC_STATE * InitializeRootHpc_Arg_4 = (EFI_HPC_STATE *)AllocateZeroPool(sizeof(EFI_HPC_STATE));
    UINT8* InitializeRootHpc_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(InitializeRootHpc_Arg_4_OutputChoice), (VOID *)InitializeRootHpc_Arg_4_OutputChoice);
    if(*InitializeRootHpc_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*InitializeRootHpc_Arg_4), (VOID *)InitializeRootHpc_Arg_4);
    }
    Status = ProtocolVariable->InitializeRootHpc(
        ProtocolVariable,
        InitializeRootHpc_Arg_1,
        InitializeRootHpc_Arg_2,
        InitializeRootHpc_Arg_3,
        InitializeRootHpc_Arg_4
    );
    return Status;
}

