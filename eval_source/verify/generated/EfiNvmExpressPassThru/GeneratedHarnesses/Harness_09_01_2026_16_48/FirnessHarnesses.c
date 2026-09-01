#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called BuildDevicePath.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzBuildDevicePath(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiNvmExpressPassThruProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 BuildDevicePath_Arg_1 = 0;
    EFI_DEVICE_PATH_PROTOCOL * BuildDevicePath_Arg_2 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(BuildDevicePath_Arg_1), (VOID *)&BuildDevicePath_Arg_1);
    
    UINT8* BuildDevicePath_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(BuildDevicePath_Arg_2_choice), (VOID *)BuildDevicePath_Arg_2_choice);
    switch(*BuildDevicePath_Arg_2_choice % 4) {
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
                BuildDevicePath_Arg_2
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
                BuildDevicePath_Arg_2
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
                BuildDevicePath_Arg_2
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
        {
            UINT8 Firness_Type;
            ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
            BuildDevicePath_Arg_2->Type = Firness_Type;
        }
        {
            UINT8 Firness_SubType;
            ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
            BuildDevicePath_Arg_2->SubType = Firness_SubType;
        }
        ReadBytes(Input, sizeof(BuildDevicePath_Arg_2->Length), (VOID *)&(BuildDevicePath_Arg_2->Length));
    
            break;
        }
    }
    Status = ProtocolVariable->BuildDevicePath(
        ProtocolVariable,
        BuildDevicePath_Arg_1,
        (EFI_DEVICE_PATH_PROTOCOL **)&BuildDevicePath_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetNextNamespace.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetNextNamespace(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiNvmExpressPassThruProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 * GetNextNamespace_Arg_1 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    
    // Fuzzable Variable Initialization
    UINT8 GetNextNamespace_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetNextNamespace_Arg_1_choice), (VOID *)&GetNextNamespace_Arg_1_choice);
    switch(GetNextNamespace_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetNextNamespace_Arg_1), (VOID *)GetNextNamespace_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(GetNextNamespace_Arg_1);
            GetNextNamespace_Arg_1 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetNextNamespace(
        ProtocolVariable,
        GetNextNamespace_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called PassThru.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzPassThru(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiNvmExpressPassThruProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 PassThru_Arg_1 = 0;
    EFI_EVENT PassThru_Arg_3 = 0;
    
    UINT8* PassThru_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(PassThru_Arg_1_choice), (VOID *)PassThru_Arg_1_choice);
    switch(*PassThru_Arg_1_choice % 2) {
        case 0:
        {
        // Constant Variable Initialization
        PassThru_Arg_1 = NVME_CONTROLLER_ID;
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(PassThru_Arg_1), (VOID *)&PassThru_Arg_1);
    
            break;
        }
    }
    UINT8* PassThru_Arg_3_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(PassThru_Arg_3_choice), (VOID *)PassThru_Arg_3_choice);
    switch(*PassThru_Arg_3_choice % 3) {
        case 0:
        {
        // Generator Struct Variable Initialization
            Status = EfiCreateEventReadyToBoot(
                &PassThru_Arg_3
            );
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            Status = EfiCreateEventLegacyBoot(
                &PassThru_Arg_3
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
                &PassThru_Arg_3
            );
    
            break;
        }
    }
    Status = ProtocolVariable->PassThru(
        ProtocolVariable,
        PassThru_Arg_1,
        NULL,
        PassThru_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetNamespace.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetNamespace(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiNvmExpressPassThruProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * GetNamespace_Arg_1 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    UINT32 * GetNamespace_Arg_2 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    
    UINT8* GetNamespace_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetNamespace_Arg_1_choice), (VOID *)GetNamespace_Arg_1_choice);
    switch(*GetNamespace_Arg_1_choice % 4) {
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
                &GetNamespace_Arg_1
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
                &GetNamespace_Arg_1
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
                &GetNamespace_Arg_1
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
        {
            UINT8 Firness_Type;
            ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
            GetNamespace_Arg_1->Type = Firness_Type;
        }
        {
            UINT8 Firness_SubType;
            ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
            GetNamespace_Arg_1->SubType = Firness_SubType;
        }
        ReadBytes(Input, sizeof(GetNamespace_Arg_1->Length), (VOID *)&(GetNamespace_Arg_1->Length));
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 GetNamespace_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetNamespace_Arg_2_choice), (VOID *)&GetNamespace_Arg_2_choice);
    switch(GetNamespace_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetNamespace_Arg_2), (VOID *)GetNamespace_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(GetNamespace_Arg_2);
            GetNamespace_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetNamespace(
        ProtocolVariable,
        GetNamespace_Arg_1,
        GetNamespace_Arg_2
    );
    return Status;
}

