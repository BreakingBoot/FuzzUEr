#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called GetTargetLun.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetTargetLun(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SCSI_PASS_THRU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiScsiPassThruProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * GetTargetLun_Arg_1 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    UINT32 * GetTargetLun_Arg_2 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT64 * GetTargetLun_Arg_3 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    
    UINT8* GetTargetLun_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetTargetLun_Arg_1_choice), (VOID *)GetTargetLun_Arg_1_choice);
    switch(*GetTargetLun_Arg_1_choice % 4) {
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
                &GetTargetLun_Arg_1
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
                &GetTargetLun_Arg_1
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
                &GetTargetLun_Arg_1
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
        {
            UINT8 Firness_Type;
            ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
            GetTargetLun_Arg_1->Type = Firness_Type;
        }
        {
            UINT8 Firness_SubType;
            ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
            GetTargetLun_Arg_1->SubType = Firness_SubType;
        }
        ReadBytes(Input, sizeof(GetTargetLun_Arg_1->Length), (VOID *)&(GetTargetLun_Arg_1->Length));
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 GetTargetLun_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetTargetLun_Arg_2_choice), (VOID *)&GetTargetLun_Arg_2_choice);
    switch(GetTargetLun_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetTargetLun_Arg_2), (VOID *)GetTargetLun_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(GetTargetLun_Arg_2);
            GetTargetLun_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetTargetLun_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(GetTargetLun_Arg_3_choice), (VOID *)&GetTargetLun_Arg_3_choice);
    switch(GetTargetLun_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetTargetLun_Arg_3), (VOID *)GetTargetLun_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(GetTargetLun_Arg_3);
            GetTargetLun_Arg_3 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetTargetLun(
        ProtocolVariable,
        GetTargetLun_Arg_1,
        GetTargetLun_Arg_2,
        GetTargetLun_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetNextDevice.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetNextDevice(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SCSI_PASS_THRU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiScsiPassThruProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 * GetNextDevice_Arg_1 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT64 * GetNextDevice_Arg_2 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    
    // Fuzzable Variable Initialization
    UINT8 GetNextDevice_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetNextDevice_Arg_1_choice), (VOID *)&GetNextDevice_Arg_1_choice);
    switch(GetNextDevice_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetNextDevice_Arg_1), (VOID *)GetNextDevice_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(GetNextDevice_Arg_1);
            GetNextDevice_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetNextDevice_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetNextDevice_Arg_2_choice), (VOID *)&GetNextDevice_Arg_2_choice);
    switch(GetNextDevice_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetNextDevice_Arg_2), (VOID *)GetNextDevice_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(GetNextDevice_Arg_2);
            GetNextDevice_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetNextDevice(
        ProtocolVariable,
        GetNextDevice_Arg_1,
        GetNextDevice_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ResetChannel.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzResetChannel(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SCSI_PASS_THRU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiScsiPassThruProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->ResetChannel(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ResetTarget.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzResetTarget(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SCSI_PASS_THRU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiScsiPassThruProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 ResetTarget_Arg_1 = 0;
    UINT64 ResetTarget_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ResetTarget_Arg_1), (VOID *)&ResetTarget_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ResetTarget_Arg_2), (VOID *)&ResetTarget_Arg_2);
    
    Status = ProtocolVariable->ResetTarget(
        ProtocolVariable,
        ResetTarget_Arg_1,
        ResetTarget_Arg_2
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
    EFI_SCSI_PASS_THRU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiScsiPassThruProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 PassThru_Arg_1 = 0;
    UINT64 PassThru_Arg_2 = 0;
    EFI_EVENT PassThru_Arg_4 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PassThru_Arg_1), (VOID *)&PassThru_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PassThru_Arg_2), (VOID *)&PassThru_Arg_2);
    
    UINT8* PassThru_Arg_4_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(PassThru_Arg_4_choice), (VOID *)PassThru_Arg_4_choice);
    switch(*PassThru_Arg_4_choice % 5) {
        case 0:
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
            
            Status = EfiCreateEventReadyToBootEx(
                EfiCreateEventReadyToBootEx_Arg_0,
                NULL,
                (void *)EfiCreateEventReadyToBootEx_Arg_2,
                &PassThru_Arg_4
            );
    
            break;
        }
        case 1:
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
            
            Status = EfiCreateEventLegacyBootEx(
                EfiCreateEventLegacyBootEx_Arg_0,
                NULL,
                (void *)EfiCreateEventLegacyBootEx_Arg_2,
                &PassThru_Arg_4
            );
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            Status = EfiCreateEventReadyToBoot(
                &PassThru_Arg_4
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            Status = EfiCreateEventLegacyBoot(
                &PassThru_Arg_4
            );
    
            break;
        }
        case 4:
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
                &PassThru_Arg_4
            );
    
            break;
        }
    }
    Status = ProtocolVariable->PassThru(
        ProtocolVariable,
        PassThru_Arg_1,
        PassThru_Arg_2,
        NULL,
        PassThru_Arg_4
    );
    return Status;
}

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
    EFI_SCSI_PASS_THRU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiScsiPassThruProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 BuildDevicePath_Arg_1 = 0;
    UINT64 BuildDevicePath_Arg_2 = 0;
    EFI_DEVICE_PATH_PROTOCOL * BuildDevicePath_Arg_3 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(BuildDevicePath_Arg_1), (VOID *)&BuildDevicePath_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(BuildDevicePath_Arg_2), (VOID *)&BuildDevicePath_Arg_2);
    
    UINT8* BuildDevicePath_Arg_3_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(BuildDevicePath_Arg_3_choice), (VOID *)BuildDevicePath_Arg_3_choice);
    switch(*BuildDevicePath_Arg_3_choice % 4) {
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
                BuildDevicePath_Arg_3
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
                BuildDevicePath_Arg_3
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
                BuildDevicePath_Arg_3
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
        {
            UINT8 Firness_Type;
            ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
            BuildDevicePath_Arg_3->Type = Firness_Type;
        }
        {
            UINT8 Firness_SubType;
            ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
            BuildDevicePath_Arg_3->SubType = Firness_SubType;
        }
        ReadBytes(Input, sizeof(BuildDevicePath_Arg_3->Length), (VOID *)&(BuildDevicePath_Arg_3->Length));
    
            break;
        }
    }
    Status = ProtocolVariable->BuildDevicePath(
        ProtocolVariable,
        BuildDevicePath_Arg_1,
        BuildDevicePath_Arg_2,
        (EFI_DEVICE_PATH_PROTOCOL **)&BuildDevicePath_Arg_3
    );
    return Status;
}

