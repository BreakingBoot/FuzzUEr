#include "FirnessHarnesses.h"

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
    EFI_SD_MMC_PASS_THRU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSdMmcPassThruProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 PassThru_Arg_1 = 0;
    EFI_SD_MMC_PASS_THRU_COMMAND_PACKET * PassThru_Arg_2 = (EFI_SD_MMC_PASS_THRU_COMMAND_PACKET *)AllocateZeroPool(sizeof(EFI_SD_MMC_PASS_THRU_COMMAND_PACKET));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PassThru_Arg_1), (VOID *)&PassThru_Arg_1);
    
    
    Status = ProtocolVariable->PassThru(
        ProtocolVariable,
        PassThru_Arg_1,
        PassThru_Arg_2,
        (EFI_EVENT){0}
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetNextSlot.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetNextSlot(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SD_MMC_PASS_THRU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSdMmcPassThruProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 * GetNextSlot_Arg_1 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    
    // Fuzzable Variable Initialization
    UINT8 GetNextSlot_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetNextSlot_Arg_1_choice), (VOID *)&GetNextSlot_Arg_1_choice);
    switch(GetNextSlot_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetNextSlot_Arg_1), (VOID *)GetNextSlot_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(GetNextSlot_Arg_1);
            GetNextSlot_Arg_1 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetNextSlot(
        ProtocolVariable,
        GetNextSlot_Arg_1
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
    EFI_SD_MMC_PASS_THRU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSdMmcPassThruProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 BuildDevicePath_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(BuildDevicePath_Arg_1), (VOID *)&BuildDevicePath_Arg_1);
    
    /*
        Output Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * * BuildDevicePath_Arg_2 = (EFI_DEVICE_PATH_PROTOCOL * *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    UINT8* BuildDevicePath_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(BuildDevicePath_Arg_2_OutputChoice), (VOID *)BuildDevicePath_Arg_2_OutputChoice);
    if(*BuildDevicePath_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*BuildDevicePath_Arg_2), (VOID *)BuildDevicePath_Arg_2);
    }
    Status = ProtocolVariable->BuildDevicePath(
        ProtocolVariable,
        BuildDevicePath_Arg_1,
        &BuildDevicePath_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetSlotNumber.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetSlotNumber(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SD_MMC_PASS_THRU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSdMmcPassThruProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * GetSlotNumber_Arg_1 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    
    UINT8* GetSlotNumber_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetSlotNumber_Arg_1_choice), (VOID *)GetSlotNumber_Arg_1_choice);
    switch(*GetSlotNumber_Arg_1_choice % 4) {
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
                &GetSlotNumber_Arg_1
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
                &GetSlotNumber_Arg_1
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
                &GetSlotNumber_Arg_1
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
        {
            UINT8 Firness_Type;
            ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
            GetSlotNumber_Arg_1->Type = Firness_Type;
        }
        {
            UINT8 Firness_SubType;
            ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
            GetSlotNumber_Arg_1->SubType = Firness_SubType;
        }
        ReadBytes(Input, sizeof(GetSlotNumber_Arg_1->Length), (VOID *)&(GetSlotNumber_Arg_1->Length));
    
            break;
        }
    }
    /*
        Output Variable(s)
    */
    UINT8 * GetSlotNumber_Arg_2 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT8* GetSlotNumber_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetSlotNumber_Arg_2_OutputChoice), (VOID *)GetSlotNumber_Arg_2_OutputChoice);
    if(*GetSlotNumber_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetSlotNumber_Arg_2), (VOID *)GetSlotNumber_Arg_2);
    }
    Status = ProtocolVariable->GetSlotNumber(
        ProtocolVariable,
        GetSlotNumber_Arg_1,
        GetSlotNumber_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ResetDevice.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzResetDevice(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SD_MMC_PASS_THRU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSdMmcPassThruProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 ResetDevice_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ResetDevice_Arg_1), (VOID *)&ResetDevice_Arg_1);
    
    Status = ProtocolVariable->ResetDevice(
        ProtocolVariable,
        ResetDevice_Arg_1
    );
    return Status;
}

