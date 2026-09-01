#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called ExecuteScsiCommand.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzExecuteScsiCommand(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SCSI_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiScsiIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_SCSI_IO_SCSI_REQUEST_PACKET * ExecuteScsiCommand_Arg_1 = (EFI_SCSI_IO_SCSI_REQUEST_PACKET *)AllocateZeroPool(sizeof(EFI_SCSI_IO_SCSI_REQUEST_PACKET));
    UINTN*  ExecuteScsiCommand_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    
    UINT8* ExecuteScsiCommand_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ExecuteScsiCommand_Arg_2_choice), (VOID *)ExecuteScsiCommand_Arg_2_choice);
    switch(*ExecuteScsiCommand_Arg_2_choice % 4) {
        case 0:
        {
        // Fuzzable Variable Initialization
        UINT8 ExecuteScsiCommand_Arg_2_choice = 0;
        ReadBytes(Input, sizeof(ExecuteScsiCommand_Arg_2_choice), (VOID *)&ExecuteScsiCommand_Arg_2_choice);
        switch(ExecuteScsiCommand_Arg_2_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(ExecuteScsiCommand_Arg_2), (VOID *)ExecuteScsiCommand_Arg_2);
                break;
            case 1:
            {
                gBS->FreePool(ExecuteScsiCommand_Arg_2);
                ExecuteScsiCommand_Arg_2 = NULL;
                break;
            }
        }
    
            break;
        }
        case 1:
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
        case 2:
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
        case 3:
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
    Status = ProtocolVariable->ExecuteScsiCommand(
        ProtocolVariable,
        ExecuteScsiCommand_Arg_1,
        (void *)ExecuteScsiCommand_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetDeviceType.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetDeviceType(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SCSI_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiScsiIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINT8 * GetDeviceType_Arg_1 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT8* GetDeviceType_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetDeviceType_Arg_1_OutputChoice), (VOID *)GetDeviceType_Arg_1_OutputChoice);
    if(*GetDeviceType_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetDeviceType_Arg_1), (VOID *)GetDeviceType_Arg_1);
    }
    Status = ProtocolVariable->GetDeviceType(
        ProtocolVariable,
        GetDeviceType_Arg_1
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
    EFI_SCSI_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiScsiIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->ResetDevice(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ResetBus.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzResetBus(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SCSI_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiScsiIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->ResetBus(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetDeviceLocation.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetDeviceLocation(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SCSI_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiScsiIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 * GetDeviceLocation_Arg_1 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    
    // Fuzzable Variable Initialization
    UINT8 GetDeviceLocation_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetDeviceLocation_Arg_1_choice), (VOID *)&GetDeviceLocation_Arg_1_choice);
    switch(GetDeviceLocation_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetDeviceLocation_Arg_1), (VOID *)GetDeviceLocation_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(GetDeviceLocation_Arg_1);
            GetDeviceLocation_Arg_1 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    UINT64 * GetDeviceLocation_Arg_2 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    UINT8* GetDeviceLocation_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetDeviceLocation_Arg_2_OutputChoice), (VOID *)GetDeviceLocation_Arg_2_OutputChoice);
    if(*GetDeviceLocation_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetDeviceLocation_Arg_2), (VOID *)GetDeviceLocation_Arg_2);
    }
    Status = ProtocolVariable->GetDeviceLocation(
        ProtocolVariable,
        (UINT8 **)&GetDeviceLocation_Arg_1,
        GetDeviceLocation_Arg_2
    );
    return Status;
}

