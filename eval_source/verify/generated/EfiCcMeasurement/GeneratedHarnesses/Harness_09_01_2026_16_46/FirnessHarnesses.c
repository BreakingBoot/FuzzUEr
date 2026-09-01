#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called MapPcrToMrIndex.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzMapPcrToMrIndex(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_CC_MEASUREMENT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiCcMeasurementProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 MapPcrToMrIndex_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(MapPcrToMrIndex_Arg_1), (VOID *)&MapPcrToMrIndex_Arg_1);
    
    /*
        Output Variable(s)
    */
    EFI_CC_MR_INDEX * MapPcrToMrIndex_Arg_2 = (EFI_CC_MR_INDEX *)AllocateZeroPool(sizeof(EFI_CC_MR_INDEX));
    UINT8* MapPcrToMrIndex_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(MapPcrToMrIndex_Arg_2_OutputChoice), (VOID *)MapPcrToMrIndex_Arg_2_OutputChoice);
    if(*MapPcrToMrIndex_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*MapPcrToMrIndex_Arg_2), (VOID *)MapPcrToMrIndex_Arg_2);
    }
    Status = ProtocolVariable->MapPcrToMrIndex(
        ProtocolVariable,
        MapPcrToMrIndex_Arg_1,
        MapPcrToMrIndex_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called HashLogExtendEvent.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzHashLogExtendEvent(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_CC_MEASUREMENT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiCcMeasurementProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT64 HashLogExtendEvent_Arg_1 = 0;
    EFI_PHYSICAL_ADDRESS HashLogExtendEvent_Arg_2 = 0;
    UINT64 HashLogExtendEvent_Arg_3 = 0;
    EFI_CC_EVENT * HashLogExtendEvent_Arg_4 = (EFI_CC_EVENT *)AllocateZeroPool(sizeof(EFI_CC_EVENT));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(HashLogExtendEvent_Arg_1), (VOID *)&HashLogExtendEvent_Arg_1);
    
    UINT8* HashLogExtendEvent_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(HashLogExtendEvent_Arg_2_choice), (VOID *)HashLogExtendEvent_Arg_2_choice);
    switch(*HashLogExtendEvent_Arg_2_choice % 4) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(HashLogExtendEvent_Arg_2), (VOID *)&HashLogExtendEvent_Arg_2);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Output Variable(s)
            */
            UINT64 * GetVariableFlashNvStorageInfo_Arg_1 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
            UINT8* GetVariableFlashNvStorageInfo_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(GetVariableFlashNvStorageInfo_Arg_1_OutputChoice), (VOID *)GetVariableFlashNvStorageInfo_Arg_1_OutputChoice);
            if(*GetVariableFlashNvStorageInfo_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*GetVariableFlashNvStorageInfo_Arg_1), (VOID *)GetVariableFlashNvStorageInfo_Arg_1);
            }
            Status = GetVariableFlashNvStorageInfo(
                &HashLogExtendEvent_Arg_2,
                GetVariableFlashNvStorageInfo_Arg_1
            );
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            /*
                Output Variable(s)
            */
            UINT64 * GetVariableFlashFtwSpareInfo_Arg_1 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
            UINT8* GetVariableFlashFtwSpareInfo_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(GetVariableFlashFtwSpareInfo_Arg_1_OutputChoice), (VOID *)GetVariableFlashFtwSpareInfo_Arg_1_OutputChoice);
            if(*GetVariableFlashFtwSpareInfo_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*GetVariableFlashFtwSpareInfo_Arg_1), (VOID *)GetVariableFlashFtwSpareInfo_Arg_1);
            }
            Status = GetVariableFlashFtwSpareInfo(
                &HashLogExtendEvent_Arg_2,
                GetVariableFlashFtwSpareInfo_Arg_1
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            /*
                Output Variable(s)
            */
            UINT64 * GetVariableFlashFtwWorkingInfo_Arg_1 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
            UINT8* GetVariableFlashFtwWorkingInfo_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(GetVariableFlashFtwWorkingInfo_Arg_1_OutputChoice), (VOID *)GetVariableFlashFtwWorkingInfo_Arg_1_OutputChoice);
            if(*GetVariableFlashFtwWorkingInfo_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*GetVariableFlashFtwWorkingInfo_Arg_1), (VOID *)GetVariableFlashFtwWorkingInfo_Arg_1);
            }
            Status = GetVariableFlashFtwWorkingInfo(
                &HashLogExtendEvent_Arg_2,
                GetVariableFlashFtwWorkingInfo_Arg_1
            );
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(HashLogExtendEvent_Arg_3), (VOID *)&HashLogExtendEvent_Arg_3);
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Size;
        ReadBytes(Input, sizeof(Firness_Size), (VOID *)&Firness_Size);
        HashLogExtendEvent_Arg_4->Size = Firness_Size;
    }
    {
        EFI_CC_EVENT_HEADER Firness_Header;
        ReadBytes(Input, sizeof(Firness_Header), (VOID *)&Firness_Header);
        HashLogExtendEvent_Arg_4->Header = Firness_Header;
    }
    ReadBytes(Input, sizeof(HashLogExtendEvent_Arg_4->Event), (VOID *)&(HashLogExtendEvent_Arg_4->Event));
    
    Status = ProtocolVariable->HashLogExtendEvent(
        ProtocolVariable,
        HashLogExtendEvent_Arg_1,
        HashLogExtendEvent_Arg_2,
        HashLogExtendEvent_Arg_3,
        HashLogExtendEvent_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetCapability.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetCapability(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_CC_MEASUREMENT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiCcMeasurementProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_CC_BOOT_SERVICE_CAPABILITY * GetCapability_Arg_1 = (EFI_CC_BOOT_SERVICE_CAPABILITY *)AllocateZeroPool(sizeof(EFI_CC_BOOT_SERVICE_CAPABILITY));
    
    
    Status = ProtocolVariable->GetCapability(
        ProtocolVariable,
        GetCapability_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetEventLog.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetEventLog(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_CC_MEASUREMENT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiCcMeasurementProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_CC_EVENT_LOG_FORMAT GetEventLog_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetEventLog_Arg_1), (VOID *)&GetEventLog_Arg_1);
    
    /*
        Output Variable(s)
    */
    EFI_PHYSICAL_ADDRESS * GetEventLog_Arg_2 = (EFI_PHYSICAL_ADDRESS *)AllocateZeroPool(sizeof(EFI_PHYSICAL_ADDRESS));
    UINT8* GetEventLog_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetEventLog_Arg_2_OutputChoice), (VOID *)GetEventLog_Arg_2_OutputChoice);
    if(*GetEventLog_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetEventLog_Arg_2), (VOID *)GetEventLog_Arg_2);
    }
    EFI_PHYSICAL_ADDRESS * GetEventLog_Arg_3 = (EFI_PHYSICAL_ADDRESS *)AllocateZeroPool(sizeof(EFI_PHYSICAL_ADDRESS));
    UINT8* GetEventLog_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetEventLog_Arg_3_OutputChoice), (VOID *)GetEventLog_Arg_3_OutputChoice);
    if(*GetEventLog_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetEventLog_Arg_3), (VOID *)GetEventLog_Arg_3);
    }
    BOOLEAN * GetEventLog_Arg_4 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
    UINT8* GetEventLog_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetEventLog_Arg_4_OutputChoice), (VOID *)GetEventLog_Arg_4_OutputChoice);
    if(*GetEventLog_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetEventLog_Arg_4), (VOID *)GetEventLog_Arg_4);
    }
    Status = ProtocolVariable->GetEventLog(
        ProtocolVariable,
        GetEventLog_Arg_1,
        GetEventLog_Arg_2,
        GetEventLog_Arg_3,
        GetEventLog_Arg_4
    );
    return Status;
}

