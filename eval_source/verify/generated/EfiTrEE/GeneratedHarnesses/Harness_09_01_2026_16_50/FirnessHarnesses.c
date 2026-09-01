#include "FirnessHarnesses.h"

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
    EFI_TREE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTrEEProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    TREE_BOOT_SERVICE_CAPABILITY * GetCapability_Arg_1 = (TREE_BOOT_SERVICE_CAPABILITY *)AllocateZeroPool(sizeof(TREE_BOOT_SERVICE_CAPABILITY));
    
    
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
    EFI_TREE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTrEEProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
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
        (TREE_EVENT_LOG_FORMAT){0},
        GetEventLog_Arg_2,
        GetEventLog_Arg_3,
        GetEventLog_Arg_4
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
    EFI_TREE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTrEEProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT64 HashLogExtendEvent_Arg_1 = 0;
    EFI_PHYSICAL_ADDRESS HashLogExtendEvent_Arg_2 = 0;
    UINT64 HashLogExtendEvent_Arg_3 = 0;
    
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
    
    Status = ProtocolVariable->HashLogExtendEvent(
        ProtocolVariable,
        HashLogExtendEvent_Arg_1,
        HashLogExtendEvent_Arg_2,
        HashLogExtendEvent_Arg_3,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SubmitCommand.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSubmitCommand(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_TREE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTrEEProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 SubmitCommand_Arg_1 = 0;
    UINT8 * SubmitCommand_Arg_2 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT32 SubmitCommand_Arg_3 = 0;
    UINT8 * SubmitCommand_Arg_4 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SubmitCommand_Arg_1), (VOID *)&SubmitCommand_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 SubmitCommand_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(SubmitCommand_Arg_2_choice), (VOID *)&SubmitCommand_Arg_2_choice);
    switch(SubmitCommand_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SubmitCommand_Arg_2), (VOID *)SubmitCommand_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(SubmitCommand_Arg_2);
            SubmitCommand_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SubmitCommand_Arg_3), (VOID *)&SubmitCommand_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 SubmitCommand_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(SubmitCommand_Arg_4_choice), (VOID *)&SubmitCommand_Arg_4_choice);
    switch(SubmitCommand_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SubmitCommand_Arg_4), (VOID *)SubmitCommand_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(SubmitCommand_Arg_4);
            SubmitCommand_Arg_4 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->SubmitCommand(
        ProtocolVariable,
        SubmitCommand_Arg_1,
        SubmitCommand_Arg_2,
        SubmitCommand_Arg_3,
        SubmitCommand_Arg_4
    );
    return Status;
}

