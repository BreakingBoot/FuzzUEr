#include "FirnessHarnesses.h"

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
    EFI_TCG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTcgProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PHYSICAL_ADDRESS HashLogExtendEvent_Arg_1 = 0;
    UINT64 HashLogExtendEvent_Arg_2 = 0;
    TPM_ALGORITHM_ID HashLogExtendEvent_Arg_3 = 0;
    TCG_PCR_EVENT * HashLogExtendEvent_Arg_4 = (TCG_PCR_EVENT *)AllocateZeroPool(sizeof(TCG_PCR_EVENT));
    UINT32 * HashLogExtendEvent_Arg_5 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    
    UINT8* HashLogExtendEvent_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(HashLogExtendEvent_Arg_1_choice), (VOID *)HashLogExtendEvent_Arg_1_choice);
    switch(*HashLogExtendEvent_Arg_1_choice % 4) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(HashLogExtendEvent_Arg_1), (VOID *)&HashLogExtendEvent_Arg_1);
    
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
                &HashLogExtendEvent_Arg_1,
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
                &HashLogExtendEvent_Arg_1,
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
                &HashLogExtendEvent_Arg_1,
                GetVariableFlashFtwWorkingInfo_Arg_1
            );
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(HashLogExtendEvent_Arg_2), (VOID *)&HashLogExtendEvent_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(HashLogExtendEvent_Arg_3), (VOID *)&HashLogExtendEvent_Arg_3);
    
    
    // Fuzzable Variable Initialization
    UINT8 HashLogExtendEvent_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(HashLogExtendEvent_Arg_5_choice), (VOID *)&HashLogExtendEvent_Arg_5_choice);
    switch(HashLogExtendEvent_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(HashLogExtendEvent_Arg_5), (VOID *)HashLogExtendEvent_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(HashLogExtendEvent_Arg_5);
            HashLogExtendEvent_Arg_5 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_PHYSICAL_ADDRESS * HashLogExtendEvent_Arg_6 = (EFI_PHYSICAL_ADDRESS *)AllocateZeroPool(sizeof(EFI_PHYSICAL_ADDRESS));
    UINT8* HashLogExtendEvent_Arg_6_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(HashLogExtendEvent_Arg_6_OutputChoice), (VOID *)HashLogExtendEvent_Arg_6_OutputChoice);
    if(*HashLogExtendEvent_Arg_6_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*HashLogExtendEvent_Arg_6), (VOID *)HashLogExtendEvent_Arg_6);
    }
    Status = ProtocolVariable->HashLogExtendEvent(
        ProtocolVariable,
        HashLogExtendEvent_Arg_1,
        HashLogExtendEvent_Arg_2,
        HashLogExtendEvent_Arg_3,
        HashLogExtendEvent_Arg_4,
        HashLogExtendEvent_Arg_5,
        HashLogExtendEvent_Arg_6
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called StatusCheck.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStatusCheck(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_TCG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTcgProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    TCG_EFI_BOOT_SERVICE_CAPABILITY * StatusCheck_Arg_1 = (TCG_EFI_BOOT_SERVICE_CAPABILITY *)AllocateZeroPool(sizeof(TCG_EFI_BOOT_SERVICE_CAPABILITY));
    UINT8* StatusCheck_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(StatusCheck_Arg_1_OutputChoice), (VOID *)StatusCheck_Arg_1_OutputChoice);
    if(*StatusCheck_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*StatusCheck_Arg_1), (VOID *)StatusCheck_Arg_1);
    }
    UINT32 * StatusCheck_Arg_2 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT8* StatusCheck_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(StatusCheck_Arg_2_OutputChoice), (VOID *)StatusCheck_Arg_2_OutputChoice);
    if(*StatusCheck_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*StatusCheck_Arg_2), (VOID *)StatusCheck_Arg_2);
    }
    EFI_PHYSICAL_ADDRESS * StatusCheck_Arg_3 = (EFI_PHYSICAL_ADDRESS *)AllocateZeroPool(sizeof(EFI_PHYSICAL_ADDRESS));
    UINT8* StatusCheck_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(StatusCheck_Arg_3_OutputChoice), (VOID *)StatusCheck_Arg_3_OutputChoice);
    if(*StatusCheck_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*StatusCheck_Arg_3), (VOID *)StatusCheck_Arg_3);
    }
    EFI_PHYSICAL_ADDRESS * StatusCheck_Arg_4 = (EFI_PHYSICAL_ADDRESS *)AllocateZeroPool(sizeof(EFI_PHYSICAL_ADDRESS));
    UINT8* StatusCheck_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(StatusCheck_Arg_4_OutputChoice), (VOID *)StatusCheck_Arg_4_OutputChoice);
    if(*StatusCheck_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*StatusCheck_Arg_4), (VOID *)StatusCheck_Arg_4);
    }
    Status = ProtocolVariable->StatusCheck(
        ProtocolVariable,
        StatusCheck_Arg_1,
        StatusCheck_Arg_2,
        StatusCheck_Arg_3,
        StatusCheck_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called HashAll.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzHashAll(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_TCG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTcgProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 * HashAll_Arg_1 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT64 HashAll_Arg_2 = 0;
    TCG_ALGORITHM_ID HashAll_Arg_3 = 0;
    UINT64 * HashAll_Arg_4 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    UINT8 * * HashAll_Arg_5 = (UINT8 * *)AllocateZeroPool(sizeof(UINT8));
    
    // Fuzzable Variable Initialization
    UINT8 HashAll_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(HashAll_Arg_1_choice), (VOID *)&HashAll_Arg_1_choice);
    switch(HashAll_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(HashAll_Arg_1), (VOID *)HashAll_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(HashAll_Arg_1);
            HashAll_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(HashAll_Arg_2), (VOID *)&HashAll_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(HashAll_Arg_3), (VOID *)&HashAll_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 HashAll_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(HashAll_Arg_4_choice), (VOID *)&HashAll_Arg_4_choice);
    switch(HashAll_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(HashAll_Arg_4), (VOID *)HashAll_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(HashAll_Arg_4);
            HashAll_Arg_4 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 HashAll_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(HashAll_Arg_5_choice), (VOID *)&HashAll_Arg_5_choice);
    switch(HashAll_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(HashAll_Arg_5), (VOID *)HashAll_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(HashAll_Arg_5);
            HashAll_Arg_5 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->HashAll(
        ProtocolVariable,
        HashAll_Arg_1,
        HashAll_Arg_2,
        HashAll_Arg_3,
        HashAll_Arg_4,
        &HashAll_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called LogEvent.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzLogEvent(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_TCG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTcgProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    TCG_PCR_EVENT * LogEvent_Arg_1 = (TCG_PCR_EVENT *)AllocateZeroPool(sizeof(TCG_PCR_EVENT));
    UINT32 * LogEvent_Arg_2 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT32 LogEvent_Arg_3 = 0;
    
    // Generator Struct Variable Initialization
    {
        TCG_PCRINDEX Firness_PCRIndex;
        ReadBytes(Input, sizeof(Firness_PCRIndex), (VOID *)&Firness_PCRIndex);
        LogEvent_Arg_1->PCRIndex = Firness_PCRIndex;
    }
    {
        TCG_EVENTTYPE Firness_EventType;
        ReadBytes(Input, sizeof(Firness_EventType), (VOID *)&Firness_EventType);
        LogEvent_Arg_1->EventType = Firness_EventType;
    }
    {
        TCG_DIGEST Firness_Digest;
        ReadBytes(Input, sizeof(Firness_Digest), (VOID *)&Firness_Digest);
        LogEvent_Arg_1->Digest = Firness_Digest;
    }
    {
        UINT32 Firness_EventSize;
        ReadBytes(Input, sizeof(Firness_EventSize), (VOID *)&Firness_EventSize);
        LogEvent_Arg_1->EventSize = Firness_EventSize;
    }
    ReadBytes(Input, sizeof(LogEvent_Arg_1->Event), (VOID *)&(LogEvent_Arg_1->Event));
    
    // Fuzzable Variable Initialization
    UINT8 LogEvent_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(LogEvent_Arg_2_choice), (VOID *)&LogEvent_Arg_2_choice);
    switch(LogEvent_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(LogEvent_Arg_2), (VOID *)LogEvent_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(LogEvent_Arg_2);
            LogEvent_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(LogEvent_Arg_3), (VOID *)&LogEvent_Arg_3);
    
    Status = ProtocolVariable->LogEvent(
        ProtocolVariable,
        LogEvent_Arg_1,
        LogEvent_Arg_2,
        LogEvent_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called PassThroughToTpm.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzPassThroughToTpm(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_TCG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTcgProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 PassThroughToTpm_Arg_1 = 0;
    UINT8 * PassThroughToTpm_Arg_2 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT32 PassThroughToTpm_Arg_3 = 0;
    UINT8 * PassThroughToTpm_Arg_4 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PassThroughToTpm_Arg_1), (VOID *)&PassThroughToTpm_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 PassThroughToTpm_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(PassThroughToTpm_Arg_2_choice), (VOID *)&PassThroughToTpm_Arg_2_choice);
    switch(PassThroughToTpm_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(PassThroughToTpm_Arg_2), (VOID *)PassThroughToTpm_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(PassThroughToTpm_Arg_2);
            PassThroughToTpm_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PassThroughToTpm_Arg_3), (VOID *)&PassThroughToTpm_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 PassThroughToTpm_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(PassThroughToTpm_Arg_4_choice), (VOID *)&PassThroughToTpm_Arg_4_choice);
    switch(PassThroughToTpm_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(PassThroughToTpm_Arg_4), (VOID *)PassThroughToTpm_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(PassThroughToTpm_Arg_4);
            PassThroughToTpm_Arg_4 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->PassThroughToTpm(
        ProtocolVariable,
        PassThroughToTpm_Arg_1,
        PassThroughToTpm_Arg_2,
        PassThroughToTpm_Arg_3,
        PassThroughToTpm_Arg_4
    );
    return Status;
}

