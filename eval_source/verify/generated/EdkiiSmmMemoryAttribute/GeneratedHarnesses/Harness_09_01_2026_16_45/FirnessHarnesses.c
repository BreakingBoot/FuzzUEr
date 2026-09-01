#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called SetMemoryAttributes.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetMemoryAttributes(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_SMM_MEMORY_ATTRIBUTE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiSmmMemoryAttributeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PHYSICAL_ADDRESS SetMemoryAttributes_Arg_1 = 0;
    UINT64 SetMemoryAttributes_Arg_2 = 0;
    UINT64 SetMemoryAttributes_Arg_3 = 0;
    
    UINT8* SetMemoryAttributes_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SetMemoryAttributes_Arg_1_choice), (VOID *)SetMemoryAttributes_Arg_1_choice);
    switch(*SetMemoryAttributes_Arg_1_choice % 4) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(SetMemoryAttributes_Arg_1), (VOID *)&SetMemoryAttributes_Arg_1);
    
            break;
        }
        case 1:
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
                &SetMemoryAttributes_Arg_1,
                GetVariableFlashFtwWorkingInfo_Arg_1
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
                &SetMemoryAttributes_Arg_1,
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
            UINT64 * GetVariableFlashNvStorageInfo_Arg_1 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
            UINT8* GetVariableFlashNvStorageInfo_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(GetVariableFlashNvStorageInfo_Arg_1_OutputChoice), (VOID *)GetVariableFlashNvStorageInfo_Arg_1_OutputChoice);
            if(*GetVariableFlashNvStorageInfo_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*GetVariableFlashNvStorageInfo_Arg_1), (VOID *)GetVariableFlashNvStorageInfo_Arg_1);
            }
            Status = GetVariableFlashNvStorageInfo(
                &SetMemoryAttributes_Arg_1,
                GetVariableFlashNvStorageInfo_Arg_1
            );
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetMemoryAttributes_Arg_2), (VOID *)&SetMemoryAttributes_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetMemoryAttributes_Arg_3), (VOID *)&SetMemoryAttributes_Arg_3);
    
    Status = ProtocolVariable->SetMemoryAttributes(
        ProtocolVariable,
        SetMemoryAttributes_Arg_1,
        SetMemoryAttributes_Arg_2,
        SetMemoryAttributes_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ClearMemoryAttributes.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzClearMemoryAttributes(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_SMM_MEMORY_ATTRIBUTE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiSmmMemoryAttributeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PHYSICAL_ADDRESS ClearMemoryAttributes_Arg_1 = 0;
    UINT64 ClearMemoryAttributes_Arg_2 = 0;
    UINT64 ClearMemoryAttributes_Arg_3 = 0;
    
    UINT8* ClearMemoryAttributes_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ClearMemoryAttributes_Arg_1_choice), (VOID *)ClearMemoryAttributes_Arg_1_choice);
    switch(*ClearMemoryAttributes_Arg_1_choice % 4) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(ClearMemoryAttributes_Arg_1), (VOID *)&ClearMemoryAttributes_Arg_1);
    
            break;
        }
        case 1:
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
                &ClearMemoryAttributes_Arg_1,
                GetVariableFlashFtwWorkingInfo_Arg_1
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
                &ClearMemoryAttributes_Arg_1,
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
            UINT64 * GetVariableFlashNvStorageInfo_Arg_1 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
            UINT8* GetVariableFlashNvStorageInfo_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(GetVariableFlashNvStorageInfo_Arg_1_OutputChoice), (VOID *)GetVariableFlashNvStorageInfo_Arg_1_OutputChoice);
            if(*GetVariableFlashNvStorageInfo_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*GetVariableFlashNvStorageInfo_Arg_1), (VOID *)GetVariableFlashNvStorageInfo_Arg_1);
            }
            Status = GetVariableFlashNvStorageInfo(
                &ClearMemoryAttributes_Arg_1,
                GetVariableFlashNvStorageInfo_Arg_1
            );
    
            break;
        }
    }
    UINT8* ClearMemoryAttributes_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ClearMemoryAttributes_Arg_2_choice), (VOID *)ClearMemoryAttributes_Arg_2_choice);
    switch(*ClearMemoryAttributes_Arg_2_choice % 2) {
        case 0:
        {
        // Constant Variable Initialization
        ClearMemoryAttributes_Arg_2 = 0;
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(ClearMemoryAttributes_Arg_2), (VOID *)&ClearMemoryAttributes_Arg_2);
    
            break;
        }
    }
    UINT8* ClearMemoryAttributes_Arg_3_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ClearMemoryAttributes_Arg_3_choice), (VOID *)ClearMemoryAttributes_Arg_3_choice);
    switch(*ClearMemoryAttributes_Arg_3_choice % 2) {
        case 0:
        {
        // Constant Variable Initialization
        ClearMemoryAttributes_Arg_3 = EFI_MEMORY_RO;
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(ClearMemoryAttributes_Arg_3), (VOID *)&ClearMemoryAttributes_Arg_3);
    
            break;
        }
    }
    Status = ProtocolVariable->ClearMemoryAttributes(
        ProtocolVariable,
        ClearMemoryAttributes_Arg_1,
        ClearMemoryAttributes_Arg_2,
        ClearMemoryAttributes_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetMemoryAttributes.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetMemoryAttributes(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_SMM_MEMORY_ATTRIBUTE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiSmmMemoryAttributeProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PHYSICAL_ADDRESS GetMemoryAttributes_Arg_1 = 0;
    UINTN GetMemoryAttributes_Arg_2 = 0;
    
    UINT8* GetMemoryAttributes_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetMemoryAttributes_Arg_1_choice), (VOID *)GetMemoryAttributes_Arg_1_choice);
    switch(*GetMemoryAttributes_Arg_1_choice % 4) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(GetMemoryAttributes_Arg_1), (VOID *)&GetMemoryAttributes_Arg_1);
    
            break;
        }
        case 1:
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
                &GetMemoryAttributes_Arg_1,
                GetVariableFlashFtwWorkingInfo_Arg_1
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
                &GetMemoryAttributes_Arg_1,
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
            UINT64 * GetVariableFlashNvStorageInfo_Arg_1 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
            UINT8* GetVariableFlashNvStorageInfo_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(GetVariableFlashNvStorageInfo_Arg_1_OutputChoice), (VOID *)GetVariableFlashNvStorageInfo_Arg_1_OutputChoice);
            if(*GetVariableFlashNvStorageInfo_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*GetVariableFlashNvStorageInfo_Arg_1), (VOID *)GetVariableFlashNvStorageInfo_Arg_1);
            }
            Status = GetVariableFlashNvStorageInfo(
                &GetMemoryAttributes_Arg_1,
                GetVariableFlashNvStorageInfo_Arg_1
            );
    
            break;
        }
    }
    UINT8* GetMemoryAttributes_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetMemoryAttributes_Arg_2_choice), (VOID *)GetMemoryAttributes_Arg_2_choice);
    switch(*GetMemoryAttributes_Arg_2_choice % 2) {
        case 0:
        {
        // Constant Variable Initialization
        GetMemoryAttributes_Arg_2 = NVME_ASQ_BUF_OFFSET;
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(GetMemoryAttributes_Arg_2), (VOID *)&GetMemoryAttributes_Arg_2);
    
            break;
        }
    }
    /*
        Output Variable(s)
    */
    UINT64 * GetMemoryAttributes_Arg_3 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    UINT8* GetMemoryAttributes_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetMemoryAttributes_Arg_3_OutputChoice), (VOID *)GetMemoryAttributes_Arg_3_OutputChoice);
    if(*GetMemoryAttributes_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetMemoryAttributes_Arg_3), (VOID *)GetMemoryAttributes_Arg_3);
    }
    Status = ProtocolVariable->GetMemoryAttributes(
        ProtocolVariable,
        GetMemoryAttributes_Arg_1,
        GetMemoryAttributes_Arg_2,
        GetMemoryAttributes_Arg_3
    );
    return Status;
}

