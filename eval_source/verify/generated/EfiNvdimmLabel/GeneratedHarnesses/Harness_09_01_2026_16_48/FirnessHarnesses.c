#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called LabelStorageInformation.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzLabelStorageInformation(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_NVDIMM_LABEL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiNvdimmLabelProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINT32 * LabelStorageInformation_Arg_1 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT8* LabelStorageInformation_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(LabelStorageInformation_Arg_1_OutputChoice), (VOID *)LabelStorageInformation_Arg_1_OutputChoice);
    if(*LabelStorageInformation_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*LabelStorageInformation_Arg_1), (VOID *)LabelStorageInformation_Arg_1);
    }
    UINT32 * LabelStorageInformation_Arg_2 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT8* LabelStorageInformation_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(LabelStorageInformation_Arg_2_OutputChoice), (VOID *)LabelStorageInformation_Arg_2_OutputChoice);
    if(*LabelStorageInformation_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*LabelStorageInformation_Arg_2), (VOID *)LabelStorageInformation_Arg_2);
    }
    Status = ProtocolVariable->LabelStorageInformation(
        ProtocolVariable,
        LabelStorageInformation_Arg_1,
        LabelStorageInformation_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called LabelStorageRead.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzLabelStorageRead(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_NVDIMM_LABEL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiNvdimmLabelProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 LabelStorageRead_Arg_1 = 0;
    UINT32 LabelStorageRead_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(LabelStorageRead_Arg_1), (VOID *)&LabelStorageRead_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(LabelStorageRead_Arg_2), (VOID *)&LabelStorageRead_Arg_2);
    
    /*
        Output Variable(s)
    */
    UINT8 * LabelStorageRead_Arg_3 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT8* LabelStorageRead_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(LabelStorageRead_Arg_3_OutputChoice), (VOID *)LabelStorageRead_Arg_3_OutputChoice);
    if(*LabelStorageRead_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*LabelStorageRead_Arg_3), (VOID *)LabelStorageRead_Arg_3);
    }
    Status = ProtocolVariable->LabelStorageRead(
        ProtocolVariable,
        LabelStorageRead_Arg_1,
        LabelStorageRead_Arg_2,
        LabelStorageRead_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called LabelStorageWrite.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzLabelStorageWrite(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_NVDIMM_LABEL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiNvdimmLabelProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 LabelStorageWrite_Arg_1 = 0;
    UINT32 LabelStorageWrite_Arg_2 = 0;
    UINT8 * LabelStorageWrite_Arg_3 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(LabelStorageWrite_Arg_1), (VOID *)&LabelStorageWrite_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(LabelStorageWrite_Arg_2), (VOID *)&LabelStorageWrite_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 LabelStorageWrite_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(LabelStorageWrite_Arg_3_choice), (VOID *)&LabelStorageWrite_Arg_3_choice);
    switch(LabelStorageWrite_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(LabelStorageWrite_Arg_3), (VOID *)LabelStorageWrite_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(LabelStorageWrite_Arg_3);
            LabelStorageWrite_Arg_3 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->LabelStorageWrite(
        ProtocolVariable,
        LabelStorageWrite_Arg_1,
        LabelStorageWrite_Arg_2,
        LabelStorageWrite_Arg_3
    );
    return Status;
}

