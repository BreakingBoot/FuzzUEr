#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called Read.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRead(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFirmwareVolumeBlockProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_LBA Read_Arg_1 = 0;
    UINTN Read_Arg_2 = 0;
    UINTN * Read_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8 * Read_Arg_4 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    
    UINT8* Read_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Read_Arg_1_choice), (VOID *)Read_Arg_1_choice);
    switch(*Read_Arg_1_choice % 6) {
        case 0:
        {
        // Constant Variable Initialization
        Read_Arg_1 = 0;
    
            break;
        }
        case 1:
        {
        // Constant Variable Initialization
        Read_Arg_1 = 0;
    
            break;
        }
        case 2:
        {
        // Constant Variable Initialization
        Read_Arg_1 = 0;
    
            break;
        }
        case 3:
        {
        // Constant Variable Initialization
        Read_Arg_1 = 0;
    
            break;
        }
        case 4:
        {
        // Constant Variable Initialization
        Read_Arg_1 = 0;
    
            break;
        }
        case 5:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(Read_Arg_1), (VOID *)&Read_Arg_1);
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Read_Arg_2), (VOID *)&Read_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 Read_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(Read_Arg_3_choice), (VOID *)&Read_Arg_3_choice);
    switch(Read_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Read_Arg_3), (VOID *)Read_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(Read_Arg_3);
            Read_Arg_3 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 Read_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(Read_Arg_4_choice), (VOID *)&Read_Arg_4_choice);
    switch(Read_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Read_Arg_4), (VOID *)Read_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(Read_Arg_4);
            Read_Arg_4 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->Read(
        ProtocolVariable,
        Read_Arg_1,
        Read_Arg_2,
        Read_Arg_3,
        Read_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetBlockSize.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetBlockSize(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFirmwareVolumeBlockProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_LBA GetBlockSize_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetBlockSize_Arg_1), (VOID *)&GetBlockSize_Arg_1);
    
    /*
        Output Variable(s)
    */
    UINTN * GetBlockSize_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetBlockSize_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetBlockSize_Arg_2_OutputChoice), (VOID *)GetBlockSize_Arg_2_OutputChoice);
    if(*GetBlockSize_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetBlockSize_Arg_2), (VOID *)GetBlockSize_Arg_2);
    }
    UINTN * GetBlockSize_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetBlockSize_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetBlockSize_Arg_3_OutputChoice), (VOID *)GetBlockSize_Arg_3_OutputChoice);
    if(*GetBlockSize_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetBlockSize_Arg_3), (VOID *)GetBlockSize_Arg_3);
    }
    Status = ProtocolVariable->GetBlockSize(
        ProtocolVariable,
        GetBlockSize_Arg_1,
        GetBlockSize_Arg_2,
        GetBlockSize_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetAttributes.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetAttributes(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFirmwareVolumeBlockProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_FVB_ATTRIBUTES_2 * GetAttributes_Arg_1 = (EFI_FVB_ATTRIBUTES_2 *)AllocateZeroPool(sizeof(EFI_FVB_ATTRIBUTES_2));
    UINT8* GetAttributes_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetAttributes_Arg_1_OutputChoice), (VOID *)GetAttributes_Arg_1_OutputChoice);
    if(*GetAttributes_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetAttributes_Arg_1), (VOID *)GetAttributes_Arg_1);
    }
    Status = ProtocolVariable->GetAttributes(
        ProtocolVariable,
        GetAttributes_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetPhysicalAddress.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetPhysicalAddress(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFirmwareVolumeBlockProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_PHYSICAL_ADDRESS * GetPhysicalAddress_Arg_1 = (EFI_PHYSICAL_ADDRESS *)AllocateZeroPool(sizeof(EFI_PHYSICAL_ADDRESS));
    UINT8* GetPhysicalAddress_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetPhysicalAddress_Arg_1_OutputChoice), (VOID *)GetPhysicalAddress_Arg_1_OutputChoice);
    if(*GetPhysicalAddress_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetPhysicalAddress_Arg_1), (VOID *)GetPhysicalAddress_Arg_1);
    }
    Status = ProtocolVariable->GetPhysicalAddress(
        ProtocolVariable,
        GetPhysicalAddress_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called EraseBlocks.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzEraseBlocks(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFirmwareVolumeBlockProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_LBA EraseBlocks_Arg_1 = 0;
    UINTN EraseBlocks_Arg_2 = 0;
    UINT64 EraseBlocks_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(EraseBlocks_Arg_1), (VOID *)&EraseBlocks_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(EraseBlocks_Arg_2), (VOID *)&EraseBlocks_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(EraseBlocks_Arg_3), (VOID *)&EraseBlocks_Arg_3);
    
    Status = ProtocolVariable->EraseBlocks(
        ProtocolVariable,
        EraseBlocks_Arg_1,
        EraseBlocks_Arg_2,
        EraseBlocks_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Write.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzWrite(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFirmwareVolumeBlockProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT64 Write_Arg_1 = 0;
    UINTN Write_Arg_2 = 0;
    UINTN * Write_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8 * Write_Arg_4 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    
    UINT8* Write_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Write_Arg_1_choice), (VOID *)Write_Arg_1_choice);
    switch(*Write_Arg_1_choice % 4) {
        case 0:
        {
        // Constant Variable Initialization
        Write_Arg_1 = 0;
    
            break;
        }
        case 1:
        {
        // Constant Variable Initialization
        Write_Arg_1 = 0;
    
            break;
        }
        case 2:
        {
        // Constant Variable Initialization
        Write_Arg_1 = 0;
    
            break;
        }
        case 3:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(Write_Arg_1), (VOID *)&Write_Arg_1);
    
            break;
        }
    }
    UINT8* Write_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Write_Arg_2_choice), (VOID *)Write_Arg_2_choice);
    switch(*Write_Arg_2_choice % 2) {
        case 0:
        {
        // Constant Variable Initialization
        Write_Arg_2 = 0;
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(Write_Arg_2), (VOID *)&Write_Arg_2);
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 Write_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(Write_Arg_3_choice), (VOID *)&Write_Arg_3_choice);
    switch(Write_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Write_Arg_3), (VOID *)Write_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(Write_Arg_3);
            Write_Arg_3 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 Write_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(Write_Arg_4_choice), (VOID *)&Write_Arg_4_choice);
    switch(Write_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Write_Arg_4), (VOID *)Write_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(Write_Arg_4);
            Write_Arg_4 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->Write(
        ProtocolVariable,
        Write_Arg_1,
        Write_Arg_2,
        Write_Arg_3,
        Write_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetAttributes.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetAttributes(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFirmwareVolumeBlockProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_FVB_ATTRIBUTES_2 * SetAttributes_Arg_1 = (EFI_FVB_ATTRIBUTES_2 *)AllocateZeroPool(sizeof(EFI_FVB_ATTRIBUTES_2));
    
    // Fuzzable Variable Initialization
    UINT8 SetAttributes_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(SetAttributes_Arg_1_choice), (VOID *)&SetAttributes_Arg_1_choice);
    switch(SetAttributes_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetAttributes_Arg_1), (VOID *)SetAttributes_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(SetAttributes_Arg_1);
            SetAttributes_Arg_1 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->SetAttributes(
        NULL,
        SetAttributes_Arg_1
    );
    return Status;
}

