#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called GetFlashid.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetFlashid(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SPI_NOR_FLASH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSpiNorFlashProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINT8 * GetFlashid_Arg_1 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT8* GetFlashid_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetFlashid_Arg_1_OutputChoice), (VOID *)GetFlashid_Arg_1_OutputChoice);
    if(*GetFlashid_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetFlashid_Arg_1), (VOID *)GetFlashid_Arg_1);
    }
    Status = ProtocolVariable->GetFlashid(
        ProtocolVariable,
        GetFlashid_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ReadData.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzReadData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SPI_NOR_FLASH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSpiNorFlashProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 ReadData_Arg_1 = 0;
    UINT32 ReadData_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ReadData_Arg_1), (VOID *)&ReadData_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ReadData_Arg_2), (VOID *)&ReadData_Arg_2);
    
    /*
        Output Variable(s)
    */
    UINT8 * ReadData_Arg_3 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT8* ReadData_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ReadData_Arg_3_OutputChoice), (VOID *)ReadData_Arg_3_OutputChoice);
    if(*ReadData_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ReadData_Arg_3), (VOID *)ReadData_Arg_3);
    }
    Status = ProtocolVariable->ReadData(
        ProtocolVariable,
        ReadData_Arg_1,
        ReadData_Arg_2,
        ReadData_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called LfReadData.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzLfReadData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SPI_NOR_FLASH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSpiNorFlashProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 LfReadData_Arg_1 = 0;
    UINT32 LfReadData_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(LfReadData_Arg_1), (VOID *)&LfReadData_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(LfReadData_Arg_2), (VOID *)&LfReadData_Arg_2);
    
    /*
        Output Variable(s)
    */
    UINT8 * LfReadData_Arg_3 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT8* LfReadData_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(LfReadData_Arg_3_OutputChoice), (VOID *)LfReadData_Arg_3_OutputChoice);
    if(*LfReadData_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*LfReadData_Arg_3), (VOID *)LfReadData_Arg_3);
    }
    Status = ProtocolVariable->LfReadData(
        ProtocolVariable,
        LfReadData_Arg_1,
        LfReadData_Arg_2,
        LfReadData_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ReadStatus.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzReadStatus(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SPI_NOR_FLASH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSpiNorFlashProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 ReadStatus_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ReadStatus_Arg_1), (VOID *)&ReadStatus_Arg_1);
    
    /*
        Output Variable(s)
    */
    UINT8 * ReadStatus_Arg_2 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT8* ReadStatus_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ReadStatus_Arg_2_OutputChoice), (VOID *)ReadStatus_Arg_2_OutputChoice);
    if(*ReadStatus_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ReadStatus_Arg_2), (VOID *)ReadStatus_Arg_2);
    }
    Status = ProtocolVariable->ReadStatus(
        ProtocolVariable,
        ReadStatus_Arg_1,
        ReadStatus_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called WriteStatus.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzWriteStatus(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SPI_NOR_FLASH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSpiNorFlashProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 WriteStatus_Arg_1 = 0;
    UINT8 * WriteStatus_Arg_2 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(WriteStatus_Arg_1), (VOID *)&WriteStatus_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 WriteStatus_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(WriteStatus_Arg_2_choice), (VOID *)&WriteStatus_Arg_2_choice);
    switch(WriteStatus_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(WriteStatus_Arg_2), (VOID *)WriteStatus_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(WriteStatus_Arg_2);
            WriteStatus_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->WriteStatus(
        ProtocolVariable,
        WriteStatus_Arg_1,
        WriteStatus_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called WriteData.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzWriteData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SPI_NOR_FLASH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSpiNorFlashProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 WriteData_Arg_1 = 0;
    UINT32 WriteData_Arg_2 = 0;
    UINT8 * WriteData_Arg_3 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(WriteData_Arg_1), (VOID *)&WriteData_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(WriteData_Arg_2), (VOID *)&WriteData_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 WriteData_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(WriteData_Arg_3_choice), (VOID *)&WriteData_Arg_3_choice);
    switch(WriteData_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(WriteData_Arg_3), (VOID *)WriteData_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(WriteData_Arg_3);
            WriteData_Arg_3 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->WriteData(
        ProtocolVariable,
        WriteData_Arg_1,
        WriteData_Arg_2,
        WriteData_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Erase.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzErase(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SPI_NOR_FLASH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSpiNorFlashProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 Erase_Arg_1 = 0;
    UINT32 Erase_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Erase_Arg_1), (VOID *)&Erase_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Erase_Arg_2), (VOID *)&Erase_Arg_2);
    
    Status = ProtocolVariable->Erase(
        ProtocolVariable,
        Erase_Arg_1,
        Erase_Arg_2
    );
    return Status;
}

