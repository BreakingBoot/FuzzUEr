#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called GetUfsHcMmioBar.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetUfsHcMmioBar(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_UFS_HOST_CONTROLLER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiUfsHostControllerProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINTN * GetUfsHcMmioBar_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetUfsHcMmioBar_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetUfsHcMmioBar_Arg_1_OutputChoice), (VOID *)GetUfsHcMmioBar_Arg_1_OutputChoice);
    if(*GetUfsHcMmioBar_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetUfsHcMmioBar_Arg_1), (VOID *)GetUfsHcMmioBar_Arg_1);
    }
    Status = ProtocolVariable->GetUfsHcMmioBar(
        ProtocolVariable,
        GetUfsHcMmioBar_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called AllocateBuffer.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAllocateBuffer(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_UFS_HOST_CONTROLLER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiUfsHostControllerProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN AllocateBuffer_Arg_3 = 0;
    UINT64 AllocateBuffer_Arg_5 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AllocateBuffer_Arg_3), (VOID *)&AllocateBuffer_Arg_3);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AllocateBuffer_Arg_5), (VOID *)&AllocateBuffer_Arg_5);
    
    /*
        Output Variable(s)
    */
    UINTN* AllocateBuffer_Arg_4 = (UINTN*)AllocateZeroPool(sizeof(UINTN));
    UINT8* AllocateBuffer_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(AllocateBuffer_Arg_4_OutputChoice), (VOID *)AllocateBuffer_Arg_4_OutputChoice);
    if(*AllocateBuffer_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*AllocateBuffer_Arg_4), (VOID *)AllocateBuffer_Arg_4);
    }
    Status = ProtocolVariable->AllocateBuffer(
        ProtocolVariable,
        (EFI_ALLOCATE_TYPE){0},
        (EFI_MEMORY_TYPE){0},
        AllocateBuffer_Arg_3,
        (VOID * *)&AllocateBuffer_Arg_4,
        AllocateBuffer_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called FreeBuffer.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFreeBuffer(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_UFS_HOST_CONTROLLER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiUfsHostControllerProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN FreeBuffer_Arg_1 = 0;
    UINTN*  FreeBuffer_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(FreeBuffer_Arg_1), (VOID *)&FreeBuffer_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 FreeBuffer_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(FreeBuffer_Arg_2_choice), (VOID *)&FreeBuffer_Arg_2_choice);
    switch(FreeBuffer_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(FreeBuffer_Arg_2), (VOID *)FreeBuffer_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(FreeBuffer_Arg_2);
            FreeBuffer_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->FreeBuffer(
        ProtocolVariable,
        FreeBuffer_Arg_1,
        (VOID *)FreeBuffer_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Map.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzMap(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_UFS_HOST_CONTROLLER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiUfsHostControllerProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  Map_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN * Map_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    UINT8 Map_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(Map_Arg_2_choice), (VOID *)&Map_Arg_2_choice);
    switch(Map_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Map_Arg_2), (VOID *)Map_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(Map_Arg_2);
            Map_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 Map_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(Map_Arg_3_choice), (VOID *)&Map_Arg_3_choice);
    switch(Map_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Map_Arg_3), (VOID *)Map_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(Map_Arg_3);
            Map_Arg_3 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_PHYSICAL_ADDRESS * Map_Arg_4 = (EFI_PHYSICAL_ADDRESS *)AllocateZeroPool(sizeof(EFI_PHYSICAL_ADDRESS));
    UINT8* Map_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Map_Arg_4_OutputChoice), (VOID *)Map_Arg_4_OutputChoice);
    if(*Map_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Map_Arg_4), (VOID *)Map_Arg_4);
    }
    UINTN* Map_Arg_5 = (UINTN*)AllocateZeroPool(sizeof(UINTN));
    UINT8* Map_Arg_5_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Map_Arg_5_OutputChoice), (VOID *)Map_Arg_5_OutputChoice);
    if(*Map_Arg_5_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Map_Arg_5), (VOID *)Map_Arg_5);
    }
    Status = ProtocolVariable->Map(
        ProtocolVariable,
        (EDKII_UFS_HOST_CONTROLLER_OPERATION){0},
        (VOID *)Map_Arg_2,
        Map_Arg_3,
        Map_Arg_4,
        (VOID * *)&Map_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Unmap.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUnmap(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_UFS_HOST_CONTROLLER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiUfsHostControllerProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  Unmap_Arg_1 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    UINT8 Unmap_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(Unmap_Arg_1_choice), (VOID *)&Unmap_Arg_1_choice);
    switch(Unmap_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Unmap_Arg_1), (VOID *)Unmap_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(Unmap_Arg_1);
            Unmap_Arg_1 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->Unmap(
        ProtocolVariable,
        (VOID *)Unmap_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Flush.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFlush(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_UFS_HOST_CONTROLLER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiUfsHostControllerProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Flush(
        ProtocolVariable
    );
    return Status;
}

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
    EDKII_UFS_HOST_CONTROLLER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiUfsHostControllerProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT64 Read_Arg_2 = 0;
    UINTN Read_Arg_3 = 0;
    UINTN*  Read_Arg_4 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Read_Arg_2), (VOID *)&Read_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Read_Arg_3), (VOID *)&Read_Arg_3);
    
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
        (EDKII_UFS_HOST_CONTROLLER_PROTOCOL_WIDTH){0},
        Read_Arg_2,
        Read_Arg_3,
        (VOID *)Read_Arg_4
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
    EDKII_UFS_HOST_CONTROLLER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiUfsHostControllerProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT64 Write_Arg_2 = 0;
    UINTN Write_Arg_3 = 0;
    UINTN*  Write_Arg_4 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Write_Arg_2), (VOID *)&Write_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Write_Arg_3), (VOID *)&Write_Arg_3);
    
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
        (EDKII_UFS_HOST_CONTROLLER_PROTOCOL_WIDTH){0},
        Write_Arg_2,
        Write_Arg_3,
        (VOID *)Write_Arg_4
    );
    return Status;
}

