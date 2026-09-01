#include "FirnessHarnesses.h"

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
    EFI_FAULT_TOLERANT_WRITE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFaultTolerantWriteProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_LBA Write_Arg_1 = 0;
    UINTN Write_Arg_2 = 0;
    UINTN Write_Arg_3 = 0;
    UINTN*  Write_Arg_4 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN*  Write_Arg_6 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Write_Arg_1), (VOID *)&Write_Arg_1);
    
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
    
    // Fuzzable Variable Initialization
    UINT8 Write_Arg_6_choice = 0;
    ReadBytes(Input, sizeof(Write_Arg_6_choice), (VOID *)&Write_Arg_6_choice);
    switch(Write_Arg_6_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Write_Arg_6), (VOID *)Write_Arg_6);
            break;
        case 1:
        {
            gBS->FreePool(Write_Arg_6);
            Write_Arg_6 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->Write(
        ProtocolVariable,
        Write_Arg_1,
        Write_Arg_2,
        Write_Arg_3,
        (void *)Write_Arg_4,
        ImageHandle,
        (void *)Write_Arg_6
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetMaxBlockSize.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetMaxBlockSize(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FAULT_TOLERANT_WRITE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFaultTolerantWriteProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINTN * GetMaxBlockSize_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetMaxBlockSize_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetMaxBlockSize_Arg_1_OutputChoice), (VOID *)GetMaxBlockSize_Arg_1_OutputChoice);
    if(*GetMaxBlockSize_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetMaxBlockSize_Arg_1), (VOID *)GetMaxBlockSize_Arg_1);
    }
    Status = ProtocolVariable->GetMaxBlockSize(
        ProtocolVariable,
        GetMaxBlockSize_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Allocate.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAllocate(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FAULT_TOLERANT_WRITE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFaultTolerantWriteProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * Allocate_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINTN Allocate_Arg_2 = 0;
    UINTN Allocate_Arg_3 = 0;
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        Allocate_Arg_1->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        Allocate_Arg_1->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        Allocate_Arg_1->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(Allocate_Arg_1->Data4), (VOID *)&(Allocate_Arg_1->Data4));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Allocate_Arg_2), (VOID *)&Allocate_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Allocate_Arg_3), (VOID *)&Allocate_Arg_3);
    
    Status = ProtocolVariable->Allocate(
        ProtocolVariable,
        Allocate_Arg_1,
        Allocate_Arg_2,
        Allocate_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Restart.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRestart(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FAULT_TOLERANT_WRITE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFaultTolerantWriteProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Restart(
        ProtocolVariable,
        ImageHandle
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Abort.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAbort(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FAULT_TOLERANT_WRITE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFaultTolerantWriteProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Abort(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetLastWrite.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetLastWrite(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FAULT_TOLERANT_WRITE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFaultTolerantWriteProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * GetLastWrite_Arg_5 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    UINT8 GetLastWrite_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(GetLastWrite_Arg_5_choice), (VOID *)&GetLastWrite_Arg_5_choice);
    switch(GetLastWrite_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetLastWrite_Arg_5), (VOID *)GetLastWrite_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(GetLastWrite_Arg_5);
            GetLastWrite_Arg_5 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_GUID * GetLastWrite_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINT8* GetLastWrite_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetLastWrite_Arg_1_OutputChoice), (VOID *)GetLastWrite_Arg_1_OutputChoice);
    if(*GetLastWrite_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetLastWrite_Arg_1), (VOID *)GetLastWrite_Arg_1);
    }
    EFI_LBA * GetLastWrite_Arg_2 = (EFI_LBA *)AllocateZeroPool(sizeof(EFI_LBA));
    UINT8* GetLastWrite_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetLastWrite_Arg_2_OutputChoice), (VOID *)GetLastWrite_Arg_2_OutputChoice);
    if(*GetLastWrite_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetLastWrite_Arg_2), (VOID *)GetLastWrite_Arg_2);
    }
    UINTN * GetLastWrite_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetLastWrite_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetLastWrite_Arg_3_OutputChoice), (VOID *)GetLastWrite_Arg_3_OutputChoice);
    if(*GetLastWrite_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetLastWrite_Arg_3), (VOID *)GetLastWrite_Arg_3);
    }
    UINTN * GetLastWrite_Arg_4 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetLastWrite_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetLastWrite_Arg_4_OutputChoice), (VOID *)GetLastWrite_Arg_4_OutputChoice);
    if(*GetLastWrite_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetLastWrite_Arg_4), (VOID *)GetLastWrite_Arg_4);
    }
    UINTN*  GetLastWrite_Arg_6 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT8* GetLastWrite_Arg_6_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetLastWrite_Arg_6_OutputChoice), (VOID *)GetLastWrite_Arg_6_OutputChoice);
    if(*GetLastWrite_Arg_6_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetLastWrite_Arg_6), (VOID *)GetLastWrite_Arg_6);
    }
    BOOLEAN * GetLastWrite_Arg_7 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
    UINT8* GetLastWrite_Arg_7_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetLastWrite_Arg_7_OutputChoice), (VOID *)GetLastWrite_Arg_7_OutputChoice);
    if(*GetLastWrite_Arg_7_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetLastWrite_Arg_7), (VOID *)GetLastWrite_Arg_7);
    }
    Status = ProtocolVariable->GetLastWrite(
        ProtocolVariable,
        GetLastWrite_Arg_1,
        GetLastWrite_Arg_2,
        GetLastWrite_Arg_3,
        GetLastWrite_Arg_4,
        GetLastWrite_Arg_5,
        (void *)GetLastWrite_Arg_6,
        GetLastWrite_Arg_7
    );
    return Status;
}

