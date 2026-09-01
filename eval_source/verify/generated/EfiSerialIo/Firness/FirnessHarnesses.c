#include "FirnessHarnesses.h"

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
    EFI_SERIAL_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSerialIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT64 SetAttributes_Arg_1 = 0;
    UINT32 SetAttributes_Arg_2 = 0;
    UINT32 SetAttributes_Arg_3 = 0;
    EFI_PARITY_TYPE SetAttributes_Arg_4 = 0;
    UINT8 SetAttributes_Arg_5 = 0;
    EFI_STOP_BITS_TYPE SetAttributes_Arg_6 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetAttributes_Arg_1), (VOID *)&SetAttributes_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetAttributes_Arg_2), (VOID *)&SetAttributes_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetAttributes_Arg_3), (VOID *)&SetAttributes_Arg_3);
    
    // Constant Variable Initialization
    UINT8* SetAttributes_Arg_4_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SetAttributes_Arg_4_choice), (VOID *)SetAttributes_Arg_4_choice);
    switch(*SetAttributes_Arg_4_choice % 7) {
        case 0:
            SetAttributes_Arg_4 = DefaultParity;
            break;
        case 1:
            SetAttributes_Arg_4 = EvenParity;
            break;
        case 2:
            SetAttributes_Arg_4 = MarkParity;
            break;
        case 3:
            SetAttributes_Arg_4 = NoParity;
            break;
        case 4:
            SetAttributes_Arg_4 = OddParity;
            break;
        case 5:
            SetAttributes_Arg_4 = SpaceParity;
            break;
        case 6:
            ReadBytes(Input, sizeof(SetAttributes_Arg_4), (VOID *)&SetAttributes_Arg_4);
            break;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetAttributes_Arg_5), (VOID *)&SetAttributes_Arg_5);
    
    // Constant Variable Initialization
    UINT8* SetAttributes_Arg_6_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SetAttributes_Arg_6_choice), (VOID *)SetAttributes_Arg_6_choice);
    switch(*SetAttributes_Arg_6_choice % 5) {
        case 0:
            SetAttributes_Arg_6 = DefaultStopBits;
            break;
        case 1:
            SetAttributes_Arg_6 = OneFiveStopBits;
            break;
        case 2:
            SetAttributes_Arg_6 = OneStopBit;
            break;
        case 3:
            SetAttributes_Arg_6 = TwoStopBits;
            break;
        case 4:
            ReadBytes(Input, sizeof(SetAttributes_Arg_6), (VOID *)&SetAttributes_Arg_6);
            break;
    }
    
    Status = ProtocolVariable->SetAttributes(
        ProtocolVariable,
        SetAttributes_Arg_1,
        SetAttributes_Arg_2,
        SetAttributes_Arg_3,
        SetAttributes_Arg_4,
        SetAttributes_Arg_5,
        SetAttributes_Arg_6
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Reset.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzReset(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SERIAL_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSerialIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Reset(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetControl.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetControl(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SERIAL_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSerialIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINT32 * GetControl_Arg_1 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT8* GetControl_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetControl_Arg_1_OutputChoice), (VOID *)GetControl_Arg_1_OutputChoice);
    if(*GetControl_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetControl_Arg_1), (VOID *)GetControl_Arg_1);
    }
    Status = ProtocolVariable->GetControl(
        ProtocolVariable,
        GetControl_Arg_1
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
    EFI_SERIAL_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSerialIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * Read_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    UINT8 Read_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(Read_Arg_1_choice), (VOID *)&Read_Arg_1_choice);
    switch(Read_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Read_Arg_1), (VOID *)Read_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(Read_Arg_1);
            Read_Arg_1 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    UINTN*  Read_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT8* Read_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Read_Arg_2_OutputChoice), (VOID *)Read_Arg_2_OutputChoice);
    if(*Read_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Read_Arg_2), (VOID *)Read_Arg_2);
    }
    Status = ProtocolVariable->Read(
        ProtocolVariable,
        Read_Arg_1,
        (void *)Read_Arg_2
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
    EFI_SERIAL_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSerialIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * Write_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN*  Write_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    UINT8 Write_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(Write_Arg_1_choice), (VOID *)&Write_Arg_1_choice);
    switch(Write_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Write_Arg_1), (VOID *)Write_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(Write_Arg_1);
            Write_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 Write_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(Write_Arg_2_choice), (VOID *)&Write_Arg_2_choice);
    switch(Write_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Write_Arg_2), (VOID *)Write_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(Write_Arg_2);
            Write_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->Write(
        ProtocolVariable,
        Write_Arg_1,
        (void *)Write_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetControl.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetControl(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SERIAL_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSerialIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 SetControl_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetControl_Arg_1), (VOID *)&SetControl_Arg_1);
    
    Status = ProtocolVariable->SetControl(
        ProtocolVariable,
        SetControl_Arg_1
    );
    return Status;
}

