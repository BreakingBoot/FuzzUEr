#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called WriteDiskEx.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzWriteDiskEx(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DISK_IO2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDiskIo2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 WriteDiskEx_Arg_1 = 0;
    UINT64 WriteDiskEx_Arg_2 = 0;
    EFI_DISK_IO2_TOKEN * WriteDiskEx_Arg_3 = (EFI_DISK_IO2_TOKEN *)AllocateZeroPool(sizeof(EFI_DISK_IO2_TOKEN));
    UINTN WriteDiskEx_Arg_4 = 0;
    UINTN*  WriteDiskEx_Arg_5 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(WriteDiskEx_Arg_1), (VOID *)&WriteDiskEx_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(WriteDiskEx_Arg_2), (VOID *)&WriteDiskEx_Arg_2);
    
    // Generator Struct Variable Initialization
    {
        EFI_EVENT Firness_Event;
        ReadBytes(Input, sizeof(Firness_Event), (VOID *)&Firness_Event);
        WriteDiskEx_Arg_3->Event = Firness_Event;
    }
    {
        EFI_STATUS Firness_TransactionStatus;
        ReadBytes(Input, sizeof(Firness_TransactionStatus), (VOID *)&Firness_TransactionStatus);
        WriteDiskEx_Arg_3->TransactionStatus = Firness_TransactionStatus;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(WriteDiskEx_Arg_4), (VOID *)&WriteDiskEx_Arg_4);
    
    // Fuzzable Variable Initialization
    UINT8 WriteDiskEx_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(WriteDiskEx_Arg_5_choice), (VOID *)&WriteDiskEx_Arg_5_choice);
    switch(WriteDiskEx_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(WriteDiskEx_Arg_5), (VOID *)WriteDiskEx_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(WriteDiskEx_Arg_5);
            WriteDiskEx_Arg_5 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->WriteDiskEx(
        ProtocolVariable,
        WriteDiskEx_Arg_1,
        WriteDiskEx_Arg_2,
        WriteDiskEx_Arg_3,
        WriteDiskEx_Arg_4,
        (void *)WriteDiskEx_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ReadDiskEx.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzReadDiskEx(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DISK_IO2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDiskIo2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 ReadDiskEx_Arg_1 = 0;
    UINT64 ReadDiskEx_Arg_2 = 0;
    EFI_DISK_IO2_TOKEN * ReadDiskEx_Arg_3 = (EFI_DISK_IO2_TOKEN *)AllocateZeroPool(sizeof(EFI_DISK_IO2_TOKEN));
    UINTN ReadDiskEx_Arg_4 = 0;
    UINTN*  ReadDiskEx_Arg_5 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ReadDiskEx_Arg_1), (VOID *)&ReadDiskEx_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ReadDiskEx_Arg_2), (VOID *)&ReadDiskEx_Arg_2);
    
    // Generator Struct Variable Initialization
    {
        EFI_EVENT Firness_Event;
        ReadBytes(Input, sizeof(Firness_Event), (VOID *)&Firness_Event);
        ReadDiskEx_Arg_3->Event = Firness_Event;
    }
    {
        EFI_STATUS Firness_TransactionStatus;
        ReadBytes(Input, sizeof(Firness_TransactionStatus), (VOID *)&Firness_TransactionStatus);
        ReadDiskEx_Arg_3->TransactionStatus = Firness_TransactionStatus;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ReadDiskEx_Arg_4), (VOID *)&ReadDiskEx_Arg_4);
    
    // Fuzzable Variable Initialization
    UINT8 ReadDiskEx_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(ReadDiskEx_Arg_5_choice), (VOID *)&ReadDiskEx_Arg_5_choice);
    switch(ReadDiskEx_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(ReadDiskEx_Arg_5), (VOID *)ReadDiskEx_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(ReadDiskEx_Arg_5);
            ReadDiskEx_Arg_5 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->ReadDiskEx(
        ProtocolVariable,
        ReadDiskEx_Arg_1,
        ReadDiskEx_Arg_2,
        ReadDiskEx_Arg_3,
        ReadDiskEx_Arg_4,
        (void *)ReadDiskEx_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called FlushDiskEx.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFlushDiskEx(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DISK_IO2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDiskIo2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DISK_IO2_TOKEN * FlushDiskEx_Arg_1 = (EFI_DISK_IO2_TOKEN *)AllocateZeroPool(sizeof(EFI_DISK_IO2_TOKEN));
    
    // Generator Struct Variable Initialization
    {
        EFI_EVENT Firness_Event;
        ReadBytes(Input, sizeof(Firness_Event), (VOID *)&Firness_Event);
        FlushDiskEx_Arg_1->Event = Firness_Event;
    }
    {
        EFI_STATUS Firness_TransactionStatus;
        ReadBytes(Input, sizeof(Firness_TransactionStatus), (VOID *)&Firness_TransactionStatus);
        FlushDiskEx_Arg_1->TransactionStatus = Firness_TransactionStatus;
    }
    
    Status = ProtocolVariable->FlushDiskEx(
        ProtocolVariable,
        FlushDiskEx_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Cancel.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzCancel(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DISK_IO2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDiskIo2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Cancel(
        ProtocolVariable
    );
    return Status;
}

