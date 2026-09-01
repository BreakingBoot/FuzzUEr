#include "FirnessHarnesses.h"

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
    EFI_DEVICE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDeviceIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PHYSICAL_ADDRESS * Map_Arg_2 = (EFI_PHYSICAL_ADDRESS *)AllocateZeroPool(sizeof(EFI_PHYSICAL_ADDRESS));
    UINTN * Map_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    UINT8* Map_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Map_Arg_2_choice), (VOID *)Map_Arg_2_choice);
    switch(*Map_Arg_2_choice % 4) {
        case 0:
        {
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
                Map_Arg_2,
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
                Map_Arg_2,
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
                Map_Arg_2,
                GetVariableFlashNvStorageInfo_Arg_1
            );
    
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
        (EFI_IO_OPERATION_TYPE){0},
        Map_Arg_2,
        Map_Arg_3,
        Map_Arg_4,
        (VOID * *)&Map_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called PciDevicePath.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzPciDevicePath(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DEVICE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDeviceIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT64 PciDevicePath_Arg_1 = 0;
    EFI_DEVICE_PATH_PROTOCOL * * PciDevicePath_Arg_2 = (EFI_DEVICE_PATH_PROTOCOL * *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PciDevicePath_Arg_1), (VOID *)&PciDevicePath_Arg_1);
    
    
    Status = ProtocolVariable->PciDevicePath(
        ProtocolVariable,
        PciDevicePath_Arg_1,
        &PciDevicePath_Arg_2
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
    EFI_DEVICE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDeviceIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    EFI_DEVICE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDeviceIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN AllocateBuffer_Arg_3 = 0;
    EFI_PHYSICAL_ADDRESS * AllocateBuffer_Arg_4 = (EFI_PHYSICAL_ADDRESS *)AllocateZeroPool(sizeof(EFI_PHYSICAL_ADDRESS));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AllocateBuffer_Arg_3), (VOID *)&AllocateBuffer_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 AllocateBuffer_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(AllocateBuffer_Arg_4_choice), (VOID *)&AllocateBuffer_Arg_4_choice);
    switch(AllocateBuffer_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(AllocateBuffer_Arg_4), (VOID *)AllocateBuffer_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(AllocateBuffer_Arg_4);
            AllocateBuffer_Arg_4 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->AllocateBuffer(
        ProtocolVariable,
        (EFI_ALLOCATE_TYPE){0},
        (EFI_MEMORY_TYPE){0},
        AllocateBuffer_Arg_3,
        AllocateBuffer_Arg_4
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
    EFI_DEVICE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDeviceIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    EFI_DEVICE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDeviceIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN FreeBuffer_Arg_1 = 0;
    EFI_PHYSICAL_ADDRESS FreeBuffer_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(FreeBuffer_Arg_1), (VOID *)&FreeBuffer_Arg_1);
    
    UINT8* FreeBuffer_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(FreeBuffer_Arg_2_choice), (VOID *)FreeBuffer_Arg_2_choice);
    switch(*FreeBuffer_Arg_2_choice % 4) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(FreeBuffer_Arg_2), (VOID *)&FreeBuffer_Arg_2);
    
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
                &FreeBuffer_Arg_2,
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
                &FreeBuffer_Arg_2,
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
                &FreeBuffer_Arg_2,
                GetVariableFlashNvStorageInfo_Arg_1
            );
    
            break;
        }
    }
    Status = ProtocolVariable->FreeBuffer(
        ProtocolVariable,
        FreeBuffer_Arg_1,
        FreeBuffer_Arg_2
    );
    return Status;
}

