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
    EFI_PCI_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PCI_IO_PROTOCOL_OPERATION Map_Arg_1 = 0;
    UINTN*  Map_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN * Map_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    EFI_PHYSICAL_ADDRESS * Map_Arg_4 = (EFI_PHYSICAL_ADDRESS *)AllocateZeroPool(sizeof(EFI_PHYSICAL_ADDRESS));
    UINTN* Map_Arg_5 = (UINTN*)AllocateZeroPool(sizeof(UINTN));
    
    // Constant Variable Initialization
    UINT8* Map_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Map_Arg_1_choice), (VOID *)Map_Arg_1_choice);
    switch(*Map_Arg_1_choice % 5) {
        case 0:
            Map_Arg_1 = EfiPciIoOperationBusMasterCommonBuffer;
            break;
        case 1:
            Map_Arg_1 = EfiPciIoOperationBusMasterRead;
            break;
        case 2:
            Map_Arg_1 = EfiPciIoOperationBusMasterWrite;
            break;
        case 3:
            Map_Arg_1 = EfiPciIoOperationMaximum;
            break;
        case 4:
            ReadBytes(Input, sizeof(Map_Arg_1), (VOID *)&Map_Arg_1);
            break;
    }
    
    UINT8* Map_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Map_Arg_2_choice), (VOID *)Map_Arg_2_choice);
    switch(*Map_Arg_2_choice % 2) {
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
                Input Variable(s)
            */
            EFI_MEMORY_TYPE PeiServicesAllocatePages_Arg_0 = 0;
            UINTN PeiServicesAllocatePages_Arg_1 = 0;
            
            // Constant Variable Initialization
            UINT8* PeiServicesAllocatePages_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(PeiServicesAllocatePages_Arg_0_choice), (VOID *)PeiServicesAllocatePages_Arg_0_choice);
            switch(*PeiServicesAllocatePages_Arg_0_choice % 18) {
                case 0:
                    PeiServicesAllocatePages_Arg_0 = EfiACPIMemoryNVS;
                    break;
                case 1:
                    PeiServicesAllocatePages_Arg_0 = EfiACPIReclaimMemory;
                    break;
                case 2:
                    PeiServicesAllocatePages_Arg_0 = EfiBootServicesCode;
                    break;
                case 3:
                    PeiServicesAllocatePages_Arg_0 = EfiBootServicesData;
                    break;
                case 4:
                    PeiServicesAllocatePages_Arg_0 = EfiConventionalMemory;
                    break;
                case 5:
                    PeiServicesAllocatePages_Arg_0 = EfiLoaderCode;
                    break;
                case 6:
                    PeiServicesAllocatePages_Arg_0 = EfiLoaderData;
                    break;
                case 7:
                    PeiServicesAllocatePages_Arg_0 = EfiMaxMemoryType;
                    break;
                case 8:
                    PeiServicesAllocatePages_Arg_0 = EfiMemoryMappedIO;
                    break;
                case 9:
                    PeiServicesAllocatePages_Arg_0 = EfiMemoryMappedIOPortSpace;
                    break;
                case 10:
                    PeiServicesAllocatePages_Arg_0 = EfiPalCode;
                    break;
                case 11:
                    PeiServicesAllocatePages_Arg_0 = EfiPersistentMemory;
                    break;
                case 12:
                    PeiServicesAllocatePages_Arg_0 = EfiReservedMemoryType;
                    break;
                case 13:
                    PeiServicesAllocatePages_Arg_0 = EfiRuntimeServicesCode;
                    break;
                case 14:
                    PeiServicesAllocatePages_Arg_0 = EfiRuntimeServicesData;
                    break;
                case 15:
                    PeiServicesAllocatePages_Arg_0 = EfiUnacceptedMemoryType;
                    break;
                case 16:
                    PeiServicesAllocatePages_Arg_0 = EfiUnusableMemory;
                    break;
                case 17:
                    ReadBytes(Input, sizeof(PeiServicesAllocatePages_Arg_0), (VOID *)&PeiServicesAllocatePages_Arg_0);
                    break;
            }
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(PeiServicesAllocatePages_Arg_1), (VOID *)&PeiServicesAllocatePages_Arg_1);
            
            /*
                Output Variable(s)
            */
            EFI_PHYSICAL_ADDRESS * PeiServicesAllocatePages_Arg_2 = (EFI_PHYSICAL_ADDRESS *)AllocateZeroPool(sizeof(EFI_PHYSICAL_ADDRESS));
            UINT8* PeiServicesAllocatePages_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(PeiServicesAllocatePages_Arg_2_OutputChoice), (VOID *)PeiServicesAllocatePages_Arg_2_OutputChoice);
            if(*PeiServicesAllocatePages_Arg_2_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*PeiServicesAllocatePages_Arg_2), (VOID *)PeiServicesAllocatePages_Arg_2);
            }
            Status = PeiServicesAllocatePages(
                PeiServicesAllocatePages_Arg_0,
                PeiServicesAllocatePages_Arg_1,
                PeiServicesAllocatePages_Arg_2
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
    
    UINT8* Map_Arg_4_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Map_Arg_4_choice), (VOID *)Map_Arg_4_choice);
    switch(*Map_Arg_4_choice % 4) {
        case 0:
        {
        // Fuzzable Variable Initialization
        UINT8 Map_Arg_4_choice = 0;
        ReadBytes(Input, sizeof(Map_Arg_4_choice), (VOID *)&Map_Arg_4_choice);
        switch(Map_Arg_4_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(Map_Arg_4), (VOID *)Map_Arg_4);
                break;
            case 1:
            {
                gBS->FreePool(Map_Arg_4);
                Map_Arg_4 = NULL;
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
                Map_Arg_4,
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
                Map_Arg_4,
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
                Map_Arg_4,
                GetVariableFlashNvStorageInfo_Arg_1
            );
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 Map_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(Map_Arg_5_choice), (VOID *)&Map_Arg_5_choice);
    switch(Map_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Map_Arg_5), (VOID *)Map_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(Map_Arg_5);
            Map_Arg_5 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->Map(
        ProtocolVariable,
        Map_Arg_1,
        (void *)Map_Arg_2,
        Map_Arg_3,
        Map_Arg_4,
        (void **)&Map_Arg_5
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
    EFI_PCI_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
        (void *)Unmap_Arg_1
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
    EFI_PCI_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    called Attributes.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAttributes(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PCI_IO_PROTOCOL_ATTRIBUTE_OPERATION Attributes_Arg_1 = 0;
    UINT64 Attributes_Arg_2 = 0;
    UINT64 * Attributes_Arg_3 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    
    // Constant Variable Initialization
    UINT8* Attributes_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Attributes_Arg_1_choice), (VOID *)Attributes_Arg_1_choice);
    switch(*Attributes_Arg_1_choice % 7) {
        case 0:
            Attributes_Arg_1 = EfiPciIoAttributeOperationDisable;
            break;
        case 1:
            Attributes_Arg_1 = EfiPciIoAttributeOperationEnable;
            break;
        case 2:
            Attributes_Arg_1 = EfiPciIoAttributeOperationGet;
            break;
        case 3:
            Attributes_Arg_1 = EfiPciIoAttributeOperationMaximum;
            break;
        case 4:
            Attributes_Arg_1 = EfiPciIoAttributeOperationSet;
            break;
        case 5:
            Attributes_Arg_1 = EfiPciIoAttributeOperationSupported;
            break;
        case 6:
            ReadBytes(Input, sizeof(Attributes_Arg_1), (VOID *)&Attributes_Arg_1);
            break;
    }
    
    UINT8* Attributes_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Attributes_Arg_2_choice), (VOID *)Attributes_Arg_2_choice);
    switch(*Attributes_Arg_2_choice % 6) {
        case 0:
        {
        // Constant Variable Initialization
        Attributes_Arg_2 = kEmptyHashValue;
    
            break;
        }
        case 1:
        {
        // Constant Variable Initialization
        Attributes_Arg_2 = EFI_PCI_IO_ATTRIBUTE_DUAL_ADDRESS_CYCLE;
    
            break;
        }
        case 2:
        {
        // Constant Variable Initialization
        Attributes_Arg_2 = 0;
    
            break;
        }
        case 3:
        {
        // Constant Variable Initialization
        Attributes_Arg_2 = EFI_PCI_DEVICE_ENABLE;
    
            break;
        }
        case 4:
        {
        // Constant Variable Initialization
        Attributes_Arg_2 = 0;
    
            break;
        }
        case 5:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(Attributes_Arg_2), (VOID *)&Attributes_Arg_2);
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 Attributes_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(Attributes_Arg_3_choice), (VOID *)&Attributes_Arg_3_choice);
    switch(Attributes_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Attributes_Arg_3), (VOID *)Attributes_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(Attributes_Arg_3);
            Attributes_Arg_3 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->Attributes(
        ProtocolVariable,
        Attributes_Arg_1,
        Attributes_Arg_2,
        Attributes_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetLocation.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetLocation(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINTN * GetLocation_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetLocation_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetLocation_Arg_1_OutputChoice), (VOID *)GetLocation_Arg_1_OutputChoice);
    if(*GetLocation_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetLocation_Arg_1), (VOID *)GetLocation_Arg_1);
    }
    UINTN * GetLocation_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetLocation_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetLocation_Arg_2_OutputChoice), (VOID *)GetLocation_Arg_2_OutputChoice);
    if(*GetLocation_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetLocation_Arg_2), (VOID *)GetLocation_Arg_2);
    }
    UINTN * GetLocation_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetLocation_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetLocation_Arg_3_OutputChoice), (VOID *)GetLocation_Arg_3_OutputChoice);
    if(*GetLocation_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetLocation_Arg_3), (VOID *)GetLocation_Arg_3);
    }
    UINTN * GetLocation_Arg_4 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetLocation_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetLocation_Arg_4_OutputChoice), (VOID *)GetLocation_Arg_4_OutputChoice);
    if(*GetLocation_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetLocation_Arg_4), (VOID *)GetLocation_Arg_4);
    }
    Status = ProtocolVariable->GetLocation(
        ProtocolVariable,
        GetLocation_Arg_1,
        GetLocation_Arg_2,
        GetLocation_Arg_3,
        GetLocation_Arg_4
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
    EFI_PCI_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_ALLOCATE_TYPE AllocateBuffer_Arg_1 = 0;
    EFI_MEMORY_TYPE AllocateBuffer_Arg_2 = 0;
    UINTN AllocateBuffer_Arg_3 = 0;
    UINTN* AllocateBuffer_Arg_4 = (UINTN*)AllocateZeroPool(sizeof(UINTN));
    UINT64 AllocateBuffer_Arg_5 = 0;
    
    // Constant Variable Initialization
    UINT8* AllocateBuffer_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(AllocateBuffer_Arg_1_choice), (VOID *)AllocateBuffer_Arg_1_choice);
    switch(*AllocateBuffer_Arg_1_choice % 5) {
        case 0:
            AllocateBuffer_Arg_1 = AllocateAddress;
            break;
        case 1:
            AllocateBuffer_Arg_1 = AllocateAnyPages;
            break;
        case 2:
            AllocateBuffer_Arg_1 = AllocateMaxAddress;
            break;
        case 3:
            AllocateBuffer_Arg_1 = MaxAllocateType;
            break;
        case 4:
            ReadBytes(Input, sizeof(AllocateBuffer_Arg_1), (VOID *)&AllocateBuffer_Arg_1);
            break;
    }
    
    // Constant Variable Initialization
    UINT8* AllocateBuffer_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(AllocateBuffer_Arg_2_choice), (VOID *)AllocateBuffer_Arg_2_choice);
    switch(*AllocateBuffer_Arg_2_choice % 18) {
        case 0:
            AllocateBuffer_Arg_2 = EfiACPIMemoryNVS;
            break;
        case 1:
            AllocateBuffer_Arg_2 = EfiACPIReclaimMemory;
            break;
        case 2:
            AllocateBuffer_Arg_2 = EfiBootServicesCode;
            break;
        case 3:
            AllocateBuffer_Arg_2 = EfiBootServicesData;
            break;
        case 4:
            AllocateBuffer_Arg_2 = EfiConventionalMemory;
            break;
        case 5:
            AllocateBuffer_Arg_2 = EfiLoaderCode;
            break;
        case 6:
            AllocateBuffer_Arg_2 = EfiLoaderData;
            break;
        case 7:
            AllocateBuffer_Arg_2 = EfiMaxMemoryType;
            break;
        case 8:
            AllocateBuffer_Arg_2 = EfiMemoryMappedIO;
            break;
        case 9:
            AllocateBuffer_Arg_2 = EfiMemoryMappedIOPortSpace;
            break;
        case 10:
            AllocateBuffer_Arg_2 = EfiPalCode;
            break;
        case 11:
            AllocateBuffer_Arg_2 = EfiPersistentMemory;
            break;
        case 12:
            AllocateBuffer_Arg_2 = EfiReservedMemoryType;
            break;
        case 13:
            AllocateBuffer_Arg_2 = EfiRuntimeServicesCode;
            break;
        case 14:
            AllocateBuffer_Arg_2 = EfiRuntimeServicesData;
            break;
        case 15:
            AllocateBuffer_Arg_2 = EfiUnacceptedMemoryType;
            break;
        case 16:
            AllocateBuffer_Arg_2 = EfiUnusableMemory;
            break;
        case 17:
            ReadBytes(Input, sizeof(AllocateBuffer_Arg_2), (VOID *)&AllocateBuffer_Arg_2);
            break;
    }
    
    UINT8* AllocateBuffer_Arg_3_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(AllocateBuffer_Arg_3_choice), (VOID *)AllocateBuffer_Arg_3_choice);
    switch(*AllocateBuffer_Arg_3_choice % 8) {
        case 0:
        {
        // Constant Variable Initialization
        AllocateBuffer_Arg_3 = kNumPosSlotBits;
    
            break;
        }
        case 1:
        {
        // Constant Variable Initialization
        AllocateBuffer_Arg_3 = 0;
    
            break;
        }
        case 2:
        {
        // Constant Variable Initialization
        AllocateBuffer_Arg_3 = 0;
    
            break;
        }
        case 3:
        {
        // Constant Variable Initialization
        AllocateBuffer_Arg_3 = SNP_MEM_PAGES (4096);
    
            break;
        }
        case 4:
        {
        // Constant Variable Initialization
        AllocateBuffer_Arg_3 = 0;
    
            break;
        }
        case 5:
        {
        // Constant Variable Initialization
        AllocateBuffer_Arg_3 = 0;
    
            break;
        }
        case 6:
        {
        // Constant Variable Initialization
        AllocateBuffer_Arg_3 = 0;
    
            break;
        }
        case 7:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(AllocateBuffer_Arg_3), (VOID *)&AllocateBuffer_Arg_3);
    
            break;
        }
    }
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
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AllocateBuffer_Arg_5), (VOID *)&AllocateBuffer_Arg_5);
    
    Status = ProtocolVariable->AllocateBuffer(
        ProtocolVariable,
        AllocateBuffer_Arg_1,
        AllocateBuffer_Arg_2,
        AllocateBuffer_Arg_3,
        (void **)&AllocateBuffer_Arg_4,
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
    EFI_PCI_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN FreeBuffer_Arg_1 = 0;
    UINTN*  FreeBuffer_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    UINT8* FreeBuffer_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(FreeBuffer_Arg_1_choice), (VOID *)FreeBuffer_Arg_1_choice);
    switch(*FreeBuffer_Arg_1_choice % 14) {
        case 0:
        {
        // Constant Variable Initialization
        FreeBuffer_Arg_1 = 0;
    
            break;
        }
        case 1:
        {
        // Constant Variable Initialization
        FreeBuffer_Arg_1 = kNumPosSlotBits;
    
            break;
        }
        case 2:
        {
        // Constant Variable Initialization
        FreeBuffer_Arg_1 = 0;
    
            break;
        }
        case 3:
        {
        // Constant Variable Initialization
        FreeBuffer_Arg_1 = SNP_MEM_PAGES (4096);
    
            break;
        }
        case 4:
        {
        // Constant Variable Initialization
        FreeBuffer_Arg_1 = 0;
    
            break;
        }
        case 5:
        {
        // Constant Variable Initialization
        FreeBuffer_Arg_1 = 0;
    
            break;
        }
        case 6:
        {
        // Constant Variable Initialization
        FreeBuffer_Arg_1 = 0;
    
            break;
        }
        case 7:
        {
        // Constant Variable Initialization
        FreeBuffer_Arg_1 = 0;
    
            break;
        }
        case 8:
        {
        // Constant Variable Initialization
        FreeBuffer_Arg_1 = 0;
    
            break;
        }
        case 9:
        {
        // Constant Variable Initialization
        FreeBuffer_Arg_1 = 0;
    
            break;
        }
        case 10:
        {
        // Constant Variable Initialization
        FreeBuffer_Arg_1 = 0;
    
            break;
        }
        case 11:
        {
        // Constant Variable Initialization
        FreeBuffer_Arg_1 = EFI_SIZE_TO_PAGES (EFI_PAGE_SIZE);
    
            break;
        }
        case 12:
        {
        // Constant Variable Initialization
        FreeBuffer_Arg_1 = EFI_SIZE_TO_PAGES (4096);
    
            break;
        }
        case 13:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(FreeBuffer_Arg_1), (VOID *)&FreeBuffer_Arg_1);
    
            break;
        }
    }
    UINT8* FreeBuffer_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(FreeBuffer_Arg_2_choice), (VOID *)FreeBuffer_Arg_2_choice);
    switch(*FreeBuffer_Arg_2_choice % 5) {
        case 0:
        {
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
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_MEMORY_TYPE PeiServicesAllocatePages_Arg_0 = 0;
            UINTN PeiServicesAllocatePages_Arg_1 = 0;
            
            // Constant Variable Initialization
            UINT8* PeiServicesAllocatePages_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(PeiServicesAllocatePages_Arg_0_choice), (VOID *)PeiServicesAllocatePages_Arg_0_choice);
            switch(*PeiServicesAllocatePages_Arg_0_choice % 18) {
                case 0:
                    PeiServicesAllocatePages_Arg_0 = EfiACPIMemoryNVS;
                    break;
                case 1:
                    PeiServicesAllocatePages_Arg_0 = EfiACPIReclaimMemory;
                    break;
                case 2:
                    PeiServicesAllocatePages_Arg_0 = EfiBootServicesCode;
                    break;
                case 3:
                    PeiServicesAllocatePages_Arg_0 = EfiBootServicesData;
                    break;
                case 4:
                    PeiServicesAllocatePages_Arg_0 = EfiConventionalMemory;
                    break;
                case 5:
                    PeiServicesAllocatePages_Arg_0 = EfiLoaderCode;
                    break;
                case 6:
                    PeiServicesAllocatePages_Arg_0 = EfiLoaderData;
                    break;
                case 7:
                    PeiServicesAllocatePages_Arg_0 = EfiMaxMemoryType;
                    break;
                case 8:
                    PeiServicesAllocatePages_Arg_0 = EfiMemoryMappedIO;
                    break;
                case 9:
                    PeiServicesAllocatePages_Arg_0 = EfiMemoryMappedIOPortSpace;
                    break;
                case 10:
                    PeiServicesAllocatePages_Arg_0 = EfiPalCode;
                    break;
                case 11:
                    PeiServicesAllocatePages_Arg_0 = EfiPersistentMemory;
                    break;
                case 12:
                    PeiServicesAllocatePages_Arg_0 = EfiReservedMemoryType;
                    break;
                case 13:
                    PeiServicesAllocatePages_Arg_0 = EfiRuntimeServicesCode;
                    break;
                case 14:
                    PeiServicesAllocatePages_Arg_0 = EfiRuntimeServicesData;
                    break;
                case 15:
                    PeiServicesAllocatePages_Arg_0 = EfiUnacceptedMemoryType;
                    break;
                case 16:
                    PeiServicesAllocatePages_Arg_0 = EfiUnusableMemory;
                    break;
                case 17:
                    ReadBytes(Input, sizeof(PeiServicesAllocatePages_Arg_0), (VOID *)&PeiServicesAllocatePages_Arg_0);
                    break;
            }
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(PeiServicesAllocatePages_Arg_1), (VOID *)&PeiServicesAllocatePages_Arg_1);
            
            /*
                Output Variable(s)
            */
            EFI_PHYSICAL_ADDRESS * PeiServicesAllocatePages_Arg_2 = (EFI_PHYSICAL_ADDRESS *)AllocateZeroPool(sizeof(EFI_PHYSICAL_ADDRESS));
            UINT8* PeiServicesAllocatePages_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(PeiServicesAllocatePages_Arg_2_OutputChoice), (VOID *)PeiServicesAllocatePages_Arg_2_OutputChoice);
            if(*PeiServicesAllocatePages_Arg_2_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*PeiServicesAllocatePages_Arg_2), (VOID *)PeiServicesAllocatePages_Arg_2);
            }
            Status = PeiServicesAllocatePages(
                PeiServicesAllocatePages_Arg_0,
                PeiServicesAllocatePages_Arg_1,
                PeiServicesAllocatePages_Arg_2
            );
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            /*
                Output Variable(s)
            */
            EFI_PHYSICAL_ADDRESS * GetVariableFlashFtwWorkingInfo_Arg_0 = (EFI_PHYSICAL_ADDRESS *)AllocateZeroPool(sizeof(EFI_PHYSICAL_ADDRESS));
            UINT8* GetVariableFlashFtwWorkingInfo_Arg_0_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(GetVariableFlashFtwWorkingInfo_Arg_0_OutputChoice), (VOID *)GetVariableFlashFtwWorkingInfo_Arg_0_OutputChoice);
            if(*GetVariableFlashFtwWorkingInfo_Arg_0_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*GetVariableFlashFtwWorkingInfo_Arg_0), (VOID *)GetVariableFlashFtwWorkingInfo_Arg_0);
            }
            UINT64 * GetVariableFlashFtwWorkingInfo_Arg_1 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
            UINT8* GetVariableFlashFtwWorkingInfo_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(GetVariableFlashFtwWorkingInfo_Arg_1_OutputChoice), (VOID *)GetVariableFlashFtwWorkingInfo_Arg_1_OutputChoice);
            if(*GetVariableFlashFtwWorkingInfo_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*GetVariableFlashFtwWorkingInfo_Arg_1), (VOID *)GetVariableFlashFtwWorkingInfo_Arg_1);
            }
            Status = GetVariableFlashFtwWorkingInfo(
                GetVariableFlashFtwWorkingInfo_Arg_0,
                GetVariableFlashFtwWorkingInfo_Arg_1
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            /*
                Output Variable(s)
            */
            EFI_PHYSICAL_ADDRESS * GetVariableFlashFtwSpareInfo_Arg_0 = (EFI_PHYSICAL_ADDRESS *)AllocateZeroPool(sizeof(EFI_PHYSICAL_ADDRESS));
            UINT8* GetVariableFlashFtwSpareInfo_Arg_0_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(GetVariableFlashFtwSpareInfo_Arg_0_OutputChoice), (VOID *)GetVariableFlashFtwSpareInfo_Arg_0_OutputChoice);
            if(*GetVariableFlashFtwSpareInfo_Arg_0_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*GetVariableFlashFtwSpareInfo_Arg_0), (VOID *)GetVariableFlashFtwSpareInfo_Arg_0);
            }
            UINT64 * GetVariableFlashFtwSpareInfo_Arg_1 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
            UINT8* GetVariableFlashFtwSpareInfo_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(GetVariableFlashFtwSpareInfo_Arg_1_OutputChoice), (VOID *)GetVariableFlashFtwSpareInfo_Arg_1_OutputChoice);
            if(*GetVariableFlashFtwSpareInfo_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*GetVariableFlashFtwSpareInfo_Arg_1), (VOID *)GetVariableFlashFtwSpareInfo_Arg_1);
            }
            Status = GetVariableFlashFtwSpareInfo(
                GetVariableFlashFtwSpareInfo_Arg_0,
                GetVariableFlashFtwSpareInfo_Arg_1
            );
    
            break;
        }
        case 4:
        {
        // Generator Struct Variable Initialization
            /*
                Output Variable(s)
            */
            EFI_PHYSICAL_ADDRESS * GetVariableFlashNvStorageInfo_Arg_0 = (EFI_PHYSICAL_ADDRESS *)AllocateZeroPool(sizeof(EFI_PHYSICAL_ADDRESS));
            UINT8* GetVariableFlashNvStorageInfo_Arg_0_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(GetVariableFlashNvStorageInfo_Arg_0_OutputChoice), (VOID *)GetVariableFlashNvStorageInfo_Arg_0_OutputChoice);
            if(*GetVariableFlashNvStorageInfo_Arg_0_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*GetVariableFlashNvStorageInfo_Arg_0), (VOID *)GetVariableFlashNvStorageInfo_Arg_0);
            }
            UINT64 * GetVariableFlashNvStorageInfo_Arg_1 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
            UINT8* GetVariableFlashNvStorageInfo_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(GetVariableFlashNvStorageInfo_Arg_1_OutputChoice), (VOID *)GetVariableFlashNvStorageInfo_Arg_1_OutputChoice);
            if(*GetVariableFlashNvStorageInfo_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*GetVariableFlashNvStorageInfo_Arg_1), (VOID *)GetVariableFlashNvStorageInfo_Arg_1);
            }
            Status = GetVariableFlashNvStorageInfo(
                GetVariableFlashNvStorageInfo_Arg_0,
                GetVariableFlashNvStorageInfo_Arg_1
            );
    
            break;
        }
    }
    Status = ProtocolVariable->FreeBuffer(
        ProtocolVariable,
        FreeBuffer_Arg_1,
        (void *)FreeBuffer_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetBarAttributes.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetBarAttributes(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 GetBarAttributes_Arg_1 = 0;
    UINT64 * GetBarAttributes_Arg_2 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    UINTN* GetBarAttributes_Arg_3 = (UINTN*)AllocateZeroPool(sizeof(UINTN));
    
    UINT8* GetBarAttributes_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetBarAttributes_Arg_1_choice), (VOID *)GetBarAttributes_Arg_1_choice);
    switch(*GetBarAttributes_Arg_1_choice % 2) {
        case 0:
        {
        // Constant Variable Initialization
        GetBarAttributes_Arg_1 = kEmptyHashValue;
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(GetBarAttributes_Arg_1), (VOID *)&GetBarAttributes_Arg_1);
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 GetBarAttributes_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetBarAttributes_Arg_2_choice), (VOID *)&GetBarAttributes_Arg_2_choice);
    switch(GetBarAttributes_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetBarAttributes_Arg_2), (VOID *)GetBarAttributes_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(GetBarAttributes_Arg_2);
            GetBarAttributes_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetBarAttributes_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(GetBarAttributes_Arg_3_choice), (VOID *)&GetBarAttributes_Arg_3_choice);
    switch(GetBarAttributes_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetBarAttributes_Arg_3), (VOID *)GetBarAttributes_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(GetBarAttributes_Arg_3);
            GetBarAttributes_Arg_3 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetBarAttributes(
        ProtocolVariable,
        GetBarAttributes_Arg_1,
        GetBarAttributes_Arg_2,
        (void **)&GetBarAttributes_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called PollIo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzPollIo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 PollIo_Arg_2 = 0;
    UINT64 PollIo_Arg_3 = 0;
    UINT64 PollIo_Arg_4 = 0;
    UINT64 PollIo_Arg_5 = 0;
    UINT64 PollIo_Arg_6 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollIo_Arg_2), (VOID *)&PollIo_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollIo_Arg_3), (VOID *)&PollIo_Arg_3);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollIo_Arg_4), (VOID *)&PollIo_Arg_4);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollIo_Arg_5), (VOID *)&PollIo_Arg_5);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollIo_Arg_6), (VOID *)&PollIo_Arg_6);
    
    /*
        Output Variable(s)
    */
    UINT64 * PollIo_Arg_7 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    UINT8* PollIo_Arg_7_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(PollIo_Arg_7_OutputChoice), (VOID *)PollIo_Arg_7_OutputChoice);
    if(*PollIo_Arg_7_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*PollIo_Arg_7), (VOID *)PollIo_Arg_7);
    }
    Status = ProtocolVariable->PollIo(
        ProtocolVariable,
        (EFI_PCI_IO_PROTOCOL_WIDTH){0},
        PollIo_Arg_2,
        PollIo_Arg_3,
        PollIo_Arg_4,
        PollIo_Arg_5,
        PollIo_Arg_6,
        PollIo_Arg_7
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetBarAttributes.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetBarAttributes(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT64 SetBarAttributes_Arg_1 = 0;
    UINT8 SetBarAttributes_Arg_2 = 0;
    UINT64 * SetBarAttributes_Arg_3 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    UINT64 * SetBarAttributes_Arg_4 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetBarAttributes_Arg_1), (VOID *)&SetBarAttributes_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetBarAttributes_Arg_2), (VOID *)&SetBarAttributes_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 SetBarAttributes_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(SetBarAttributes_Arg_3_choice), (VOID *)&SetBarAttributes_Arg_3_choice);
    switch(SetBarAttributes_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetBarAttributes_Arg_3), (VOID *)SetBarAttributes_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(SetBarAttributes_Arg_3);
            SetBarAttributes_Arg_3 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 SetBarAttributes_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(SetBarAttributes_Arg_4_choice), (VOID *)&SetBarAttributes_Arg_4_choice);
    switch(SetBarAttributes_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetBarAttributes_Arg_4), (VOID *)SetBarAttributes_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(SetBarAttributes_Arg_4);
            SetBarAttributes_Arg_4 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->SetBarAttributes(
        ProtocolVariable,
        SetBarAttributes_Arg_1,
        SetBarAttributes_Arg_2,
        SetBarAttributes_Arg_3,
        SetBarAttributes_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called PollMem.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzPollMem(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 PollMem_Arg_2 = 0;
    UINT64 PollMem_Arg_3 = 0;
    UINT64 PollMem_Arg_4 = 0;
    UINT64 PollMem_Arg_5 = 0;
    UINT64 PollMem_Arg_6 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollMem_Arg_2), (VOID *)&PollMem_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollMem_Arg_3), (VOID *)&PollMem_Arg_3);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollMem_Arg_4), (VOID *)&PollMem_Arg_4);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollMem_Arg_5), (VOID *)&PollMem_Arg_5);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollMem_Arg_6), (VOID *)&PollMem_Arg_6);
    
    /*
        Output Variable(s)
    */
    UINT64 * PollMem_Arg_7 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    UINT8* PollMem_Arg_7_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(PollMem_Arg_7_OutputChoice), (VOID *)PollMem_Arg_7_OutputChoice);
    if(*PollMem_Arg_7_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*PollMem_Arg_7), (VOID *)PollMem_Arg_7);
    }
    Status = ProtocolVariable->PollMem(
        ProtocolVariable,
        (EFI_PCI_IO_PROTOCOL_WIDTH){0},
        PollMem_Arg_2,
        PollMem_Arg_3,
        PollMem_Arg_4,
        PollMem_Arg_5,
        PollMem_Arg_6,
        PollMem_Arg_7
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called CopyMem.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzCopyMem(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 CopyMem_Arg_2 = 0;
    UINT64 CopyMem_Arg_3 = 0;
    UINT8 CopyMem_Arg_4 = 0;
    UINT64 CopyMem_Arg_5 = 0;
    UINTN CopyMem_Arg_6 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(CopyMem_Arg_2), (VOID *)&CopyMem_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(CopyMem_Arg_3), (VOID *)&CopyMem_Arg_3);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(CopyMem_Arg_4), (VOID *)&CopyMem_Arg_4);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(CopyMem_Arg_5), (VOID *)&CopyMem_Arg_5);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(CopyMem_Arg_6), (VOID *)&CopyMem_Arg_6);
    
    Status = ProtocolVariable->CopyMem(
        ProtocolVariable,
        (EFI_PCI_IO_PROTOCOL_WIDTH){0},
        CopyMem_Arg_2,
        CopyMem_Arg_3,
        CopyMem_Arg_4,
        CopyMem_Arg_5,
        CopyMem_Arg_6
    );
    return Status;
}

