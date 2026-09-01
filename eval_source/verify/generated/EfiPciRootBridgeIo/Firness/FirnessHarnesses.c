#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called Configuration.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzConfiguration(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN* Configuration_Arg_1 = (UINTN*)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    UINT8 Configuration_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(Configuration_Arg_1_choice), (VOID *)&Configuration_Arg_1_choice);
    switch(Configuration_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Configuration_Arg_1), (VOID *)Configuration_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(Configuration_Arg_1);
            Configuration_Arg_1 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->Configuration(
        ProtocolVariable,
        (void **)&Configuration_Arg_1
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
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH PollMem_Arg_1 = 0;
    UINT64 PollMem_Arg_2 = 0;
    UINT64 PollMem_Arg_3 = 0;
    UINT64 PollMem_Arg_4 = 0;
    UINT64 PollMem_Arg_5 = 0;
    UINT64 * PollMem_Arg_6 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    
    // Constant Variable Initialization
    UINT8* PollMem_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(PollMem_Arg_1_choice), (VOID *)PollMem_Arg_1_choice);
    switch(*PollMem_Arg_1_choice % 14) {
        case 0:
            PollMem_Arg_1 = EfiPciWidthFifoUint16;
            break;
        case 1:
            PollMem_Arg_1 = EfiPciWidthFifoUint32;
            break;
        case 2:
            PollMem_Arg_1 = EfiPciWidthFifoUint64;
            break;
        case 3:
            PollMem_Arg_1 = EfiPciWidthFifoUint8;
            break;
        case 4:
            PollMem_Arg_1 = EfiPciWidthFillUint16;
            break;
        case 5:
            PollMem_Arg_1 = EfiPciWidthFillUint32;
            break;
        case 6:
            PollMem_Arg_1 = EfiPciWidthFillUint64;
            break;
        case 7:
            PollMem_Arg_1 = EfiPciWidthFillUint8;
            break;
        case 8:
            PollMem_Arg_1 = EfiPciWidthMaximum;
            break;
        case 9:
            PollMem_Arg_1 = EfiPciWidthUint16;
            break;
        case 10:
            PollMem_Arg_1 = EfiPciWidthUint32;
            break;
        case 11:
            PollMem_Arg_1 = EfiPciWidthUint64;
            break;
        case 12:
            PollMem_Arg_1 = EfiPciWidthUint8;
            break;
        case 13:
            ReadBytes(Input, sizeof(PollMem_Arg_1), (VOID *)&PollMem_Arg_1);
            break;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollMem_Arg_2), (VOID *)&PollMem_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollMem_Arg_3), (VOID *)&PollMem_Arg_3);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollMem_Arg_4), (VOID *)&PollMem_Arg_4);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollMem_Arg_5), (VOID *)&PollMem_Arg_5);
    
    // Fuzzable Variable Initialization
    UINT8 PollMem_Arg_6_choice = 0;
    ReadBytes(Input, sizeof(PollMem_Arg_6_choice), (VOID *)&PollMem_Arg_6_choice);
    switch(PollMem_Arg_6_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(PollMem_Arg_6), (VOID *)PollMem_Arg_6);
            break;
        case 1:
        {
            gBS->FreePool(PollMem_Arg_6);
            PollMem_Arg_6 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->PollMem(
        ProtocolVariable,
        PollMem_Arg_1,
        PollMem_Arg_2,
        PollMem_Arg_3,
        PollMem_Arg_4,
        PollMem_Arg_5,
        PollMem_Arg_6
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
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH PollIo_Arg_1 = 0;
    UINT64 PollIo_Arg_2 = 0;
    UINT64 PollIo_Arg_3 = 0;
    UINT64 PollIo_Arg_4 = 0;
    UINT64 PollIo_Arg_5 = 0;
    UINT64 * PollIo_Arg_6 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    
    // Constant Variable Initialization
    UINT8* PollIo_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(PollIo_Arg_1_choice), (VOID *)PollIo_Arg_1_choice);
    switch(*PollIo_Arg_1_choice % 14) {
        case 0:
            PollIo_Arg_1 = EfiPciWidthFifoUint16;
            break;
        case 1:
            PollIo_Arg_1 = EfiPciWidthFifoUint32;
            break;
        case 2:
            PollIo_Arg_1 = EfiPciWidthFifoUint64;
            break;
        case 3:
            PollIo_Arg_1 = EfiPciWidthFifoUint8;
            break;
        case 4:
            PollIo_Arg_1 = EfiPciWidthFillUint16;
            break;
        case 5:
            PollIo_Arg_1 = EfiPciWidthFillUint32;
            break;
        case 6:
            PollIo_Arg_1 = EfiPciWidthFillUint64;
            break;
        case 7:
            PollIo_Arg_1 = EfiPciWidthFillUint8;
            break;
        case 8:
            PollIo_Arg_1 = EfiPciWidthMaximum;
            break;
        case 9:
            PollIo_Arg_1 = EfiPciWidthUint16;
            break;
        case 10:
            PollIo_Arg_1 = EfiPciWidthUint32;
            break;
        case 11:
            PollIo_Arg_1 = EfiPciWidthUint64;
            break;
        case 12:
            PollIo_Arg_1 = EfiPciWidthUint8;
            break;
        case 13:
            ReadBytes(Input, sizeof(PollIo_Arg_1), (VOID *)&PollIo_Arg_1);
            break;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollIo_Arg_2), (VOID *)&PollIo_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollIo_Arg_3), (VOID *)&PollIo_Arg_3);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollIo_Arg_4), (VOID *)&PollIo_Arg_4);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollIo_Arg_5), (VOID *)&PollIo_Arg_5);
    
    // Fuzzable Variable Initialization
    UINT8 PollIo_Arg_6_choice = 0;
    ReadBytes(Input, sizeof(PollIo_Arg_6_choice), (VOID *)&PollIo_Arg_6_choice);
    switch(PollIo_Arg_6_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(PollIo_Arg_6), (VOID *)PollIo_Arg_6);
            break;
        case 1:
        {
            gBS->FreePool(PollIo_Arg_6);
            PollIo_Arg_6 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->PollIo(
        ProtocolVariable,
        PollIo_Arg_1,
        PollIo_Arg_2,
        PollIo_Arg_3,
        PollIo_Arg_4,
        PollIo_Arg_5,
        PollIo_Arg_6
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
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH CopyMem_Arg_1 = 0;
    UINT64 CopyMem_Arg_2 = 0;
    UINT64 CopyMem_Arg_3 = 0;
    UINTN CopyMem_Arg_4 = 0;
    
    // Constant Variable Initialization
    UINT8* CopyMem_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(CopyMem_Arg_1_choice), (VOID *)CopyMem_Arg_1_choice);
    switch(*CopyMem_Arg_1_choice % 14) {
        case 0:
            CopyMem_Arg_1 = EfiPciWidthFifoUint16;
            break;
        case 1:
            CopyMem_Arg_1 = EfiPciWidthFifoUint32;
            break;
        case 2:
            CopyMem_Arg_1 = EfiPciWidthFifoUint64;
            break;
        case 3:
            CopyMem_Arg_1 = EfiPciWidthFifoUint8;
            break;
        case 4:
            CopyMem_Arg_1 = EfiPciWidthFillUint16;
            break;
        case 5:
            CopyMem_Arg_1 = EfiPciWidthFillUint32;
            break;
        case 6:
            CopyMem_Arg_1 = EfiPciWidthFillUint64;
            break;
        case 7:
            CopyMem_Arg_1 = EfiPciWidthFillUint8;
            break;
        case 8:
            CopyMem_Arg_1 = EfiPciWidthMaximum;
            break;
        case 9:
            CopyMem_Arg_1 = EfiPciWidthUint16;
            break;
        case 10:
            CopyMem_Arg_1 = EfiPciWidthUint32;
            break;
        case 11:
            CopyMem_Arg_1 = EfiPciWidthUint64;
            break;
        case 12:
            CopyMem_Arg_1 = EfiPciWidthUint8;
            break;
        case 13:
            ReadBytes(Input, sizeof(CopyMem_Arg_1), (VOID *)&CopyMem_Arg_1);
            break;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(CopyMem_Arg_2), (VOID *)&CopyMem_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(CopyMem_Arg_3), (VOID *)&CopyMem_Arg_3);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(CopyMem_Arg_4), (VOID *)&CopyMem_Arg_4);
    
    Status = ProtocolVariable->CopyMem(
        ProtocolVariable,
        CopyMem_Arg_1,
        CopyMem_Arg_2,
        CopyMem_Arg_3,
        CopyMem_Arg_4
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
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_OPERATION Map_Arg_1 = 0;
    UINTN*  Map_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN * Map_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    EFI_PHYSICAL_ADDRESS * Map_Arg_4 = (EFI_PHYSICAL_ADDRESS *)AllocateZeroPool(sizeof(EFI_PHYSICAL_ADDRESS));
    UINTN* Map_Arg_5 = (UINTN*)AllocateZeroPool(sizeof(UINTN));
    
    // Constant Variable Initialization
    UINT8* Map_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Map_Arg_1_choice), (VOID *)Map_Arg_1_choice);
    switch(*Map_Arg_1_choice % 8) {
        case 0:
            Map_Arg_1 = EfiPciOperationBusMasterCommonBuffer;
            break;
        case 1:
            Map_Arg_1 = EfiPciOperationBusMasterCommonBuffer64;
            break;
        case 2:
            Map_Arg_1 = EfiPciOperationBusMasterRead;
            break;
        case 3:
            Map_Arg_1 = EfiPciOperationBusMasterRead64;
            break;
        case 4:
            Map_Arg_1 = EfiPciOperationBusMasterWrite;
            break;
        case 5:
            Map_Arg_1 = EfiPciOperationBusMasterWrite64;
            break;
        case 6:
            Map_Arg_1 = EfiPciOperationMaximum;
            break;
        case 7:
            ReadBytes(Input, sizeof(Map_Arg_1), (VOID *)&Map_Arg_1);
            break;
    }
    
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
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
        (void *)FreeBuffer_Arg_2
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
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT64 * GetAttributes_Arg_1 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    UINT64 * GetAttributes_Arg_2 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    
    // Fuzzable Variable Initialization
    UINT8 GetAttributes_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetAttributes_Arg_1_choice), (VOID *)&GetAttributes_Arg_1_choice);
    switch(GetAttributes_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetAttributes_Arg_1), (VOID *)GetAttributes_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(GetAttributes_Arg_1);
            GetAttributes_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetAttributes_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetAttributes_Arg_2_choice), (VOID *)&GetAttributes_Arg_2_choice);
    switch(GetAttributes_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetAttributes_Arg_2), (VOID *)GetAttributes_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(GetAttributes_Arg_2);
            GetAttributes_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetAttributes(
        ProtocolVariable,
        GetAttributes_Arg_1,
        GetAttributes_Arg_2
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
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT64 SetAttributes_Arg_1 = 0;
    UINT64 * SetAttributes_Arg_2 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    UINT64 * SetAttributes_Arg_3 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetAttributes_Arg_1), (VOID *)&SetAttributes_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 SetAttributes_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(SetAttributes_Arg_2_choice), (VOID *)&SetAttributes_Arg_2_choice);
    switch(SetAttributes_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetAttributes_Arg_2), (VOID *)SetAttributes_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(SetAttributes_Arg_2);
            SetAttributes_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 SetAttributes_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(SetAttributes_Arg_3_choice), (VOID *)&SetAttributes_Arg_3_choice);
    switch(SetAttributes_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetAttributes_Arg_3), (VOID *)SetAttributes_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(SetAttributes_Arg_3);
            SetAttributes_Arg_3 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->SetAttributes(
        ProtocolVariable,
        SetAttributes_Arg_1,
        SetAttributes_Arg_2,
        SetAttributes_Arg_3
    );
    return Status;
}

