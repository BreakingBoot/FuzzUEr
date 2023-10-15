#include "FuzzUfsHostController.h"

EFI_STATUS
EFIAPI
FuzzUfsHostController(
    IN INPUT_BUFFER* Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: UfsHostController\n"));
    UINTN ProtocolChoice = 0;
    ReadInput(Input, 1, ProtocolChoice);
    switch(ProtocolChoice%8)
    {
        case GET_UFS_HC_MMIO_BAR:
            Status = FuzzGetUfsHcMmioBar(Input);
            break;
        case ALLOCATE_BUFFER:
            Status = FuzzAllocateBuffer(Input);
            break;
        case FREE_BUFFER:
            Status = FuzzFreeBuffer(Input);
            break;
        case MAP:
            Status = FuzzMap(Input);
            break;
        case UNMAP:
            Status = FuzzUnmap(Input);
            break;
        case FLUSH:
            Status = FuzzFlush(Input);
            break;
        case MMIO_READ:
            Status = FuzzRead(Input);
            break;
        case MMIO_WRITE:
            Status = FuzzWrite(Input);
            break;
    }

    return Status;
}

EFI_STATUS
EFIAPI
FuzzGetUfsHcMmioBar(
    IN INPUT_BUFFER* Input
)
{
    EFI_STATUS Status = EFI_STATUS;
    DEBUG((DEBUG_ERROR, "FUZZING: GetUfsHcMmioBar\n"));
    EDKII_UFS_HOST_CONTROLLER_PROTOCOL *UfsHostControllerProtocol;
    gBS->LocateProtocol(&gEdkiiUfsHostControllerProtocolGuid, NULL, (VOID **)&UfsHostControllerProtocol);

    UINTN MmioBar;

    Status = UfsHostControllerProtocol->GetUfsHcMmioBar(UfsHostControllerProtocol, &MmioBar);

    return Status;
}


EFI_STATUS
EFIAPI
FuzzAllocateBuffer(
    IN INPUT_BUFFER* Input
)
{
    EFI_STATUS Status = EFI_STATUS;
    DEBUG((DEBUG_ERROR, "FUZZING: AllocateBuffer\n"));
    EDKII_UFS_HOST_CONTROLLER_PROTOCOL *UfsHostControllerProtocol;
    gBS->LocateProtocol(&gEdkiiUfsHostControllerProtocolGuid, NULL, (VOID **)&UfsHostControllerProtocol);

    EFI_ALLOCATE_TYPE AllocateType = NULL;
    UINTN AllocateChoice = 0;
    ReadInput(Input, 1, &AllocateChoice);
    switch(AllocateChoice%4)
    {
        case 0:
            AllocateType = AllocateAnyPages;
            break;
        case 1:
            AllocateType = AllocateMaxAddress;
            break;
        case 2:
            AllocateType = AllocateAddress;
            break;
        case 3:
            AllocateType = MaxAllocateType;
            break;
    }

    EFI_MEMORY_TYPE MemoryType = NULL;
    UINTN MemoryChoice = 0;
    ReadInput(Input, 1, &MemoryChoice);

    switch(MemoryChoice%16)
    {
        case 0:
            MemoryType = EfiReservedMemoryType;
            break;
        case 1:
            MemoryType = EfiLoaderCode;
            break;
        case 2:
            MemoryType = EfiLoaderData;
            break;
        case 3:
            MemoryType = EfiBootServicesCode;
            break;
        case 4:
            MemoryType = EfiBootServicesData;
            break;
        case 5:
            MemoryType = EfiRuntimeServicesCode;
            break;
        case 6:
            MemoryType = EfiRuntimeServicesData;
            break;
        case 7:
            MemoryType = EfiConventionalMemory;
            break;
        case 8:
            MemoryType = EfiUnusableMemory;
            break;
        case 9:
            MemoryType = EfiACPIReclaimMemory;
            break;
        case 10:
            MemoryType = EfiACPIMemoryNVS;
            break;
        case 11:
            MemoryType = EfiMemoryMappedIO;
            break;
        case 12:
            MemoryType = EfiMemoryMappedIOPortSpace;
            break;
        case 13:
            MemoryType = EfiPalCode;
            break;
        case 14:
            MemoryType = EfiPersistentMemory;
            break;
        case 15:
            MemoryType = EfiMaxMemoryType;
    }


    UINTN Pages = 0
    ReadInput(Input, 1, &Pages);

    UINTN AttributesChoice = 0;
    UINT64 Attributes = 0;
    ReadInput(Input, 1, &AttributesChoice);
    switch(AttributesChoice%4)
    {
        case 0:
            Attribute = EdkiiUfsHcOperationBusMasterRead;
            break;
        case 1:
            Attribute = EdkiiUfsHcOperationBusMasterWrite;
            break;
        case 2:
            Attribute = EdkiiUfsHcOperationBusMasterCommonBuffer;
            break;
        case 3:
            Attribute = EdkiiUfsHcOperationMaximum;
            break;
    }
    
    UINTN HostAddress = 0;

    Status = UfsHostControllerProtocol->AllocateBuffer(UfsHostControllerProtocol, 
                                                        AllocateType, 
                                                        MemoryType, 
                                                        Pages, 
                                                        (VOID **)&HostAddress, 
                                                        Attributes);

    return Status;
}

EFI_STATUS
EFIAPI
FuzzFreeBuffer(
    IN INPUT_BUFFER* Input
)
{
    EFI_STATUS Status = EFI_STATUS;
    DEBUG((DEBUG_ERROR, "FUZZING: FreeBuffer\n"));
    EDKII_UFS_HOST_CONTROLLER_PROTOCOL *UfsHostControllerProtocol;
    gBS->LocateProtocol(&gEdkiiUfsHostControllerProtocolGuid, NULL, (VOID **)&UfsHostControllerProtocol);

    UINTN Pages = 0
    ReadInput(Input, 1, &Pages);

    UINTN HostAddress = 0;
    ReadInput(Input, sizeof(HostAddress), &HostAddress);

    Status = UfsHostControllerProtocol->FreeBuffer(UfsHostControllerProtocol, Pages, (VOID *)HostAddress);

    return Status;
}


EFI_STATUS
EFIAPI
FuzzMap(
    IN INPUT_BUFFER* Input
)
{
    EFI_STATUS Status = EFI_STATUS;
    DEBUG((DEBUG_ERROR, "FUZZING: Map\n"));
    EDKII_UFS_HOST_CONTROLLER_PROTOCOL *UfsHostControllerProtocol;
    gBS->LocateProtocol(&gEdkiiUfsHostControllerProtocolGuid, NULL, (VOID **)&UfsHostControllerProtocol);

    EDKII_UFS_HOST_CONTROLLER_OPERATION Operation;

    UINTN OperationChoice = 0;
    ReadInput(Input, 1, &OperationChoice);
    switch(OperationChoice%4)
    {
        case 0:
            Operation = EdkiiUfsHcOperationBusMasterRead;
            break;
        case 1:
            Operation = EdkiiUfsHcOperationBusMasterWrite;
            break;
        case 2:
            Operation = EdkiiUfsHcOperationBusMasterCommonBuffer;
            break;
        case 3:
            Operation = EdkiiUfsHcOperationMaximum;
            break;
    }

    UINTN HostAddress = 0;
    ReadInput(Input, sizeof(HostAddress), &HostAddress);

    UINTN NumberOfBytes = 0;
    ReadInput(Input, sizeof(NumberOfBytes), &NumberOfBytes);
    EFI_PHYSICAL_ADDRESS DeviceAddress;
    UINTN Mapping = 0;
    ReadInput(Input, sizeof(Mapping), &Mapping);


    Status = UfsHostControllerProtocol->Map(UfsHostControllerProtocol, 
                                            Operation, 
                                            (VOID *)HostAddress, 
                                            &NumberOfBytes, 
                                            &DeviceAddress, 
                                            (VOID **)&Mapping);

    return Status;
}

EFI_STATUS
EFIAPI
FuzzUnmap(
    IN INPUT_BUFFER* Input
)
{
    EFI_STATUS Status = EFI_STATUS;
    DEBUG((DEBUG_ERROR, "FUZZING: Unmap\n"));
    EDKII_UFS_HOST_CONTROLLER_PROTOCOL *UfsHostControllerProtocol;
    gBS->LocateProtocol(&gEdkiiUfsHostControllerProtocolGuid, NULL, (VOID **)&UfsHostControllerProtocol);

    UINTN Mapping = 0;
    ReadInput(Input, sizeof(Mapping), &Mapping);

    Status = UfsHostControllerProtocol->Unmap(UfsHostControllerProtocol, (VOID *)Mapping)

    return Status;
}


EFI_STATUS
EFIAPI
FuzzFlush(
    IN INPUT_BUFFER* Input
)
{
    EFI_STATUS Status = EFI_STATUS;
    DEBUG((DEBUG_ERROR, "FUZZING: Flush\n"));
    EDKII_UFS_HOST_CONTROLLER_PROTOCOL *UfsHostControllerProtocol;
    gBS->LocateProtocol(&gEdkiiUfsHostControllerProtocolGuid, NULL, (VOID **)&UfsHostControllerProtocol);

    Status = UfsHostControllerProtocol->Flush(UfsHostControllerProtocol);

    return Status;
}

EFI_STATUS
EFIAPI
FuzzRead(
    IN INPUT_BUFFER* Input
)
{
    EFI_STATUS Status = EFI_STATUS;
    DEBUG((DEBUG_ERROR, "FUZZING: Read\n"));
    EDKII_UFS_HOST_CONTROLLER_PROTOCOL *UfsHostControllerProtocol;
    gBS->LocateProtocol(&gEdkiiUfsHostControllerProtocolGuid, NULL, (VOID **)&UfsHostControllerProtocol);

    EDKII_UFS_HOST_CONTROLLER_PROTOCOL_WIDTH ControllerWidth;
    UINTN WidthChoice = 0;
    ReadInput(Input, 1, &WidthChoice);
    switch(WidthChoice%5)
    {
        case 0:
            ControllerWidth = EfiUfsHcWidthUint8;
            break;
        case 1:
            ControllerWidth = EfiUfsHcWidthUint16;
            break;
        case 2:
            ControllerWidth = EfiUfsHcWidthUint32;
            break;
        case 3:
            ControllerWidth = EfiUfsHcWidthUint64;
            break;
        case 4:
            ControllerWidth = EfiUfsHcWidthMaximum;
            break;
    }

    UINT64 Offset = 0;
    ReadInput(Input, 8, &Offset);

    UINTN Count = 0;
    ReadInput(Input, sizeof(Count), &Count);

    UINTN Buffer = 0;
    ReadInput(Input, sizeof(Buffer), &Buffer);

    Status = UfsHostControllerProtocol->Read(UfsHostControllerProtocol, 
                                             ControllerWidth, 
                                             Offset, 
                                             Count, 
                                             (VOID *)Buffer);


    return Status;
}


EFI_STATUS
EFIAPI
FuzzWrite(
    IN INPUT_BUFFER* Input
)
{
    EFI_STATUS Status = EFI_STATUS;
    DEBUG((DEBUG_ERROR, "FUZZING: Write\n"));
    EDKII_UFS_HOST_CONTROLLER_PROTOCOL *UfsHostControllerProtocol;
    gBS->LocateProtocol(&gEdkiiUfsHostControllerProtocolGuid, NULL, (VOID **)&UfsHostControllerProtocol);

    EDKII_UFS_HOST_CONTROLLER_PROTOCOL_WIDTH ControllerWidth;
    UINTN WidthChoice = 0;
    ReadInput(Input, 1, &WidthChoice);
    switch(WidthChoice%5)
    {
        case 0:
            ControllerWidth = EfiUfsHcWidthUint8;
            break;
        case 1:
            ControllerWidth = EfiUfsHcWidthUint16;
            break;
        case 2:
            ControllerWidth = EfiUfsHcWidthUint32;
            break;
        case 3:
            ControllerWidth = EfiUfsHcWidthUint64;
            break;
        case 4:
            ControllerWidth = EfiUfsHcWidthMaximum;
            break;
    }

    UINT64 Offset = 0;
    ReadInput(Input, 8, &Offset);

    UINTN Count = 0;
    ReadInput(Input, sizeof(Count), &Count);

    UINTN Buffer = 0;
    ReadInput(Input, sizeof(Buffer), &Buffer);

    Status = UfsHostControllerProtocol->Write(UfsHostControllerProtocol, 
                                             ControllerWidth, 
                                             Offset, 
                                             Count, 
                                             (VOID *)Buffer);


    return Status;
}