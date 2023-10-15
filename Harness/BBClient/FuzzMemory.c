#include "FuzzMemory.h"

EFI_STATUS
EFIAPI
FuzzMemory(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    UINT8 MemoryService = 0;
    ReadInput(Input, 2, &MemoryService);
    switch(MemoryService%15)
    {
        case ADD_MEMORY_SPACE:
            Status = FuzzAddMemorySpace(Input);
            break;
        case ALLOCATE_MEMORY_SPACE:
            Status = FuzzAllocateMemorySpace(Input);
            break;
        case FREE_MEMORY_SPACE:
            Status = FuzzFreeMemorySpace(Input);
            break;
        case REMOVE_MEMORY_SPACE:
            Status = FuzzRemoveMemorySpace(Input);
            break;
        case GET_MEMORY_SPACE_DESCRIPTOR:
            Status = FuzzGetMemorySpaceDescriptor(Input);
            break;
        case SET_MEMORY_SPACE_ATTRIBUTES:
            Status = FuzzSetMemorySpaceAttributes(Input);
            break;
        case GET_MEMORY_SPACE_MAP:
            Status = FuzzGetMemorySpaceMap(Input);
            break;
        case SET_MEMORY_SPACE_CAPABILITIES:
            Status = FuzzSetMemorySpaceCapabilities(Input);
            break;
        case ALLOCATE_PAGES:
            Status = FuzzAllocatePages(Input);
            break;
        case FREE_PAGES:
            Status = FuzzFreePages(Input);
            break;
        case GET_MEMORY_MAP:
            Status = FuzzGetMemoryMap(Input);
            break;
        case ALLOCATE_POOL:
            Status = FuzzAllocatePool(Input);
            break;
        case FREE_POOL:
            Status = FuzzFreePool(Input);
            break;
        case COPY_MEM:
            Status = FuzzCopyMem(Input);
            break;
        case SET_MEM:
            Status = FuzzSetMem(Input);
            break;
    }
    return Status;
}

EFI_STATUS
EFIAPI
FuzzAddMemorySpace(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: AddMemorySpace\n"));

    EFI_GCD_MEMORY_TYPE GcdMemoryType; // IN
    UINT8 MemoryChoice = 0;
    ReadInput(Input, 1, &MemoryChoice);
    switch(MemoryChoice%8)
    {
        case 0:
            GcdMemoryType = EfiGcdMemoryTypeNonExistent;
            break;
        case 1:
            GcdMemoryType = EfiGcdMemoryTypeReserved;
            break;            
        case 2:
            GcdMemoryType = EfiGcdMemoryTypeSystemMemory;
            break;
        case 3:
            GcdMemoryType = EfiGcdMemoryTypeMemoryMappedIo;
            break;
        case 4:
            GcdMemoryType = EfiGcdMemoryTypePersistent;
            break;
        case 5:
            GcdMemoryType = EfiGcdMemoryTypePersistentMemory;
            break;
        case 6:
            GcdMemoryType = EfiGcdMemoryTypeMoreReliable;
            break;
        case 7:
            GcdMemoryType = EfiGcdMemoryTypeMaximum;
            break;
    }
    UINT8* BaseAddress = AllocatePool(sizeof(UINTN)); // IN
    ReadInput(Input, sizeof(BaseAddress), BaseAddress);
    UINT8* Length = AllocatePool(sizeof(UINTN)); // IN
    ReadInput(Input, sizeof(Length), Length);
    UINT64 Capabilities = 0; // IN
    UINT8 NumberOfCapabilities = 0;
    ReadInput(Input, 1, &NumberOfCapabilities);
    UINT8 CurrentCapability = 0;
    for(UINTN i = 0; i < NumberOfCapabilities; i++)
    {
        ReadInput(Input, 1, &CurrentCapability);
        switch(CurrentCapability%10)
        {
            case 0:
                Capabilities |= EFI_MEMORY_RO;
                break;
            case 1:
                Capabilities |= EFI_MEMORY_RP;
                break;
            case 2:
                Capabilities |= EFI_MEMORY_XP;
                break;
            case 3:
                Capabilities |= EFI_MEMORY_WP;
                break;
            case 4:
                Capabilities |= EFI_MEMORY_WC;
                break;
            case 5:
                Capabilities |= EFI_MEMORY_UC;
                break;
            case 6:
                Capabilities |= EFI_MEMORY_UCE;
                break;
            case 7:
                Capabilities |= EFI_MEMORY_WT;
                break;
            case 8:
                Capabilities |= EFI_MEMORY_WB;
                break;
            case 9:
                Capabilities |= EFI_MEMORY_NV;
                break;
        }  
    }

    Status = gDS->AddMemorySpace(GcdMemoryType,
                                (EFI_PHYSICAL_ADDRESS)BaseAddress,
                                *(UINTN *)Length,
                                Capabilities);
    return Status;
}

EFI_STATUS
EFIAPI
FuzzAllocateMemorySpace(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: AllocateMemorySpace\n"));
    EFI_GCD_MEMORY_TYPE GcdMemoryType; // IN
    UINT8 MemoryChoice = 0;
    ReadInput(Input, 1, &MemoryChoice);
    switch(MemoryChoice%8)
    {
        case 0:
            GcdMemoryType = EfiGcdMemoryTypeNonExistent;
            break;
        case 1:
            GcdMemoryType = EfiGcdMemoryTypeReserved;
            break;            
        case 2:
            GcdMemoryType = EfiGcdMemoryTypeSystemMemory;
            break;
        case 3:
            GcdMemoryType = EfiGcdMemoryTypeMemoryMappedIo;
            break;
        case 4:
            GcdMemoryType = EfiGcdMemoryTypePersistent;
            break;
        case 5:
            GcdMemoryType = EfiGcdMemoryTypePersistentMemory;
            break;
        case 6:
            GcdMemoryType = EfiGcdMemoryTypeMoreReliable;
            break;
        case 7:
            GcdMemoryType = EfiGcdMemoryTypeMaximum;
            break;
    }
    EFI_GCD_ALLOCATE_TYPE GcdAllocateType; // IN
    UINT8 AllocateChoice = 0;
    ReadInput(Input, 1, &AllocateChoice);
    switch(AllocateChoice%6)
    {
        case 0:
            GcdAllocateType = EfiGcdAllocateAnySearchBottomUp;
            break;
        case 1:
            GcdAllocateType = EfiGcdAllocateMaxAddressSearchBottomUp;
            break;
        case 2:
            GcdAllocateType = EfiGcdAllocateAddress;
            break;
        case 3:
            GcdAllocateType = EfiGcdAllocateAnySearchTopDown;
            break;
        case 4:
            GcdAllocateType = EfiGcdAllocateMaxAddressSearchTopDown;
            break;
        case 5:
            GcdAllocateType = EfiGcdMaxAllocateType;
            break;           
    }
    UINT8 Alignment = 0; // IN
    ReadInput(Input, sizeof(Alignment), &Alignment);
    UINT8* Length = AllocatePool(sizeof(UINTN)); // IN
    ReadInput(Input, sizeof(Length), Length);
    UINT8* BaseAddress = AllocatePool(sizeof(UINTN)); // IN OUT
    ReadInput(Input, sizeof(BaseAddress), BaseAddress);
    //EFI_HANDLE ImageHandle = NULL; // IN
    EFI_HANDLE DeviceHandle = NULL; // IN

    Status = gDS->AllocateMemorySpace(GcdAllocateType,
                                    GcdMemoryType,
                                    Alignment,
                                    *(UINT64 *)Length,
                                    (EFI_PHYSICAL_ADDRESS *)BaseAddress,
                                    gImageHandle,
                                    DeviceHandle);

    return Status;
}

EFI_STATUS
EFIAPI
FuzzFreeMemorySpace(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: FreeMemorySpace\n"));
    UINT8* Length = AllocatePool(sizeof(UINTN)); // IN
    ReadInput(Input, sizeof(Length), Length);
    UINT8* BaseAddress = AllocatePool(sizeof(UINTN)); // IN
    ReadInput(Input, sizeof(BaseAddress), BaseAddress);

    Status = gDS->FreeMemorySpace((EFI_PHYSICAL_ADDRESS)*(UINTN *)BaseAddress,
                                *(UINT64 *)Length);

    return Status;
}

EFI_STATUS
EFIAPI
FuzzRemoveMemorySpace(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: RemoveMemorySpace\n"));
    UINT8* Length = AllocatePool(sizeof(UINTN)); // IN
    ReadInput(Input, sizeof(Length), Length);
    UINT8* BaseAddress = AllocatePool(sizeof(UINTN)); // IN
    ReadInput(Input, sizeof(BaseAddress), BaseAddress);

    Status = gDS->RemoveMemorySpace((EFI_PHYSICAL_ADDRESS)*(UINTN *)BaseAddress,
                                    *(UINT64 *)Length);
    return Status;
}

EFI_STATUS
EFIAPI
FuzzGetMemorySpaceDescriptor(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: GetMemorySpaceDescriptor\n"));
    UINT8* BaseAddress = AllocatePool(sizeof(UINTN)); // IN
    ReadInput(Input, sizeof(BaseAddress), BaseAddress);
    EFI_GCD_MEMORY_SPACE_DESCRIPTOR Descriptor; // OUT

    Status = gDS->GetMemorySpaceDescriptor((EFI_PHYSICAL_ADDRESS)*(UINTN *)BaseAddress,
                                            &Descriptor);
    return Status;
}

EFI_STATUS
EFIAPI
FuzzSetMemorySpaceAttributes(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: SetMemorySpaceAttributes\n"));
    UINT8* Length = AllocatePool(sizeof(UINTN)); // IN
    ReadInput(Input, sizeof(Length), Length);
    UINT8* BaseAddress = AllocatePool(sizeof(UINTN)); // IN
    ReadInput(Input, sizeof(BaseAddress), BaseAddress);
    UINT64 Attributes = 0; // IN

    UINT8 NumberOfAttributes = 0;
    ReadInput(Input, 1, &NumberOfAttributes);
    UINT8 CurrentAttributes = 0;
    for(UINTN i = 0; i < NumberOfAttributes; i++)
    {
        ReadInput(Input, 1, &CurrentAttributes);
        switch(CurrentAttributes%10)
        {
            case 0:
                Attributes |= EFI_MEMORY_RO;
                break;
            case 1:
                Attributes |= EFI_MEMORY_RP;
                break;
            case 2:
                Attributes |= EFI_MEMORY_XP;
                break;
            case 3:
                Attributes |= EFI_MEMORY_WP;
                break;
            case 4:
                Attributes |= EFI_MEMORY_WC;
                break;
            case 5:
                Attributes |= EFI_MEMORY_UC;
                break;
            case 6:
                Attributes |= EFI_MEMORY_UCE;
                break;
            case 7:
                Attributes |= EFI_MEMORY_WT;
                break;
            case 8:
                Attributes |= EFI_MEMORY_WB;
                break;
            case 9:
                Attributes |= EFI_MEMORY_NV;
                break;
        }  
    }

    Status = gDS->SetMemorySpaceAttributes((EFI_PHYSICAL_ADDRESS)*(UINTN *)BaseAddress,
                                            *(UINT64 *)Length,
                                            Attributes);

    return Status;
}


EFI_STATUS
EFIAPI
FuzzGetMemorySpaceMap(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: GetMemorySpaceMap\n"));
    UINTN NumberOfDescriptors; // OUT
    EFI_GCD_MEMORY_SPACE_DESCRIPTOR *MemorySpaceMap = NULL; // OUT
    Status = gDS->GetMemorySpaceMap(&NumberOfDescriptors,
                                    &MemorySpaceMap);

    return Status;
}

EFI_STATUS
EFIAPI
FuzzSetMemorySpaceCapabilities(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: SetMemorySpaceCapabilities\n"));
    UINT8* Length = AllocatePool(sizeof(UINTN)); // IN
    ReadInput(Input, sizeof(Length), Length);
    UINT8* BaseAddress = AllocatePool(sizeof(UINTN)); // IN
    ReadInput(Input, sizeof(BaseAddress), BaseAddress);
    UINT64 Capabilities = 0; // IN
    UINT8 NumberOfCapabilities = 0;
    ReadInput(Input, 1, &NumberOfCapabilities);
    UINT8 CurrentCapability = 0;
    for(UINTN i = 0; i < NumberOfCapabilities; i++)
    {
        ReadInput(Input, 1, &CurrentCapability);
        switch(CurrentCapability%10)
        {
            case 0:
                Capabilities |= EFI_MEMORY_RO;
                break;
            case 1:
                Capabilities |= EFI_MEMORY_RP;
                break;
            case 2:
                Capabilities |= EFI_MEMORY_XP;
                break;
            case 3:
                Capabilities |= EFI_MEMORY_WP;
                break;
            case 4:
                Capabilities |= EFI_MEMORY_WC;
                break;
            case 5:
                Capabilities |= EFI_MEMORY_UC;
                break;
            case 6:
                Capabilities |= EFI_MEMORY_UCE;
                break;
            case 7:
                Capabilities |= EFI_MEMORY_WT;
                break;
            case 8:
                Capabilities |= EFI_MEMORY_WB;
                break;
            case 9:
                Capabilities |= EFI_MEMORY_NV;
                break;
        }  
    }

    Status = gDS->SetMemorySpaceCapabilities((EFI_PHYSICAL_ADDRESS)*(UINTN *)BaseAddress,
                                                *(UINT64 *)Length,
                                                Capabilities);

    return Status;
}

EFI_STATUS
EFIAPI
FuzzAllocatePages(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: AllocatePages\n"));
    EFI_ALLOCATE_TYPE Type; // IN
    UINT8 TypeChoice = 0;
    ReadInput(Input, 1, &TypeChoice);
    switch(TypeChoice%4)
    {
        case 0:
            Type = AllocateAnyPages;
            break;
        case 1:
            Type = AllocateMaxAddress;
            break;
        case 2:
            Type = AllocateAddress;
            break;
        case 3:
            Type = MaxAllocateType;
            break;
    } 
    EFI_MEMORY_TYPE MemoryType; // IN
    UINT8 MemoryChoice = 0;
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
            break;
    }
    UINT8* PageSize = AllocatePool(sizeof(UINTN));
    ReadInput(Input, sizeof(UINTN), PageSize);
    UINTN NumberOfPages = EFI_SIZE_TO_PAGES(*(UINTN *)PageSize); // IN
    UINT8* Memory = AllocatePool(sizeof(UINTN)); // IN OUT
    ReadInput(Input, sizeof(UINTN), Memory);

    Status = gBS->AllocatePages(Type,
                                MemoryType,
                                NumberOfPages,
                                (EFI_PHYSICAL_ADDRESS *)*(UINTN *)Memory);

    return Status;
}

EFI_STATUS
EFIAPI
FuzzFreePages(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: FreePages\n"));
    UINT8* Memory = AllocatePool(sizeof(UINTN)); // IN
    ReadInput(Input, sizeof(UINTN), Memory);
    UINTN NumberOfPages = EFI_SIZE_TO_PAGES(*(UINTN *)Memory); // IN

    Status = gBS->FreePages((EFI_PHYSICAL_ADDRESS)*(UINTN *)Memory,
                            NumberOfPages);
    return Status;
}

EFI_STATUS
EFIAPI
FuzzGetMemoryMap(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: GetMemoryMap\n"));
    UINT8* MemoryMapSize = AllocatePool(sizeof(UINTN)); // IN OUT
    ReadInput(Input, sizeof(UINTN), MemoryMapSize);
    EFI_MEMORY_DESCRIPTOR *MemoryMap = (EFI_MEMORY_DESCRIPTOR *)AllocatePool(*(UINTN *)MemoryMapSize); // IN OUT
    UINTN MapKey = 0; // OUT
    UINTN DescriptorSize = 0; // OUT
    UINT32 DescriptorVersion = 0; // OUT

    Status = gBS->GetMemoryMap((UINTN *)MemoryMapSize,
                                MemoryMap,
                                &MapKey,
                                &DescriptorSize,
                                &DescriptorVersion);
    return Status;
}

EFI_STATUS
EFIAPI
FuzzAllocatePool(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: AllocatePool\n"));
    EFI_MEMORY_TYPE PoolType; // IN
    UINT8 MemoryChoice = 0;
    ReadInput(Input, 1, &MemoryChoice);
    switch(MemoryChoice%16)
    {
        case 0:
            PoolType = EfiReservedMemoryType;
            break;
        case 1:
            PoolType = EfiLoaderCode;
            break;
        case 2:
            PoolType = EfiLoaderData;
            break;
        case 3:
            PoolType = EfiBootServicesCode;
            break;
        case 4:
            PoolType = EfiBootServicesData;
            break;
        case 5:
            PoolType = EfiRuntimeServicesCode;
            break;
        case 6:
            PoolType = EfiRuntimeServicesData;
            break;
        case 7:
            PoolType = EfiConventionalMemory;
            break;
        case 8:
            PoolType = EfiUnusableMemory;
            break;
        case 9:
            PoolType = EfiACPIReclaimMemory;
            break;
        case 10:
            PoolType = EfiACPIMemoryNVS;
            break;
        case 11:
            PoolType = EfiMemoryMappedIO;
            break;
        case 12:
            PoolType = EfiMemoryMappedIOPortSpace;
            break;
        case 13:
            PoolType = EfiPalCode;
            break;
        case 14:
            PoolType = EfiPersistentMemory;
            break;
        case 15:
            PoolType = EfiMaxMemoryType;
            break;
    }
    UINT8* Size = AllocatePool(sizeof(UINTN)); // IN
    ReadInput(Input, sizeof(UINTN), Size);
    UINT8* Buffer = AllocatePool(sizeof(UINTN)); // OUT
    ReadInput(Input, sizeof(UINTN), Buffer);

    Status = gBS->AllocatePool(PoolType,
                                *(UINTN *)Size,
                                (VOID **)(UINTN *)Buffer);
    return Status;
}

EFI_STATUS
EFIAPI
FuzzFreePool(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: FreePool\n"));
    UINT8* Buffer = AllocatePool(sizeof(UINTN)); // IN
    ReadInput(Input, sizeof(UINTN), Buffer);

    Status = gBS->FreePool((VOID *)*(UINTN *)Buffer);

    return Status;
}

EFI_STATUS
EFIAPI
FuzzCopyMem(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: CopyMem\n"));
    UINT8* Destination = AllocatePool(sizeof(UINTN)); // OUT
    ReadInput(Input, sizeof(UINTN), Destination);
    UINT8* Source = AllocatePool(sizeof(UINTN)); // IN
    ReadInput(Input, sizeof(UINTN), Source);
    UINT8* Length = AllocatePool(sizeof(UINTN)); // IN
    ReadInput(Input, sizeof(UINTN), Length);



    gBS->CopyMem((VOID *)*(UINTN *)Destination,
                (VOID *)*(UINTN *)Source,
                *(UINTN *)Length);
    
    return Status;
}

EFI_STATUS
EFIAPI
FuzzSetMem(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: SetMem\n"));
    UINT8* Destination = AllocatePool(sizeof(UINTN)); // OUT
    ReadInput(Input, sizeof(UINTN), Destination);
    UINT8* Length = AllocatePool(sizeof(UINTN)); // IN
    ReadInput(Input, sizeof(UINTN), Length);
    UINT8* Value = AllocatePool(sizeof(UINTN)); // IN
    ReadInput(Input, sizeof(UINTN), Value);

    gBS->SetMem((VOID *)*(UINTN *)Destination,
                *(UINTN *)Length,
                *(UINTN *)Value);
    return Status;
}