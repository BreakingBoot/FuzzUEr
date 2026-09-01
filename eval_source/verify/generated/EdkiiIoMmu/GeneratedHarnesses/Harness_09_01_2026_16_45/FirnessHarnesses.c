#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called SetAttribute.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetAttribute(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_IOMMU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiIoMmuProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  SetAttribute_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT64 SetAttribute_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    UINT8 SetAttribute_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(SetAttribute_Arg_2_choice), (VOID *)&SetAttribute_Arg_2_choice);
    switch(SetAttribute_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetAttribute_Arg_2), (VOID *)SetAttribute_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(SetAttribute_Arg_2);
            SetAttribute_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetAttribute_Arg_3), (VOID *)&SetAttribute_Arg_3);
    
    Status = ProtocolVariable->SetAttribute(
        ProtocolVariable,
        ImageHandle,
        (void *)SetAttribute_Arg_2,
        SetAttribute_Arg_3
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
    EDKII_IOMMU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiIoMmuProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EDKII_IOMMU_OPERATION Map_Arg_1 = 0;
    UINTN*  Map_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN * Map_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Constant Variable Initialization
    UINT8* Map_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Map_Arg_1_choice), (VOID *)Map_Arg_1_choice);
    switch(*Map_Arg_1_choice % 8) {
        case 0:
            Map_Arg_1 = EdkiiIoMmuOperationBusMasterCommonBuffer;
            break;
        case 1:
            Map_Arg_1 = EdkiiIoMmuOperationBusMasterCommonBuffer64;
            break;
        case 2:
            Map_Arg_1 = EdkiiIoMmuOperationBusMasterRead;
            break;
        case 3:
            Map_Arg_1 = EdkiiIoMmuOperationBusMasterRead64;
            break;
        case 4:
            Map_Arg_1 = EdkiiIoMmuOperationBusMasterWrite;
            break;
        case 5:
            Map_Arg_1 = EdkiiIoMmuOperationBusMasterWrite64;
            break;
        case 6:
            Map_Arg_1 = EdkiiIoMmuOperationMaximum;
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
    EDKII_IOMMU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiIoMmuProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    EDKII_IOMMU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiIoMmuProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    EDKII_IOMMU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiIoMmuProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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

