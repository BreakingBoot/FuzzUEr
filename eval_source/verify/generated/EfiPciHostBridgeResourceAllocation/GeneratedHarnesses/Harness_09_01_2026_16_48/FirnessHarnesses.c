#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called GetNextRootBridge.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetNextRootBridge(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciHostBridgeResourceAllocationProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->GetNextRootBridge(
        ProtocolVariable,
        ImageHandle
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SubmitResources.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSubmitResources(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciHostBridgeResourceAllocationProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  SubmitResources_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    UINT8 SubmitResources_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(SubmitResources_Arg_2_choice), (VOID *)&SubmitResources_Arg_2_choice);
    switch(SubmitResources_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SubmitResources_Arg_2), (VOID *)SubmitResources_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(SubmitResources_Arg_2);
            SubmitResources_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->SubmitResources(
        ProtocolVariable,
        ImageHandle,
        (void *)SubmitResources_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called NotifyPhase.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzNotifyPhase(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciHostBridgeResourceAllocationProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PHASE NotifyPhase_Arg_1 = 0;
    
    // Constant Variable Initialization
    UINT8* NotifyPhase_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(NotifyPhase_Arg_1_choice), (VOID *)NotifyPhase_Arg_1_choice);
    switch(*NotifyPhase_Arg_1_choice % 11) {
        case 0:
            NotifyPhase_Arg_1 = EfiMaxPciHostBridgeEnumerationPhase;
            break;
        case 1:
            NotifyPhase_Arg_1 = EfiPciHostBridgeAllocateResources;
            break;
        case 2:
            NotifyPhase_Arg_1 = EfiPciHostBridgeBeginBusAllocation;
            break;
        case 3:
            NotifyPhase_Arg_1 = EfiPciHostBridgeBeginEnumeration;
            break;
        case 4:
            NotifyPhase_Arg_1 = EfiPciHostBridgeBeginResourceAllocation;
            break;
        case 5:
            NotifyPhase_Arg_1 = EfiPciHostBridgeEndBusAllocation;
            break;
        case 6:
            NotifyPhase_Arg_1 = EfiPciHostBridgeEndEnumeration;
            break;
        case 7:
            NotifyPhase_Arg_1 = EfiPciHostBridgeEndResourceAllocation;
            break;
        case 8:
            NotifyPhase_Arg_1 = EfiPciHostBridgeFreeResources;
            break;
        case 9:
            NotifyPhase_Arg_1 = EfiPciHostBridgeSetResources;
            break;
        case 10:
            ReadBytes(Input, sizeof(NotifyPhase_Arg_1), (VOID *)&NotifyPhase_Arg_1);
            break;
    }
    
    Status = ProtocolVariable->NotifyPhase(
        ProtocolVariable,
        NotifyPhase_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetProposedResources.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetProposedResources(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciHostBridgeResourceAllocationProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINTN* GetProposedResources_Arg_2 = (UINTN*)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetProposedResources_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetProposedResources_Arg_2_OutputChoice), (VOID *)GetProposedResources_Arg_2_OutputChoice);
    if(*GetProposedResources_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetProposedResources_Arg_2), (VOID *)GetProposedResources_Arg_2);
    }
    Status = ProtocolVariable->GetProposedResources(
        ProtocolVariable,
        ImageHandle,
        (void **)&GetProposedResources_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called StartBusEnumeration.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStartBusEnumeration(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciHostBridgeResourceAllocationProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINTN* StartBusEnumeration_Arg_2 = (UINTN*)AllocateZeroPool(sizeof(UINTN));
    UINT8* StartBusEnumeration_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(StartBusEnumeration_Arg_2_OutputChoice), (VOID *)StartBusEnumeration_Arg_2_OutputChoice);
    if(*StartBusEnumeration_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*StartBusEnumeration_Arg_2), (VOID *)StartBusEnumeration_Arg_2);
    }
    Status = ProtocolVariable->StartBusEnumeration(
        ProtocolVariable,
        ImageHandle,
        (void **)&StartBusEnumeration_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetBusNumbers.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetBusNumbers(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciHostBridgeResourceAllocationProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  SetBusNumbers_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    UINT8 SetBusNumbers_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(SetBusNumbers_Arg_2_choice), (VOID *)&SetBusNumbers_Arg_2_choice);
    switch(SetBusNumbers_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetBusNumbers_Arg_2), (VOID *)SetBusNumbers_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(SetBusNumbers_Arg_2);
            SetBusNumbers_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->SetBusNumbers(
        ProtocolVariable,
        ImageHandle,
        (void *)SetBusNumbers_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetAllocAttributes.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetAllocAttributes(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciHostBridgeResourceAllocationProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINT64 * GetAllocAttributes_Arg_2 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    UINT8* GetAllocAttributes_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetAllocAttributes_Arg_2_OutputChoice), (VOID *)GetAllocAttributes_Arg_2_OutputChoice);
    if(*GetAllocAttributes_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetAllocAttributes_Arg_2), (VOID *)GetAllocAttributes_Arg_2);
    }
    Status = ProtocolVariable->GetAllocAttributes(
        ProtocolVariable,
        ImageHandle,
        GetAllocAttributes_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called PreprocessController.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzPreprocessController(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciHostBridgeResourceAllocationProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_PCI_ADDRESS PreprocessController_Arg_2 = {0};
    EFI_PCI_CONTROLLER_RESOURCE_ALLOCATION_PHASE PreprocessController_Arg_3 = 0;
    
    // Generator Struct Variable Initialization
    {
        UINT8 Firness_Register;
        ReadBytes(Input, sizeof(Firness_Register), (VOID *)&Firness_Register);
        PreprocessController_Arg_2.Register = Firness_Register;
    }
    {
        UINT8 Firness_Function;
        ReadBytes(Input, sizeof(Firness_Function), (VOID *)&Firness_Function);
        PreprocessController_Arg_2.Function = Firness_Function;
    }
    {
        UINT8 Firness_Device;
        ReadBytes(Input, sizeof(Firness_Device), (VOID *)&Firness_Device);
        PreprocessController_Arg_2.Device = Firness_Device;
    }
    {
        UINT8 Firness_Bus;
        ReadBytes(Input, sizeof(Firness_Bus), (VOID *)&Firness_Bus);
        PreprocessController_Arg_2.Bus = Firness_Bus;
    }
    {
        UINT32 Firness_ExtendedRegister;
        ReadBytes(Input, sizeof(Firness_ExtendedRegister), (VOID *)&Firness_ExtendedRegister);
        PreprocessController_Arg_2.ExtendedRegister = Firness_ExtendedRegister;
    }
    
    // Constant Variable Initialization
    UINT8* PreprocessController_Arg_3_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(PreprocessController_Arg_3_choice), (VOID *)PreprocessController_Arg_3_choice);
    switch(*PreprocessController_Arg_3_choice % 3) {
        case 0:
            PreprocessController_Arg_3 = EfiPciBeforeChildBusEnumeration;
            break;
        case 1:
            PreprocessController_Arg_3 = EfiPciBeforeResourceCollection;
            break;
        case 2:
            ReadBytes(Input, sizeof(PreprocessController_Arg_3), (VOID *)&PreprocessController_Arg_3);
            break;
    }
    
    Status = ProtocolVariable->PreprocessController(
        ProtocolVariable,
        ImageHandle,
        PreprocessController_Arg_2,
        PreprocessController_Arg_3
    );
    return Status;
}

