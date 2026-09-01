#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called GetPciRom.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetPciRom(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_PLATFORM_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciPlatformProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINTN* GetPciRom_Arg_2 = (UINTN*)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetPciRom_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetPciRom_Arg_2_OutputChoice), (VOID *)GetPciRom_Arg_2_OutputChoice);
    if(*GetPciRom_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetPciRom_Arg_2), (VOID *)GetPciRom_Arg_2);
    }
    UINTN * GetPciRom_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetPciRom_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetPciRom_Arg_3_OutputChoice), (VOID *)GetPciRom_Arg_3_OutputChoice);
    if(*GetPciRom_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetPciRom_Arg_3), (VOID *)GetPciRom_Arg_3);
    }
    Status = ProtocolVariable->GetPciRom(
        ProtocolVariable,
        ImageHandle,
        (void **)&GetPciRom_Arg_2,
        GetPciRom_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetPlatformPolicy.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetPlatformPolicy(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_PLATFORM_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciPlatformProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_PCI_PLATFORM_POLICY * GetPlatformPolicy_Arg_1 = (EFI_PCI_PLATFORM_POLICY *)AllocateZeroPool(sizeof(EFI_PCI_PLATFORM_POLICY));
    UINT8* GetPlatformPolicy_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetPlatformPolicy_Arg_1_OutputChoice), (VOID *)GetPlatformPolicy_Arg_1_OutputChoice);
    if(*GetPlatformPolicy_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetPlatformPolicy_Arg_1), (VOID *)GetPlatformPolicy_Arg_1);
    }
    Status = ProtocolVariable->GetPlatformPolicy(
        ProtocolVariable,
        GetPlatformPolicy_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called PlatformNotify.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzPlatformNotify(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_PLATFORM_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciPlatformProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PHASE PlatformNotify_Arg_2 = 0;
    EFI_PCI_EXECUTION_PHASE PlatformNotify_Arg_3 = 0;
    
    // Constant Variable Initialization
    UINT8* PlatformNotify_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(PlatformNotify_Arg_2_choice), (VOID *)PlatformNotify_Arg_2_choice);
    switch(*PlatformNotify_Arg_2_choice % 11) {
        case 0:
            PlatformNotify_Arg_2 = EfiMaxPciHostBridgeEnumerationPhase;
            break;
        case 1:
            PlatformNotify_Arg_2 = EfiPciHostBridgeAllocateResources;
            break;
        case 2:
            PlatformNotify_Arg_2 = EfiPciHostBridgeBeginBusAllocation;
            break;
        case 3:
            PlatformNotify_Arg_2 = EfiPciHostBridgeBeginEnumeration;
            break;
        case 4:
            PlatformNotify_Arg_2 = EfiPciHostBridgeBeginResourceAllocation;
            break;
        case 5:
            PlatformNotify_Arg_2 = EfiPciHostBridgeEndBusAllocation;
            break;
        case 6:
            PlatformNotify_Arg_2 = EfiPciHostBridgeEndEnumeration;
            break;
        case 7:
            PlatformNotify_Arg_2 = EfiPciHostBridgeEndResourceAllocation;
            break;
        case 8:
            PlatformNotify_Arg_2 = EfiPciHostBridgeFreeResources;
            break;
        case 9:
            PlatformNotify_Arg_2 = EfiPciHostBridgeSetResources;
            break;
        case 10:
            ReadBytes(Input, sizeof(PlatformNotify_Arg_2), (VOID *)&PlatformNotify_Arg_2);
            break;
    }
    
    // Constant Variable Initialization
    UINT8* PlatformNotify_Arg_3_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(PlatformNotify_Arg_3_choice), (VOID *)PlatformNotify_Arg_3_choice);
    switch(*PlatformNotify_Arg_3_choice % 6) {
        case 0:
            PlatformNotify_Arg_3 = AfterPciHostBridge;
            break;
        case 1:
            PlatformNotify_Arg_3 = BeforePciHostBridge;
            break;
        case 2:
            PlatformNotify_Arg_3 = ChipsetEntry;
            break;
        case 3:
            PlatformNotify_Arg_3 = ChipsetExit;
            break;
        case 4:
            PlatformNotify_Arg_3 = MaximumChipsetPhase;
            break;
        case 5:
            ReadBytes(Input, sizeof(PlatformNotify_Arg_3), (VOID *)&PlatformNotify_Arg_3);
            break;
    }
    
    Status = ProtocolVariable->PlatformNotify(
        ProtocolVariable,
        ImageHandle,
        PlatformNotify_Arg_2,
        PlatformNotify_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called PlatformPrepController.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzPlatformPrepController(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_PLATFORM_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciPlatformProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_PCI_ADDRESS PlatformPrepController_Arg_3 = {0};
    EFI_PCI_CONTROLLER_RESOURCE_ALLOCATION_PHASE PlatformPrepController_Arg_4 = 0;
    EFI_PCI_EXECUTION_PHASE PlatformPrepController_Arg_5 = 0;
    
    // Generator Struct Variable Initialization
    {
        UINT8 Firness_Register;
        ReadBytes(Input, sizeof(Firness_Register), (VOID *)&Firness_Register);
        PlatformPrepController_Arg_3.Register = Firness_Register;
    }
    {
        UINT8 Firness_Function;
        ReadBytes(Input, sizeof(Firness_Function), (VOID *)&Firness_Function);
        PlatformPrepController_Arg_3.Function = Firness_Function;
    }
    {
        UINT8 Firness_Device;
        ReadBytes(Input, sizeof(Firness_Device), (VOID *)&Firness_Device);
        PlatformPrepController_Arg_3.Device = Firness_Device;
    }
    {
        UINT8 Firness_Bus;
        ReadBytes(Input, sizeof(Firness_Bus), (VOID *)&Firness_Bus);
        PlatformPrepController_Arg_3.Bus = Firness_Bus;
    }
    {
        UINT32 Firness_ExtendedRegister;
        ReadBytes(Input, sizeof(Firness_ExtendedRegister), (VOID *)&Firness_ExtendedRegister);
        PlatformPrepController_Arg_3.ExtendedRegister = Firness_ExtendedRegister;
    }
    
    // Constant Variable Initialization
    UINT8* PlatformPrepController_Arg_4_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(PlatformPrepController_Arg_4_choice), (VOID *)PlatformPrepController_Arg_4_choice);
    switch(*PlatformPrepController_Arg_4_choice % 3) {
        case 0:
            PlatformPrepController_Arg_4 = EfiPciBeforeChildBusEnumeration;
            break;
        case 1:
            PlatformPrepController_Arg_4 = EfiPciBeforeResourceCollection;
            break;
        case 2:
            ReadBytes(Input, sizeof(PlatformPrepController_Arg_4), (VOID *)&PlatformPrepController_Arg_4);
            break;
    }
    
    // Constant Variable Initialization
    UINT8* PlatformPrepController_Arg_5_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(PlatformPrepController_Arg_5_choice), (VOID *)PlatformPrepController_Arg_5_choice);
    switch(*PlatformPrepController_Arg_5_choice % 6) {
        case 0:
            PlatformPrepController_Arg_5 = AfterPciHostBridge;
            break;
        case 1:
            PlatformPrepController_Arg_5 = BeforePciHostBridge;
            break;
        case 2:
            PlatformPrepController_Arg_5 = ChipsetEntry;
            break;
        case 3:
            PlatformPrepController_Arg_5 = ChipsetExit;
            break;
        case 4:
            PlatformPrepController_Arg_5 = MaximumChipsetPhase;
            break;
        case 5:
            ReadBytes(Input, sizeof(PlatformPrepController_Arg_5), (VOID *)&PlatformPrepController_Arg_5);
            break;
    }
    
    Status = ProtocolVariable->PlatformPrepController(
        ProtocolVariable,
        ImageHandle,
        ImageHandle,
        PlatformPrepController_Arg_3,
        PlatformPrepController_Arg_4,
        PlatformPrepController_Arg_5
    );
    return Status;
}

