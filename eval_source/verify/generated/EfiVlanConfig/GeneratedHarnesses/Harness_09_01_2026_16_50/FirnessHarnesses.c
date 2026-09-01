#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called Set.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSet(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_VLAN_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiVlanConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT16 Set_Arg_1 = 0;
    UINT8 Set_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Set_Arg_1), (VOID *)&Set_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Set_Arg_2), (VOID *)&Set_Arg_2);
    
    Status = ProtocolVariable->Set(
        ProtocolVariable,
        Set_Arg_1,
        Set_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Remove.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRemove(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_VLAN_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiVlanConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT16 Remove_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Remove_Arg_1), (VOID *)&Remove_Arg_1);
    
    Status = ProtocolVariable->Remove(
        ProtocolVariable,
        Remove_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Find.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFind(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_VLAN_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiVlanConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT16 * Find_Arg_1 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    
    // Fuzzable Variable Initialization
    UINT8 Find_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(Find_Arg_1_choice), (VOID *)&Find_Arg_1_choice);
    switch(Find_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Find_Arg_1), (VOID *)Find_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(Find_Arg_1);
            Find_Arg_1 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    UINT16 * Find_Arg_2 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    UINT8* Find_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Find_Arg_2_OutputChoice), (VOID *)Find_Arg_2_OutputChoice);
    if(*Find_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Find_Arg_2), (VOID *)Find_Arg_2);
    }
    EFI_VLAN_FIND_DATA * Find_Arg_3 = (EFI_VLAN_FIND_DATA *)AllocateZeroPool(sizeof(EFI_VLAN_FIND_DATA));
    UINT8* Find_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Find_Arg_3_OutputChoice), (VOID *)Find_Arg_3_OutputChoice);
    if(*Find_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Find_Arg_3), (VOID *)Find_Arg_3);
    }
    Status = ProtocolVariable->Find(
        ProtocolVariable,
        Find_Arg_1,
        Find_Arg_2,
        (EFI_VLAN_FIND_DATA **)&Find_Arg_3
    );
    return Status;
}

