#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the Protocols service
    called DisableVariablePolicy.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDisableVariablePolicy(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_VARIABLE_POLICY_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiVariablePolicyProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->DisableVariablePolicy(
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called RegisterVariablePolicy.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterVariablePolicy(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_VARIABLE_POLICY_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiVariablePolicyProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    VARIABLE_POLICY_ENTRY * RegisterVariablePolicy_Arg_0 = (VARIABLE_POLICY_ENTRY *)AllocateZeroPool(sizeof(VARIABLE_POLICY_ENTRY));
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Version;
        ReadBytes(Input, sizeof(Firness_Version), (VOID *)&Firness_Version);
        RegisterVariablePolicy_Arg_0->Version = Firness_Version;
    }
    {
        UINT16 Firness_Size;
        ReadBytes(Input, sizeof(Firness_Size), (VOID *)&Firness_Size);
        RegisterVariablePolicy_Arg_0->Size = Firness_Size;
    }
    {
        UINT16 Firness_OffsetToName;
        ReadBytes(Input, sizeof(Firness_OffsetToName), (VOID *)&Firness_OffsetToName);
        RegisterVariablePolicy_Arg_0->OffsetToName = Firness_OffsetToName;
    }
    {
        EFI_GUID Firness_Namespace;
        ReadBytes(Input, sizeof(Firness_Namespace), (VOID *)&Firness_Namespace);
        RegisterVariablePolicy_Arg_0->Namespace = Firness_Namespace;
    }
    {
        UINT32 Firness_MinSize;
        ReadBytes(Input, sizeof(Firness_MinSize), (VOID *)&Firness_MinSize);
        RegisterVariablePolicy_Arg_0->MinSize = Firness_MinSize;
    }
    {
        UINT32 Firness_MaxSize;
        ReadBytes(Input, sizeof(Firness_MaxSize), (VOID *)&Firness_MaxSize);
        RegisterVariablePolicy_Arg_0->MaxSize = Firness_MaxSize;
    }
    {
        UINT32 Firness_AttributesMustHave;
        ReadBytes(Input, sizeof(Firness_AttributesMustHave), (VOID *)&Firness_AttributesMustHave);
        RegisterVariablePolicy_Arg_0->AttributesMustHave = Firness_AttributesMustHave;
    }
    {
        UINT32 Firness_AttributesCantHave;
        ReadBytes(Input, sizeof(Firness_AttributesCantHave), (VOID *)&Firness_AttributesCantHave);
        RegisterVariablePolicy_Arg_0->AttributesCantHave = Firness_AttributesCantHave;
    }
    {
        UINT8 Firness_LockPolicyType;
        ReadBytes(Input, sizeof(Firness_LockPolicyType), (VOID *)&Firness_LockPolicyType);
        RegisterVariablePolicy_Arg_0->LockPolicyType = Firness_LockPolicyType;
    }
    ReadBytes(Input, sizeof(RegisterVariablePolicy_Arg_0->Padding), (VOID *)&(RegisterVariablePolicy_Arg_0->Padding));
    
    Status = ProtocolVariable->RegisterVariablePolicy(
        RegisterVariablePolicy_Arg_0
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called LockVariablePolicy.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzLockVariablePolicy(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_VARIABLE_POLICY_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiVariablePolicyProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->LockVariablePolicy(
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called IsVariablePolicyEnabled.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzIsVariablePolicyEnabled(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_VARIABLE_POLICY_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiVariablePolicyProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    BOOLEAN * IsVariablePolicyEnabled_Arg_0 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
    UINT8* IsVariablePolicyEnabled_Arg_0_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(IsVariablePolicyEnabled_Arg_0_OutputChoice), (VOID *)IsVariablePolicyEnabled_Arg_0_OutputChoice);
    if(*IsVariablePolicyEnabled_Arg_0_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*IsVariablePolicyEnabled_Arg_0), (VOID *)IsVariablePolicyEnabled_Arg_0);
    }
    Status = ProtocolVariable->IsVariablePolicyEnabled(
        IsVariablePolicyEnabled_Arg_0
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called DumpVariablePolicy.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDumpVariablePolicy(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_VARIABLE_POLICY_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiVariablePolicyProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 * DumpVariablePolicy_Arg_0 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT32 * DumpVariablePolicy_Arg_1 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    
    // Fuzzable Variable Initialization
    UINT8 DumpVariablePolicy_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(DumpVariablePolicy_Arg_0_choice), (VOID *)&DumpVariablePolicy_Arg_0_choice);
    switch(DumpVariablePolicy_Arg_0_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(DumpVariablePolicy_Arg_0), (VOID *)DumpVariablePolicy_Arg_0);
            break;
        case 1:
        {
            gBS->FreePool(DumpVariablePolicy_Arg_0);
            DumpVariablePolicy_Arg_0 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 DumpVariablePolicy_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(DumpVariablePolicy_Arg_1_choice), (VOID *)&DumpVariablePolicy_Arg_1_choice);
    switch(DumpVariablePolicy_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(DumpVariablePolicy_Arg_1), (VOID *)DumpVariablePolicy_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(DumpVariablePolicy_Arg_1);
            DumpVariablePolicy_Arg_1 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->DumpVariablePolicy(
        DumpVariablePolicy_Arg_0,
        DumpVariablePolicy_Arg_1
    );
    return Status;
}

