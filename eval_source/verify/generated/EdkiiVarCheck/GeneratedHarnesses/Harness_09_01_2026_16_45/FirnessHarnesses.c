#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the Protocols service
    called RegisterSetVariableCheckHandler.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterSetVariableCheckHandler(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_VAR_CHECK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiVarCheckProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->RegisterSetVariableCheckHandler(
        (VAR_CHECK_SET_VARIABLE_CHECK_HANDLER){0}
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called VariablePropertySet.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzVariablePropertySet(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_VAR_CHECK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiVarCheckProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * VariablePropertySet_Arg_0 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    EFI_GUID * VariablePropertySet_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    VAR_CHECK_VARIABLE_PROPERTY * VariablePropertySet_Arg_2 = (VAR_CHECK_VARIABLE_PROPERTY *)AllocateZeroPool(sizeof(VAR_CHECK_VARIABLE_PROPERTY));
    
    // Fuzzable Variable Initialization
    UINT8 VariablePropertySet_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(VariablePropertySet_Arg_0_choice), (VOID *)&VariablePropertySet_Arg_0_choice);
    switch(VariablePropertySet_Arg_0_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(VariablePropertySet_Arg_0), (VOID *)VariablePropertySet_Arg_0);
            break;
        case 1:
        {
            gBS->FreePool(VariablePropertySet_Arg_0);
            VariablePropertySet_Arg_0 = NULL;
            break;
        }
    }
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        VariablePropertySet_Arg_1->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        VariablePropertySet_Arg_1->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        VariablePropertySet_Arg_1->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(VariablePropertySet_Arg_1->Data4), (VOID *)&(VariablePropertySet_Arg_1->Data4));
    
    // Generator Struct Variable Initialization
    {
        UINT16 Firness_Revision;
        ReadBytes(Input, sizeof(Firness_Revision), (VOID *)&Firness_Revision);
        VariablePropertySet_Arg_2->Revision = Firness_Revision;
    }
    {
        UINT16 Firness_Property;
        ReadBytes(Input, sizeof(Firness_Property), (VOID *)&Firness_Property);
        VariablePropertySet_Arg_2->Property = Firness_Property;
    }
    {
        UINT32 Firness_Attributes;
        ReadBytes(Input, sizeof(Firness_Attributes), (VOID *)&Firness_Attributes);
        VariablePropertySet_Arg_2->Attributes = Firness_Attributes;
    }
    {
        UINTN Firness_MinSize;
        ReadBytes(Input, sizeof(Firness_MinSize), (VOID *)&Firness_MinSize);
        VariablePropertySet_Arg_2->MinSize = Firness_MinSize;
    }
    {
        UINTN Firness_MaxSize;
        ReadBytes(Input, sizeof(Firness_MaxSize), (VOID *)&Firness_MaxSize);
        VariablePropertySet_Arg_2->MaxSize = Firness_MaxSize;
    }
    
    Status = ProtocolVariable->VariablePropertySet(
        VariablePropertySet_Arg_0,
        VariablePropertySet_Arg_1,
        VariablePropertySet_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called VariablePropertyGet.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzVariablePropertyGet(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_VAR_CHECK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiVarCheckProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * VariablePropertyGet_Arg_0 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    EFI_GUID * VariablePropertyGet_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
    // Fuzzable Variable Initialization
    UINT8 VariablePropertyGet_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(VariablePropertyGet_Arg_0_choice), (VOID *)&VariablePropertyGet_Arg_0_choice);
    switch(VariablePropertyGet_Arg_0_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(VariablePropertyGet_Arg_0), (VOID *)VariablePropertyGet_Arg_0);
            break;
        case 1:
        {
            gBS->FreePool(VariablePropertyGet_Arg_0);
            VariablePropertyGet_Arg_0 = NULL;
            break;
        }
    }
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        VariablePropertyGet_Arg_1->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        VariablePropertyGet_Arg_1->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        VariablePropertyGet_Arg_1->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(VariablePropertyGet_Arg_1->Data4), (VOID *)&(VariablePropertyGet_Arg_1->Data4));
    
    /*
        Output Variable(s)
    */
    VAR_CHECK_VARIABLE_PROPERTY * VariablePropertyGet_Arg_2 = (VAR_CHECK_VARIABLE_PROPERTY *)AllocateZeroPool(sizeof(VAR_CHECK_VARIABLE_PROPERTY));
    UINT8* VariablePropertyGet_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(VariablePropertyGet_Arg_2_OutputChoice), (VOID *)VariablePropertyGet_Arg_2_OutputChoice);
    if(*VariablePropertyGet_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*VariablePropertyGet_Arg_2), (VOID *)VariablePropertyGet_Arg_2);
    }
    Status = ProtocolVariable->VariablePropertyGet(
        VariablePropertyGet_Arg_0,
        VariablePropertyGet_Arg_1,
        VariablePropertyGet_Arg_2
    );
    return Status;
}

