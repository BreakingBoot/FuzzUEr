#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called PossibleResources.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzPossibleResources(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSioProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    ACPI_RESOURCE_HEADER_PTR * PossibleResources_Arg_1 = (ACPI_RESOURCE_HEADER_PTR *)AllocateZeroPool(sizeof(ACPI_RESOURCE_HEADER_PTR));
    UINT8* PossibleResources_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(PossibleResources_Arg_1_OutputChoice), (VOID *)PossibleResources_Arg_1_OutputChoice);
    if(*PossibleResources_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*PossibleResources_Arg_1), (VOID *)PossibleResources_Arg_1);
    }
    Status = ProtocolVariable->PossibleResources(
        ProtocolVariable,
        PossibleResources_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetResources.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetResources(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSioProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->SetResources(
        ProtocolVariable,
        (ACPI_RESOURCE_HEADER_PTR){0}
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RegisterAccess.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterAccess(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSioProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN RegisterAccess_Arg_1 = FALSE;
    BOOLEAN RegisterAccess_Arg_2 = FALSE;
    UINT8 RegisterAccess_Arg_3 = 0;
    UINT8 * RegisterAccess_Arg_4 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RegisterAccess_Arg_1), (VOID *)&RegisterAccess_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RegisterAccess_Arg_2), (VOID *)&RegisterAccess_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RegisterAccess_Arg_3), (VOID *)&RegisterAccess_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 RegisterAccess_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(RegisterAccess_Arg_4_choice), (VOID *)&RegisterAccess_Arg_4_choice);
    switch(RegisterAccess_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(RegisterAccess_Arg_4), (VOID *)RegisterAccess_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(RegisterAccess_Arg_4);
            RegisterAccess_Arg_4 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->RegisterAccess(
        ProtocolVariable,
        RegisterAccess_Arg_1,
        RegisterAccess_Arg_2,
        RegisterAccess_Arg_3,
        RegisterAccess_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Modify.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzModify(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSioProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_SIO_REGISTER_MODIFY * Modify_Arg_1 = (EFI_SIO_REGISTER_MODIFY *)AllocateZeroPool(sizeof(EFI_SIO_REGISTER_MODIFY));
    UINTN Modify_Arg_2 = 0;
    
    // Generator Struct Variable Initialization
    {
        UINT8 Firness_Register;
        ReadBytes(Input, sizeof(Firness_Register), (VOID *)&Firness_Register);
        Modify_Arg_1->Register = Firness_Register;
    }
    {
        UINT8 Firness_AndMask;
        ReadBytes(Input, sizeof(Firness_AndMask), (VOID *)&Firness_AndMask);
        Modify_Arg_1->AndMask = Firness_AndMask;
    }
    {
        UINT8 Firness_OrMask;
        ReadBytes(Input, sizeof(Firness_OrMask), (VOID *)&Firness_OrMask);
        Modify_Arg_1->OrMask = Firness_OrMask;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Modify_Arg_2), (VOID *)&Modify_Arg_2);
    
    Status = ProtocolVariable->Modify(
        ProtocolVariable,
        Modify_Arg_1,
        Modify_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetResources.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetResources(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SIO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSioProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    ACPI_RESOURCE_HEADER_PTR * GetResources_Arg_1 = (ACPI_RESOURCE_HEADER_PTR *)AllocateZeroPool(sizeof(ACPI_RESOURCE_HEADER_PTR));
    UINT8* GetResources_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetResources_Arg_1_OutputChoice), (VOID *)GetResources_Arg_1_OutputChoice);
    if(*GetResources_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetResources_Arg_1), (VOID *)GetResources_Arg_1);
    }
    Status = ProtocolVariable->GetResources(
        ProtocolVariable,
        GetResources_Arg_1
    );
    return Status;
}

