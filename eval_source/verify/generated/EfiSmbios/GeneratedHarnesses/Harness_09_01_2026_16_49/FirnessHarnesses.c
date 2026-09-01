#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called Add.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAdd(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMBIOS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  Add_Arg_1 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    EFI_SMBIOS_HANDLE * Add_Arg_2 = (EFI_SMBIOS_HANDLE *)AllocateZeroPool(sizeof(EFI_SMBIOS_HANDLE));
    EFI_SMBIOS_TABLE_HEADER * Add_Arg_3 = (EFI_SMBIOS_TABLE_HEADER *)AllocateZeroPool(sizeof(EFI_SMBIOS_TABLE_HEADER));
    
    // Fuzzable Variable Initialization
    UINT8 Add_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(Add_Arg_1_choice), (VOID *)&Add_Arg_1_choice);
    switch(Add_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Add_Arg_1), (VOID *)Add_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(Add_Arg_1);
            Add_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 Add_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(Add_Arg_2_choice), (VOID *)&Add_Arg_2_choice);
    switch(Add_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Add_Arg_2), (VOID *)Add_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(Add_Arg_2);
            Add_Arg_2 = NULL;
            break;
        }
    }
    
    // Generator Struct Variable Initialization
    {
        SMBIOS_TYPE Firness_Type;
        ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
        Add_Arg_3->Type = Firness_Type;
    }
    {
        UINT8 Firness_Length;
        ReadBytes(Input, sizeof(Firness_Length), (VOID *)&Firness_Length);
        Add_Arg_3->Length = Firness_Length;
    }
    {
        SMBIOS_HANDLE Firness_Handle;
        ReadBytes(Input, sizeof(Firness_Handle), (VOID *)&Firness_Handle);
        Add_Arg_3->Handle = Firness_Handle;
    }
    
    Status = ProtocolVariable->Add(
        ProtocolVariable,
        (void *)Add_Arg_1,
        Add_Arg_2,
        Add_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetNext.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetNext(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMBIOS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_SMBIOS_HANDLE * GetNext_Arg_1 = (EFI_SMBIOS_HANDLE *)AllocateZeroPool(sizeof(EFI_SMBIOS_HANDLE));
    EFI_SMBIOS_TYPE * GetNext_Arg_2 = (EFI_SMBIOS_TYPE *)AllocateZeroPool(sizeof(EFI_SMBIOS_TYPE));
    
    // Fuzzable Variable Initialization
    UINT8 GetNext_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetNext_Arg_1_choice), (VOID *)&GetNext_Arg_1_choice);
    switch(GetNext_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetNext_Arg_1), (VOID *)GetNext_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(GetNext_Arg_1);
            GetNext_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetNext_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetNext_Arg_2_choice), (VOID *)&GetNext_Arg_2_choice);
    switch(GetNext_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetNext_Arg_2), (VOID *)GetNext_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(GetNext_Arg_2);
            GetNext_Arg_2 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_SMBIOS_TABLE_HEADER * GetNext_Arg_3 = (EFI_SMBIOS_TABLE_HEADER *)AllocateZeroPool(sizeof(EFI_SMBIOS_TABLE_HEADER));
    UINT8* GetNext_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetNext_Arg_3_OutputChoice), (VOID *)GetNext_Arg_3_OutputChoice);
    if(*GetNext_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetNext_Arg_3), (VOID *)GetNext_Arg_3);
    }
    EFI_HANDLE * GetNext_Arg_4 = (EFI_HANDLE *)AllocateZeroPool(sizeof(EFI_HANDLE));
    UINT8* GetNext_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetNext_Arg_4_OutputChoice), (VOID *)GetNext_Arg_4_OutputChoice);
    if(*GetNext_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetNext_Arg_4), (VOID *)GetNext_Arg_4);
    }
    Status = ProtocolVariable->GetNext(
        ProtocolVariable,
        GetNext_Arg_1,
        GetNext_Arg_2,
        (EFI_SMBIOS_TABLE_HEADER **)&GetNext_Arg_3,
        GetNext_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UpdateString.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUpdateString(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMBIOS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_SMBIOS_HANDLE * UpdateString_Arg_1 = (EFI_SMBIOS_HANDLE *)AllocateZeroPool(sizeof(EFI_SMBIOS_HANDLE));
    UINTN * UpdateString_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    CHAR8 * UpdateString_Arg_3 = (CHAR8 *)AllocateZeroPool(sizeof(CHAR8));
    
    // Fuzzable Variable Initialization
    UINT8 UpdateString_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(UpdateString_Arg_1_choice), (VOID *)&UpdateString_Arg_1_choice);
    switch(UpdateString_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UpdateString_Arg_1), (VOID *)UpdateString_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(UpdateString_Arg_1);
            UpdateString_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 UpdateString_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(UpdateString_Arg_2_choice), (VOID *)&UpdateString_Arg_2_choice);
    switch(UpdateString_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UpdateString_Arg_2), (VOID *)UpdateString_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(UpdateString_Arg_2);
            UpdateString_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 UpdateString_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(UpdateString_Arg_3_choice), (VOID *)&UpdateString_Arg_3_choice);
    switch(UpdateString_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UpdateString_Arg_3), (VOID *)UpdateString_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(UpdateString_Arg_3);
            UpdateString_Arg_3 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->UpdateString(
        ProtocolVariable,
        UpdateString_Arg_1,
        UpdateString_Arg_2,
        UpdateString_Arg_3
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
    EFI_SMBIOS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_SMBIOS_HANDLE Remove_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Remove_Arg_1), (VOID *)&Remove_Arg_1);
    
    Status = ProtocolVariable->Remove(
        ProtocolVariable,
        Remove_Arg_1
    );
    return Status;
}

