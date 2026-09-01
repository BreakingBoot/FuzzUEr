#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the Protocols service
    called GetAcpiTable.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetAcpiTable(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ACPI_SDT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN GetAcpiTable_Arg_0 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetAcpiTable_Arg_0), (VOID *)&GetAcpiTable_Arg_0);
    
    /*
        Output Variable(s)
    */
    EFI_ACPI_SDT_HEADER * * GetAcpiTable_Arg_1 = (EFI_ACPI_SDT_HEADER * *)AllocateZeroPool(sizeof(EFI_ACPI_SDT_HEADER));
    UINT8* GetAcpiTable_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetAcpiTable_Arg_1_OutputChoice), (VOID *)GetAcpiTable_Arg_1_OutputChoice);
    if(*GetAcpiTable_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetAcpiTable_Arg_1), (VOID *)GetAcpiTable_Arg_1);
    }
    EFI_ACPI_TABLE_VERSION * GetAcpiTable_Arg_2 = (EFI_ACPI_TABLE_VERSION *)AllocateZeroPool(sizeof(EFI_ACPI_TABLE_VERSION));
    UINT8* GetAcpiTable_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetAcpiTable_Arg_2_OutputChoice), (VOID *)GetAcpiTable_Arg_2_OutputChoice);
    if(*GetAcpiTable_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetAcpiTable_Arg_2), (VOID *)GetAcpiTable_Arg_2);
    }
    UINTN * GetAcpiTable_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetAcpiTable_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetAcpiTable_Arg_3_OutputChoice), (VOID *)GetAcpiTable_Arg_3_OutputChoice);
    if(*GetAcpiTable_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetAcpiTable_Arg_3), (VOID *)GetAcpiTable_Arg_3);
    }
    Status = ProtocolVariable->GetAcpiTable(
        GetAcpiTable_Arg_0,
        &GetAcpiTable_Arg_1,
        GetAcpiTable_Arg_2,
        GetAcpiTable_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called RegisterNotify.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterNotify(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ACPI_SDT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN RegisterNotify_Arg_0 = FALSE;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RegisterNotify_Arg_0), (VOID *)&RegisterNotify_Arg_0);
    
    Status = ProtocolVariable->RegisterNotify(
        RegisterNotify_Arg_0,
        (EFI_ACPI_NOTIFICATION_FN){0}
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called Open.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzOpen(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ACPI_SDT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  Open_Arg_0 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    UINT8 Open_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(Open_Arg_0_choice), (VOID *)&Open_Arg_0_choice);
    switch(Open_Arg_0_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Open_Arg_0), (VOID *)Open_Arg_0);
            break;
        case 1:
        {
            gBS->FreePool(Open_Arg_0);
            Open_Arg_0 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_ACPI_HANDLE * Open_Arg_1 = (EFI_ACPI_HANDLE *)AllocateZeroPool(sizeof(EFI_ACPI_HANDLE));
    UINT8* Open_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Open_Arg_1_OutputChoice), (VOID *)Open_Arg_1_OutputChoice);
    if(*Open_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Open_Arg_1), (VOID *)Open_Arg_1);
    }
    Status = ProtocolVariable->Open(
        (VOID *)Open_Arg_0,
        Open_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called OpenSdt.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzOpenSdt(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ACPI_SDT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN OpenSdt_Arg_0 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(OpenSdt_Arg_0), (VOID *)&OpenSdt_Arg_0);
    
    /*
        Output Variable(s)
    */
    EFI_ACPI_HANDLE * OpenSdt_Arg_1 = (EFI_ACPI_HANDLE *)AllocateZeroPool(sizeof(EFI_ACPI_HANDLE));
    UINT8* OpenSdt_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(OpenSdt_Arg_1_OutputChoice), (VOID *)OpenSdt_Arg_1_OutputChoice);
    if(*OpenSdt_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*OpenSdt_Arg_1), (VOID *)OpenSdt_Arg_1);
    }
    Status = ProtocolVariable->OpenSdt(
        OpenSdt_Arg_0,
        OpenSdt_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called Close.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzClose(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ACPI_SDT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_ACPI_HANDLE Close_Arg_0 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Close_Arg_0), (VOID *)&Close_Arg_0);
    
    Status = ProtocolVariable->Close(
        Close_Arg_0
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetChild.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetChild(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ACPI_SDT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_ACPI_HANDLE GetChild_Arg_0 = 0;
    EFI_ACPI_HANDLE * GetChild_Arg_1 = (EFI_ACPI_HANDLE *)AllocateZeroPool(sizeof(EFI_ACPI_HANDLE));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetChild_Arg_0), (VOID *)&GetChild_Arg_0);
    
    // Fuzzable Variable Initialization
    UINT8 GetChild_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetChild_Arg_1_choice), (VOID *)&GetChild_Arg_1_choice);
    switch(GetChild_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetChild_Arg_1), (VOID *)GetChild_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(GetChild_Arg_1);
            GetChild_Arg_1 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetChild(
        GetChild_Arg_0,
        GetChild_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetOption.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetOption(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ACPI_SDT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_ACPI_HANDLE GetOption_Arg_0 = 0;
    UINTN GetOption_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetOption_Arg_0), (VOID *)&GetOption_Arg_0);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetOption_Arg_1), (VOID *)&GetOption_Arg_1);
    
    /*
        Output Variable(s)
    */
    EFI_ACPI_DATA_TYPE * GetOption_Arg_2 = (EFI_ACPI_DATA_TYPE *)AllocateZeroPool(sizeof(EFI_ACPI_DATA_TYPE));
    UINT8* GetOption_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetOption_Arg_2_OutputChoice), (VOID *)GetOption_Arg_2_OutputChoice);
    if(*GetOption_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetOption_Arg_2), (VOID *)GetOption_Arg_2);
    }
    UINTN* GetOption_Arg_3 = (UINTN*)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetOption_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetOption_Arg_3_OutputChoice), (VOID *)GetOption_Arg_3_OutputChoice);
    if(*GetOption_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetOption_Arg_3), (VOID *)GetOption_Arg_3);
    }
    UINTN * GetOption_Arg_4 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetOption_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetOption_Arg_4_OutputChoice), (VOID *)GetOption_Arg_4_OutputChoice);
    if(*GetOption_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetOption_Arg_4), (VOID *)GetOption_Arg_4);
    }
    Status = ProtocolVariable->GetOption(
        GetOption_Arg_0,
        GetOption_Arg_1,
        GetOption_Arg_2,
        (VOID * *)&GetOption_Arg_3,
        GetOption_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called SetOption.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetOption(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ACPI_SDT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_ACPI_HANDLE SetOption_Arg_0 = 0;
    UINTN SetOption_Arg_1 = 0;
    UINTN*  SetOption_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN SetOption_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetOption_Arg_0), (VOID *)&SetOption_Arg_0);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetOption_Arg_1), (VOID *)&SetOption_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 SetOption_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(SetOption_Arg_2_choice), (VOID *)&SetOption_Arg_2_choice);
    switch(SetOption_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetOption_Arg_2), (VOID *)SetOption_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(SetOption_Arg_2);
            SetOption_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetOption_Arg_3), (VOID *)&SetOption_Arg_3);
    
    Status = ProtocolVariable->SetOption(
        SetOption_Arg_0,
        SetOption_Arg_1,
        (VOID *)SetOption_Arg_2,
        SetOption_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called FindPath.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFindPath(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ACPI_SDT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_ACPI_HANDLE FindPath_Arg_0 = 0;
    UINTN*  FindPath_Arg_1 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(FindPath_Arg_0), (VOID *)&FindPath_Arg_0);
    
    // Fuzzable Variable Initialization
    UINT8 FindPath_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(FindPath_Arg_1_choice), (VOID *)&FindPath_Arg_1_choice);
    switch(FindPath_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(FindPath_Arg_1), (VOID *)FindPath_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(FindPath_Arg_1);
            FindPath_Arg_1 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_ACPI_HANDLE * FindPath_Arg_2 = (EFI_ACPI_HANDLE *)AllocateZeroPool(sizeof(EFI_ACPI_HANDLE));
    UINT8* FindPath_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(FindPath_Arg_2_OutputChoice), (VOID *)FindPath_Arg_2_OutputChoice);
    if(*FindPath_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*FindPath_Arg_2), (VOID *)FindPath_Arg_2);
    }
    Status = ProtocolVariable->FindPath(
        FindPath_Arg_0,
        (VOID *)FindPath_Arg_1,
        FindPath_Arg_2
    );
    return Status;
}

