#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called NewString.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzNewString(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_STRING_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiStringProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE NewString_Arg_1 = {0};
    CHAR8 * NewString_Arg_3 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
    CHAR16 * NewString_Arg_4 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    EFI_STRING NewString_Arg_5 = {0};
    EFI_FONT_INFO * NewString_Arg_6 = (EFI_FONT_INFO *)AllocateZeroPool(sizeof(EFI_FONT_INFO));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(NewString_Arg_1), (VOID *)&NewString_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 NewString_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(NewString_Arg_3_choice), (VOID *)&NewString_Arg_3_choice);
    switch(NewString_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*NewString_Arg_3), (VOID *)NewString_Arg_3);
            NewString_Arg_3[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(NewString_Arg_3);
            NewString_Arg_3 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 NewString_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(NewString_Arg_4_choice), (VOID *)&NewString_Arg_4_choice);
    switch(NewString_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*NewString_Arg_4), (VOID *)NewString_Arg_4);
            NewString_Arg_4[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(NewString_Arg_4);
            NewString_Arg_4 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(NewString_Arg_5), (VOID *)&NewString_Arg_5);
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(NewString_Arg_6->FontStyle), (VOID *)&(NewString_Arg_6->FontStyle));
    NewString_Arg_6->FontSize = sizeof(EFI_FONT_INFO);
    ReadBytes(Input, sizeof(NewString_Arg_6->FontName), (VOID *)&(NewString_Arg_6->FontName));
    
    /*
        Output Variable(s)
    */
    EFI_STRING_ID * NewString_Arg_2 = (EFI_STRING_ID *)AllocateZeroPool(sizeof(EFI_STRING_ID));
    UINT8* NewString_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*NewString_Arg_2_OutputChoice), (VOID *)NewString_Arg_2_OutputChoice);
    if(*NewString_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*NewString_Arg_2), (VOID *)NewString_Arg_2);
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->NewString(
        ProtocolVariable,
        NewString_Arg_1,
        NewString_Arg_2,
        NewString_Arg_3,
        NewString_Arg_4,
        NewString_Arg_5,
        NewString_Arg_6
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetString.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetString(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_STRING_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiStringProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE SetString_Arg_1 = {0};
    EFI_STRING_ID SetString_Arg_2 = {0};
    CHAR8 * SetString_Arg_3 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
    EFI_STRING SetString_Arg_4 = {0};
    EFI_FONT_INFO * SetString_Arg_5 = (EFI_FONT_INFO *)AllocateZeroPool(sizeof(EFI_FONT_INFO));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetString_Arg_1), (VOID *)&SetString_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetString_Arg_2), (VOID *)&SetString_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 SetString_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(SetString_Arg_3_choice), (VOID *)&SetString_Arg_3_choice);
    switch(SetString_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*SetString_Arg_3), (VOID *)SetString_Arg_3);
            SetString_Arg_3[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(SetString_Arg_3);
            SetString_Arg_3 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetString_Arg_4), (VOID *)&SetString_Arg_4);
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(SetString_Arg_5->FontStyle), (VOID *)&(SetString_Arg_5->FontStyle));
    SetString_Arg_5->FontSize = sizeof(EFI_FONT_INFO);
    ReadBytes(Input, sizeof(SetString_Arg_5->FontName), (VOID *)&(SetString_Arg_5->FontName));
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->SetString(
        ProtocolVariable,
        SetString_Arg_1,
        SetString_Arg_2,
        SetString_Arg_3,
        SetString_Arg_4,
        SetString_Arg_5
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetString.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetString(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_STRING_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiStringProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR8 * GetString_Arg_1 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
    EFI_HII_HANDLE GetString_Arg_2 = {0};
    EFI_STRING_ID GetString_Arg_3 = {0};
    CHAR16 * GetString_Arg_4 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    UINTN * GetString_Arg_5 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    EFI_FONT_INFO * GetString_Arg_6 = (EFI_FONT_INFO *)AllocateZeroPool(sizeof(EFI_FONT_INFO));
    
    // Fuzzable Variable Initialization
    UINT8 GetString_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetString_Arg_1_choice), (VOID *)&GetString_Arg_1_choice);
    switch(GetString_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*GetString_Arg_1), (VOID *)GetString_Arg_1);
            GetString_Arg_1[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(GetString_Arg_1);
            GetString_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetString_Arg_2), (VOID *)&GetString_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetString_Arg_3), (VOID *)&GetString_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 GetString_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(GetString_Arg_4_choice), (VOID *)&GetString_Arg_4_choice);
    switch(GetString_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*GetString_Arg_4), (VOID *)GetString_Arg_4);
            GetString_Arg_4[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(GetString_Arg_4);
            GetString_Arg_4 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetString_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(GetString_Arg_5_choice), (VOID *)&GetString_Arg_5_choice);
    switch(GetString_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(*GetString_Arg_5), (VOID *)GetString_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(GetString_Arg_5);
            GetString_Arg_5 = NULL;
            break;
        }
    }
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(GetString_Arg_6->FontStyle), (VOID *)&(GetString_Arg_6->FontStyle));
    GetString_Arg_6->FontSize = sizeof(EFI_FONT_INFO);
    ReadBytes(Input, sizeof(GetString_Arg_6->FontName), (VOID *)&(GetString_Arg_6->FontName));
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetString(
        ProtocolVariable,
        GetString_Arg_1,
        GetString_Arg_2,
        GetString_Arg_3,
        GetString_Arg_4,
        GetString_Arg_5,
        (EFI_FONT_INFO **)&GetString_Arg_6
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetLanguages.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetLanguages(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_STRING_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiStringProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE GetLanguages_Arg_1 = {0};
    CHAR8 * GetLanguages_Arg_2 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
    UINTN * GetLanguages_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetLanguages_Arg_1), (VOID *)&GetLanguages_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 GetLanguages_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetLanguages_Arg_2_choice), (VOID *)&GetLanguages_Arg_2_choice);
    switch(GetLanguages_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*GetLanguages_Arg_2), (VOID *)GetLanguages_Arg_2);
            GetLanguages_Arg_2[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(GetLanguages_Arg_2);
            GetLanguages_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetLanguages_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(GetLanguages_Arg_3_choice), (VOID *)&GetLanguages_Arg_3_choice);
    switch(GetLanguages_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(*GetLanguages_Arg_3), (VOID *)GetLanguages_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(GetLanguages_Arg_3);
            GetLanguages_Arg_3 = NULL;
            break;
        }
    }
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetLanguages(
        ProtocolVariable,
        GetLanguages_Arg_1,
        GetLanguages_Arg_2,
        GetLanguages_Arg_3
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetSecondaryLanguages.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetSecondaryLanguages(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_STRING_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiStringProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE GetSecondaryLanguages_Arg_1 = {0};
    CHAR8 * GetSecondaryLanguages_Arg_2 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
    CHAR8 * GetSecondaryLanguages_Arg_3 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
    UINTN * GetSecondaryLanguages_Arg_4 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    UINT8* GetSecondaryLanguages_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetSecondaryLanguages_Arg_1_choice), (VOID *)GetSecondaryLanguages_Arg_1_choice);
    switch(*GetSecondaryLanguages_Arg_1_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(GetSecondaryLanguages_Arg_1), (VOID *)&GetSecondaryLanguages_Arg_1);
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(GetSecondaryLanguages_Arg_1), (VOID *)&GetSecondaryLanguages_Arg_1);
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 GetSecondaryLanguages_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetSecondaryLanguages_Arg_2_choice), (VOID *)&GetSecondaryLanguages_Arg_2_choice);
    switch(GetSecondaryLanguages_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*GetSecondaryLanguages_Arg_2), (VOID *)GetSecondaryLanguages_Arg_2);
            GetSecondaryLanguages_Arg_2[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(GetSecondaryLanguages_Arg_2);
            GetSecondaryLanguages_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetSecondaryLanguages_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(GetSecondaryLanguages_Arg_3_choice), (VOID *)&GetSecondaryLanguages_Arg_3_choice);
    switch(GetSecondaryLanguages_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*GetSecondaryLanguages_Arg_3), (VOID *)GetSecondaryLanguages_Arg_3);
            GetSecondaryLanguages_Arg_3[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(GetSecondaryLanguages_Arg_3);
            GetSecondaryLanguages_Arg_3 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetSecondaryLanguages_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(GetSecondaryLanguages_Arg_4_choice), (VOID *)&GetSecondaryLanguages_Arg_4_choice);
    switch(GetSecondaryLanguages_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(*GetSecondaryLanguages_Arg_4), (VOID *)GetSecondaryLanguages_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(GetSecondaryLanguages_Arg_4);
            GetSecondaryLanguages_Arg_4 = NULL;
            break;
        }
    }
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetSecondaryLanguages(
        ProtocolVariable,
        GetSecondaryLanguages_Arg_1,
        GetSecondaryLanguages_Arg_2,
        GetSecondaryLanguages_Arg_3,
        GetSecondaryLanguages_Arg_4
    );
    FirnessSanitizer(FALSE);
    return Status;
}

