#include "FirnessHarnesses.h"

//
// Objects produced by one call in a sequence, available to later ones.
// Reset every iteration, because the fuzzer restores the machine.
//
CHAR16 * FirnessLive_CHAR16__[4];
UINTN FirnessLive_CHAR16___Count = 0;
CHAR8 * FirnessLive_CHAR8__[4];
UINTN FirnessLive_CHAR8___Count = 0;
EFI_FONT_DISPLAY_INFO * FirnessLive_EFI_FONT_DISPLAY_INFO__[4];
UINTN FirnessLive_EFI_FONT_DISPLAY_INFO___Count = 0;
EFI_FONT_INFO * FirnessLive_EFI_FONT_INFO__[4];
UINTN FirnessLive_EFI_FONT_INFO___Count = 0;
EFI_GUID * FirnessLive_EFI_GUID__[4];
UINTN FirnessLive_EFI_GUID___Count = 0;
EFI_HII_PACKAGE_LIST_HEADER * FirnessLive_EFI_HII_PACKAGE_LIST_HEADER__[4];
UINTN FirnessLive_EFI_HII_PACKAGE_LIST_HEADER___Count = 0;
EFI_IMAGE_OUTPUT * FirnessLive_EFI_IMAGE_OUTPUT__[4];
UINTN FirnessLive_EFI_IMAGE_OUTPUT___Count = 0;
UINT16 * FirnessLive_UINT16__[4];
UINTN FirnessLive_UINT16___Count = 0;
UINTN * FirnessLive_UINTN__[4];
UINTN FirnessLive_UINTN___Count = 0;

/*
    This is a harness for fuzzing the protocol service
    called ExportPackageLists.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzExportPackageLists(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE ExportPackageLists_Arg_1 = {0};
    UINTN * ExportPackageLists_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    UINT8* ExportPackageLists_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*ExportPackageLists_Arg_1_choice), (VOID *)ExportPackageLists_Arg_1_choice);
    switch(*ExportPackageLists_Arg_1_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(ExportPackageLists_Arg_1), (VOID *)&ExportPackageLists_Arg_1);
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(ExportPackageLists_Arg_1), (VOID *)&ExportPackageLists_Arg_1);
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 ExportPackageLists_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(ExportPackageLists_Arg_2_choice), (VOID *)&ExportPackageLists_Arg_2_choice);
    switch(ExportPackageLists_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(*ExportPackageLists_Arg_2), (VOID *)ExportPackageLists_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(ExportPackageLists_Arg_2);
            ExportPackageLists_Arg_2 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_HII_PACKAGE_LIST_HEADER * ExportPackageLists_Arg_3 = (EFI_HII_PACKAGE_LIST_HEADER *)AllocateZeroPool(sizeof(EFI_HII_PACKAGE_LIST_HEADER));
    UINT8* ExportPackageLists_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*ExportPackageLists_Arg_3_OutputChoice), (VOID *)ExportPackageLists_Arg_3_OutputChoice);
    if(*ExportPackageLists_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ExportPackageLists_Arg_3), (VOID *)ExportPackageLists_Arg_3);
    }
    UINT8 ExportPackageLists_Arg_2_LiveChoice = 0;
    ReadBytes(Input, sizeof(ExportPackageLists_Arg_2_LiveChoice), (VOID *)&ExportPackageLists_Arg_2_LiveChoice);
    if (FirnessLive_UINTN___Count > 0 && (ExportPackageLists_Arg_2_LiveChoice & 1)) {
        ExportPackageLists_Arg_2 = FirnessLive_UINTN__[ExportPackageLists_Arg_2_LiveChoice % FirnessLive_UINTN___Count];
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->ExportPackageLists(
        ProtocolVariable,
        ExportPackageLists_Arg_1,
        ExportPackageLists_Arg_2,
        ExportPackageLists_Arg_3
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_UINTN___Count < 4 && ExportPackageLists_Arg_2 != NULL) {
        FirnessLive_UINTN__[FirnessLive_UINTN___Count++] = ExportPackageLists_Arg_2;
    }
    if (FirnessLive_EFI_HII_PACKAGE_LIST_HEADER___Count < 4 && ExportPackageLists_Arg_3 != NULL) {
        FirnessLive_EFI_HII_PACKAGE_LIST_HEADER__[FirnessLive_EFI_HII_PACKAGE_LIST_HEADER___Count++] = ExportPackageLists_Arg_3;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetPackageListHandle.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetPackageListHandle(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE GetPackageListHandle_Arg_1 = {0};
    
    UINT8* GetPackageListHandle_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetPackageListHandle_Arg_1_choice), (VOID *)GetPackageListHandle_Arg_1_choice);
    switch(*GetPackageListHandle_Arg_1_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(GetPackageListHandle_Arg_1), (VOID *)&GetPackageListHandle_Arg_1);
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(GetPackageListHandle_Arg_1), (VOID *)&GetPackageListHandle_Arg_1);
    
            break;
        }
    }
    /*
        Output Variable(s)
    */
    EFI_HANDLE * GetPackageListHandle_Arg_2 = (EFI_HANDLE *)AllocateZeroPool(sizeof(EFI_HANDLE));
    UINT8* GetPackageListHandle_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetPackageListHandle_Arg_2_OutputChoice), (VOID *)GetPackageListHandle_Arg_2_OutputChoice);
    if(*GetPackageListHandle_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetPackageListHandle_Arg_2), (VOID *)GetPackageListHandle_Arg_2);
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetPackageListHandle(
        ProtocolVariable,
        GetPackageListHandle_Arg_1,
        GetPackageListHandle_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RegisterPackageNotify.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterPackageNotify(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 RegisterPackageNotify_Arg_1 = {0};
    EFI_GUID * RegisterPackageNotify_Arg_2 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    EFI_HII_DATABASE_NOTIFY_TYPE RegisterPackageNotify_Arg_4 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RegisterPackageNotify_Arg_1), (VOID *)&RegisterPackageNotify_Arg_1);
    
    UINT8* RegisterPackageNotify_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*RegisterPackageNotify_Arg_2_choice), (VOID *)RegisterPackageNotify_Arg_2_choice);
    switch(*RegisterPackageNotify_Arg_2_choice % 7) {
        case 0:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            GUID * CopyGuid_Arg_1 = (GUID *)AllocateZeroPool(sizeof(GUID));
            
            // Generator Struct Variable Initialization
            {
                UINT32 Firness_Data1;
                ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
                CopyGuid_Arg_1->Data1 = Firness_Data1;
            }
            {
                UINT16 Firness_Data2;
                ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
                CopyGuid_Arg_1->Data2 = Firness_Data2;
            }
            {
                UINT16 Firness_Data3;
                ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
                CopyGuid_Arg_1->Data3 = Firness_Data3;
            }
            ReadBytes(Input, sizeof(CopyGuid_Arg_1->Data4), (VOID *)&(CopyGuid_Arg_1->Data4));
            
            FirnessSanitizer(TRUE);
            CopyGuid(
                RegisterPackageNotify_Arg_2,
                CopyGuid_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            ExtractGuidedSectionGetGuidList(
                &RegisterPackageNotify_Arg_2
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * StrToGuid_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 StrToGuid_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(StrToGuid_Arg_0_choice), (VOID *)&StrToGuid_Arg_0_choice);
            switch(StrToGuid_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*StrToGuid_Arg_0), (VOID *)StrToGuid_Arg_0);
                    StrToGuid_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(StrToGuid_Arg_0);
                    StrToGuid_Arg_0 = NULL;
                    break;
                }
            }
            
            UINT8 StrToGuid_Arg_0_LiveChoice = 0;
            ReadBytes(Input, sizeof(StrToGuid_Arg_0_LiveChoice), (VOID *)&StrToGuid_Arg_0_LiveChoice);
            if (FirnessLive_CHAR16___Count > 0 && (StrToGuid_Arg_0_LiveChoice & 1)) {
                StrToGuid_Arg_0 = FirnessLive_CHAR16__[StrToGuid_Arg_0_LiveChoice % FirnessLive_CHAR16___Count];
            }
            FirnessSanitizer(TRUE);
            StrToGuid(
                StrToGuid_Arg_0,
                RegisterPackageNotify_Arg_2
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            Status = NetLibGetSystemGuid(
                RegisterPackageNotify_Arg_2
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 4:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * GetGuidFromStringName_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            CHAR8 * GetGuidFromStringName_Arg_1 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
            
            // Fuzzable Variable Initialization
            UINT8 GetGuidFromStringName_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(GetGuidFromStringName_Arg_0_choice), (VOID *)&GetGuidFromStringName_Arg_0_choice);
            switch(GetGuidFromStringName_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*GetGuidFromStringName_Arg_0), (VOID *)GetGuidFromStringName_Arg_0);
                    GetGuidFromStringName_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(GetGuidFromStringName_Arg_0);
                    GetGuidFromStringName_Arg_0 = NULL;
                    break;
                }
            }
            
            // Fuzzable Variable Initialization
            UINT8 GetGuidFromStringName_Arg_1_choice = 0;
            ReadBytes(Input, sizeof(GetGuidFromStringName_Arg_1_choice), (VOID *)&GetGuidFromStringName_Arg_1_choice);
            switch(GetGuidFromStringName_Arg_1_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*GetGuidFromStringName_Arg_1), (VOID *)GetGuidFromStringName_Arg_1);
                    GetGuidFromStringName_Arg_1[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(GetGuidFromStringName_Arg_1);
                    GetGuidFromStringName_Arg_1 = NULL;
                    break;
                }
            }
            
            UINT8 GetGuidFromStringName_Arg_0_LiveChoice = 0;
            ReadBytes(Input, sizeof(GetGuidFromStringName_Arg_0_LiveChoice), (VOID *)&GetGuidFromStringName_Arg_0_LiveChoice);
            if (FirnessLive_CHAR16___Count > 0 && (GetGuidFromStringName_Arg_0_LiveChoice & 1)) {
                GetGuidFromStringName_Arg_0 = FirnessLive_CHAR16__[GetGuidFromStringName_Arg_0_LiveChoice % FirnessLive_CHAR16___Count];
            }
            UINT8 GetGuidFromStringName_Arg_1_LiveChoice = 0;
            ReadBytes(Input, sizeof(GetGuidFromStringName_Arg_1_LiveChoice), (VOID *)&GetGuidFromStringName_Arg_1_LiveChoice);
            if (FirnessLive_CHAR8___Count > 0 && (GetGuidFromStringName_Arg_1_LiveChoice & 1)) {
                GetGuidFromStringName_Arg_1 = FirnessLive_CHAR8__[GetGuidFromStringName_Arg_1_LiveChoice % FirnessLive_CHAR8___Count];
            }
            FirnessSanitizer(TRUE);
            Status = GetGuidFromStringName(
                GetGuidFromStringName_Arg_0,
                GetGuidFromStringName_Arg_1,
                &RegisterPackageNotify_Arg_2
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 5:
        {
        // Fuzzable Variable Initialization
        UINT8 RegisterPackageNotify_Arg_2_choice = 0;
        ReadBytes(Input, sizeof(RegisterPackageNotify_Arg_2_choice), (VOID *)&RegisterPackageNotify_Arg_2_choice);
        switch(RegisterPackageNotify_Arg_2_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(*RegisterPackageNotify_Arg_2), (VOID *)RegisterPackageNotify_Arg_2);
                break;
            case 1:
            {
                gBS->FreePool(RegisterPackageNotify_Arg_2);
                RegisterPackageNotify_Arg_2 = NULL;
                break;
            }
        }
    
            break;
        }
        case 6:
        {
        // Generator Struct Variable Initialization
        {
            UINT32 Firness_Data1;
            ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
            RegisterPackageNotify_Arg_2->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            RegisterPackageNotify_Arg_2->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            RegisterPackageNotify_Arg_2->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(RegisterPackageNotify_Arg_2->Data4), (VOID *)&(RegisterPackageNotify_Arg_2->Data4));
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RegisterPackageNotify_Arg_4), (VOID *)&RegisterPackageNotify_Arg_4);
    
    /*
        Output Variable(s)
    */
    EFI_HANDLE * RegisterPackageNotify_Arg_5 = (EFI_HANDLE *)AllocateZeroPool(sizeof(EFI_HANDLE));
    UINT8* RegisterPackageNotify_Arg_5_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*RegisterPackageNotify_Arg_5_OutputChoice), (VOID *)RegisterPackageNotify_Arg_5_OutputChoice);
    if(*RegisterPackageNotify_Arg_5_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*RegisterPackageNotify_Arg_5), (VOID *)RegisterPackageNotify_Arg_5);
    }
    UINT8 RegisterPackageNotify_Arg_2_LiveChoice = 0;
    ReadBytes(Input, sizeof(RegisterPackageNotify_Arg_2_LiveChoice), (VOID *)&RegisterPackageNotify_Arg_2_LiveChoice);
    if (FirnessLive_EFI_GUID___Count > 0 && (RegisterPackageNotify_Arg_2_LiveChoice & 1)) {
        RegisterPackageNotify_Arg_2 = FirnessLive_EFI_GUID__[RegisterPackageNotify_Arg_2_LiveChoice % FirnessLive_EFI_GUID___Count];
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->RegisterPackageNotify(
        ProtocolVariable,
        RegisterPackageNotify_Arg_1,
        RegisterPackageNotify_Arg_2,
        NULL,
        RegisterPackageNotify_Arg_4,
        RegisterPackageNotify_Arg_5
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UnregisterPackageNotify.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUnregisterPackageNotify(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->UnregisterPackageNotify(
        ProtocolVariable,
        ImageHandle
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetKeyboardLayout.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetKeyboardLayout(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * SetKeyboardLayout_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
    UINT8* SetKeyboardLayout_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*SetKeyboardLayout_Arg_1_choice), (VOID *)SetKeyboardLayout_Arg_1_choice);
    switch(*SetKeyboardLayout_Arg_1_choice % 8) {
        case 0:
        {
        // EFI_GUID Variable Initialization
        SetKeyboardLayout_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            GUID * CopyGuid_Arg_1 = (GUID *)AllocateZeroPool(sizeof(GUID));
            
            // Generator Struct Variable Initialization
            {
                UINT32 Firness_Data1;
                ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
                CopyGuid_Arg_1->Data1 = Firness_Data1;
            }
            {
                UINT16 Firness_Data2;
                ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
                CopyGuid_Arg_1->Data2 = Firness_Data2;
            }
            {
                UINT16 Firness_Data3;
                ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
                CopyGuid_Arg_1->Data3 = Firness_Data3;
            }
            ReadBytes(Input, sizeof(CopyGuid_Arg_1->Data4), (VOID *)&(CopyGuid_Arg_1->Data4));
            
            FirnessSanitizer(TRUE);
            CopyGuid(
                SetKeyboardLayout_Arg_1,
                CopyGuid_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            ExtractGuidedSectionGetGuidList(
                &SetKeyboardLayout_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * StrToGuid_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 StrToGuid_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(StrToGuid_Arg_0_choice), (VOID *)&StrToGuid_Arg_0_choice);
            switch(StrToGuid_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*StrToGuid_Arg_0), (VOID *)StrToGuid_Arg_0);
                    StrToGuid_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(StrToGuid_Arg_0);
                    StrToGuid_Arg_0 = NULL;
                    break;
                }
            }
            
            UINT8 StrToGuid_Arg_0_LiveChoice = 0;
            ReadBytes(Input, sizeof(StrToGuid_Arg_0_LiveChoice), (VOID *)&StrToGuid_Arg_0_LiveChoice);
            if (FirnessLive_CHAR16___Count > 0 && (StrToGuid_Arg_0_LiveChoice & 1)) {
                StrToGuid_Arg_0 = FirnessLive_CHAR16__[StrToGuid_Arg_0_LiveChoice % FirnessLive_CHAR16___Count];
            }
            FirnessSanitizer(TRUE);
            StrToGuid(
                StrToGuid_Arg_0,
                SetKeyboardLayout_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 4:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            Status = NetLibGetSystemGuid(
                SetKeyboardLayout_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 5:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * GetGuidFromStringName_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            CHAR8 * GetGuidFromStringName_Arg_1 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
            
            // Fuzzable Variable Initialization
            UINT8 GetGuidFromStringName_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(GetGuidFromStringName_Arg_0_choice), (VOID *)&GetGuidFromStringName_Arg_0_choice);
            switch(GetGuidFromStringName_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*GetGuidFromStringName_Arg_0), (VOID *)GetGuidFromStringName_Arg_0);
                    GetGuidFromStringName_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(GetGuidFromStringName_Arg_0);
                    GetGuidFromStringName_Arg_0 = NULL;
                    break;
                }
            }
            
            // Fuzzable Variable Initialization
            UINT8 GetGuidFromStringName_Arg_1_choice = 0;
            ReadBytes(Input, sizeof(GetGuidFromStringName_Arg_1_choice), (VOID *)&GetGuidFromStringName_Arg_1_choice);
            switch(GetGuidFromStringName_Arg_1_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*GetGuidFromStringName_Arg_1), (VOID *)GetGuidFromStringName_Arg_1);
                    GetGuidFromStringName_Arg_1[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(GetGuidFromStringName_Arg_1);
                    GetGuidFromStringName_Arg_1 = NULL;
                    break;
                }
            }
            
            UINT8 GetGuidFromStringName_Arg_0_LiveChoice = 0;
            ReadBytes(Input, sizeof(GetGuidFromStringName_Arg_0_LiveChoice), (VOID *)&GetGuidFromStringName_Arg_0_LiveChoice);
            if (FirnessLive_CHAR16___Count > 0 && (GetGuidFromStringName_Arg_0_LiveChoice & 1)) {
                GetGuidFromStringName_Arg_0 = FirnessLive_CHAR16__[GetGuidFromStringName_Arg_0_LiveChoice % FirnessLive_CHAR16___Count];
            }
            UINT8 GetGuidFromStringName_Arg_1_LiveChoice = 0;
            ReadBytes(Input, sizeof(GetGuidFromStringName_Arg_1_LiveChoice), (VOID *)&GetGuidFromStringName_Arg_1_LiveChoice);
            if (FirnessLive_CHAR8___Count > 0 && (GetGuidFromStringName_Arg_1_LiveChoice & 1)) {
                GetGuidFromStringName_Arg_1 = FirnessLive_CHAR8__[GetGuidFromStringName_Arg_1_LiveChoice % FirnessLive_CHAR8___Count];
            }
            FirnessSanitizer(TRUE);
            Status = GetGuidFromStringName(
                GetGuidFromStringName_Arg_0,
                GetGuidFromStringName_Arg_1,
                &SetKeyboardLayout_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 6:
        {
        // Fuzzable Variable Initialization
        UINT8 SetKeyboardLayout_Arg_1_choice = 0;
        ReadBytes(Input, sizeof(SetKeyboardLayout_Arg_1_choice), (VOID *)&SetKeyboardLayout_Arg_1_choice);
        switch(SetKeyboardLayout_Arg_1_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(*SetKeyboardLayout_Arg_1), (VOID *)SetKeyboardLayout_Arg_1);
                break;
            case 1:
            {
                gBS->FreePool(SetKeyboardLayout_Arg_1);
                SetKeyboardLayout_Arg_1 = NULL;
                break;
            }
        }
    
            break;
        }
        case 7:
        {
        // Generator Struct Variable Initialization
        {
            UINT32 Firness_Data1;
            ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
            SetKeyboardLayout_Arg_1->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            SetKeyboardLayout_Arg_1->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            SetKeyboardLayout_Arg_1->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(SetKeyboardLayout_Arg_1->Data4), (VOID *)&(SetKeyboardLayout_Arg_1->Data4));
    
            break;
        }
    }
    UINT8 SetKeyboardLayout_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(SetKeyboardLayout_Arg_1_LiveChoice), (VOID *)&SetKeyboardLayout_Arg_1_LiveChoice);
    if (FirnessLive_EFI_GUID___Count > 0 && (SetKeyboardLayout_Arg_1_LiveChoice & 1)) {
        SetKeyboardLayout_Arg_1 = FirnessLive_EFI_GUID__[SetKeyboardLayout_Arg_1_LiveChoice % FirnessLive_EFI_GUID___Count];
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->SetKeyboardLayout(
        ProtocolVariable,
        SetKeyboardLayout_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetKeyboardLayout.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetKeyboardLayout(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * GetKeyboardLayout_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINT16 * GetKeyboardLayout_Arg_2 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    
    UINT8* GetKeyboardLayout_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetKeyboardLayout_Arg_1_choice), (VOID *)GetKeyboardLayout_Arg_1_choice);
    switch(*GetKeyboardLayout_Arg_1_choice % 7) {
        case 0:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            GUID * CopyGuid_Arg_1 = (GUID *)AllocateZeroPool(sizeof(GUID));
            
            // Generator Struct Variable Initialization
            {
                UINT32 Firness_Data1;
                ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
                CopyGuid_Arg_1->Data1 = Firness_Data1;
            }
            {
                UINT16 Firness_Data2;
                ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
                CopyGuid_Arg_1->Data2 = Firness_Data2;
            }
            {
                UINT16 Firness_Data3;
                ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
                CopyGuid_Arg_1->Data3 = Firness_Data3;
            }
            ReadBytes(Input, sizeof(CopyGuid_Arg_1->Data4), (VOID *)&(CopyGuid_Arg_1->Data4));
            
            FirnessSanitizer(TRUE);
            CopyGuid(
                GetKeyboardLayout_Arg_1,
                CopyGuid_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            ExtractGuidedSectionGetGuidList(
                &GetKeyboardLayout_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * StrToGuid_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 StrToGuid_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(StrToGuid_Arg_0_choice), (VOID *)&StrToGuid_Arg_0_choice);
            switch(StrToGuid_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*StrToGuid_Arg_0), (VOID *)StrToGuid_Arg_0);
                    StrToGuid_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(StrToGuid_Arg_0);
                    StrToGuid_Arg_0 = NULL;
                    break;
                }
            }
            
            UINT8 StrToGuid_Arg_0_LiveChoice = 0;
            ReadBytes(Input, sizeof(StrToGuid_Arg_0_LiveChoice), (VOID *)&StrToGuid_Arg_0_LiveChoice);
            if (FirnessLive_CHAR16___Count > 0 && (StrToGuid_Arg_0_LiveChoice & 1)) {
                StrToGuid_Arg_0 = FirnessLive_CHAR16__[StrToGuid_Arg_0_LiveChoice % FirnessLive_CHAR16___Count];
            }
            FirnessSanitizer(TRUE);
            StrToGuid(
                StrToGuid_Arg_0,
                GetKeyboardLayout_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            Status = NetLibGetSystemGuid(
                GetKeyboardLayout_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 4:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * GetGuidFromStringName_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            CHAR8 * GetGuidFromStringName_Arg_1 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
            
            // Fuzzable Variable Initialization
            UINT8 GetGuidFromStringName_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(GetGuidFromStringName_Arg_0_choice), (VOID *)&GetGuidFromStringName_Arg_0_choice);
            switch(GetGuidFromStringName_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*GetGuidFromStringName_Arg_0), (VOID *)GetGuidFromStringName_Arg_0);
                    GetGuidFromStringName_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(GetGuidFromStringName_Arg_0);
                    GetGuidFromStringName_Arg_0 = NULL;
                    break;
                }
            }
            
            // Fuzzable Variable Initialization
            UINT8 GetGuidFromStringName_Arg_1_choice = 0;
            ReadBytes(Input, sizeof(GetGuidFromStringName_Arg_1_choice), (VOID *)&GetGuidFromStringName_Arg_1_choice);
            switch(GetGuidFromStringName_Arg_1_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*GetGuidFromStringName_Arg_1), (VOID *)GetGuidFromStringName_Arg_1);
                    GetGuidFromStringName_Arg_1[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(GetGuidFromStringName_Arg_1);
                    GetGuidFromStringName_Arg_1 = NULL;
                    break;
                }
            }
            
            UINT8 GetGuidFromStringName_Arg_0_LiveChoice = 0;
            ReadBytes(Input, sizeof(GetGuidFromStringName_Arg_0_LiveChoice), (VOID *)&GetGuidFromStringName_Arg_0_LiveChoice);
            if (FirnessLive_CHAR16___Count > 0 && (GetGuidFromStringName_Arg_0_LiveChoice & 1)) {
                GetGuidFromStringName_Arg_0 = FirnessLive_CHAR16__[GetGuidFromStringName_Arg_0_LiveChoice % FirnessLive_CHAR16___Count];
            }
            UINT8 GetGuidFromStringName_Arg_1_LiveChoice = 0;
            ReadBytes(Input, sizeof(GetGuidFromStringName_Arg_1_LiveChoice), (VOID *)&GetGuidFromStringName_Arg_1_LiveChoice);
            if (FirnessLive_CHAR8___Count > 0 && (GetGuidFromStringName_Arg_1_LiveChoice & 1)) {
                GetGuidFromStringName_Arg_1 = FirnessLive_CHAR8__[GetGuidFromStringName_Arg_1_LiveChoice % FirnessLive_CHAR8___Count];
            }
            FirnessSanitizer(TRUE);
            Status = GetGuidFromStringName(
                GetGuidFromStringName_Arg_0,
                GetGuidFromStringName_Arg_1,
                &GetKeyboardLayout_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 5:
        {
        // Fuzzable Variable Initialization
        UINT8 GetKeyboardLayout_Arg_1_choice = 0;
        ReadBytes(Input, sizeof(GetKeyboardLayout_Arg_1_choice), (VOID *)&GetKeyboardLayout_Arg_1_choice);
        switch(GetKeyboardLayout_Arg_1_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(*GetKeyboardLayout_Arg_1), (VOID *)GetKeyboardLayout_Arg_1);
                break;
            case 1:
            {
                gBS->FreePool(GetKeyboardLayout_Arg_1);
                GetKeyboardLayout_Arg_1 = NULL;
                break;
            }
        }
    
            break;
        }
        case 6:
        {
        // Generator Struct Variable Initialization
        {
            UINT32 Firness_Data1;
            ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
            GetKeyboardLayout_Arg_1->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            GetKeyboardLayout_Arg_1->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            GetKeyboardLayout_Arg_1->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(GetKeyboardLayout_Arg_1->Data4), (VOID *)&(GetKeyboardLayout_Arg_1->Data4));
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 GetKeyboardLayout_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetKeyboardLayout_Arg_2_choice), (VOID *)&GetKeyboardLayout_Arg_2_choice);
    switch(GetKeyboardLayout_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(*GetKeyboardLayout_Arg_2), (VOID *)GetKeyboardLayout_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(GetKeyboardLayout_Arg_2);
            GetKeyboardLayout_Arg_2 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_HII_KEYBOARD_LAYOUT * GetKeyboardLayout_Arg_3 = (EFI_HII_KEYBOARD_LAYOUT *)AllocateZeroPool(sizeof(EFI_HII_KEYBOARD_LAYOUT));
    UINT8* GetKeyboardLayout_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetKeyboardLayout_Arg_3_OutputChoice), (VOID *)GetKeyboardLayout_Arg_3_OutputChoice);
    if(*GetKeyboardLayout_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetKeyboardLayout_Arg_3), (VOID *)GetKeyboardLayout_Arg_3);
    }
    UINT8 GetKeyboardLayout_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetKeyboardLayout_Arg_1_LiveChoice), (VOID *)&GetKeyboardLayout_Arg_1_LiveChoice);
    if (FirnessLive_EFI_GUID___Count > 0 && (GetKeyboardLayout_Arg_1_LiveChoice & 1)) {
        GetKeyboardLayout_Arg_1 = FirnessLive_EFI_GUID__[GetKeyboardLayout_Arg_1_LiveChoice % FirnessLive_EFI_GUID___Count];
    }
    UINT8 GetKeyboardLayout_Arg_2_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetKeyboardLayout_Arg_2_LiveChoice), (VOID *)&GetKeyboardLayout_Arg_2_LiveChoice);
    if (FirnessLive_UINT16___Count > 0 && (GetKeyboardLayout_Arg_2_LiveChoice & 1)) {
        GetKeyboardLayout_Arg_2 = FirnessLive_UINT16__[GetKeyboardLayout_Arg_2_LiveChoice % FirnessLive_UINT16___Count];
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetKeyboardLayout(
        ProtocolVariable,
        GetKeyboardLayout_Arg_1,
        GetKeyboardLayout_Arg_2,
        GetKeyboardLayout_Arg_3
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_UINT16___Count < 4 && GetKeyboardLayout_Arg_2 != NULL) {
        FirnessLive_UINT16__[FirnessLive_UINT16___Count++] = GetKeyboardLayout_Arg_2;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called NewPackageList.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzNewPackageList(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_PACKAGE_LIST_HEADER * NewPackageList_Arg_1 = (EFI_HII_PACKAGE_LIST_HEADER *)AllocateZeroPool(sizeof(EFI_HII_PACKAGE_LIST_HEADER));
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(NewPackageList_Arg_1->PackageListGuid), (VOID *)&(NewPackageList_Arg_1->PackageListGuid));
    NewPackageList_Arg_1->PackageLength = sizeof(EFI_HII_PACKAGE_LIST_HEADER);
    
    /*
        Output Variable(s)
    */
    EFI_HII_HANDLE * NewPackageList_Arg_3 = (EFI_HII_HANDLE *)AllocateZeroPool(sizeof(EFI_HII_HANDLE));
    UINT8* NewPackageList_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*NewPackageList_Arg_3_OutputChoice), (VOID *)NewPackageList_Arg_3_OutputChoice);
    if(*NewPackageList_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*NewPackageList_Arg_3), (VOID *)NewPackageList_Arg_3);
    }
    UINT8 NewPackageList_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(NewPackageList_Arg_1_LiveChoice), (VOID *)&NewPackageList_Arg_1_LiveChoice);
    if (FirnessLive_EFI_HII_PACKAGE_LIST_HEADER___Count > 0 && (NewPackageList_Arg_1_LiveChoice & 1)) {
        NewPackageList_Arg_1 = FirnessLive_EFI_HII_PACKAGE_LIST_HEADER__[NewPackageList_Arg_1_LiveChoice % FirnessLive_EFI_HII_PACKAGE_LIST_HEADER___Count];
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->NewPackageList(
        ProtocolVariable,
        NewPackageList_Arg_1,
        ImageHandle,
        NewPackageList_Arg_3
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RemovePackageList.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRemovePackageList(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE RemovePackageList_Arg_1 = {0};
    
    UINT8* RemovePackageList_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*RemovePackageList_Arg_1_choice), (VOID *)RemovePackageList_Arg_1_choice);
    switch(*RemovePackageList_Arg_1_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(RemovePackageList_Arg_1), (VOID *)&RemovePackageList_Arg_1);
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(RemovePackageList_Arg_1), (VOID *)&RemovePackageList_Arg_1);
    
            break;
        }
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->RemovePackageList(
        ProtocolVariable,
        RemovePackageList_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ListPackageLists.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzListPackageLists(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 ListPackageLists_Arg_1 = {0};
    EFI_GUID * ListPackageLists_Arg_2 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINTN * ListPackageLists_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ListPackageLists_Arg_1), (VOID *)&ListPackageLists_Arg_1);
    ListPackageLists_Arg_1 = ListPackageLists_Arg_1 % (4096 + 1);
    
    UINT8* ListPackageLists_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*ListPackageLists_Arg_2_choice), (VOID *)ListPackageLists_Arg_2_choice);
    switch(*ListPackageLists_Arg_2_choice % 7) {
        case 0:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            GUID * CopyGuid_Arg_1 = (GUID *)AllocateZeroPool(sizeof(GUID));
            
            // Generator Struct Variable Initialization
            {
                UINT32 Firness_Data1;
                ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
                CopyGuid_Arg_1->Data1 = Firness_Data1;
            }
            {
                UINT16 Firness_Data2;
                ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
                CopyGuid_Arg_1->Data2 = Firness_Data2;
            }
            {
                UINT16 Firness_Data3;
                ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
                CopyGuid_Arg_1->Data3 = Firness_Data3;
            }
            ReadBytes(Input, sizeof(CopyGuid_Arg_1->Data4), (VOID *)&(CopyGuid_Arg_1->Data4));
            
            FirnessSanitizer(TRUE);
            CopyGuid(
                ListPackageLists_Arg_2,
                CopyGuid_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            ExtractGuidedSectionGetGuidList(
                &ListPackageLists_Arg_2
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * StrToGuid_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 StrToGuid_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(StrToGuid_Arg_0_choice), (VOID *)&StrToGuid_Arg_0_choice);
            switch(StrToGuid_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*StrToGuid_Arg_0), (VOID *)StrToGuid_Arg_0);
                    StrToGuid_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(StrToGuid_Arg_0);
                    StrToGuid_Arg_0 = NULL;
                    break;
                }
            }
            
            UINT8 StrToGuid_Arg_0_LiveChoice = 0;
            ReadBytes(Input, sizeof(StrToGuid_Arg_0_LiveChoice), (VOID *)&StrToGuid_Arg_0_LiveChoice);
            if (FirnessLive_CHAR16___Count > 0 && (StrToGuid_Arg_0_LiveChoice & 1)) {
                StrToGuid_Arg_0 = FirnessLive_CHAR16__[StrToGuid_Arg_0_LiveChoice % FirnessLive_CHAR16___Count];
            }
            FirnessSanitizer(TRUE);
            StrToGuid(
                StrToGuid_Arg_0,
                ListPackageLists_Arg_2
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            Status = NetLibGetSystemGuid(
                ListPackageLists_Arg_2
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 4:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * GetGuidFromStringName_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            CHAR8 * GetGuidFromStringName_Arg_1 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
            
            // Fuzzable Variable Initialization
            UINT8 GetGuidFromStringName_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(GetGuidFromStringName_Arg_0_choice), (VOID *)&GetGuidFromStringName_Arg_0_choice);
            switch(GetGuidFromStringName_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*GetGuidFromStringName_Arg_0), (VOID *)GetGuidFromStringName_Arg_0);
                    GetGuidFromStringName_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(GetGuidFromStringName_Arg_0);
                    GetGuidFromStringName_Arg_0 = NULL;
                    break;
                }
            }
            
            // Fuzzable Variable Initialization
            UINT8 GetGuidFromStringName_Arg_1_choice = 0;
            ReadBytes(Input, sizeof(GetGuidFromStringName_Arg_1_choice), (VOID *)&GetGuidFromStringName_Arg_1_choice);
            switch(GetGuidFromStringName_Arg_1_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*GetGuidFromStringName_Arg_1), (VOID *)GetGuidFromStringName_Arg_1);
                    GetGuidFromStringName_Arg_1[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(GetGuidFromStringName_Arg_1);
                    GetGuidFromStringName_Arg_1 = NULL;
                    break;
                }
            }
            
            UINT8 GetGuidFromStringName_Arg_0_LiveChoice = 0;
            ReadBytes(Input, sizeof(GetGuidFromStringName_Arg_0_LiveChoice), (VOID *)&GetGuidFromStringName_Arg_0_LiveChoice);
            if (FirnessLive_CHAR16___Count > 0 && (GetGuidFromStringName_Arg_0_LiveChoice & 1)) {
                GetGuidFromStringName_Arg_0 = FirnessLive_CHAR16__[GetGuidFromStringName_Arg_0_LiveChoice % FirnessLive_CHAR16___Count];
            }
            UINT8 GetGuidFromStringName_Arg_1_LiveChoice = 0;
            ReadBytes(Input, sizeof(GetGuidFromStringName_Arg_1_LiveChoice), (VOID *)&GetGuidFromStringName_Arg_1_LiveChoice);
            if (FirnessLive_CHAR8___Count > 0 && (GetGuidFromStringName_Arg_1_LiveChoice & 1)) {
                GetGuidFromStringName_Arg_1 = FirnessLive_CHAR8__[GetGuidFromStringName_Arg_1_LiveChoice % FirnessLive_CHAR8___Count];
            }
            FirnessSanitizer(TRUE);
            Status = GetGuidFromStringName(
                GetGuidFromStringName_Arg_0,
                GetGuidFromStringName_Arg_1,
                &ListPackageLists_Arg_2
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 5:
        {
        // Fuzzable Variable Initialization
        UINT8 ListPackageLists_Arg_2_choice = 0;
        ReadBytes(Input, sizeof(ListPackageLists_Arg_2_choice), (VOID *)&ListPackageLists_Arg_2_choice);
        switch(ListPackageLists_Arg_2_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(*ListPackageLists_Arg_2), (VOID *)ListPackageLists_Arg_2);
                break;
            case 1:
            {
                gBS->FreePool(ListPackageLists_Arg_2);
                ListPackageLists_Arg_2 = NULL;
                break;
            }
        }
    
            break;
        }
        case 6:
        {
        // Generator Struct Variable Initialization
        {
            UINT32 Firness_Data1;
            ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
            ListPackageLists_Arg_2->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            ListPackageLists_Arg_2->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            ListPackageLists_Arg_2->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(ListPackageLists_Arg_2->Data4), (VOID *)&(ListPackageLists_Arg_2->Data4));
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 ListPackageLists_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(ListPackageLists_Arg_3_choice), (VOID *)&ListPackageLists_Arg_3_choice);
    switch(ListPackageLists_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(*ListPackageLists_Arg_3), (VOID *)ListPackageLists_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(ListPackageLists_Arg_3);
            ListPackageLists_Arg_3 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_HII_HANDLE * ListPackageLists_Arg_4 = (EFI_HII_HANDLE *)AllocateZeroPool(sizeof(EFI_HII_HANDLE));
    UINT8* ListPackageLists_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*ListPackageLists_Arg_4_OutputChoice), (VOID *)ListPackageLists_Arg_4_OutputChoice);
    if(*ListPackageLists_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ListPackageLists_Arg_4), (VOID *)ListPackageLists_Arg_4);
    }
    UINT8 ListPackageLists_Arg_2_LiveChoice = 0;
    ReadBytes(Input, sizeof(ListPackageLists_Arg_2_LiveChoice), (VOID *)&ListPackageLists_Arg_2_LiveChoice);
    if (FirnessLive_EFI_GUID___Count > 0 && (ListPackageLists_Arg_2_LiveChoice & 1)) {
        ListPackageLists_Arg_2 = FirnessLive_EFI_GUID__[ListPackageLists_Arg_2_LiveChoice % FirnessLive_EFI_GUID___Count];
    }
    UINT8 ListPackageLists_Arg_3_LiveChoice = 0;
    ReadBytes(Input, sizeof(ListPackageLists_Arg_3_LiveChoice), (VOID *)&ListPackageLists_Arg_3_LiveChoice);
    if (FirnessLive_UINTN___Count > 0 && (ListPackageLists_Arg_3_LiveChoice & 1)) {
        ListPackageLists_Arg_3 = FirnessLive_UINTN__[ListPackageLists_Arg_3_LiveChoice % FirnessLive_UINTN___Count];
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->ListPackageLists(
        ProtocolVariable,
        ListPackageLists_Arg_1,
        ListPackageLists_Arg_2,
        ListPackageLists_Arg_3,
        ListPackageLists_Arg_4
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_UINTN___Count < 4 && ListPackageLists_Arg_3 != NULL) {
        FirnessLive_UINTN__[FirnessLive_UINTN___Count++] = ListPackageLists_Arg_3;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UpdatePackageList.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUpdatePackageList(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE UpdatePackageList_Arg_1 = {0};
    EFI_HII_PACKAGE_LIST_HEADER * UpdatePackageList_Arg_2 = (EFI_HII_PACKAGE_LIST_HEADER *)AllocateZeroPool(sizeof(EFI_HII_PACKAGE_LIST_HEADER));
    
    UINT8* UpdatePackageList_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*UpdatePackageList_Arg_1_choice), (VOID *)UpdatePackageList_Arg_1_choice);
    switch(*UpdatePackageList_Arg_1_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(UpdatePackageList_Arg_1), (VOID *)&UpdatePackageList_Arg_1);
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(UpdatePackageList_Arg_1), (VOID *)&UpdatePackageList_Arg_1);
    
            break;
        }
    }
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(UpdatePackageList_Arg_2->PackageListGuid), (VOID *)&(UpdatePackageList_Arg_2->PackageListGuid));
    UpdatePackageList_Arg_2->PackageLength = sizeof(EFI_HII_PACKAGE_LIST_HEADER);
    
    UINT8 UpdatePackageList_Arg_2_LiveChoice = 0;
    ReadBytes(Input, sizeof(UpdatePackageList_Arg_2_LiveChoice), (VOID *)&UpdatePackageList_Arg_2_LiveChoice);
    if (FirnessLive_EFI_HII_PACKAGE_LIST_HEADER___Count > 0 && (UpdatePackageList_Arg_2_LiveChoice & 1)) {
        UpdatePackageList_Arg_2 = FirnessLive_EFI_HII_PACKAGE_LIST_HEADER__[UpdatePackageList_Arg_2_LiveChoice % FirnessLive_EFI_HII_PACKAGE_LIST_HEADER___Count];
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->UpdatePackageList(
        ProtocolVariable,
        UpdatePackageList_Arg_1,
        UpdatePackageList_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}

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
    
    UINT8* NewString_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*NewString_Arg_1_choice), (VOID *)NewString_Arg_1_choice);
    switch(*NewString_Arg_1_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(NewString_Arg_1), (VOID *)&NewString_Arg_1);
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(NewString_Arg_1), (VOID *)&NewString_Arg_1);
    
            break;
        }
    }
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
    UINT8 NewString_Arg_3_LiveChoice = 0;
    ReadBytes(Input, sizeof(NewString_Arg_3_LiveChoice), (VOID *)&NewString_Arg_3_LiveChoice);
    if (FirnessLive_CHAR8___Count > 0 && (NewString_Arg_3_LiveChoice & 1)) {
        NewString_Arg_3 = FirnessLive_CHAR8__[NewString_Arg_3_LiveChoice % FirnessLive_CHAR8___Count];
    }
    UINT8 NewString_Arg_4_LiveChoice = 0;
    ReadBytes(Input, sizeof(NewString_Arg_4_LiveChoice), (VOID *)&NewString_Arg_4_LiveChoice);
    if (FirnessLive_CHAR16___Count > 0 && (NewString_Arg_4_LiveChoice & 1)) {
        NewString_Arg_4 = FirnessLive_CHAR16__[NewString_Arg_4_LiveChoice % FirnessLive_CHAR16___Count];
    }
    UINT8 NewString_Arg_6_LiveChoice = 0;
    ReadBytes(Input, sizeof(NewString_Arg_6_LiveChoice), (VOID *)&NewString_Arg_6_LiveChoice);
    if (FirnessLive_EFI_FONT_INFO___Count > 0 && (NewString_Arg_6_LiveChoice & 1)) {
        NewString_Arg_6 = FirnessLive_EFI_FONT_INFO__[NewString_Arg_6_LiveChoice % FirnessLive_EFI_FONT_INFO___Count];
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
    
    UINT8* SetString_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*SetString_Arg_1_choice), (VOID *)SetString_Arg_1_choice);
    switch(*SetString_Arg_1_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(SetString_Arg_1), (VOID *)&SetString_Arg_1);
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(SetString_Arg_1), (VOID *)&SetString_Arg_1);
    
            break;
        }
    }
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
    
    UINT8 SetString_Arg_3_LiveChoice = 0;
    ReadBytes(Input, sizeof(SetString_Arg_3_LiveChoice), (VOID *)&SetString_Arg_3_LiveChoice);
    if (FirnessLive_CHAR8___Count > 0 && (SetString_Arg_3_LiveChoice & 1)) {
        SetString_Arg_3 = FirnessLive_CHAR8__[SetString_Arg_3_LiveChoice % FirnessLive_CHAR8___Count];
    }
    UINT8 SetString_Arg_5_LiveChoice = 0;
    ReadBytes(Input, sizeof(SetString_Arg_5_LiveChoice), (VOID *)&SetString_Arg_5_LiveChoice);
    if (FirnessLive_EFI_FONT_INFO___Count > 0 && (SetString_Arg_5_LiveChoice & 1)) {
        SetString_Arg_5 = FirnessLive_EFI_FONT_INFO__[SetString_Arg_5_LiveChoice % FirnessLive_EFI_FONT_INFO___Count];
    }
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
    UINTN * GetString_Arg_5 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
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
    
    UINT8* GetString_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetString_Arg_2_choice), (VOID *)GetString_Arg_2_choice);
    switch(*GetString_Arg_2_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(GetString_Arg_2), (VOID *)&GetString_Arg_2);
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(GetString_Arg_2), (VOID *)&GetString_Arg_2);
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetString_Arg_3), (VOID *)&GetString_Arg_3);
    
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
    
    /*
        Output Variable(s)
    */
    CHAR16 * GetString_Arg_4 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    UINT8* GetString_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetString_Arg_4_OutputChoice), (VOID *)GetString_Arg_4_OutputChoice);
    if(*GetString_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetString_Arg_4), (VOID *)GetString_Arg_4);
    }
    EFI_FONT_INFO * GetString_Arg_6 = NULL;
    UINT8* GetString_Arg_6_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetString_Arg_6_OutputChoice), (VOID *)GetString_Arg_6_OutputChoice);
    if(*GetString_Arg_6_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetString_Arg_6), (VOID *)GetString_Arg_6);
    }
    UINT8 GetString_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetString_Arg_1_LiveChoice), (VOID *)&GetString_Arg_1_LiveChoice);
    if (FirnessLive_CHAR8___Count > 0 && (GetString_Arg_1_LiveChoice & 1)) {
        GetString_Arg_1 = FirnessLive_CHAR8__[GetString_Arg_1_LiveChoice % FirnessLive_CHAR8___Count];
    }
    UINT8 GetString_Arg_5_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetString_Arg_5_LiveChoice), (VOID *)&GetString_Arg_5_LiveChoice);
    if (FirnessLive_UINTN___Count > 0 && (GetString_Arg_5_LiveChoice & 1)) {
        GetString_Arg_5 = FirnessLive_UINTN__[GetString_Arg_5_LiveChoice % FirnessLive_UINTN___Count];
    }
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
    if (FirnessLive_CHAR16___Count < 4 && GetString_Arg_4 != NULL) {
        FirnessLive_CHAR16__[FirnessLive_CHAR16___Count++] = GetString_Arg_4;
    }
    if (FirnessLive_UINTN___Count < 4 && GetString_Arg_5 != NULL) {
        FirnessLive_UINTN__[FirnessLive_UINTN___Count++] = GetString_Arg_5;
    }
    if (FirnessLive_EFI_FONT_INFO___Count < 4 && GetString_Arg_6 != NULL) {
        FirnessLive_EFI_FONT_INFO__[FirnessLive_EFI_FONT_INFO___Count++] = GetString_Arg_6;
    }
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
    
    UINT8* GetLanguages_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetLanguages_Arg_1_choice), (VOID *)GetLanguages_Arg_1_choice);
    switch(*GetLanguages_Arg_1_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(GetLanguages_Arg_1), (VOID *)&GetLanguages_Arg_1);
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(GetLanguages_Arg_1), (VOID *)&GetLanguages_Arg_1);
    
            break;
        }
    }
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
    
    UINT8 GetLanguages_Arg_2_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetLanguages_Arg_2_LiveChoice), (VOID *)&GetLanguages_Arg_2_LiveChoice);
    if (FirnessLive_CHAR8___Count > 0 && (GetLanguages_Arg_2_LiveChoice & 1)) {
        GetLanguages_Arg_2 = FirnessLive_CHAR8__[GetLanguages_Arg_2_LiveChoice % FirnessLive_CHAR8___Count];
    }
    UINT8 GetLanguages_Arg_3_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetLanguages_Arg_3_LiveChoice), (VOID *)&GetLanguages_Arg_3_LiveChoice);
    if (FirnessLive_UINTN___Count > 0 && (GetLanguages_Arg_3_LiveChoice & 1)) {
        GetLanguages_Arg_3 = FirnessLive_UINTN__[GetLanguages_Arg_3_LiveChoice % FirnessLive_UINTN___Count];
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
    called StringToImage.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStringToImage(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_FONT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiFontProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_OUT_FLAGS StringToImage_Arg_1 = {0};
    CHAR16 * StringToImage_Arg_2 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    EFI_FONT_DISPLAY_INFO * StringToImage_Arg_3 = (EFI_FONT_DISPLAY_INFO *)AllocateZeroPool(sizeof(EFI_FONT_DISPLAY_INFO));
    EFI_IMAGE_OUTPUT * StringToImage_Arg_4 = NULL;
    UINTN StringToImage_Arg_5 = {0};
    UINTN StringToImage_Arg_6 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StringToImage_Arg_1), (VOID *)&StringToImage_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 StringToImage_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(StringToImage_Arg_2_choice), (VOID *)&StringToImage_Arg_2_choice);
    switch(StringToImage_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*StringToImage_Arg_2), (VOID *)StringToImage_Arg_2);
            StringToImage_Arg_2[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(StringToImage_Arg_2);
            StringToImage_Arg_2 = NULL;
            break;
        }
    }
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(StringToImage_Arg_3->ForegroundColor), (VOID *)&(StringToImage_Arg_3->ForegroundColor));
    ReadBytes(Input, sizeof(StringToImage_Arg_3->BackgroundColor), (VOID *)&(StringToImage_Arg_3->BackgroundColor));
    ReadBytes(Input, sizeof(StringToImage_Arg_3->FontInfoMask), (VOID *)&(StringToImage_Arg_3->FontInfoMask));
    ReadBytes(Input, sizeof(StringToImage_Arg_3->FontInfo), (VOID *)&(StringToImage_Arg_3->FontInfo));
    
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StringToImage_Arg_5), (VOID *)&StringToImage_Arg_5);
    StringToImage_Arg_5 = StringToImage_Arg_5 % (4096 + 1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StringToImage_Arg_6), (VOID *)&StringToImage_Arg_6);
    StringToImage_Arg_6 = StringToImage_Arg_6 % (4096 + 1);
    
    /*
        Output Variable(s)
    */
    EFI_HII_ROW_INFO * StringToImage_Arg_7 = NULL;
    UINT8* StringToImage_Arg_7_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*StringToImage_Arg_7_OutputChoice), (VOID *)StringToImage_Arg_7_OutputChoice);
    if(*StringToImage_Arg_7_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*StringToImage_Arg_7), (VOID *)StringToImage_Arg_7);
    }
    UINTN * StringToImage_Arg_8 = (UINTN *)AllocateZeroPool(4096);
    UINT8* StringToImage_Arg_8_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*StringToImage_Arg_8_OutputChoice), (VOID *)StringToImage_Arg_8_OutputChoice);
    if(*StringToImage_Arg_8_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*StringToImage_Arg_8), (VOID *)StringToImage_Arg_8);
    }
    UINTN * StringToImage_Arg_9 = (UINTN *)AllocateZeroPool(4096);
    UINT8* StringToImage_Arg_9_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*StringToImage_Arg_9_OutputChoice), (VOID *)StringToImage_Arg_9_OutputChoice);
    if(*StringToImage_Arg_9_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*StringToImage_Arg_9), (VOID *)StringToImage_Arg_9);
    }
    UINT8 StringToImage_Arg_2_LiveChoice = 0;
    ReadBytes(Input, sizeof(StringToImage_Arg_2_LiveChoice), (VOID *)&StringToImage_Arg_2_LiveChoice);
    if (FirnessLive_CHAR16___Count > 0 && (StringToImage_Arg_2_LiveChoice & 1)) {
        StringToImage_Arg_2 = FirnessLive_CHAR16__[StringToImage_Arg_2_LiveChoice % FirnessLive_CHAR16___Count];
    }
    UINT8 StringToImage_Arg_3_LiveChoice = 0;
    ReadBytes(Input, sizeof(StringToImage_Arg_3_LiveChoice), (VOID *)&StringToImage_Arg_3_LiveChoice);
    if (FirnessLive_EFI_FONT_DISPLAY_INFO___Count > 0 && (StringToImage_Arg_3_LiveChoice & 1)) {
        StringToImage_Arg_3 = FirnessLive_EFI_FONT_DISPLAY_INFO__[StringToImage_Arg_3_LiveChoice % FirnessLive_EFI_FONT_DISPLAY_INFO___Count];
    }
    UINT8 StringToImage_Arg_4_LiveChoice = 0;
    ReadBytes(Input, sizeof(StringToImage_Arg_4_LiveChoice), (VOID *)&StringToImage_Arg_4_LiveChoice);
    if (FirnessLive_EFI_IMAGE_OUTPUT___Count > 0 && (StringToImage_Arg_4_LiveChoice & 1)) {
        StringToImage_Arg_4 = FirnessLive_EFI_IMAGE_OUTPUT__[StringToImage_Arg_4_LiveChoice % FirnessLive_EFI_IMAGE_OUTPUT___Count];
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->StringToImage(
        ProtocolVariable,
        StringToImage_Arg_1,
        StringToImage_Arg_2,
        StringToImage_Arg_3,
        (EFI_IMAGE_OUTPUT **)&StringToImage_Arg_4,
        StringToImage_Arg_5,
        StringToImage_Arg_6,
        (EFI_HII_ROW_INFO **)&StringToImage_Arg_7,
        StringToImage_Arg_8,
        StringToImage_Arg_9
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_IMAGE_OUTPUT___Count < 4 && StringToImage_Arg_4 != NULL) {
        FirnessLive_EFI_IMAGE_OUTPUT__[FirnessLive_EFI_IMAGE_OUTPUT___Count++] = StringToImage_Arg_4;
    }
    if (FirnessLive_UINTN___Count < 4 && StringToImage_Arg_8 != NULL) {
        FirnessLive_UINTN__[FirnessLive_UINTN___Count++] = StringToImage_Arg_8;
    }
    if (FirnessLive_UINTN___Count < 4 && StringToImage_Arg_9 != NULL) {
        FirnessLive_UINTN__[FirnessLive_UINTN___Count++] = StringToImage_Arg_9;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetGlyph.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetGlyph(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_FONT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiFontProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 GetGlyph_Arg_1 = {0};
    EFI_FONT_DISPLAY_INFO * GetGlyph_Arg_2 = (EFI_FONT_DISPLAY_INFO *)AllocateZeroPool(sizeof(EFI_FONT_DISPLAY_INFO));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetGlyph_Arg_1), (VOID *)&GetGlyph_Arg_1);
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(GetGlyph_Arg_2->ForegroundColor), (VOID *)&(GetGlyph_Arg_2->ForegroundColor));
    ReadBytes(Input, sizeof(GetGlyph_Arg_2->BackgroundColor), (VOID *)&(GetGlyph_Arg_2->BackgroundColor));
    ReadBytes(Input, sizeof(GetGlyph_Arg_2->FontInfoMask), (VOID *)&(GetGlyph_Arg_2->FontInfoMask));
    ReadBytes(Input, sizeof(GetGlyph_Arg_2->FontInfo), (VOID *)&(GetGlyph_Arg_2->FontInfo));
    
    /*
        Output Variable(s)
    */
    EFI_IMAGE_OUTPUT * GetGlyph_Arg_3 = NULL;
    UINT8* GetGlyph_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetGlyph_Arg_3_OutputChoice), (VOID *)GetGlyph_Arg_3_OutputChoice);
    if(*GetGlyph_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetGlyph_Arg_3), (VOID *)GetGlyph_Arg_3);
    }
    UINTN * GetGlyph_Arg_4 = (UINTN *)AllocateZeroPool(4096);
    UINT8* GetGlyph_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetGlyph_Arg_4_OutputChoice), (VOID *)GetGlyph_Arg_4_OutputChoice);
    if(*GetGlyph_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetGlyph_Arg_4), (VOID *)GetGlyph_Arg_4);
    }
    UINT8 GetGlyph_Arg_2_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetGlyph_Arg_2_LiveChoice), (VOID *)&GetGlyph_Arg_2_LiveChoice);
    if (FirnessLive_EFI_FONT_DISPLAY_INFO___Count > 0 && (GetGlyph_Arg_2_LiveChoice & 1)) {
        GetGlyph_Arg_2 = FirnessLive_EFI_FONT_DISPLAY_INFO__[GetGlyph_Arg_2_LiveChoice % FirnessLive_EFI_FONT_DISPLAY_INFO___Count];
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetGlyph(
        ProtocolVariable,
        GetGlyph_Arg_1,
        GetGlyph_Arg_2,
        (EFI_IMAGE_OUTPUT **)&GetGlyph_Arg_3,
        GetGlyph_Arg_4
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_IMAGE_OUTPUT___Count < 4 && GetGlyph_Arg_3 != NULL) {
        FirnessLive_EFI_IMAGE_OUTPUT__[FirnessLive_EFI_IMAGE_OUTPUT___Count++] = GetGlyph_Arg_3;
    }
    if (FirnessLive_UINTN___Count < 4 && GetGlyph_Arg_4 != NULL) {
        FirnessLive_UINTN__[FirnessLive_UINTN___Count++] = GetGlyph_Arg_4;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called FindKeyboardLayouts.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFindKeyboardLayouts(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_GUID * FindKeyboardLayouts_Arg_2 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINT8* FindKeyboardLayouts_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*FindKeyboardLayouts_Arg_2_OutputChoice), (VOID *)FindKeyboardLayouts_Arg_2_OutputChoice);
    if(*FindKeyboardLayouts_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*FindKeyboardLayouts_Arg_2), (VOID *)FindKeyboardLayouts_Arg_2);
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->FindKeyboardLayouts(
        ProtocolVariable,
        NULL,
        FindKeyboardLayouts_Arg_2
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_GUID___Count < 4 && FindKeyboardLayouts_Arg_2 != NULL) {
        FirnessLive_EFI_GUID__[FirnessLive_EFI_GUID___Count++] = FindKeyboardLayouts_Arg_2;
    }
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
    
    UINT8 GetSecondaryLanguages_Arg_2_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetSecondaryLanguages_Arg_2_LiveChoice), (VOID *)&GetSecondaryLanguages_Arg_2_LiveChoice);
    if (FirnessLive_CHAR8___Count > 0 && (GetSecondaryLanguages_Arg_2_LiveChoice & 1)) {
        GetSecondaryLanguages_Arg_2 = FirnessLive_CHAR8__[GetSecondaryLanguages_Arg_2_LiveChoice % FirnessLive_CHAR8___Count];
    }
    UINT8 GetSecondaryLanguages_Arg_3_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetSecondaryLanguages_Arg_3_LiveChoice), (VOID *)&GetSecondaryLanguages_Arg_3_LiveChoice);
    if (FirnessLive_CHAR8___Count > 0 && (GetSecondaryLanguages_Arg_3_LiveChoice & 1)) {
        GetSecondaryLanguages_Arg_3 = FirnessLive_CHAR8__[GetSecondaryLanguages_Arg_3_LiveChoice % FirnessLive_CHAR8___Count];
    }
    UINT8 GetSecondaryLanguages_Arg_4_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetSecondaryLanguages_Arg_4_LiveChoice), (VOID *)&GetSecondaryLanguages_Arg_4_LiveChoice);
    if (FirnessLive_UINTN___Count > 0 && (GetSecondaryLanguages_Arg_4_LiveChoice & 1)) {
        GetSecondaryLanguages_Arg_4 = FirnessLive_UINTN__[GetSecondaryLanguages_Arg_4_LiveChoice % FirnessLive_UINTN___Count];
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
    if (FirnessLive_CHAR8___Count < 4 && GetSecondaryLanguages_Arg_3 != NULL) {
        FirnessLive_CHAR8__[FirnessLive_CHAR8___Count++] = GetSecondaryLanguages_Arg_3;
    }
    if (FirnessLive_UINTN___Count < 4 && GetSecondaryLanguages_Arg_4 != NULL) {
        FirnessLive_UINTN__[FirnessLive_UINTN___Count++] = GetSecondaryLanguages_Arg_4;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called StringIdToImage.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStringIdToImage(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_FONT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiFontProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_OUT_FLAGS StringIdToImage_Arg_1 = {0};
    EFI_HII_HANDLE StringIdToImage_Arg_2 = {0};
    EFI_STRING_ID StringIdToImage_Arg_3 = {0};
    CHAR8 * StringIdToImage_Arg_4 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
    EFI_FONT_DISPLAY_INFO * StringIdToImage_Arg_5 = (EFI_FONT_DISPLAY_INFO *)AllocateZeroPool(sizeof(EFI_FONT_DISPLAY_INFO));
    UINTN StringIdToImage_Arg_7 = {0};
    UINTN StringIdToImage_Arg_8 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StringIdToImage_Arg_1), (VOID *)&StringIdToImage_Arg_1);
    
    UINT8* StringIdToImage_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*StringIdToImage_Arg_2_choice), (VOID *)StringIdToImage_Arg_2_choice);
    switch(*StringIdToImage_Arg_2_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(StringIdToImage_Arg_2), (VOID *)&StringIdToImage_Arg_2);
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(StringIdToImage_Arg_2), (VOID *)&StringIdToImage_Arg_2);
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StringIdToImage_Arg_3), (VOID *)&StringIdToImage_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 StringIdToImage_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(StringIdToImage_Arg_4_choice), (VOID *)&StringIdToImage_Arg_4_choice);
    switch(StringIdToImage_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*StringIdToImage_Arg_4), (VOID *)StringIdToImage_Arg_4);
            StringIdToImage_Arg_4[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(StringIdToImage_Arg_4);
            StringIdToImage_Arg_4 = NULL;
            break;
        }
    }
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(StringIdToImage_Arg_5->ForegroundColor), (VOID *)&(StringIdToImage_Arg_5->ForegroundColor));
    ReadBytes(Input, sizeof(StringIdToImage_Arg_5->BackgroundColor), (VOID *)&(StringIdToImage_Arg_5->BackgroundColor));
    ReadBytes(Input, sizeof(StringIdToImage_Arg_5->FontInfoMask), (VOID *)&(StringIdToImage_Arg_5->FontInfoMask));
    ReadBytes(Input, sizeof(StringIdToImage_Arg_5->FontInfo), (VOID *)&(StringIdToImage_Arg_5->FontInfo));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StringIdToImage_Arg_7), (VOID *)&StringIdToImage_Arg_7);
    StringIdToImage_Arg_7 = StringIdToImage_Arg_7 % (4096 + 1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StringIdToImage_Arg_8), (VOID *)&StringIdToImage_Arg_8);
    StringIdToImage_Arg_8 = StringIdToImage_Arg_8 % (4096 + 1);
    
    /*
        Output Variable(s)
    */
    EFI_HII_ROW_INFO * StringIdToImage_Arg_9 = NULL;
    UINT8* StringIdToImage_Arg_9_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*StringIdToImage_Arg_9_OutputChoice), (VOID *)StringIdToImage_Arg_9_OutputChoice);
    if(*StringIdToImage_Arg_9_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*StringIdToImage_Arg_9), (VOID *)StringIdToImage_Arg_9);
    }
    UINTN * StringIdToImage_Arg_10 = (UINTN *)AllocateZeroPool(4096);
    UINT8* StringIdToImage_Arg_10_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*StringIdToImage_Arg_10_OutputChoice), (VOID *)StringIdToImage_Arg_10_OutputChoice);
    if(*StringIdToImage_Arg_10_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*StringIdToImage_Arg_10), (VOID *)StringIdToImage_Arg_10);
    }
    UINTN * StringIdToImage_Arg_11 = (UINTN *)AllocateZeroPool(4096);
    UINT8* StringIdToImage_Arg_11_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*StringIdToImage_Arg_11_OutputChoice), (VOID *)StringIdToImage_Arg_11_OutputChoice);
    if(*StringIdToImage_Arg_11_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*StringIdToImage_Arg_11), (VOID *)StringIdToImage_Arg_11);
    }
    UINT8 StringIdToImage_Arg_4_LiveChoice = 0;
    ReadBytes(Input, sizeof(StringIdToImage_Arg_4_LiveChoice), (VOID *)&StringIdToImage_Arg_4_LiveChoice);
    if (FirnessLive_CHAR8___Count > 0 && (StringIdToImage_Arg_4_LiveChoice & 1)) {
        StringIdToImage_Arg_4 = FirnessLive_CHAR8__[StringIdToImage_Arg_4_LiveChoice % FirnessLive_CHAR8___Count];
    }
    UINT8 StringIdToImage_Arg_5_LiveChoice = 0;
    ReadBytes(Input, sizeof(StringIdToImage_Arg_5_LiveChoice), (VOID *)&StringIdToImage_Arg_5_LiveChoice);
    if (FirnessLive_EFI_FONT_DISPLAY_INFO___Count > 0 && (StringIdToImage_Arg_5_LiveChoice & 1)) {
        StringIdToImage_Arg_5 = FirnessLive_EFI_FONT_DISPLAY_INFO__[StringIdToImage_Arg_5_LiveChoice % FirnessLive_EFI_FONT_DISPLAY_INFO___Count];
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->StringIdToImage(
        ProtocolVariable,
        StringIdToImage_Arg_1,
        StringIdToImage_Arg_2,
        StringIdToImage_Arg_3,
        StringIdToImage_Arg_4,
        StringIdToImage_Arg_5,
        NULL,
        StringIdToImage_Arg_7,
        StringIdToImage_Arg_8,
        (EFI_HII_ROW_INFO **)&StringIdToImage_Arg_9,
        StringIdToImage_Arg_10,
        StringIdToImage_Arg_11
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_UINTN___Count < 4 && StringIdToImage_Arg_10 != NULL) {
        FirnessLive_UINTN__[FirnessLive_UINTN___Count++] = StringIdToImage_Arg_10;
    }
    if (FirnessLive_UINTN___Count < 4 && StringIdToImage_Arg_11 != NULL) {
        FirnessLive_UINTN__[FirnessLive_UINTN___Count++] = StringIdToImage_Arg_11;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetFontInfo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetFontInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_FONT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiFontProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_FONT_DISPLAY_INFO * GetFontInfo_Arg_2 = (EFI_FONT_DISPLAY_INFO *)AllocateZeroPool(sizeof(EFI_FONT_DISPLAY_INFO));
    EFI_STRING GetFontInfo_Arg_4 = {0};
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(GetFontInfo_Arg_2->ForegroundColor), (VOID *)&(GetFontInfo_Arg_2->ForegroundColor));
    ReadBytes(Input, sizeof(GetFontInfo_Arg_2->BackgroundColor), (VOID *)&(GetFontInfo_Arg_2->BackgroundColor));
    ReadBytes(Input, sizeof(GetFontInfo_Arg_2->FontInfoMask), (VOID *)&(GetFontInfo_Arg_2->FontInfoMask));
    ReadBytes(Input, sizeof(GetFontInfo_Arg_2->FontInfo), (VOID *)&(GetFontInfo_Arg_2->FontInfo));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetFontInfo_Arg_4), (VOID *)&GetFontInfo_Arg_4);
    
    /*
        Output Variable(s)
    */
    EFI_FONT_DISPLAY_INFO * GetFontInfo_Arg_3 = NULL;
    UINT8* GetFontInfo_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetFontInfo_Arg_3_OutputChoice), (VOID *)GetFontInfo_Arg_3_OutputChoice);
    if(*GetFontInfo_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetFontInfo_Arg_3), (VOID *)GetFontInfo_Arg_3);
    }
    UINT8 GetFontInfo_Arg_2_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetFontInfo_Arg_2_LiveChoice), (VOID *)&GetFontInfo_Arg_2_LiveChoice);
    if (FirnessLive_EFI_FONT_DISPLAY_INFO___Count > 0 && (GetFontInfo_Arg_2_LiveChoice & 1)) {
        GetFontInfo_Arg_2 = FirnessLive_EFI_FONT_DISPLAY_INFO__[GetFontInfo_Arg_2_LiveChoice % FirnessLive_EFI_FONT_DISPLAY_INFO___Count];
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetFontInfo(
        ProtocolVariable,
        NULL,
        GetFontInfo_Arg_2,
        (EFI_FONT_DISPLAY_INFO **)&GetFontInfo_Arg_3,
        GetFontInfo_Arg_4
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_FONT_DISPLAY_INFO___Count < 4 && GetFontInfo_Arg_3 != NULL) {
        FirnessLive_EFI_FONT_DISPLAY_INFO__[FirnessLive_EFI_FONT_DISPLAY_INFO___Count++] = GetFontInfo_Arg_3;
    }
    return Status;
}

