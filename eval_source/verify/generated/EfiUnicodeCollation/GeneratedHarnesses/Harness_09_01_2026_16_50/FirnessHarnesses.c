#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called StriColl.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStriColl(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_UNICODE_COLLATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUnicodeCollationProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * StriColl_Arg_1 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    CHAR16 * StriColl_Arg_2 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    
    UINT8* StriColl_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(StriColl_Arg_1_choice), (VOID *)StriColl_Arg_1_choice);
    switch(*StriColl_Arg_1_choice % 19) {
        case 0:
        {
        // Constant Variable Initialization
        StriColl_Arg_1 = StrDuplicate(L"in");
    
            break;
        }
        case 1:
        {
        // Constant Variable Initialization
        StriColl_Arg_1 = StrDuplicate(L"run");
    
            break;
        }
        case 2:
        {
        // Constant Variable Initialization
        StriColl_Arg_1 = StrDuplicate(L"-startup");
    
            break;
        }
        case 3:
        {
        // Constant Variable Initialization
        StriColl_Arg_1 = StrDuplicate(L"-nostartup");
    
            break;
        }
        case 4:
        {
        // Constant Variable Initialization
        StriColl_Arg_1 = StrDuplicate(L"-noconsoleout");
    
            break;
        }
        case 5:
        {
        // Constant Variable Initialization
        StriColl_Arg_1 = StrDuplicate(L"-noconsolein");
    
            break;
        }
        case 6:
        {
        // Constant Variable Initialization
        StriColl_Arg_1 = StrDuplicate(L"-nointerrupt");
    
            break;
        }
        case 7:
        {
        // Constant Variable Initialization
        StriColl_Arg_1 = StrDuplicate(L"-nomap");
    
            break;
        }
        case 8:
        {
        // Constant Variable Initialization
        StriColl_Arg_1 = StrDuplicate(L"-noversion");
    
            break;
        }
        case 9:
        {
        // Constant Variable Initialization
        StriColl_Arg_1 = StrDuplicate(L"-nonest");
    
            break;
        }
        case 10:
        {
        // Constant Variable Initialization
        StriColl_Arg_1 = StrDuplicate(L"-delay");
    
            break;
        }
        case 11:
        {
        // Constant Variable Initialization
        StriColl_Arg_1 = StrDuplicate(L"-exit");
    
            break;
        }
        case 12:
        {
        // Constant Variable Initialization
        StriColl_Arg_1 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    
            break;
        }
        case 13:
        {
        // Constant Variable Initialization
        StriColl_Arg_1 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    
            break;
        }
        case 14:
        {
        // Constant Variable Initialization
        StriColl_Arg_1 = StrDuplicate(L"decode");
    
            break;
        }
        case 15:
        {
        // Constant Variable Initialization
        StriColl_Arg_1 = StrDuplicate(_PCD_VALUE_PcdUsbExtendedDecode);
    
            break;
        }
        case 16:
        {
        // Constant Variable Initialization
        StriColl_Arg_1 = StrDuplicate(kMatchMinLen);
    
            break;
        }
        case 17:
        {
        // Constant Variable Initialization
        StriColl_Arg_1 = StrDuplicate(kStartMaxLen);
    
            break;
        }
        case 18:
        {
        // Fuzzable Variable Initialization
        UINT8 StriColl_Arg_1_choice = 0;
        ReadBytes(Input, sizeof(StriColl_Arg_1_choice), (VOID *)&StriColl_Arg_1_choice);
        switch(StriColl_Arg_1_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(StriColl_Arg_1), (VOID *)StriColl_Arg_1);
                break;
            case 1:
            {
                gBS->FreePool(StriColl_Arg_1);
                StriColl_Arg_1 = NULL;
                break;
            }
        }
    
            break;
        }
    }
    UINT8* StriColl_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(StriColl_Arg_2_choice), (VOID *)StriColl_Arg_2_choice);
    switch(*StriColl_Arg_2_choice % 28) {
        case 0:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = StrDuplicate(kMatchMinLen);
    
            break;
        }
        case 1:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = StrDuplicate(L"NUL");
    
            break;
        }
        case 2:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = StrDuplicate(L"NULL");
    
            break;
        }
        case 3:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    
            break;
        }
        case 4:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = StrDuplicate(L"all");
    
            break;
        }
        case 5:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = StrDuplicate(L"_local");
    
            break;
        }
        case 6:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = StrDuplicate(L"or");
    
            break;
        }
        case 7:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = StrDuplicate(L"and");
    
            break;
        }
        case 8:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = StrDuplicate(L"then");
    
            break;
        }
        case 9:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = StrDuplicate(L"If");
    
            break;
        }
        case 10:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    
            break;
        }
        case 11:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    
            break;
        }
        case 12:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = StrDuplicate(L"/i");
    
            break;
        }
        case 13:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = StrDuplicate(L"/s");
    
            break;
        }
        case 14:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = StrDuplicate(L"special");
    
            break;
        }
        case 15:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = StrDuplicate(L"driver");
    
            break;
        }
        case 16:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = StrDuplicate(L"boot");
    
            break;
        }
        case 17:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = StrDuplicate(L"dump");
    
            break;
        }
        case 18:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = StrDuplicate(L"add");
    
            break;
        }
        case 19:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = StrDuplicate(L"addp");
    
            break;
        }
        case 20:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = StrDuplicate(L"addh");
    
            break;
        }
        case 21:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = StrDuplicate(L"rm");
    
            break;
        }
        case 22:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = StrDuplicate(L"mv");
    
            break;
        }
        case 23:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = StrDuplicate(L"mod");
    
            break;
        }
        case 24:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = StrDuplicate(L"modf");
    
            break;
        }
        case 25:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = StrDuplicate(L"modp");
    
            break;
        }
        case 26:
        {
        // Constant Variable Initialization
        StriColl_Arg_2 = StrDuplicate(L"modh");
    
            break;
        }
        case 27:
        {
        // Fuzzable Variable Initialization
        UINT8 StriColl_Arg_2_choice = 0;
        ReadBytes(Input, sizeof(StriColl_Arg_2_choice), (VOID *)&StriColl_Arg_2_choice);
        switch(StriColl_Arg_2_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(StriColl_Arg_2), (VOID *)StriColl_Arg_2);
                break;
            case 1:
            {
                gBS->FreePool(StriColl_Arg_2);
                StriColl_Arg_2 = NULL;
                break;
            }
        }
    
            break;
        }
    }
    ProtocolVariable->StriColl(
        ProtocolVariable,
        StriColl_Arg_1,
        StriColl_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called MetaiMatch.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzMetaiMatch(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_UNICODE_COLLATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUnicodeCollationProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * MetaiMatch_Arg_1 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    CHAR16 * MetaiMatch_Arg_2 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    
    // Fuzzable Variable Initialization
    UINT8 MetaiMatch_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(MetaiMatch_Arg_1_choice), (VOID *)&MetaiMatch_Arg_1_choice);
    switch(MetaiMatch_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(MetaiMatch_Arg_1), (VOID *)MetaiMatch_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(MetaiMatch_Arg_1);
            MetaiMatch_Arg_1 = NULL;
            break;
        }
    }
    
    UINT8* MetaiMatch_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(MetaiMatch_Arg_2_choice), (VOID *)MetaiMatch_Arg_2_choice);
    switch(*MetaiMatch_Arg_2_choice % 2) {
        case 0:
        {
        // Constant Variable Initialization
        MetaiMatch_Arg_2 = StrDuplicate(_PCD_VALUE_PcdUsbExtendedDecode);
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        UINT8 MetaiMatch_Arg_2_choice = 0;
        ReadBytes(Input, sizeof(MetaiMatch_Arg_2_choice), (VOID *)&MetaiMatch_Arg_2_choice);
        switch(MetaiMatch_Arg_2_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(MetaiMatch_Arg_2), (VOID *)MetaiMatch_Arg_2);
                break;
            case 1:
            {
                gBS->FreePool(MetaiMatch_Arg_2);
                MetaiMatch_Arg_2 = NULL;
                break;
            }
        }
    
            break;
        }
    }
    ProtocolVariable->MetaiMatch(
        ProtocolVariable,
        MetaiMatch_Arg_1,
        MetaiMatch_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called StrUpr.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStrUpr(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_UNICODE_COLLATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUnicodeCollationProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * StrUpr_Arg_1 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    
    // Fuzzable Variable Initialization
    UINT8 StrUpr_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(StrUpr_Arg_1_choice), (VOID *)&StrUpr_Arg_1_choice);
    switch(StrUpr_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(StrUpr_Arg_1), (VOID *)StrUpr_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(StrUpr_Arg_1);
            StrUpr_Arg_1 = NULL;
            break;
        }
    }
    
    ProtocolVariable->StrUpr(
        ProtocolVariable,
        StrUpr_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called StrLwr.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStrLwr(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_UNICODE_COLLATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUnicodeCollationProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * StrLwr_Arg_1 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    
    // Fuzzable Variable Initialization
    UINT8 StrLwr_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(StrLwr_Arg_1_choice), (VOID *)&StrLwr_Arg_1_choice);
    switch(StrLwr_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(StrLwr_Arg_1), (VOID *)StrLwr_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(StrLwr_Arg_1);
            StrLwr_Arg_1 = NULL;
            break;
        }
    }
    
    ProtocolVariable->StrLwr(
        ProtocolVariable,
        StrLwr_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called FatToStr.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFatToStr(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_UNICODE_COLLATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUnicodeCollationProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN FatToStr_Arg_1 = 0;
    CHAR8 * FatToStr_Arg_2 = (CHAR8 *)AllocateZeroPool(sizeof(CHAR8));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(FatToStr_Arg_1), (VOID *)&FatToStr_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 FatToStr_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(FatToStr_Arg_2_choice), (VOID *)&FatToStr_Arg_2_choice);
    switch(FatToStr_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(FatToStr_Arg_2), (VOID *)FatToStr_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(FatToStr_Arg_2);
            FatToStr_Arg_2 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    CHAR16 * FatToStr_Arg_3 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    UINT8* FatToStr_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(FatToStr_Arg_3_OutputChoice), (VOID *)FatToStr_Arg_3_OutputChoice);
    if(*FatToStr_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*FatToStr_Arg_3), (VOID *)FatToStr_Arg_3);
    }
    ProtocolVariable->FatToStr(
        ProtocolVariable,
        FatToStr_Arg_1,
        FatToStr_Arg_2,
        FatToStr_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called StrToFat.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStrToFat(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_UNICODE_COLLATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUnicodeCollationProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * StrToFat_Arg_1 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    UINTN StrToFat_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    UINT8 StrToFat_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(StrToFat_Arg_1_choice), (VOID *)&StrToFat_Arg_1_choice);
    switch(StrToFat_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(StrToFat_Arg_1), (VOID *)StrToFat_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(StrToFat_Arg_1);
            StrToFat_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StrToFat_Arg_2), (VOID *)&StrToFat_Arg_2);
    
    /*
        Output Variable(s)
    */
    CHAR8 * StrToFat_Arg_3 = (CHAR8 *)AllocateZeroPool(sizeof(CHAR8));
    UINT8* StrToFat_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(StrToFat_Arg_3_OutputChoice), (VOID *)StrToFat_Arg_3_OutputChoice);
    if(*StrToFat_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*StrToFat_Arg_3), (VOID *)StrToFat_Arg_3);
    }
    ProtocolVariable->StrToFat(
        ProtocolVariable,
        StrToFat_Arg_1,
        StrToFat_Arg_2,
        StrToFat_Arg_3
    );
    return Status;
}

