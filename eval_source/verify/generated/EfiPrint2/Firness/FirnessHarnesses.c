#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the Protocols service
    called UnicodeBSPrint.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUnicodeBSPrint(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PRINT2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPrint2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN UnicodeBSPrint_Arg_1 = 0;
    CHAR16 * UnicodeBSPrint_Arg_2 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    BASE_LIST UnicodeBSPrint_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UnicodeBSPrint_Arg_1), (VOID *)&UnicodeBSPrint_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 UnicodeBSPrint_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(UnicodeBSPrint_Arg_2_choice), (VOID *)&UnicodeBSPrint_Arg_2_choice);
    switch(UnicodeBSPrint_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UnicodeBSPrint_Arg_2), (VOID *)UnicodeBSPrint_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(UnicodeBSPrint_Arg_2);
            UnicodeBSPrint_Arg_2 = NULL;
            break;
        }
    }
    
    UINT8* UnicodeBSPrint_Arg_3_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(UnicodeBSPrint_Arg_3_choice), (VOID *)UnicodeBSPrint_Arg_3_choice);
    switch(*UnicodeBSPrint_Arg_3_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(UnicodeBSPrint_Arg_3), (VOID *)&UnicodeBSPrint_Arg_3);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_STATUS_CODE_DATA * ReportStatusCodeExtractDebugInfo_Arg_0 = (EFI_STATUS_CODE_DATA *)AllocateZeroPool(sizeof(EFI_STATUS_CODE_DATA));
            
            // Generator Struct Variable Initialization
            {
                UINT16 Firness_HeaderSize;
                ReadBytes(Input, sizeof(Firness_HeaderSize), (VOID *)&Firness_HeaderSize);
                ReportStatusCodeExtractDebugInfo_Arg_0->HeaderSize = Firness_HeaderSize;
            }
            {
                UINT16 Firness_Size;
                ReadBytes(Input, sizeof(Firness_Size), (VOID *)&Firness_Size);
                ReportStatusCodeExtractDebugInfo_Arg_0->Size = Firness_Size;
            }
            {
                EFI_GUID Firness_Type;
                ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
                ReportStatusCodeExtractDebugInfo_Arg_0->Type = Firness_Type;
            }
            
            /*
                Output Variable(s)
            */
            UINT32 * ReportStatusCodeExtractDebugInfo_Arg_1 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
            UINT8* ReportStatusCodeExtractDebugInfo_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(ReportStatusCodeExtractDebugInfo_Arg_1_OutputChoice), (VOID *)ReportStatusCodeExtractDebugInfo_Arg_1_OutputChoice);
            if(*ReportStatusCodeExtractDebugInfo_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*ReportStatusCodeExtractDebugInfo_Arg_1), (VOID *)ReportStatusCodeExtractDebugInfo_Arg_1);
            }
            CHAR8 * ReportStatusCodeExtractDebugInfo_Arg_3 = (CHAR8 *)AllocateZeroPool(sizeof(CHAR8));
            UINT8* ReportStatusCodeExtractDebugInfo_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(ReportStatusCodeExtractDebugInfo_Arg_3_OutputChoice), (VOID *)ReportStatusCodeExtractDebugInfo_Arg_3_OutputChoice);
            if(*ReportStatusCodeExtractDebugInfo_Arg_3_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*ReportStatusCodeExtractDebugInfo_Arg_3), (VOID *)ReportStatusCodeExtractDebugInfo_Arg_3);
            }
            ReportStatusCodeExtractDebugInfo(
                ReportStatusCodeExtractDebugInfo_Arg_0,
                ReportStatusCodeExtractDebugInfo_Arg_1,
                &UnicodeBSPrint_Arg_3,
                (CHAR8 **)&ReportStatusCodeExtractDebugInfo_Arg_3
            );
    
            break;
        }
    }
    /*
        Output Variable(s)
    */
    CHAR16 * UnicodeBSPrint_Arg_0 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    UINT8* UnicodeBSPrint_Arg_0_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(UnicodeBSPrint_Arg_0_OutputChoice), (VOID *)UnicodeBSPrint_Arg_0_OutputChoice);
    if(*UnicodeBSPrint_Arg_0_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*UnicodeBSPrint_Arg_0), (VOID *)UnicodeBSPrint_Arg_0);
    }
    ProtocolVariable->UnicodeBSPrint(
        UnicodeBSPrint_Arg_0,
        UnicodeBSPrint_Arg_1,
        UnicodeBSPrint_Arg_2,
        UnicodeBSPrint_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called UnicodeBSPrintAsciiFormat.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUnicodeBSPrintAsciiFormat(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PRINT2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPrint2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN UnicodeBSPrintAsciiFormat_Arg_1 = 0;
    CHAR8 * UnicodeBSPrintAsciiFormat_Arg_2 = (CHAR8 *)AllocateZeroPool(sizeof(CHAR8));
    BASE_LIST UnicodeBSPrintAsciiFormat_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UnicodeBSPrintAsciiFormat_Arg_1), (VOID *)&UnicodeBSPrintAsciiFormat_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 UnicodeBSPrintAsciiFormat_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(UnicodeBSPrintAsciiFormat_Arg_2_choice), (VOID *)&UnicodeBSPrintAsciiFormat_Arg_2_choice);
    switch(UnicodeBSPrintAsciiFormat_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UnicodeBSPrintAsciiFormat_Arg_2), (VOID *)UnicodeBSPrintAsciiFormat_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(UnicodeBSPrintAsciiFormat_Arg_2);
            UnicodeBSPrintAsciiFormat_Arg_2 = NULL;
            break;
        }
    }
    
    UINT8* UnicodeBSPrintAsciiFormat_Arg_3_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(UnicodeBSPrintAsciiFormat_Arg_3_choice), (VOID *)UnicodeBSPrintAsciiFormat_Arg_3_choice);
    switch(*UnicodeBSPrintAsciiFormat_Arg_3_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(UnicodeBSPrintAsciiFormat_Arg_3), (VOID *)&UnicodeBSPrintAsciiFormat_Arg_3);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_STATUS_CODE_DATA * ReportStatusCodeExtractDebugInfo_Arg_0 = (EFI_STATUS_CODE_DATA *)AllocateZeroPool(sizeof(EFI_STATUS_CODE_DATA));
            
            // Generator Struct Variable Initialization
            {
                UINT16 Firness_HeaderSize;
                ReadBytes(Input, sizeof(Firness_HeaderSize), (VOID *)&Firness_HeaderSize);
                ReportStatusCodeExtractDebugInfo_Arg_0->HeaderSize = Firness_HeaderSize;
            }
            {
                UINT16 Firness_Size;
                ReadBytes(Input, sizeof(Firness_Size), (VOID *)&Firness_Size);
                ReportStatusCodeExtractDebugInfo_Arg_0->Size = Firness_Size;
            }
            {
                EFI_GUID Firness_Type;
                ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
                ReportStatusCodeExtractDebugInfo_Arg_0->Type = Firness_Type;
            }
            
            /*
                Output Variable(s)
            */
            UINT32 * ReportStatusCodeExtractDebugInfo_Arg_1 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
            UINT8* ReportStatusCodeExtractDebugInfo_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(ReportStatusCodeExtractDebugInfo_Arg_1_OutputChoice), (VOID *)ReportStatusCodeExtractDebugInfo_Arg_1_OutputChoice);
            if(*ReportStatusCodeExtractDebugInfo_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*ReportStatusCodeExtractDebugInfo_Arg_1), (VOID *)ReportStatusCodeExtractDebugInfo_Arg_1);
            }
            CHAR8 * ReportStatusCodeExtractDebugInfo_Arg_3 = (CHAR8 *)AllocateZeroPool(sizeof(CHAR8));
            UINT8* ReportStatusCodeExtractDebugInfo_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(ReportStatusCodeExtractDebugInfo_Arg_3_OutputChoice), (VOID *)ReportStatusCodeExtractDebugInfo_Arg_3_OutputChoice);
            if(*ReportStatusCodeExtractDebugInfo_Arg_3_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*ReportStatusCodeExtractDebugInfo_Arg_3), (VOID *)ReportStatusCodeExtractDebugInfo_Arg_3);
            }
            ReportStatusCodeExtractDebugInfo(
                ReportStatusCodeExtractDebugInfo_Arg_0,
                ReportStatusCodeExtractDebugInfo_Arg_1,
                &UnicodeBSPrintAsciiFormat_Arg_3,
                (CHAR8 **)&ReportStatusCodeExtractDebugInfo_Arg_3
            );
    
            break;
        }
    }
    /*
        Output Variable(s)
    */
    CHAR16 * UnicodeBSPrintAsciiFormat_Arg_0 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    UINT8* UnicodeBSPrintAsciiFormat_Arg_0_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(UnicodeBSPrintAsciiFormat_Arg_0_OutputChoice), (VOID *)UnicodeBSPrintAsciiFormat_Arg_0_OutputChoice);
    if(*UnicodeBSPrintAsciiFormat_Arg_0_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*UnicodeBSPrintAsciiFormat_Arg_0), (VOID *)UnicodeBSPrintAsciiFormat_Arg_0);
    }
    ProtocolVariable->UnicodeBSPrintAsciiFormat(
        UnicodeBSPrintAsciiFormat_Arg_0,
        UnicodeBSPrintAsciiFormat_Arg_1,
        UnicodeBSPrintAsciiFormat_Arg_2,
        UnicodeBSPrintAsciiFormat_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called UnicodeValueToString.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUnicodeValueToString(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PRINT2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPrint2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * UnicodeValueToString_Arg_0 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    UINTN UnicodeValueToString_Arg_1 = 0;
    INT64 UnicodeValueToString_Arg_2 = 0;
    UINTN UnicodeValueToString_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    UINT8 UnicodeValueToString_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(UnicodeValueToString_Arg_0_choice), (VOID *)&UnicodeValueToString_Arg_0_choice);
    switch(UnicodeValueToString_Arg_0_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(UnicodeValueToString_Arg_0), (VOID *)UnicodeValueToString_Arg_0);
            break;
        case 1:
        {
            gBS->FreePool(UnicodeValueToString_Arg_0);
            UnicodeValueToString_Arg_0 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UnicodeValueToString_Arg_1), (VOID *)&UnicodeValueToString_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UnicodeValueToString_Arg_2), (VOID *)&UnicodeValueToString_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UnicodeValueToString_Arg_3), (VOID *)&UnicodeValueToString_Arg_3);
    
    ProtocolVariable->UnicodeValueToString(
        UnicodeValueToString_Arg_0,
        UnicodeValueToString_Arg_1,
        UnicodeValueToString_Arg_2,
        UnicodeValueToString_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called AsciiBSPrint.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAsciiBSPrint(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PRINT2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPrint2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN AsciiBSPrint_Arg_1 = 0;
    CHAR8 * AsciiBSPrint_Arg_2 = (CHAR8 *)AllocateZeroPool(sizeof(CHAR8));
    BASE_LIST AsciiBSPrint_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AsciiBSPrint_Arg_1), (VOID *)&AsciiBSPrint_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 AsciiBSPrint_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(AsciiBSPrint_Arg_2_choice), (VOID *)&AsciiBSPrint_Arg_2_choice);
    switch(AsciiBSPrint_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(AsciiBSPrint_Arg_2), (VOID *)AsciiBSPrint_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(AsciiBSPrint_Arg_2);
            AsciiBSPrint_Arg_2 = NULL;
            break;
        }
    }
    
    UINT8* AsciiBSPrint_Arg_3_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(AsciiBSPrint_Arg_3_choice), (VOID *)AsciiBSPrint_Arg_3_choice);
    switch(*AsciiBSPrint_Arg_3_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(AsciiBSPrint_Arg_3), (VOID *)&AsciiBSPrint_Arg_3);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_STATUS_CODE_DATA * ReportStatusCodeExtractDebugInfo_Arg_0 = (EFI_STATUS_CODE_DATA *)AllocateZeroPool(sizeof(EFI_STATUS_CODE_DATA));
            
            // Generator Struct Variable Initialization
            {
                UINT16 Firness_HeaderSize;
                ReadBytes(Input, sizeof(Firness_HeaderSize), (VOID *)&Firness_HeaderSize);
                ReportStatusCodeExtractDebugInfo_Arg_0->HeaderSize = Firness_HeaderSize;
            }
            {
                UINT16 Firness_Size;
                ReadBytes(Input, sizeof(Firness_Size), (VOID *)&Firness_Size);
                ReportStatusCodeExtractDebugInfo_Arg_0->Size = Firness_Size;
            }
            {
                EFI_GUID Firness_Type;
                ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
                ReportStatusCodeExtractDebugInfo_Arg_0->Type = Firness_Type;
            }
            
            /*
                Output Variable(s)
            */
            UINT32 * ReportStatusCodeExtractDebugInfo_Arg_1 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
            UINT8* ReportStatusCodeExtractDebugInfo_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(ReportStatusCodeExtractDebugInfo_Arg_1_OutputChoice), (VOID *)ReportStatusCodeExtractDebugInfo_Arg_1_OutputChoice);
            if(*ReportStatusCodeExtractDebugInfo_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*ReportStatusCodeExtractDebugInfo_Arg_1), (VOID *)ReportStatusCodeExtractDebugInfo_Arg_1);
            }
            CHAR8 * ReportStatusCodeExtractDebugInfo_Arg_3 = (CHAR8 *)AllocateZeroPool(sizeof(CHAR8));
            UINT8* ReportStatusCodeExtractDebugInfo_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(ReportStatusCodeExtractDebugInfo_Arg_3_OutputChoice), (VOID *)ReportStatusCodeExtractDebugInfo_Arg_3_OutputChoice);
            if(*ReportStatusCodeExtractDebugInfo_Arg_3_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*ReportStatusCodeExtractDebugInfo_Arg_3), (VOID *)ReportStatusCodeExtractDebugInfo_Arg_3);
            }
            ReportStatusCodeExtractDebugInfo(
                ReportStatusCodeExtractDebugInfo_Arg_0,
                ReportStatusCodeExtractDebugInfo_Arg_1,
                &AsciiBSPrint_Arg_3,
                (CHAR8 **)&ReportStatusCodeExtractDebugInfo_Arg_3
            );
    
            break;
        }
    }
    /*
        Output Variable(s)
    */
    CHAR8 * AsciiBSPrint_Arg_0 = (CHAR8 *)AllocateZeroPool(sizeof(CHAR8));
    UINT8* AsciiBSPrint_Arg_0_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(AsciiBSPrint_Arg_0_OutputChoice), (VOID *)AsciiBSPrint_Arg_0_OutputChoice);
    if(*AsciiBSPrint_Arg_0_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*AsciiBSPrint_Arg_0), (VOID *)AsciiBSPrint_Arg_0);
    }
    ProtocolVariable->AsciiBSPrint(
        AsciiBSPrint_Arg_0,
        AsciiBSPrint_Arg_1,
        AsciiBSPrint_Arg_2,
        AsciiBSPrint_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called AsciiBSPrintUnicodeFormat.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAsciiBSPrintUnicodeFormat(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PRINT2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPrint2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN AsciiBSPrintUnicodeFormat_Arg_1 = 0;
    CHAR16 * AsciiBSPrintUnicodeFormat_Arg_2 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    BASE_LIST AsciiBSPrintUnicodeFormat_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AsciiBSPrintUnicodeFormat_Arg_1), (VOID *)&AsciiBSPrintUnicodeFormat_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 AsciiBSPrintUnicodeFormat_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(AsciiBSPrintUnicodeFormat_Arg_2_choice), (VOID *)&AsciiBSPrintUnicodeFormat_Arg_2_choice);
    switch(AsciiBSPrintUnicodeFormat_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(AsciiBSPrintUnicodeFormat_Arg_2), (VOID *)AsciiBSPrintUnicodeFormat_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(AsciiBSPrintUnicodeFormat_Arg_2);
            AsciiBSPrintUnicodeFormat_Arg_2 = NULL;
            break;
        }
    }
    
    UINT8* AsciiBSPrintUnicodeFormat_Arg_3_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(AsciiBSPrintUnicodeFormat_Arg_3_choice), (VOID *)AsciiBSPrintUnicodeFormat_Arg_3_choice);
    switch(*AsciiBSPrintUnicodeFormat_Arg_3_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(AsciiBSPrintUnicodeFormat_Arg_3), (VOID *)&AsciiBSPrintUnicodeFormat_Arg_3);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_STATUS_CODE_DATA * ReportStatusCodeExtractDebugInfo_Arg_0 = (EFI_STATUS_CODE_DATA *)AllocateZeroPool(sizeof(EFI_STATUS_CODE_DATA));
            
            // Generator Struct Variable Initialization
            {
                UINT16 Firness_HeaderSize;
                ReadBytes(Input, sizeof(Firness_HeaderSize), (VOID *)&Firness_HeaderSize);
                ReportStatusCodeExtractDebugInfo_Arg_0->HeaderSize = Firness_HeaderSize;
            }
            {
                UINT16 Firness_Size;
                ReadBytes(Input, sizeof(Firness_Size), (VOID *)&Firness_Size);
                ReportStatusCodeExtractDebugInfo_Arg_0->Size = Firness_Size;
            }
            {
                EFI_GUID Firness_Type;
                ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
                ReportStatusCodeExtractDebugInfo_Arg_0->Type = Firness_Type;
            }
            
            /*
                Output Variable(s)
            */
            UINT32 * ReportStatusCodeExtractDebugInfo_Arg_1 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
            UINT8* ReportStatusCodeExtractDebugInfo_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(ReportStatusCodeExtractDebugInfo_Arg_1_OutputChoice), (VOID *)ReportStatusCodeExtractDebugInfo_Arg_1_OutputChoice);
            if(*ReportStatusCodeExtractDebugInfo_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*ReportStatusCodeExtractDebugInfo_Arg_1), (VOID *)ReportStatusCodeExtractDebugInfo_Arg_1);
            }
            CHAR8 * ReportStatusCodeExtractDebugInfo_Arg_3 = (CHAR8 *)AllocateZeroPool(sizeof(CHAR8));
            UINT8* ReportStatusCodeExtractDebugInfo_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(ReportStatusCodeExtractDebugInfo_Arg_3_OutputChoice), (VOID *)ReportStatusCodeExtractDebugInfo_Arg_3_OutputChoice);
            if(*ReportStatusCodeExtractDebugInfo_Arg_3_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*ReportStatusCodeExtractDebugInfo_Arg_3), (VOID *)ReportStatusCodeExtractDebugInfo_Arg_3);
            }
            ReportStatusCodeExtractDebugInfo(
                ReportStatusCodeExtractDebugInfo_Arg_0,
                ReportStatusCodeExtractDebugInfo_Arg_1,
                &AsciiBSPrintUnicodeFormat_Arg_3,
                (CHAR8 **)&ReportStatusCodeExtractDebugInfo_Arg_3
            );
    
            break;
        }
    }
    /*
        Output Variable(s)
    */
    CHAR8 * AsciiBSPrintUnicodeFormat_Arg_0 = (CHAR8 *)AllocateZeroPool(sizeof(CHAR8));
    UINT8* AsciiBSPrintUnicodeFormat_Arg_0_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(AsciiBSPrintUnicodeFormat_Arg_0_OutputChoice), (VOID *)AsciiBSPrintUnicodeFormat_Arg_0_OutputChoice);
    if(*AsciiBSPrintUnicodeFormat_Arg_0_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*AsciiBSPrintUnicodeFormat_Arg_0), (VOID *)AsciiBSPrintUnicodeFormat_Arg_0);
    }
    ProtocolVariable->AsciiBSPrintUnicodeFormat(
        AsciiBSPrintUnicodeFormat_Arg_0,
        AsciiBSPrintUnicodeFormat_Arg_1,
        AsciiBSPrintUnicodeFormat_Arg_2,
        AsciiBSPrintUnicodeFormat_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called AsciiValueToString.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAsciiValueToString(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PRINT2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPrint2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN AsciiValueToString_Arg_1 = 0;
    INT64 AsciiValueToString_Arg_2 = 0;
    UINTN AsciiValueToString_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AsciiValueToString_Arg_1), (VOID *)&AsciiValueToString_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AsciiValueToString_Arg_2), (VOID *)&AsciiValueToString_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AsciiValueToString_Arg_3), (VOID *)&AsciiValueToString_Arg_3);
    
    /*
        Output Variable(s)
    */
    CHAR8 * AsciiValueToString_Arg_0 = (CHAR8 *)AllocateZeroPool(sizeof(CHAR8));
    UINT8* AsciiValueToString_Arg_0_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(AsciiValueToString_Arg_0_OutputChoice), (VOID *)AsciiValueToString_Arg_0_OutputChoice);
    if(*AsciiValueToString_Arg_0_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*AsciiValueToString_Arg_0), (VOID *)AsciiValueToString_Arg_0);
    }
    ProtocolVariable->AsciiValueToString(
        AsciiValueToString_Arg_0,
        AsciiValueToString_Arg_1,
        AsciiValueToString_Arg_2,
        AsciiValueToString_Arg_3
    );
    return Status;
}

