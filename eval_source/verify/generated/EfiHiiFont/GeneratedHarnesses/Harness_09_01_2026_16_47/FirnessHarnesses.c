#include "FirnessHarnesses.h"

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
    EFI_HII_OUT_FLAGS StringToImage_Arg_1 = 0;
    CHAR16 * StringToImage_Arg_2 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    EFI_FONT_DISPLAY_INFO * StringToImage_Arg_3 = (EFI_FONT_DISPLAY_INFO *)AllocateZeroPool(sizeof(EFI_FONT_DISPLAY_INFO));
    EFI_IMAGE_OUTPUT * StringToImage_Arg_4 = (EFI_IMAGE_OUTPUT *)AllocateZeroPool(sizeof(EFI_IMAGE_OUTPUT));
    UINTN StringToImage_Arg_5 = 0;
    UINTN StringToImage_Arg_6 = 0;
    
    UINT8* StringToImage_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(StringToImage_Arg_1_choice), (VOID *)StringToImage_Arg_1_choice);
    switch(*StringToImage_Arg_1_choice % 5) {
        case 0:
        {
        // Constant Variable Initialization
        StringToImage_Arg_1 = EFI_HII_IGNORE_IF_NO_GLYPH | EFI_HII_OUT_FLAG_CLIP | EFI_HII_OUT_FLAG_CLIP_CLEAN_X | EFI_HII_OUT_FLAG_CLIP_CLEAN_Y | EFI_HII_IGNORE_LINE_BREAK | EFI_HII_DIRECT_TO_SCREEN;
    
            break;
        }
        case 1:
        {
        // Constant Variable Initialization
        StringToImage_Arg_1 = EFI_HII_IGNORE_IF_NO_GLYPH | EFI_HII_OUT_FLAG_CLIP | EFI_HII_OUT_FLAG_CLIP_CLEAN_X | EFI_HII_OUT_FLAG_CLIP_CLEAN_Y | EFI_HII_IGNORE_LINE_BREAK;
    
            break;
        }
        case 2:
        {
        // Constant Variable Initialization
        StringToImage_Arg_1 = EFI_HII_IGNORE_IF_NO_GLYPH | EFI_HII_DIRECT_TO_SCREEN | EFI_HII_IGNORE_LINE_BREAK;
    
            break;
        }
        case 3:
        {
        // Constant Variable Initialization
        StringToImage_Arg_1 = EFI_HII_IGNORE_IF_NO_GLYPH | EFI_HII_IGNORE_LINE_BREAK;
    
            break;
        }
        case 4:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(StringToImage_Arg_1), (VOID *)&StringToImage_Arg_1);
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 StringToImage_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(StringToImage_Arg_2_choice), (VOID *)&StringToImage_Arg_2_choice);
    switch(StringToImage_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(StringToImage_Arg_2), (VOID *)StringToImage_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(StringToImage_Arg_2);
            StringToImage_Arg_2 = NULL;
            break;
        }
    }
    
    // Generator Struct Variable Initialization
    {
        EFI_GRAPHICS_OUTPUT_BLT_PIXEL Firness_ForegroundColor;
        ReadBytes(Input, sizeof(Firness_ForegroundColor), (VOID *)&Firness_ForegroundColor);
        StringToImage_Arg_3->ForegroundColor = Firness_ForegroundColor;
    }
    {
        EFI_GRAPHICS_OUTPUT_BLT_PIXEL Firness_BackgroundColor;
        ReadBytes(Input, sizeof(Firness_BackgroundColor), (VOID *)&Firness_BackgroundColor);
        StringToImage_Arg_3->BackgroundColor = Firness_BackgroundColor;
    }
    {
        EFI_FONT_INFO_MASK Firness_FontInfoMask;
        ReadBytes(Input, sizeof(Firness_FontInfoMask), (VOID *)&Firness_FontInfoMask);
        StringToImage_Arg_3->FontInfoMask = Firness_FontInfoMask;
    }
    {
        EFI_FONT_INFO Firness_FontInfo;
        ReadBytes(Input, sizeof(Firness_FontInfo), (VOID *)&Firness_FontInfo);
        StringToImage_Arg_3->FontInfo = Firness_FontInfo;
    }
    
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StringToImage_Arg_5), (VOID *)&StringToImage_Arg_5);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StringToImage_Arg_6), (VOID *)&StringToImage_Arg_6);
    
    /*
        Output Variable(s)
    */
    EFI_HII_ROW_INFO * StringToImage_Arg_7 = (EFI_HII_ROW_INFO *)AllocateZeroPool(sizeof(EFI_HII_ROW_INFO));
    UINT8* StringToImage_Arg_7_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(StringToImage_Arg_7_OutputChoice), (VOID *)StringToImage_Arg_7_OutputChoice);
    if(*StringToImage_Arg_7_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*StringToImage_Arg_7), (VOID *)StringToImage_Arg_7);
    }
    UINTN * StringToImage_Arg_8 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* StringToImage_Arg_8_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(StringToImage_Arg_8_OutputChoice), (VOID *)StringToImage_Arg_8_OutputChoice);
    if(*StringToImage_Arg_8_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*StringToImage_Arg_8), (VOID *)StringToImage_Arg_8);
    }
    UINTN * StringToImage_Arg_9 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* StringToImage_Arg_9_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(StringToImage_Arg_9_OutputChoice), (VOID *)StringToImage_Arg_9_OutputChoice);
    if(*StringToImage_Arg_9_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*StringToImage_Arg_9), (VOID *)StringToImage_Arg_9);
    }
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
    CHAR16 GetGlyph_Arg_1 = 0;
    EFI_FONT_DISPLAY_INFO * GetGlyph_Arg_2 = (EFI_FONT_DISPLAY_INFO *)AllocateZeroPool(sizeof(EFI_FONT_DISPLAY_INFO));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetGlyph_Arg_1), (VOID *)&GetGlyph_Arg_1);
    
    // Generator Struct Variable Initialization
    {
        EFI_GRAPHICS_OUTPUT_BLT_PIXEL Firness_ForegroundColor;
        ReadBytes(Input, sizeof(Firness_ForegroundColor), (VOID *)&Firness_ForegroundColor);
        GetGlyph_Arg_2->ForegroundColor = Firness_ForegroundColor;
    }
    {
        EFI_GRAPHICS_OUTPUT_BLT_PIXEL Firness_BackgroundColor;
        ReadBytes(Input, sizeof(Firness_BackgroundColor), (VOID *)&Firness_BackgroundColor);
        GetGlyph_Arg_2->BackgroundColor = Firness_BackgroundColor;
    }
    {
        EFI_FONT_INFO_MASK Firness_FontInfoMask;
        ReadBytes(Input, sizeof(Firness_FontInfoMask), (VOID *)&Firness_FontInfoMask);
        GetGlyph_Arg_2->FontInfoMask = Firness_FontInfoMask;
    }
    {
        EFI_FONT_INFO Firness_FontInfo;
        ReadBytes(Input, sizeof(Firness_FontInfo), (VOID *)&Firness_FontInfo);
        GetGlyph_Arg_2->FontInfo = Firness_FontInfo;
    }
    
    /*
        Output Variable(s)
    */
    EFI_IMAGE_OUTPUT * GetGlyph_Arg_3 = (EFI_IMAGE_OUTPUT *)AllocateZeroPool(sizeof(EFI_IMAGE_OUTPUT));
    UINT8* GetGlyph_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetGlyph_Arg_3_OutputChoice), (VOID *)GetGlyph_Arg_3_OutputChoice);
    if(*GetGlyph_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetGlyph_Arg_3), (VOID *)GetGlyph_Arg_3);
    }
    UINTN * GetGlyph_Arg_4 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetGlyph_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetGlyph_Arg_4_OutputChoice), (VOID *)GetGlyph_Arg_4_OutputChoice);
    if(*GetGlyph_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetGlyph_Arg_4), (VOID *)GetGlyph_Arg_4);
    }
    Status = ProtocolVariable->GetGlyph(
        ProtocolVariable,
        GetGlyph_Arg_1,
        GetGlyph_Arg_2,
        (EFI_IMAGE_OUTPUT **)&GetGlyph_Arg_3,
        GetGlyph_Arg_4
    );
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
    EFI_HII_OUT_FLAGS StringIdToImage_Arg_1 = 0;
    EFI_HII_HANDLE StringIdToImage_Arg_2 = 0;
    EFI_STRING_ID StringIdToImage_Arg_3 = 0;
    CHAR8 * StringIdToImage_Arg_4 = (CHAR8 *)AllocateZeroPool(sizeof(CHAR8));
    EFI_FONT_DISPLAY_INFO * StringIdToImage_Arg_5 = (EFI_FONT_DISPLAY_INFO *)AllocateZeroPool(sizeof(EFI_FONT_DISPLAY_INFO));
    UINTN StringIdToImage_Arg_7 = 0;
    UINTN StringIdToImage_Arg_8 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StringIdToImage_Arg_1), (VOID *)&StringIdToImage_Arg_1);
    
    UINT8* StringIdToImage_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(StringIdToImage_Arg_2_choice), (VOID *)StringIdToImage_Arg_2_choice);
    switch(*StringIdToImage_Arg_2_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(StringIdToImage_Arg_2), (VOID *)&StringIdToImage_Arg_2);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * FindHiiHandleViaDevPath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            
            // Generator Struct Variable Initialization
            {
                UINT8 Firness_Type;
                ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
                FindHiiHandleViaDevPath_Arg_0->Type = Firness_Type;
            }
            {
                UINT8 Firness_SubType;
                ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
                FindHiiHandleViaDevPath_Arg_0->SubType = Firness_SubType;
            }
            ReadBytes(Input, sizeof(FindHiiHandleViaDevPath_Arg_0->Length), (VOID *)&(FindHiiHandleViaDevPath_Arg_0->Length));
            
            Status = FindHiiHandleViaDevPath(
                FindHiiHandleViaDevPath_Arg_0,
                &StringIdToImage_Arg_2,
                NULL
            );
    
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
            ReadBytes(Input, sizeof(StringIdToImage_Arg_4), (VOID *)StringIdToImage_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(StringIdToImage_Arg_4);
            StringIdToImage_Arg_4 = NULL;
            break;
        }
    }
    
    // Generator Struct Variable Initialization
    {
        EFI_GRAPHICS_OUTPUT_BLT_PIXEL Firness_ForegroundColor;
        ReadBytes(Input, sizeof(Firness_ForegroundColor), (VOID *)&Firness_ForegroundColor);
        StringIdToImage_Arg_5->ForegroundColor = Firness_ForegroundColor;
    }
    {
        EFI_GRAPHICS_OUTPUT_BLT_PIXEL Firness_BackgroundColor;
        ReadBytes(Input, sizeof(Firness_BackgroundColor), (VOID *)&Firness_BackgroundColor);
        StringIdToImage_Arg_5->BackgroundColor = Firness_BackgroundColor;
    }
    {
        EFI_FONT_INFO_MASK Firness_FontInfoMask;
        ReadBytes(Input, sizeof(Firness_FontInfoMask), (VOID *)&Firness_FontInfoMask);
        StringIdToImage_Arg_5->FontInfoMask = Firness_FontInfoMask;
    }
    {
        EFI_FONT_INFO Firness_FontInfo;
        ReadBytes(Input, sizeof(Firness_FontInfo), (VOID *)&Firness_FontInfo);
        StringIdToImage_Arg_5->FontInfo = Firness_FontInfo;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StringIdToImage_Arg_7), (VOID *)&StringIdToImage_Arg_7);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StringIdToImage_Arg_8), (VOID *)&StringIdToImage_Arg_8);
    
    /*
        Output Variable(s)
    */
    EFI_HII_ROW_INFO * StringIdToImage_Arg_9 = (EFI_HII_ROW_INFO *)AllocateZeroPool(sizeof(EFI_HII_ROW_INFO));
    UINT8* StringIdToImage_Arg_9_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(StringIdToImage_Arg_9_OutputChoice), (VOID *)StringIdToImage_Arg_9_OutputChoice);
    if(*StringIdToImage_Arg_9_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*StringIdToImage_Arg_9), (VOID *)StringIdToImage_Arg_9);
    }
    UINTN * StringIdToImage_Arg_10 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* StringIdToImage_Arg_10_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(StringIdToImage_Arg_10_OutputChoice), (VOID *)StringIdToImage_Arg_10_OutputChoice);
    if(*StringIdToImage_Arg_10_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*StringIdToImage_Arg_10), (VOID *)StringIdToImage_Arg_10);
    }
    UINTN * StringIdToImage_Arg_11 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* StringIdToImage_Arg_11_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(StringIdToImage_Arg_11_OutputChoice), (VOID *)StringIdToImage_Arg_11_OutputChoice);
    if(*StringIdToImage_Arg_11_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*StringIdToImage_Arg_11), (VOID *)StringIdToImage_Arg_11);
    }
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
    EFI_STRING GetFontInfo_Arg_4 = 0;
    
    // Generator Struct Variable Initialization
    {
        EFI_GRAPHICS_OUTPUT_BLT_PIXEL Firness_ForegroundColor;
        ReadBytes(Input, sizeof(Firness_ForegroundColor), (VOID *)&Firness_ForegroundColor);
        GetFontInfo_Arg_2->ForegroundColor = Firness_ForegroundColor;
    }
    {
        EFI_GRAPHICS_OUTPUT_BLT_PIXEL Firness_BackgroundColor;
        ReadBytes(Input, sizeof(Firness_BackgroundColor), (VOID *)&Firness_BackgroundColor);
        GetFontInfo_Arg_2->BackgroundColor = Firness_BackgroundColor;
    }
    {
        EFI_FONT_INFO_MASK Firness_FontInfoMask;
        ReadBytes(Input, sizeof(Firness_FontInfoMask), (VOID *)&Firness_FontInfoMask);
        GetFontInfo_Arg_2->FontInfoMask = Firness_FontInfoMask;
    }
    {
        EFI_FONT_INFO Firness_FontInfo;
        ReadBytes(Input, sizeof(Firness_FontInfo), (VOID *)&Firness_FontInfo);
        GetFontInfo_Arg_2->FontInfo = Firness_FontInfo;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetFontInfo_Arg_4), (VOID *)&GetFontInfo_Arg_4);
    
    /*
        Output Variable(s)
    */
    EFI_FONT_DISPLAY_INFO * GetFontInfo_Arg_3 = (EFI_FONT_DISPLAY_INFO *)AllocateZeroPool(sizeof(EFI_FONT_DISPLAY_INFO));
    UINT8* GetFontInfo_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetFontInfo_Arg_3_OutputChoice), (VOID *)GetFontInfo_Arg_3_OutputChoice);
    if(*GetFontInfo_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetFontInfo_Arg_3), (VOID *)GetFontInfo_Arg_3);
    }
    Status = ProtocolVariable->GetFontInfo(
        ProtocolVariable,
        NULL,
        GetFontInfo_Arg_2,
        (EFI_FONT_DISPLAY_INFO **)&GetFontInfo_Arg_3,
        GetFontInfo_Arg_4
    );
    return Status;
}

