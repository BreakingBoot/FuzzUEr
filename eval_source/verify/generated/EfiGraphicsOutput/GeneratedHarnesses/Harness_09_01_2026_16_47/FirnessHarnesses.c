#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called QueryMode.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzQueryMode(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_GRAPHICS_OUTPUT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiGraphicsOutputProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 QueryMode_Arg_1 = 0;
    UINTN * QueryMode_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(QueryMode_Arg_1), (VOID *)&QueryMode_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 QueryMode_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(QueryMode_Arg_2_choice), (VOID *)&QueryMode_Arg_2_choice);
    switch(QueryMode_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(QueryMode_Arg_2), (VOID *)QueryMode_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(QueryMode_Arg_2);
            QueryMode_Arg_2 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION * QueryMode_Arg_3 = (EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *)AllocateZeroPool(sizeof(EFI_GRAPHICS_OUTPUT_MODE_INFORMATION));
    UINT8* QueryMode_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(QueryMode_Arg_3_OutputChoice), (VOID *)QueryMode_Arg_3_OutputChoice);
    if(*QueryMode_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*QueryMode_Arg_3), (VOID *)QueryMode_Arg_3);
    }
    Status = ProtocolVariable->QueryMode(
        ProtocolVariable,
        QueryMode_Arg_1,
        QueryMode_Arg_2,
        (EFI_GRAPHICS_OUTPUT_MODE_INFORMATION **)&QueryMode_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetMode.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetMode(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_GRAPHICS_OUTPUT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiGraphicsOutputProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 SetMode_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetMode_Arg_1), (VOID *)&SetMode_Arg_1);
    
    Status = ProtocolVariable->SetMode(
        ProtocolVariable,
        SetMode_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Blt.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzBlt(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_GRAPHICS_OUTPUT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiGraphicsOutputProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GRAPHICS_OUTPUT_BLT_PIXEL * Blt_Arg_1 = (EFI_GRAPHICS_OUTPUT_BLT_PIXEL *)AllocateZeroPool(sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL));
    EFI_GRAPHICS_OUTPUT_BLT_OPERATION Blt_Arg_2 = 0;
    UINTN Blt_Arg_3 = 0;
    UINTN Blt_Arg_4 = 0;
    UINTN Blt_Arg_5 = 0;
    UINTN Blt_Arg_6 = 0;
    UINTN Blt_Arg_7 = 0;
    UINTN Blt_Arg_8 = 0;
    UINTN Blt_Arg_9 = 0;
    
    UINT8* Blt_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Blt_Arg_1_choice), (VOID *)Blt_Arg_1_choice);
    switch(*Blt_Arg_1_choice % 2) {
        case 0:
        {
        // Constant Variable Initialization
        Blt_Arg_1 = kEmptyHashValue;
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
        {
            UINT8 Firness_Blue;
            ReadBytes(Input, sizeof(Firness_Blue), (VOID *)&Firness_Blue);
            Blt_Arg_1->Blue = Firness_Blue;
        }
        {
            UINT8 Firness_Green;
            ReadBytes(Input, sizeof(Firness_Green), (VOID *)&Firness_Green);
            Blt_Arg_1->Green = Firness_Green;
        }
        {
            UINT8 Firness_Red;
            ReadBytes(Input, sizeof(Firness_Red), (VOID *)&Firness_Red);
            Blt_Arg_1->Red = Firness_Red;
        }
        {
            UINT8 Firness_Reserved;
            ReadBytes(Input, sizeof(Firness_Reserved), (VOID *)&Firness_Reserved);
            Blt_Arg_1->Reserved = Firness_Reserved;
        }
    
            break;
        }
    }
    // Constant Variable Initialization
    UINT8* Blt_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Blt_Arg_2_choice), (VOID *)Blt_Arg_2_choice);
    switch(*Blt_Arg_2_choice % 6) {
        case 0:
            Blt_Arg_2 = EfiBltBufferToVideo;
            break;
        case 1:
            Blt_Arg_2 = EfiBltVideoFill;
            break;
        case 2:
            Blt_Arg_2 = EfiBltVideoToBltBuffer;
            break;
        case 3:
            Blt_Arg_2 = EfiBltVideoToVideo;
            break;
        case 4:
            Blt_Arg_2 = EfiGraphicsOutputBltOperationMax;
            break;
        case 5:
            ReadBytes(Input, sizeof(Blt_Arg_2), (VOID *)&Blt_Arg_2);
            break;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Blt_Arg_3), (VOID *)&Blt_Arg_3);
    
    UINT8* Blt_Arg_4_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Blt_Arg_4_choice), (VOID *)Blt_Arg_4_choice);
    switch(*Blt_Arg_4_choice % 2) {
        case 0:
        {
        // Constant Variable Initialization
        Blt_Arg_4 = 0;
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(Blt_Arg_4), (VOID *)&Blt_Arg_4);
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Blt_Arg_5), (VOID *)&Blt_Arg_5);
    
    UINT8* Blt_Arg_6_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Blt_Arg_6_choice), (VOID *)Blt_Arg_6_choice);
    switch(*Blt_Arg_6_choice % 4) {
        case 0:
        {
        // Constant Variable Initialization
        Blt_Arg_6 = kEmptyHashValue;
    
            break;
        }
        case 1:
        {
        // Constant Variable Initialization
        Blt_Arg_6 = 0;
    
            break;
        }
        case 2:
        {
        // Constant Variable Initialization
        Blt_Arg_6 = 0;
    
            break;
        }
        case 3:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(Blt_Arg_6), (VOID *)&Blt_Arg_6);
    
            break;
        }
    }
    UINT8* Blt_Arg_7_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Blt_Arg_7_choice), (VOID *)Blt_Arg_7_choice);
    switch(*Blt_Arg_7_choice % 2) {
        case 0:
        {
        // Constant Variable Initialization
        Blt_Arg_7 = EFI_GLYPH_WIDTH;
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(Blt_Arg_7), (VOID *)&Blt_Arg_7);
    
            break;
        }
    }
    UINT8* Blt_Arg_8_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Blt_Arg_8_choice), (VOID *)Blt_Arg_8_choice);
    switch(*Blt_Arg_8_choice % 2) {
        case 0:
        {
        // Constant Variable Initialization
        Blt_Arg_8 = EFI_GLYPH_HEIGHT;
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(Blt_Arg_8), (VOID *)&Blt_Arg_8);
    
            break;
        }
    }
    UINT8* Blt_Arg_9_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(Blt_Arg_9_choice), (VOID *)Blt_Arg_9_choice);
    switch(*Blt_Arg_9_choice % 8) {
        case 0:
        {
        // Constant Variable Initialization
        Blt_Arg_9 = 0;
    
            break;
        }
        case 1:
        {
        // Constant Variable Initialization
        Blt_Arg_9 = 0;
    
            break;
        }
        case 2:
        {
        // Constant Variable Initialization
        Blt_Arg_9 = 0;
    
            break;
        }
        case 3:
        {
        // Constant Variable Initialization
        Blt_Arg_9 = 0;
    
            break;
        }
        case 4:
        {
        // Constant Variable Initialization
        Blt_Arg_9 = kEmptyHashValue;
    
            break;
        }
        case 5:
        {
        // Constant Variable Initialization
        Blt_Arg_9 = EFI_GLYPH_WIDTH * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL);
    
            break;
        }
        case 6:
        {
        // Constant Variable Initialization
        Blt_Arg_9 = 0;
    
            break;
        }
        case 7:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(Blt_Arg_9), (VOID *)&Blt_Arg_9);
    
            break;
        }
    }
    Status = ProtocolVariable->Blt(
        ProtocolVariable,
        Blt_Arg_1,
        Blt_Arg_2,
        Blt_Arg_3,
        Blt_Arg_4,
        Blt_Arg_5,
        Blt_Arg_6,
        Blt_Arg_7,
        Blt_Arg_8,
        Blt_Arg_9
    );
    return Status;
}

