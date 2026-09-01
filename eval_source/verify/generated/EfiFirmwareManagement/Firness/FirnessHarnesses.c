#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called GetImageInfo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetImageInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FIRMWARE_MANAGEMENT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFirmwareManagementProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * GetImageInfo_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    EFI_FIRMWARE_IMAGE_DESCRIPTOR * GetImageInfo_Arg_2 = (EFI_FIRMWARE_IMAGE_DESCRIPTOR *)AllocateZeroPool(sizeof(EFI_FIRMWARE_IMAGE_DESCRIPTOR));
    
    // Fuzzable Variable Initialization
    UINT8 GetImageInfo_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetImageInfo_Arg_1_choice), (VOID *)&GetImageInfo_Arg_1_choice);
    switch(GetImageInfo_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetImageInfo_Arg_1), (VOID *)GetImageInfo_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(GetImageInfo_Arg_1);
            GetImageInfo_Arg_1 = NULL;
            break;
        }
    }
    
    
    /*
        Output Variable(s)
    */
    UINT32 * GetImageInfo_Arg_3 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT8* GetImageInfo_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetImageInfo_Arg_3_OutputChoice), (VOID *)GetImageInfo_Arg_3_OutputChoice);
    if(*GetImageInfo_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetImageInfo_Arg_3), (VOID *)GetImageInfo_Arg_3);
    }
    UINT8 * GetImageInfo_Arg_4 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT8* GetImageInfo_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetImageInfo_Arg_4_OutputChoice), (VOID *)GetImageInfo_Arg_4_OutputChoice);
    if(*GetImageInfo_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetImageInfo_Arg_4), (VOID *)GetImageInfo_Arg_4);
    }
    UINTN * GetImageInfo_Arg_5 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetImageInfo_Arg_5_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetImageInfo_Arg_5_OutputChoice), (VOID *)GetImageInfo_Arg_5_OutputChoice);
    if(*GetImageInfo_Arg_5_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetImageInfo_Arg_5), (VOID *)GetImageInfo_Arg_5);
    }
    UINT32 * GetImageInfo_Arg_6 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT8* GetImageInfo_Arg_6_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetImageInfo_Arg_6_OutputChoice), (VOID *)GetImageInfo_Arg_6_OutputChoice);
    if(*GetImageInfo_Arg_6_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetImageInfo_Arg_6), (VOID *)GetImageInfo_Arg_6);
    }
    CHAR16 * GetImageInfo_Arg_7 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    UINT8* GetImageInfo_Arg_7_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetImageInfo_Arg_7_OutputChoice), (VOID *)GetImageInfo_Arg_7_OutputChoice);
    if(*GetImageInfo_Arg_7_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetImageInfo_Arg_7), (VOID *)GetImageInfo_Arg_7);
    }
    Status = ProtocolVariable->GetImageInfo(
        ProtocolVariable,
        GetImageInfo_Arg_1,
        GetImageInfo_Arg_2,
        GetImageInfo_Arg_3,
        GetImageInfo_Arg_4,
        GetImageInfo_Arg_5,
        GetImageInfo_Arg_6,
        (CHAR16 **)&GetImageInfo_Arg_7
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetImage.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetImage(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FIRMWARE_MANAGEMENT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFirmwareManagementProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 GetImage_Arg_1 = 0;
    UINTN * GetImage_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetImage_Arg_1), (VOID *)&GetImage_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 GetImage_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(GetImage_Arg_3_choice), (VOID *)&GetImage_Arg_3_choice);
    switch(GetImage_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetImage_Arg_3), (VOID *)GetImage_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(GetImage_Arg_3);
            GetImage_Arg_3 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    UINTN*  GetImage_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT8* GetImage_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetImage_Arg_2_OutputChoice), (VOID *)GetImage_Arg_2_OutputChoice);
    if(*GetImage_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetImage_Arg_2), (VOID *)GetImage_Arg_2);
    }
    Status = ProtocolVariable->GetImage(
        ProtocolVariable,
        GetImage_Arg_1,
        (VOID *)GetImage_Arg_2,
        GetImage_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetImage.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetImage(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FIRMWARE_MANAGEMENT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFirmwareManagementProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 SetImage_Arg_1 = 0;
    UINTN*  SetImage_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN SetImage_Arg_3 = 0;
    UINTN*  SetImage_Arg_4 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetImage_Arg_1), (VOID *)&SetImage_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 SetImage_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(SetImage_Arg_2_choice), (VOID *)&SetImage_Arg_2_choice);
    switch(SetImage_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetImage_Arg_2), (VOID *)SetImage_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(SetImage_Arg_2);
            SetImage_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetImage_Arg_3), (VOID *)&SetImage_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 SetImage_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(SetImage_Arg_4_choice), (VOID *)&SetImage_Arg_4_choice);
    switch(SetImage_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetImage_Arg_4), (VOID *)SetImage_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(SetImage_Arg_4);
            SetImage_Arg_4 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    CHAR16 * * SetImage_Arg_6 = (CHAR16 * *)AllocateZeroPool(sizeof(CHAR16));
    UINT8* SetImage_Arg_6_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SetImage_Arg_6_OutputChoice), (VOID *)SetImage_Arg_6_OutputChoice);
    if(*SetImage_Arg_6_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*SetImage_Arg_6), (VOID *)SetImage_Arg_6);
    }
    Status = ProtocolVariable->SetImage(
        ProtocolVariable,
        SetImage_Arg_1,
        (VOID *)SetImage_Arg_2,
        SetImage_Arg_3,
        (VOID *)SetImage_Arg_4,
        (EFI_FIRMWARE_MANAGEMENT_UPDATE_IMAGE_PROGRESS){0},
        &SetImage_Arg_6
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called CheckImage.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzCheckImage(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FIRMWARE_MANAGEMENT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFirmwareManagementProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 CheckImage_Arg_1 = 0;
    UINTN*  CheckImage_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN CheckImage_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(CheckImage_Arg_1), (VOID *)&CheckImage_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 CheckImage_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(CheckImage_Arg_2_choice), (VOID *)&CheckImage_Arg_2_choice);
    switch(CheckImage_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(CheckImage_Arg_2), (VOID *)CheckImage_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(CheckImage_Arg_2);
            CheckImage_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(CheckImage_Arg_3), (VOID *)&CheckImage_Arg_3);
    
    /*
        Output Variable(s)
    */
    UINT32 * CheckImage_Arg_4 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT8* CheckImage_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(CheckImage_Arg_4_OutputChoice), (VOID *)CheckImage_Arg_4_OutputChoice);
    if(*CheckImage_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*CheckImage_Arg_4), (VOID *)CheckImage_Arg_4);
    }
    Status = ProtocolVariable->CheckImage(
        ProtocolVariable,
        CheckImage_Arg_1,
        (VOID *)CheckImage_Arg_2,
        CheckImage_Arg_3,
        CheckImage_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetPackageInfo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetPackageInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FIRMWARE_MANAGEMENT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFirmwareManagementProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINT32 * GetPackageInfo_Arg_1 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT8* GetPackageInfo_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetPackageInfo_Arg_1_OutputChoice), (VOID *)GetPackageInfo_Arg_1_OutputChoice);
    if(*GetPackageInfo_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetPackageInfo_Arg_1), (VOID *)GetPackageInfo_Arg_1);
    }
    CHAR16 * * GetPackageInfo_Arg_2 = (CHAR16 * *)AllocateZeroPool(sizeof(CHAR16));
    UINT8* GetPackageInfo_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetPackageInfo_Arg_2_OutputChoice), (VOID *)GetPackageInfo_Arg_2_OutputChoice);
    if(*GetPackageInfo_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetPackageInfo_Arg_2), (VOID *)GetPackageInfo_Arg_2);
    }
    UINT32 * GetPackageInfo_Arg_3 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT8* GetPackageInfo_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetPackageInfo_Arg_3_OutputChoice), (VOID *)GetPackageInfo_Arg_3_OutputChoice);
    if(*GetPackageInfo_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetPackageInfo_Arg_3), (VOID *)GetPackageInfo_Arg_3);
    }
    UINT64 * GetPackageInfo_Arg_4 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    UINT8* GetPackageInfo_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetPackageInfo_Arg_4_OutputChoice), (VOID *)GetPackageInfo_Arg_4_OutputChoice);
    if(*GetPackageInfo_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetPackageInfo_Arg_4), (VOID *)GetPackageInfo_Arg_4);
    }
    UINT64 * GetPackageInfo_Arg_5 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    UINT8* GetPackageInfo_Arg_5_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetPackageInfo_Arg_5_OutputChoice), (VOID *)GetPackageInfo_Arg_5_OutputChoice);
    if(*GetPackageInfo_Arg_5_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetPackageInfo_Arg_5), (VOID *)GetPackageInfo_Arg_5);
    }
    Status = ProtocolVariable->GetPackageInfo(
        ProtocolVariable,
        GetPackageInfo_Arg_1,
        &GetPackageInfo_Arg_2,
        GetPackageInfo_Arg_3,
        GetPackageInfo_Arg_4,
        GetPackageInfo_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetPackageInfo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetPackageInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FIRMWARE_MANAGEMENT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFirmwareManagementProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  SetPackageInfo_Arg_1 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN SetPackageInfo_Arg_2 = 0;
    UINTN*  SetPackageInfo_Arg_3 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT32 SetPackageInfo_Arg_4 = 0;
    CHAR16 * SetPackageInfo_Arg_5 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
    
    // Fuzzable Variable Initialization
    UINT8 SetPackageInfo_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(SetPackageInfo_Arg_1_choice), (VOID *)&SetPackageInfo_Arg_1_choice);
    switch(SetPackageInfo_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetPackageInfo_Arg_1), (VOID *)SetPackageInfo_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(SetPackageInfo_Arg_1);
            SetPackageInfo_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetPackageInfo_Arg_2), (VOID *)&SetPackageInfo_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 SetPackageInfo_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(SetPackageInfo_Arg_3_choice), (VOID *)&SetPackageInfo_Arg_3_choice);
    switch(SetPackageInfo_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetPackageInfo_Arg_3), (VOID *)SetPackageInfo_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(SetPackageInfo_Arg_3);
            SetPackageInfo_Arg_3 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetPackageInfo_Arg_4), (VOID *)&SetPackageInfo_Arg_4);
    
    // Fuzzable Variable Initialization
    UINT8 SetPackageInfo_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(SetPackageInfo_Arg_5_choice), (VOID *)&SetPackageInfo_Arg_5_choice);
    switch(SetPackageInfo_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetPackageInfo_Arg_5), (VOID *)SetPackageInfo_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(SetPackageInfo_Arg_5);
            SetPackageInfo_Arg_5 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->SetPackageInfo(
        ProtocolVariable,
        (VOID *)SetPackageInfo_Arg_1,
        SetPackageInfo_Arg_2,
        (VOID *)SetPackageInfo_Arg_3,
        SetPackageInfo_Arg_4,
        SetPackageInfo_Arg_5
    );
    return Status;
}

