#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the Protocols service
    called DisablePageBreak.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDisablePageBreak(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    FirnessSanitizer(TRUE);
    ProtocolVariable->DisablePageBreak(
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetPageBreak.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetPageBreak(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    FirnessSanitizer(TRUE);
    ProtocolVariable->GetPageBreak(
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called RemoveDupInFileList.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRemoveDupInFileList(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->RemoveDupInFileList(
        NULL
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called Execute.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzExecute(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Execute(
        ImageHandle,
        NULL,
        NULL,
        NULL
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetEnv.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetEnv(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    FirnessSanitizer(TRUE);
    ProtocolVariable->GetEnv(
        NULL
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called SetEnv.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetEnv(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * SetEnv_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    CHAR16 * SetEnv_Arg_1 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    BOOLEAN SetEnv_Arg_2 = {0};
    
    // Fuzzable Variable Initialization
    UINT8 SetEnv_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(SetEnv_Arg_0_choice), (VOID *)&SetEnv_Arg_0_choice);
    switch(SetEnv_Arg_0_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*SetEnv_Arg_0), (VOID *)SetEnv_Arg_0);
            SetEnv_Arg_0[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(SetEnv_Arg_0);
            SetEnv_Arg_0 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 SetEnv_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(SetEnv_Arg_1_choice), (VOID *)&SetEnv_Arg_1_choice);
    switch(SetEnv_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*SetEnv_Arg_1), (VOID *)SetEnv_Arg_1);
            SetEnv_Arg_1[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(SetEnv_Arg_1);
            SetEnv_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetEnv_Arg_2), (VOID *)&SetEnv_Arg_2);
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->SetEnv(
        SetEnv_Arg_0,
        SetEnv_Arg_1,
        SetEnv_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetAlias.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetAlias(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * GetAlias_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    
    // Fuzzable Variable Initialization
    UINT8 GetAlias_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(GetAlias_Arg_0_choice), (VOID *)&GetAlias_Arg_0_choice);
    switch(GetAlias_Arg_0_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*GetAlias_Arg_0), (VOID *)GetAlias_Arg_0);
            GetAlias_Arg_0[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(GetAlias_Arg_0);
            GetAlias_Arg_0 = NULL;
            break;
        }
    }
    
    FirnessSanitizer(TRUE);
    ProtocolVariable->GetAlias(
        GetAlias_Arg_0,
        NULL
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called SetAlias.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetAlias(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * SetAlias_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    CHAR16 * SetAlias_Arg_1 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    BOOLEAN SetAlias_Arg_2 = {0};
    BOOLEAN SetAlias_Arg_3 = {0};
    
    // Fuzzable Variable Initialization
    UINT8 SetAlias_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(SetAlias_Arg_0_choice), (VOID *)&SetAlias_Arg_0_choice);
    switch(SetAlias_Arg_0_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*SetAlias_Arg_0), (VOID *)SetAlias_Arg_0);
            SetAlias_Arg_0[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(SetAlias_Arg_0);
            SetAlias_Arg_0 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 SetAlias_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(SetAlias_Arg_1_choice), (VOID *)&SetAlias_Arg_1_choice);
    switch(SetAlias_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*SetAlias_Arg_1), (VOID *)SetAlias_Arg_1);
            SetAlias_Arg_1[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(SetAlias_Arg_1);
            SetAlias_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetAlias_Arg_2), (VOID *)&SetAlias_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetAlias_Arg_3), (VOID *)&SetAlias_Arg_3);
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->SetAlias(
        SetAlias_Arg_0,
        SetAlias_Arg_1,
        SetAlias_Arg_2,
        SetAlias_Arg_3
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetHelpText.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetHelpText(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * GetHelpText_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    
    // Fuzzable Variable Initialization
    UINT8 GetHelpText_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(GetHelpText_Arg_0_choice), (VOID *)&GetHelpText_Arg_0_choice);
    switch(GetHelpText_Arg_0_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*GetHelpText_Arg_0), (VOID *)GetHelpText_Arg_0);
            GetHelpText_Arg_0[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(GetHelpText_Arg_0);
            GetHelpText_Arg_0 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    CHAR16 * GetHelpText_Arg_2 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    UINT8* GetHelpText_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetHelpText_Arg_2_OutputChoice), (VOID *)GetHelpText_Arg_2_OutputChoice);
    if(*GetHelpText_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetHelpText_Arg_2), (VOID *)GetHelpText_Arg_2);
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetHelpText(
        GetHelpText_Arg_0,
        NULL,
        (CHAR16 * *)&GetHelpText_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetDevicePathFromMap.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetDevicePathFromMap(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * GetDevicePathFromMap_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    
    // Fuzzable Variable Initialization
    UINT8 GetDevicePathFromMap_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(GetDevicePathFromMap_Arg_0_choice), (VOID *)&GetDevicePathFromMap_Arg_0_choice);
    switch(GetDevicePathFromMap_Arg_0_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*GetDevicePathFromMap_Arg_0), (VOID *)GetDevicePathFromMap_Arg_0);
            GetDevicePathFromMap_Arg_0[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(GetDevicePathFromMap_Arg_0);
            GetDevicePathFromMap_Arg_0 = NULL;
            break;
        }
    }
    
    FirnessSanitizer(TRUE);
    ProtocolVariable->GetDevicePathFromMap(
        GetDevicePathFromMap_Arg_0
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetMapFromDevicePath.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetMapFromDevicePath(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * GetMapFromDevicePath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    if (GetMapFromDevicePath_Arg_0 != NULL) {
        GetMapFromDevicePath_Arg_0->Type = 0x7F;
        GetMapFromDevicePath_Arg_0->SubType = 0xFF;
        GetMapFromDevicePath_Arg_0->Length[0] = 4;
        GetMapFromDevicePath_Arg_0->Length[1] = 0;
    }
    
    
    FirnessSanitizer(TRUE);
    ProtocolVariable->GetMapFromDevicePath(
        (EFI_DEVICE_PATH_PROTOCOL * *)&GetMapFromDevicePath_Arg_0
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetDevicePathFromFilePath.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetDevicePathFromFilePath(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * GetDevicePathFromFilePath_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    
    // Fuzzable Variable Initialization
    UINT8 GetDevicePathFromFilePath_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(GetDevicePathFromFilePath_Arg_0_choice), (VOID *)&GetDevicePathFromFilePath_Arg_0_choice);
    switch(GetDevicePathFromFilePath_Arg_0_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*GetDevicePathFromFilePath_Arg_0), (VOID *)GetDevicePathFromFilePath_Arg_0);
            GetDevicePathFromFilePath_Arg_0[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(GetDevicePathFromFilePath_Arg_0);
            GetDevicePathFromFilePath_Arg_0 = NULL;
            break;
        }
    }
    
    FirnessSanitizer(TRUE);
    ProtocolVariable->GetDevicePathFromFilePath(
        GetDevicePathFromFilePath_Arg_0
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetFilePathFromDevicePath.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetFilePathFromDevicePath(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * GetFilePathFromDevicePath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    if (GetFilePathFromDevicePath_Arg_0 != NULL) {
        GetFilePathFromDevicePath_Arg_0->Type = 0x7F;
        GetFilePathFromDevicePath_Arg_0->SubType = 0xFF;
        GetFilePathFromDevicePath_Arg_0->Length[0] = 4;
        GetFilePathFromDevicePath_Arg_0->Length[1] = 0;
    }
    
    UINT8* GetFilePathFromDevicePath_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetFilePathFromDevicePath_Arg_0_choice), (VOID *)GetFilePathFromDevicePath_Arg_0_choice);
    switch(*GetFilePathFromDevicePath_Arg_0_choice % 2) {
        case 0:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * ChooseFile_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            if (ChooseFile_Arg_0 != NULL) {
                ChooseFile_Arg_0->Type = 0x7F;
                ChooseFile_Arg_0->SubType = 0xFF;
                ChooseFile_Arg_0->Length[0] = 4;
                ChooseFile_Arg_0->Length[1] = 0;
            }
            unsigned short * ChooseFile_Arg_1 = (unsigned short *)AllocateZeroPool(sizeof(unsigned short));
            
            // Generator Struct Variable Initialization
            {
                UINT8 Firness_Type;
                ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
                ChooseFile_Arg_0->Type = Firness_Type;
            }
            {
                UINT8 Firness_SubType;
                ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
                ChooseFile_Arg_0->SubType = Firness_SubType;
            }
            ReadBytes(Input, sizeof(ChooseFile_Arg_0->Length), (VOID *)&(ChooseFile_Arg_0->Length));
            
            // Fuzzable Variable Initialization
            UINT8 ChooseFile_Arg_1_choice = 0;
            ReadBytes(Input, sizeof(ChooseFile_Arg_1_choice), (VOID *)&ChooseFile_Arg_1_choice);
            switch(ChooseFile_Arg_1_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(*ChooseFile_Arg_1), (VOID *)ChooseFile_Arg_1);
                    break;
                case 1:
                {
                    gBS->FreePool(ChooseFile_Arg_1);
                    ChooseFile_Arg_1 = NULL;
                    break;
                }
            }
            
            FirnessSanitizer(TRUE);
            Status = ChooseFile(
                ChooseFile_Arg_0,
                ChooseFile_Arg_1,
                NULL,
                &GetFilePathFromDevicePath_Arg_0
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
        {
            UINT8 Firness_Type;
            ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
            GetFilePathFromDevicePath_Arg_0->Type = Firness_Type;
        }
        {
            UINT8 Firness_SubType;
            ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
            GetFilePathFromDevicePath_Arg_0->SubType = Firness_SubType;
        }
        ReadBytes(Input, sizeof(GetFilePathFromDevicePath_Arg_0->Length), (VOID *)&(GetFilePathFromDevicePath_Arg_0->Length));
    
            break;
        }
    }
    FirnessSanitizer(TRUE);
    ProtocolVariable->GetFilePathFromDevicePath(
        GetFilePathFromDevicePath_Arg_0
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetMap.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetMap(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * SetMap_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    if (SetMap_Arg_0 != NULL) {
        SetMap_Arg_0->Type = 0x7F;
        SetMap_Arg_0->SubType = 0xFF;
        SetMap_Arg_0->Length[0] = 4;
        SetMap_Arg_0->Length[1] = 0;
    }
    CHAR16 * SetMap_Arg_1 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    
    UINT8* SetMap_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*SetMap_Arg_0_choice), (VOID *)SetMap_Arg_0_choice);
    switch(*SetMap_Arg_0_choice % 4) {
        case 0:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * ChooseFile_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            if (ChooseFile_Arg_0 != NULL) {
                ChooseFile_Arg_0->Type = 0x7F;
                ChooseFile_Arg_0->SubType = 0xFF;
                ChooseFile_Arg_0->Length[0] = 4;
                ChooseFile_Arg_0->Length[1] = 0;
            }
            unsigned short * ChooseFile_Arg_1 = (unsigned short *)AllocateZeroPool(sizeof(unsigned short));
            
            // Generator Struct Variable Initialization
            {
                UINT8 Firness_Type;
                ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
                ChooseFile_Arg_0->Type = Firness_Type;
            }
            {
                UINT8 Firness_SubType;
                ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
                ChooseFile_Arg_0->SubType = Firness_SubType;
            }
            ReadBytes(Input, sizeof(ChooseFile_Arg_0->Length), (VOID *)&(ChooseFile_Arg_0->Length));
            
            // Fuzzable Variable Initialization
            UINT8 ChooseFile_Arg_1_choice = 0;
            ReadBytes(Input, sizeof(ChooseFile_Arg_1_choice), (VOID *)&ChooseFile_Arg_1_choice);
            switch(ChooseFile_Arg_1_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(*ChooseFile_Arg_1), (VOID *)ChooseFile_Arg_1);
                    break;
                case 1:
                {
                    gBS->FreePool(ChooseFile_Arg_1);
                    ChooseFile_Arg_1 = NULL;
                    break;
                }
            }
            
            FirnessSanitizer(TRUE);
            Status = ChooseFile(
                ChooseFile_Arg_0,
                ChooseFile_Arg_1,
                NULL,
                &SetMap_Arg_0
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        UINT8 SetMap_Arg_0_choice = 0;
        ReadBytes(Input, sizeof(SetMap_Arg_0_choice), (VOID *)&SetMap_Arg_0_choice);
        switch(SetMap_Arg_0_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(*SetMap_Arg_0), (VOID *)SetMap_Arg_0);
                break;
            case 1:
            {
                gBS->FreePool(SetMap_Arg_0);
                SetMap_Arg_0 = NULL;
                break;
            }
        }
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_GUID * GetFileDevicePathFromAnyFv_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
            EFI_SECTION_TYPE GetFileDevicePathFromAnyFv_Arg_1 = {0};
            UINTN GetFileDevicePathFromAnyFv_Arg_2 = {0};
            
            // Generator Struct Variable Initialization
            {
                UINT32 Firness_Data1;
                ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
                GetFileDevicePathFromAnyFv_Arg_0->Data1 = Firness_Data1;
            }
            {
                UINT16 Firness_Data2;
                ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
                GetFileDevicePathFromAnyFv_Arg_0->Data2 = Firness_Data2;
            }
            {
                UINT16 Firness_Data3;
                ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
                GetFileDevicePathFromAnyFv_Arg_0->Data3 = Firness_Data3;
            }
            ReadBytes(Input, sizeof(GetFileDevicePathFromAnyFv_Arg_0->Data4), (VOID *)&(GetFileDevicePathFromAnyFv_Arg_0->Data4));
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(GetFileDevicePathFromAnyFv_Arg_1), (VOID *)&GetFileDevicePathFromAnyFv_Arg_1);
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(GetFileDevicePathFromAnyFv_Arg_2), (VOID *)&GetFileDevicePathFromAnyFv_Arg_2);
            
            FirnessSanitizer(TRUE);
            Status = GetFileDevicePathFromAnyFv(
                GetFileDevicePathFromAnyFv_Arg_0,
                GetFileDevicePathFromAnyFv_Arg_1,
                GetFileDevicePathFromAnyFv_Arg_2,
                &SetMap_Arg_0
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
        {
            UINT8 Firness_Type;
            ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
            SetMap_Arg_0->Type = Firness_Type;
        }
        {
            UINT8 Firness_SubType;
            ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
            SetMap_Arg_0->SubType = Firness_SubType;
        }
        ReadBytes(Input, sizeof(SetMap_Arg_0->Length), (VOID *)&(SetMap_Arg_0->Length));
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 SetMap_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(SetMap_Arg_1_choice), (VOID *)&SetMap_Arg_1_choice);
    switch(SetMap_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*SetMap_Arg_1), (VOID *)SetMap_Arg_1);
            SetMap_Arg_1[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(SetMap_Arg_1);
            SetMap_Arg_1 = NULL;
            break;
        }
    }
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->SetMap(
        SetMap_Arg_0,
        SetMap_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetCurDir.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetCurDir(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    FirnessSanitizer(TRUE);
    ProtocolVariable->GetCurDir(
        NULL
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called SetCurDir.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetCurDir(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * SetCurDir_Arg_1 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    
    // Fuzzable Variable Initialization
    UINT8 SetCurDir_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(SetCurDir_Arg_1_choice), (VOID *)&SetCurDir_Arg_1_choice);
    switch(SetCurDir_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*SetCurDir_Arg_1), (VOID *)SetCurDir_Arg_1);
            SetCurDir_Arg_1[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(SetCurDir_Arg_1);
            SetCurDir_Arg_1 = NULL;
            break;
        }
    }
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->SetCurDir(
        NULL,
        SetCurDir_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called OpenFileList.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzOpenFileList(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * OpenFileList_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    UINT64 OpenFileList_Arg_1 = {0};
    EFI_SHELL_FILE_INFO * OpenFileList_Arg_2 = (EFI_SHELL_FILE_INFO *)AllocateZeroPool(sizeof(EFI_SHELL_FILE_INFO));
    
    // Fuzzable Variable Initialization
    UINT8 OpenFileList_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(OpenFileList_Arg_0_choice), (VOID *)&OpenFileList_Arg_0_choice);
    switch(OpenFileList_Arg_0_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*OpenFileList_Arg_0), (VOID *)OpenFileList_Arg_0);
            OpenFileList_Arg_0[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(OpenFileList_Arg_0);
            OpenFileList_Arg_0 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(OpenFileList_Arg_1), (VOID *)&OpenFileList_Arg_1);
    OpenFileList_Arg_1 = OpenFileList_Arg_1 % (4096 + 1);
    
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->OpenFileList(
        OpenFileList_Arg_0,
        OpenFileList_Arg_1,
        (EFI_SHELL_FILE_INFO * *)&OpenFileList_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called FreeFileList.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFreeFileList(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->FreeFileList(
        NULL
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called BatchIsActive.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzBatchIsActive(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    FirnessSanitizer(TRUE);
    ProtocolVariable->BatchIsActive(
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called IsRootShell.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzIsRootShell(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    FirnessSanitizer(TRUE);
    ProtocolVariable->IsRootShell(
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called EnablePageBreak.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzEnablePageBreak(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    FirnessSanitizer(TRUE);
    ProtocolVariable->EnablePageBreak(
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetDeviceName.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetDeviceName(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_SHELL_DEVICE_NAME_FLAGS GetDeviceName_Arg_1 = {0};
    CHAR8 * GetDeviceName_Arg_2 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetDeviceName_Arg_1), (VOID *)&GetDeviceName_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 GetDeviceName_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetDeviceName_Arg_2_choice), (VOID *)&GetDeviceName_Arg_2_choice);
    switch(GetDeviceName_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*GetDeviceName_Arg_2), (VOID *)GetDeviceName_Arg_2);
            GetDeviceName_Arg_2[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(GetDeviceName_Arg_2);
            GetDeviceName_Arg_2 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    CHAR16 * GetDeviceName_Arg_3 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    UINT8* GetDeviceName_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetDeviceName_Arg_3_OutputChoice), (VOID *)GetDeviceName_Arg_3_OutputChoice);
    if(*GetDeviceName_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetDeviceName_Arg_3), (VOID *)GetDeviceName_Arg_3);
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetDeviceName(
        ImageHandle,
        GetDeviceName_Arg_1,
        GetDeviceName_Arg_2,
        (CHAR16 * *)&GetDeviceName_Arg_3
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetFileInfo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetFileInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    SHELL_FILE_HANDLE GetFileInfo_Arg_0 = {0};
    
    UINT8* GetFileInfo_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetFileInfo_Arg_0_choice), (VOID *)GetFileInfo_Arg_0_choice);
    switch(*GetFileInfo_Arg_0_choice % 4) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(GetFileInfo_Arg_0), (VOID *)&GetFileInfo_Arg_0);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * ShellOpenFileByName_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            unsigned long long ShellOpenFileByName_Arg_2 = {0};
            UINT64 ShellOpenFileByName_Arg_3 = {0};
            
            // Fuzzable Variable Initialization
            UINT8 ShellOpenFileByName_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_0_choice), (VOID *)&ShellOpenFileByName_Arg_0_choice);
            switch(ShellOpenFileByName_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*ShellOpenFileByName_Arg_0), (VOID *)ShellOpenFileByName_Arg_0);
                    ShellOpenFileByName_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(ShellOpenFileByName_Arg_0);
                    ShellOpenFileByName_Arg_0 = NULL;
                    break;
                }
            }
            
            UINT8* ShellOpenFileByName_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*ShellOpenFileByName_Arg_2_choice), (VOID *)ShellOpenFileByName_Arg_2_choice);
            switch(*ShellOpenFileByName_Arg_2_choice % 7) {
                case 0:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ;
            
                    break;
                }
                case 1:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ;
            
                    break;
                }
                case 2:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ;
            
                    break;
                }
                case 3:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE;
            
                    break;
                }
                case 4:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE;
            
                    break;
                }
                case 5:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ | EFI_FILE_MODE_CREATE;
            
                    break;
                }
                case 6:
                {
                // Fuzzable Variable Initialization
                ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_2), (VOID *)&ShellOpenFileByName_Arg_2);
            
                    break;
                }
            }
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_3), (VOID *)&ShellOpenFileByName_Arg_3);
            ShellOpenFileByName_Arg_3 = ShellOpenFileByName_Arg_3 % (4096 + 1);
            
            FirnessSanitizer(TRUE);
            Status = ShellOpenFileByName(
                ShellOpenFileByName_Arg_0,
                &GetFileInfo_Arg_0,
                ShellOpenFileByName_Arg_2,
                ShellOpenFileByName_Arg_3
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
            EFI_DEVICE_PATH_PROTOCOL * EfiOpenFileByDevicePath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            if (EfiOpenFileByDevicePath_Arg_0 != NULL) {
                EfiOpenFileByDevicePath_Arg_0->Type = 0x7F;
                EfiOpenFileByDevicePath_Arg_0->SubType = 0xFF;
                EfiOpenFileByDevicePath_Arg_0->Length[0] = 4;
                EfiOpenFileByDevicePath_Arg_0->Length[1] = 0;
            }
            UINT64 EfiOpenFileByDevicePath_Arg_2 = {0};
            UINT64 EfiOpenFileByDevicePath_Arg_3 = {0};
            
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiOpenFileByDevicePath_Arg_2), (VOID *)&EfiOpenFileByDevicePath_Arg_2);
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiOpenFileByDevicePath_Arg_3), (VOID *)&EfiOpenFileByDevicePath_Arg_3);
            
            /*
                Output Variable(s)
            */
            EFI_FILE_PROTOCOL * EfiOpenFileByDevicePath_Arg_1 = (EFI_FILE_PROTOCOL *)AllocateZeroPool(sizeof(EFI_FILE_PROTOCOL));
            UINT8* EfiOpenFileByDevicePath_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*EfiOpenFileByDevicePath_Arg_1_OutputChoice), (VOID *)EfiOpenFileByDevicePath_Arg_1_OutputChoice);
            if(*EfiOpenFileByDevicePath_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*EfiOpenFileByDevicePath_Arg_1), (VOID *)EfiOpenFileByDevicePath_Arg_1);
            }
            FirnessSanitizer(TRUE);
            Status = EfiOpenFileByDevicePath(
                (EFI_DEVICE_PATH_PROTOCOL **)&EfiOpenFileByDevicePath_Arg_0,
                (EFI_FILE_PROTOCOL **)&EfiOpenFileByDevicePath_Arg_1,
                EfiOpenFileByDevicePath_Arg_2,
                EfiOpenFileByDevicePath_Arg_3
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
            CHAR16 * ShellCreateDirectory_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 ShellCreateDirectory_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(ShellCreateDirectory_Arg_0_choice), (VOID *)&ShellCreateDirectory_Arg_0_choice);
            switch(ShellCreateDirectory_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*ShellCreateDirectory_Arg_0), (VOID *)ShellCreateDirectory_Arg_0);
                    ShellCreateDirectory_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(ShellCreateDirectory_Arg_0);
                    ShellCreateDirectory_Arg_0 = NULL;
                    break;
                }
            }
            
            FirnessSanitizer(TRUE);
            Status = ShellCreateDirectory(
                ShellCreateDirectory_Arg_0,
                &GetFileInfo_Arg_0
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
    }
    FirnessSanitizer(TRUE);
    ProtocolVariable->GetFileInfo(
        GetFileInfo_Arg_0
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called SetFileInfo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetFileInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    SHELL_FILE_HANDLE SetFileInfo_Arg_0 = {0};
    EFI_FILE_INFO * SetFileInfo_Arg_1 = (EFI_FILE_INFO *)AllocateZeroPool(sizeof(EFI_FILE_INFO));
    
    UINT8* SetFileInfo_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*SetFileInfo_Arg_0_choice), (VOID *)SetFileInfo_Arg_0_choice);
    switch(*SetFileInfo_Arg_0_choice % 4) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(SetFileInfo_Arg_0), (VOID *)&SetFileInfo_Arg_0);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * ShellOpenFileByName_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            unsigned long long ShellOpenFileByName_Arg_2 = {0};
            UINT64 ShellOpenFileByName_Arg_3 = {0};
            
            // Fuzzable Variable Initialization
            UINT8 ShellOpenFileByName_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_0_choice), (VOID *)&ShellOpenFileByName_Arg_0_choice);
            switch(ShellOpenFileByName_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*ShellOpenFileByName_Arg_0), (VOID *)ShellOpenFileByName_Arg_0);
                    ShellOpenFileByName_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(ShellOpenFileByName_Arg_0);
                    ShellOpenFileByName_Arg_0 = NULL;
                    break;
                }
            }
            
            UINT8* ShellOpenFileByName_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*ShellOpenFileByName_Arg_2_choice), (VOID *)ShellOpenFileByName_Arg_2_choice);
            switch(*ShellOpenFileByName_Arg_2_choice % 7) {
                case 0:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ;
            
                    break;
                }
                case 1:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ;
            
                    break;
                }
                case 2:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ;
            
                    break;
                }
                case 3:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE;
            
                    break;
                }
                case 4:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE;
            
                    break;
                }
                case 5:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ | EFI_FILE_MODE_CREATE;
            
                    break;
                }
                case 6:
                {
                // Fuzzable Variable Initialization
                ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_2), (VOID *)&ShellOpenFileByName_Arg_2);
            
                    break;
                }
            }
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_3), (VOID *)&ShellOpenFileByName_Arg_3);
            ShellOpenFileByName_Arg_3 = ShellOpenFileByName_Arg_3 % (4096 + 1);
            
            FirnessSanitizer(TRUE);
            Status = ShellOpenFileByName(
                ShellOpenFileByName_Arg_0,
                &SetFileInfo_Arg_0,
                ShellOpenFileByName_Arg_2,
                ShellOpenFileByName_Arg_3
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
            EFI_DEVICE_PATH_PROTOCOL * EfiOpenFileByDevicePath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            if (EfiOpenFileByDevicePath_Arg_0 != NULL) {
                EfiOpenFileByDevicePath_Arg_0->Type = 0x7F;
                EfiOpenFileByDevicePath_Arg_0->SubType = 0xFF;
                EfiOpenFileByDevicePath_Arg_0->Length[0] = 4;
                EfiOpenFileByDevicePath_Arg_0->Length[1] = 0;
            }
            UINT64 EfiOpenFileByDevicePath_Arg_2 = {0};
            UINT64 EfiOpenFileByDevicePath_Arg_3 = {0};
            
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiOpenFileByDevicePath_Arg_2), (VOID *)&EfiOpenFileByDevicePath_Arg_2);
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiOpenFileByDevicePath_Arg_3), (VOID *)&EfiOpenFileByDevicePath_Arg_3);
            
            /*
                Output Variable(s)
            */
            EFI_FILE_PROTOCOL * EfiOpenFileByDevicePath_Arg_1 = (EFI_FILE_PROTOCOL *)AllocateZeroPool(sizeof(EFI_FILE_PROTOCOL));
            UINT8* EfiOpenFileByDevicePath_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*EfiOpenFileByDevicePath_Arg_1_OutputChoice), (VOID *)EfiOpenFileByDevicePath_Arg_1_OutputChoice);
            if(*EfiOpenFileByDevicePath_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*EfiOpenFileByDevicePath_Arg_1), (VOID *)EfiOpenFileByDevicePath_Arg_1);
            }
            FirnessSanitizer(TRUE);
            Status = EfiOpenFileByDevicePath(
                (EFI_DEVICE_PATH_PROTOCOL **)&EfiOpenFileByDevicePath_Arg_0,
                (EFI_FILE_PROTOCOL **)&EfiOpenFileByDevicePath_Arg_1,
                EfiOpenFileByDevicePath_Arg_2,
                EfiOpenFileByDevicePath_Arg_3
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
            CHAR16 * ShellCreateDirectory_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 ShellCreateDirectory_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(ShellCreateDirectory_Arg_0_choice), (VOID *)&ShellCreateDirectory_Arg_0_choice);
            switch(ShellCreateDirectory_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*ShellCreateDirectory_Arg_0), (VOID *)ShellCreateDirectory_Arg_0);
                    ShellCreateDirectory_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(ShellCreateDirectory_Arg_0);
                    ShellCreateDirectory_Arg_0 = NULL;
                    break;
                }
            }
            
            FirnessSanitizer(TRUE);
            Status = ShellCreateDirectory(
                ShellCreateDirectory_Arg_0,
                &SetFileInfo_Arg_0
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
    }
    UINT8* SetFileInfo_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*SetFileInfo_Arg_1_choice), (VOID *)SetFileInfo_Arg_1_choice);
    switch(*SetFileInfo_Arg_1_choice % 3) {
        case 0:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            Status = FileHandleFindFirstFile(
                (EFI_FILE_HANDLE){0},
                &SetFileInfo_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Output Variable(s)
            */
            BOOLEAN * FileHandleFindNextFile_Arg_2 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
            UINT8* FileHandleFindNextFile_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*FileHandleFindNextFile_Arg_2_OutputChoice), (VOID *)FileHandleFindNextFile_Arg_2_OutputChoice);
            if(*FileHandleFindNextFile_Arg_2_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*FileHandleFindNextFile_Arg_2), (VOID *)FileHandleFindNextFile_Arg_2);
            }
            FirnessSanitizer(TRUE);
            Status = FileHandleFindNextFile(
                (EFI_FILE_HANDLE){0},
                SetFileInfo_Arg_1,
                FileHandleFindNextFile_Arg_2
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
        {
            UINT64 Firness_Size;
            ReadBytes(Input, sizeof(Firness_Size), (VOID *)&Firness_Size);
            SetFileInfo_Arg_1->Size = Firness_Size;
        }
        {
            UINT64 Firness_FileSize;
            ReadBytes(Input, sizeof(Firness_FileSize), (VOID *)&Firness_FileSize);
            SetFileInfo_Arg_1->FileSize = Firness_FileSize;
        }
        {
            UINT64 Firness_PhysicalSize;
            ReadBytes(Input, sizeof(Firness_PhysicalSize), (VOID *)&Firness_PhysicalSize);
            SetFileInfo_Arg_1->PhysicalSize = Firness_PhysicalSize;
        }
        ReadBytes(Input, sizeof(SetFileInfo_Arg_1->CreateTime), (VOID *)&(SetFileInfo_Arg_1->CreateTime));
        ReadBytes(Input, sizeof(SetFileInfo_Arg_1->LastAccessTime), (VOID *)&(SetFileInfo_Arg_1->LastAccessTime));
        ReadBytes(Input, sizeof(SetFileInfo_Arg_1->ModificationTime), (VOID *)&(SetFileInfo_Arg_1->ModificationTime));
        {
            UINT64 Firness_Attribute;
            ReadBytes(Input, sizeof(Firness_Attribute), (VOID *)&Firness_Attribute);
            SetFileInfo_Arg_1->Attribute = Firness_Attribute;
        }
        ReadBytes(Input, sizeof(SetFileInfo_Arg_1->FileName), (VOID *)&(SetFileInfo_Arg_1->FileName));
    
            break;
        }
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->SetFileInfo(
        SetFileInfo_Arg_0,
        SetFileInfo_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called OpenFileByName.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzOpenFileByName(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * OpenFileByName_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    UINT64 OpenFileByName_Arg_2 = {0};
    
    // Fuzzable Variable Initialization
    UINT8 OpenFileByName_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(OpenFileByName_Arg_0_choice), (VOID *)&OpenFileByName_Arg_0_choice);
    switch(OpenFileByName_Arg_0_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*OpenFileByName_Arg_0), (VOID *)OpenFileByName_Arg_0);
            OpenFileByName_Arg_0[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(OpenFileByName_Arg_0);
            OpenFileByName_Arg_0 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(OpenFileByName_Arg_2), (VOID *)&OpenFileByName_Arg_2);
    OpenFileByName_Arg_2 = OpenFileByName_Arg_2 % (4096 + 1);
    
    /*
        Output Variable(s)
    */
    SHELL_FILE_HANDLE * OpenFileByName_Arg_1 = (SHELL_FILE_HANDLE *)AllocateZeroPool(sizeof(SHELL_FILE_HANDLE));
    UINT8* OpenFileByName_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*OpenFileByName_Arg_1_OutputChoice), (VOID *)OpenFileByName_Arg_1_OutputChoice);
    if(*OpenFileByName_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*OpenFileByName_Arg_1), (VOID *)OpenFileByName_Arg_1);
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->OpenFileByName(
        OpenFileByName_Arg_0,
        OpenFileByName_Arg_1,
        OpenFileByName_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called CloseFile.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzCloseFile(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    SHELL_FILE_HANDLE CloseFile_Arg_0 = {0};
    
    UINT8* CloseFile_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*CloseFile_Arg_0_choice), (VOID *)CloseFile_Arg_0_choice);
    switch(*CloseFile_Arg_0_choice % 4) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(CloseFile_Arg_0), (VOID *)&CloseFile_Arg_0);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * ShellOpenFileByName_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            unsigned long long ShellOpenFileByName_Arg_2 = {0};
            UINT64 ShellOpenFileByName_Arg_3 = {0};
            
            // Fuzzable Variable Initialization
            UINT8 ShellOpenFileByName_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_0_choice), (VOID *)&ShellOpenFileByName_Arg_0_choice);
            switch(ShellOpenFileByName_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*ShellOpenFileByName_Arg_0), (VOID *)ShellOpenFileByName_Arg_0);
                    ShellOpenFileByName_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(ShellOpenFileByName_Arg_0);
                    ShellOpenFileByName_Arg_0 = NULL;
                    break;
                }
            }
            
            UINT8* ShellOpenFileByName_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*ShellOpenFileByName_Arg_2_choice), (VOID *)ShellOpenFileByName_Arg_2_choice);
            switch(*ShellOpenFileByName_Arg_2_choice % 7) {
                case 0:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ;
            
                    break;
                }
                case 1:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ;
            
                    break;
                }
                case 2:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ;
            
                    break;
                }
                case 3:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE;
            
                    break;
                }
                case 4:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE;
            
                    break;
                }
                case 5:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ | EFI_FILE_MODE_CREATE;
            
                    break;
                }
                case 6:
                {
                // Fuzzable Variable Initialization
                ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_2), (VOID *)&ShellOpenFileByName_Arg_2);
            
                    break;
                }
            }
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_3), (VOID *)&ShellOpenFileByName_Arg_3);
            ShellOpenFileByName_Arg_3 = ShellOpenFileByName_Arg_3 % (4096 + 1);
            
            FirnessSanitizer(TRUE);
            Status = ShellOpenFileByName(
                ShellOpenFileByName_Arg_0,
                &CloseFile_Arg_0,
                ShellOpenFileByName_Arg_2,
                ShellOpenFileByName_Arg_3
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
            EFI_DEVICE_PATH_PROTOCOL * EfiOpenFileByDevicePath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            if (EfiOpenFileByDevicePath_Arg_0 != NULL) {
                EfiOpenFileByDevicePath_Arg_0->Type = 0x7F;
                EfiOpenFileByDevicePath_Arg_0->SubType = 0xFF;
                EfiOpenFileByDevicePath_Arg_0->Length[0] = 4;
                EfiOpenFileByDevicePath_Arg_0->Length[1] = 0;
            }
            UINT64 EfiOpenFileByDevicePath_Arg_2 = {0};
            UINT64 EfiOpenFileByDevicePath_Arg_3 = {0};
            
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiOpenFileByDevicePath_Arg_2), (VOID *)&EfiOpenFileByDevicePath_Arg_2);
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiOpenFileByDevicePath_Arg_3), (VOID *)&EfiOpenFileByDevicePath_Arg_3);
            
            /*
                Output Variable(s)
            */
            EFI_FILE_PROTOCOL * EfiOpenFileByDevicePath_Arg_1 = (EFI_FILE_PROTOCOL *)AllocateZeroPool(sizeof(EFI_FILE_PROTOCOL));
            UINT8* EfiOpenFileByDevicePath_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*EfiOpenFileByDevicePath_Arg_1_OutputChoice), (VOID *)EfiOpenFileByDevicePath_Arg_1_OutputChoice);
            if(*EfiOpenFileByDevicePath_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*EfiOpenFileByDevicePath_Arg_1), (VOID *)EfiOpenFileByDevicePath_Arg_1);
            }
            FirnessSanitizer(TRUE);
            Status = EfiOpenFileByDevicePath(
                (EFI_DEVICE_PATH_PROTOCOL **)&EfiOpenFileByDevicePath_Arg_0,
                (EFI_FILE_PROTOCOL **)&EfiOpenFileByDevicePath_Arg_1,
                EfiOpenFileByDevicePath_Arg_2,
                EfiOpenFileByDevicePath_Arg_3
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
            CHAR16 * ShellCreateDirectory_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 ShellCreateDirectory_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(ShellCreateDirectory_Arg_0_choice), (VOID *)&ShellCreateDirectory_Arg_0_choice);
            switch(ShellCreateDirectory_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*ShellCreateDirectory_Arg_0), (VOID *)ShellCreateDirectory_Arg_0);
                    ShellCreateDirectory_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(ShellCreateDirectory_Arg_0);
                    ShellCreateDirectory_Arg_0 = NULL;
                    break;
                }
            }
            
            FirnessSanitizer(TRUE);
            Status = ShellCreateDirectory(
                ShellCreateDirectory_Arg_0,
                &CloseFile_Arg_0
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->CloseFile(
        CloseFile_Arg_0
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called CreateFile.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzCreateFile(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * CreateFile_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    UINT64 CreateFile_Arg_1 = {0};
    
    // Fuzzable Variable Initialization
    UINT8 CreateFile_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(CreateFile_Arg_0_choice), (VOID *)&CreateFile_Arg_0_choice);
    switch(CreateFile_Arg_0_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*CreateFile_Arg_0), (VOID *)CreateFile_Arg_0);
            CreateFile_Arg_0[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(CreateFile_Arg_0);
            CreateFile_Arg_0 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(CreateFile_Arg_1), (VOID *)&CreateFile_Arg_1);
    CreateFile_Arg_1 = CreateFile_Arg_1 % (4096 + 1);
    
    /*
        Output Variable(s)
    */
    SHELL_FILE_HANDLE * CreateFile_Arg_2 = (SHELL_FILE_HANDLE *)AllocateZeroPool(sizeof(SHELL_FILE_HANDLE));
    UINT8* CreateFile_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*CreateFile_Arg_2_OutputChoice), (VOID *)CreateFile_Arg_2_OutputChoice);
    if(*CreateFile_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*CreateFile_Arg_2), (VOID *)CreateFile_Arg_2);
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->CreateFile(
        CreateFile_Arg_0,
        CreateFile_Arg_1,
        CreateFile_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called ReadFile.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzReadFile(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    SHELL_FILE_HANDLE ReadFile_Arg_0 = {0};
    UINTN * ReadFile_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN*  ReadFile_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    UINT8* ReadFile_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*ReadFile_Arg_0_choice), (VOID *)ReadFile_Arg_0_choice);
    switch(*ReadFile_Arg_0_choice % 4) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(ReadFile_Arg_0), (VOID *)&ReadFile_Arg_0);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * ShellOpenFileByName_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            unsigned long long ShellOpenFileByName_Arg_2 = {0};
            UINT64 ShellOpenFileByName_Arg_3 = {0};
            
            // Fuzzable Variable Initialization
            UINT8 ShellOpenFileByName_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_0_choice), (VOID *)&ShellOpenFileByName_Arg_0_choice);
            switch(ShellOpenFileByName_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*ShellOpenFileByName_Arg_0), (VOID *)ShellOpenFileByName_Arg_0);
                    ShellOpenFileByName_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(ShellOpenFileByName_Arg_0);
                    ShellOpenFileByName_Arg_0 = NULL;
                    break;
                }
            }
            
            UINT8* ShellOpenFileByName_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*ShellOpenFileByName_Arg_2_choice), (VOID *)ShellOpenFileByName_Arg_2_choice);
            switch(*ShellOpenFileByName_Arg_2_choice % 7) {
                case 0:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ;
            
                    break;
                }
                case 1:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ;
            
                    break;
                }
                case 2:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ;
            
                    break;
                }
                case 3:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE;
            
                    break;
                }
                case 4:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE;
            
                    break;
                }
                case 5:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ | EFI_FILE_MODE_CREATE;
            
                    break;
                }
                case 6:
                {
                // Fuzzable Variable Initialization
                ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_2), (VOID *)&ShellOpenFileByName_Arg_2);
            
                    break;
                }
            }
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_3), (VOID *)&ShellOpenFileByName_Arg_3);
            ShellOpenFileByName_Arg_3 = ShellOpenFileByName_Arg_3 % (4096 + 1);
            
            FirnessSanitizer(TRUE);
            Status = ShellOpenFileByName(
                ShellOpenFileByName_Arg_0,
                &ReadFile_Arg_0,
                ShellOpenFileByName_Arg_2,
                ShellOpenFileByName_Arg_3
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
            EFI_DEVICE_PATH_PROTOCOL * EfiOpenFileByDevicePath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            if (EfiOpenFileByDevicePath_Arg_0 != NULL) {
                EfiOpenFileByDevicePath_Arg_0->Type = 0x7F;
                EfiOpenFileByDevicePath_Arg_0->SubType = 0xFF;
                EfiOpenFileByDevicePath_Arg_0->Length[0] = 4;
                EfiOpenFileByDevicePath_Arg_0->Length[1] = 0;
            }
            UINT64 EfiOpenFileByDevicePath_Arg_2 = {0};
            UINT64 EfiOpenFileByDevicePath_Arg_3 = {0};
            
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiOpenFileByDevicePath_Arg_2), (VOID *)&EfiOpenFileByDevicePath_Arg_2);
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiOpenFileByDevicePath_Arg_3), (VOID *)&EfiOpenFileByDevicePath_Arg_3);
            
            /*
                Output Variable(s)
            */
            EFI_FILE_PROTOCOL * EfiOpenFileByDevicePath_Arg_1 = (EFI_FILE_PROTOCOL *)AllocateZeroPool(sizeof(EFI_FILE_PROTOCOL));
            UINT8* EfiOpenFileByDevicePath_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*EfiOpenFileByDevicePath_Arg_1_OutputChoice), (VOID *)EfiOpenFileByDevicePath_Arg_1_OutputChoice);
            if(*EfiOpenFileByDevicePath_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*EfiOpenFileByDevicePath_Arg_1), (VOID *)EfiOpenFileByDevicePath_Arg_1);
            }
            FirnessSanitizer(TRUE);
            Status = EfiOpenFileByDevicePath(
                (EFI_DEVICE_PATH_PROTOCOL **)&EfiOpenFileByDevicePath_Arg_0,
                (EFI_FILE_PROTOCOL **)&EfiOpenFileByDevicePath_Arg_1,
                EfiOpenFileByDevicePath_Arg_2,
                EfiOpenFileByDevicePath_Arg_3
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
            CHAR16 * ShellCreateDirectory_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 ShellCreateDirectory_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(ShellCreateDirectory_Arg_0_choice), (VOID *)&ShellCreateDirectory_Arg_0_choice);
            switch(ShellCreateDirectory_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*ShellCreateDirectory_Arg_0), (VOID *)ShellCreateDirectory_Arg_0);
                    ShellCreateDirectory_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(ShellCreateDirectory_Arg_0);
                    ShellCreateDirectory_Arg_0 = NULL;
                    break;
                }
            }
            
            FirnessSanitizer(TRUE);
            Status = ShellCreateDirectory(
                ShellCreateDirectory_Arg_0,
                &ReadFile_Arg_0
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 ReadFile_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(ReadFile_Arg_1_choice), (VOID *)&ReadFile_Arg_1_choice);
    switch(ReadFile_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(*ReadFile_Arg_1), (VOID *)ReadFile_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(ReadFile_Arg_1);
            ReadFile_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 ReadFile_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(ReadFile_Arg_2_choice), (VOID *)&ReadFile_Arg_2_choice);
    switch(ReadFile_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(*ReadFile_Arg_2), (VOID *)ReadFile_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(ReadFile_Arg_2);
            ReadFile_Arg_2 = NULL;
            break;
        }
    }
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->ReadFile(
        ReadFile_Arg_0,
        ReadFile_Arg_1,
        (VOID *)ReadFile_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called WriteFile.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzWriteFile(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    SHELL_FILE_HANDLE WriteFile_Arg_0 = {0};
    UINTN * WriteFile_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINTN*  WriteFile_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    UINT8* WriteFile_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*WriteFile_Arg_0_choice), (VOID *)WriteFile_Arg_0_choice);
    switch(*WriteFile_Arg_0_choice % 4) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(WriteFile_Arg_0), (VOID *)&WriteFile_Arg_0);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * ShellOpenFileByName_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            unsigned long long ShellOpenFileByName_Arg_2 = {0};
            UINT64 ShellOpenFileByName_Arg_3 = {0};
            
            // Fuzzable Variable Initialization
            UINT8 ShellOpenFileByName_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_0_choice), (VOID *)&ShellOpenFileByName_Arg_0_choice);
            switch(ShellOpenFileByName_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*ShellOpenFileByName_Arg_0), (VOID *)ShellOpenFileByName_Arg_0);
                    ShellOpenFileByName_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(ShellOpenFileByName_Arg_0);
                    ShellOpenFileByName_Arg_0 = NULL;
                    break;
                }
            }
            
            UINT8* ShellOpenFileByName_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*ShellOpenFileByName_Arg_2_choice), (VOID *)ShellOpenFileByName_Arg_2_choice);
            switch(*ShellOpenFileByName_Arg_2_choice % 7) {
                case 0:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ;
            
                    break;
                }
                case 1:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ;
            
                    break;
                }
                case 2:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ;
            
                    break;
                }
                case 3:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE;
            
                    break;
                }
                case 4:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE;
            
                    break;
                }
                case 5:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ | EFI_FILE_MODE_CREATE;
            
                    break;
                }
                case 6:
                {
                // Fuzzable Variable Initialization
                ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_2), (VOID *)&ShellOpenFileByName_Arg_2);
            
                    break;
                }
            }
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_3), (VOID *)&ShellOpenFileByName_Arg_3);
            ShellOpenFileByName_Arg_3 = ShellOpenFileByName_Arg_3 % (4096 + 1);
            
            FirnessSanitizer(TRUE);
            Status = ShellOpenFileByName(
                ShellOpenFileByName_Arg_0,
                &WriteFile_Arg_0,
                ShellOpenFileByName_Arg_2,
                ShellOpenFileByName_Arg_3
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
            EFI_DEVICE_PATH_PROTOCOL * EfiOpenFileByDevicePath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            if (EfiOpenFileByDevicePath_Arg_0 != NULL) {
                EfiOpenFileByDevicePath_Arg_0->Type = 0x7F;
                EfiOpenFileByDevicePath_Arg_0->SubType = 0xFF;
                EfiOpenFileByDevicePath_Arg_0->Length[0] = 4;
                EfiOpenFileByDevicePath_Arg_0->Length[1] = 0;
            }
            UINT64 EfiOpenFileByDevicePath_Arg_2 = {0};
            UINT64 EfiOpenFileByDevicePath_Arg_3 = {0};
            
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiOpenFileByDevicePath_Arg_2), (VOID *)&EfiOpenFileByDevicePath_Arg_2);
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiOpenFileByDevicePath_Arg_3), (VOID *)&EfiOpenFileByDevicePath_Arg_3);
            
            /*
                Output Variable(s)
            */
            EFI_FILE_PROTOCOL * EfiOpenFileByDevicePath_Arg_1 = (EFI_FILE_PROTOCOL *)AllocateZeroPool(sizeof(EFI_FILE_PROTOCOL));
            UINT8* EfiOpenFileByDevicePath_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*EfiOpenFileByDevicePath_Arg_1_OutputChoice), (VOID *)EfiOpenFileByDevicePath_Arg_1_OutputChoice);
            if(*EfiOpenFileByDevicePath_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*EfiOpenFileByDevicePath_Arg_1), (VOID *)EfiOpenFileByDevicePath_Arg_1);
            }
            FirnessSanitizer(TRUE);
            Status = EfiOpenFileByDevicePath(
                (EFI_DEVICE_PATH_PROTOCOL **)&EfiOpenFileByDevicePath_Arg_0,
                (EFI_FILE_PROTOCOL **)&EfiOpenFileByDevicePath_Arg_1,
                EfiOpenFileByDevicePath_Arg_2,
                EfiOpenFileByDevicePath_Arg_3
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
            CHAR16 * ShellCreateDirectory_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 ShellCreateDirectory_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(ShellCreateDirectory_Arg_0_choice), (VOID *)&ShellCreateDirectory_Arg_0_choice);
            switch(ShellCreateDirectory_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*ShellCreateDirectory_Arg_0), (VOID *)ShellCreateDirectory_Arg_0);
                    ShellCreateDirectory_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(ShellCreateDirectory_Arg_0);
                    ShellCreateDirectory_Arg_0 = NULL;
                    break;
                }
            }
            
            FirnessSanitizer(TRUE);
            Status = ShellCreateDirectory(
                ShellCreateDirectory_Arg_0,
                &WriteFile_Arg_0
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 WriteFile_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(WriteFile_Arg_1_choice), (VOID *)&WriteFile_Arg_1_choice);
    switch(WriteFile_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(*WriteFile_Arg_1), (VOID *)WriteFile_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(WriteFile_Arg_1);
            WriteFile_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 WriteFile_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(WriteFile_Arg_2_choice), (VOID *)&WriteFile_Arg_2_choice);
    switch(WriteFile_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(*WriteFile_Arg_2), (VOID *)WriteFile_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(WriteFile_Arg_2);
            WriteFile_Arg_2 = NULL;
            break;
        }
    }
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->WriteFile(
        WriteFile_Arg_0,
        WriteFile_Arg_1,
        (VOID *)WriteFile_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called DeleteFile.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDeleteFile(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    SHELL_FILE_HANDLE DeleteFile_Arg_0 = {0};
    
    UINT8* DeleteFile_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*DeleteFile_Arg_0_choice), (VOID *)DeleteFile_Arg_0_choice);
    switch(*DeleteFile_Arg_0_choice % 4) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(DeleteFile_Arg_0), (VOID *)&DeleteFile_Arg_0);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * ShellOpenFileByName_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            unsigned long long ShellOpenFileByName_Arg_2 = {0};
            UINT64 ShellOpenFileByName_Arg_3 = {0};
            
            // Fuzzable Variable Initialization
            UINT8 ShellOpenFileByName_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_0_choice), (VOID *)&ShellOpenFileByName_Arg_0_choice);
            switch(ShellOpenFileByName_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*ShellOpenFileByName_Arg_0), (VOID *)ShellOpenFileByName_Arg_0);
                    ShellOpenFileByName_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(ShellOpenFileByName_Arg_0);
                    ShellOpenFileByName_Arg_0 = NULL;
                    break;
                }
            }
            
            UINT8* ShellOpenFileByName_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*ShellOpenFileByName_Arg_2_choice), (VOID *)ShellOpenFileByName_Arg_2_choice);
            switch(*ShellOpenFileByName_Arg_2_choice % 7) {
                case 0:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ;
            
                    break;
                }
                case 1:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ;
            
                    break;
                }
                case 2:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ;
            
                    break;
                }
                case 3:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE;
            
                    break;
                }
                case 4:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE;
            
                    break;
                }
                case 5:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ | EFI_FILE_MODE_CREATE;
            
                    break;
                }
                case 6:
                {
                // Fuzzable Variable Initialization
                ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_2), (VOID *)&ShellOpenFileByName_Arg_2);
            
                    break;
                }
            }
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_3), (VOID *)&ShellOpenFileByName_Arg_3);
            ShellOpenFileByName_Arg_3 = ShellOpenFileByName_Arg_3 % (4096 + 1);
            
            FirnessSanitizer(TRUE);
            Status = ShellOpenFileByName(
                ShellOpenFileByName_Arg_0,
                &DeleteFile_Arg_0,
                ShellOpenFileByName_Arg_2,
                ShellOpenFileByName_Arg_3
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
            EFI_DEVICE_PATH_PROTOCOL * EfiOpenFileByDevicePath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            if (EfiOpenFileByDevicePath_Arg_0 != NULL) {
                EfiOpenFileByDevicePath_Arg_0->Type = 0x7F;
                EfiOpenFileByDevicePath_Arg_0->SubType = 0xFF;
                EfiOpenFileByDevicePath_Arg_0->Length[0] = 4;
                EfiOpenFileByDevicePath_Arg_0->Length[1] = 0;
            }
            UINT64 EfiOpenFileByDevicePath_Arg_2 = {0};
            UINT64 EfiOpenFileByDevicePath_Arg_3 = {0};
            
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiOpenFileByDevicePath_Arg_2), (VOID *)&EfiOpenFileByDevicePath_Arg_2);
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiOpenFileByDevicePath_Arg_3), (VOID *)&EfiOpenFileByDevicePath_Arg_3);
            
            /*
                Output Variable(s)
            */
            EFI_FILE_PROTOCOL * EfiOpenFileByDevicePath_Arg_1 = (EFI_FILE_PROTOCOL *)AllocateZeroPool(sizeof(EFI_FILE_PROTOCOL));
            UINT8* EfiOpenFileByDevicePath_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*EfiOpenFileByDevicePath_Arg_1_OutputChoice), (VOID *)EfiOpenFileByDevicePath_Arg_1_OutputChoice);
            if(*EfiOpenFileByDevicePath_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*EfiOpenFileByDevicePath_Arg_1), (VOID *)EfiOpenFileByDevicePath_Arg_1);
            }
            FirnessSanitizer(TRUE);
            Status = EfiOpenFileByDevicePath(
                (EFI_DEVICE_PATH_PROTOCOL **)&EfiOpenFileByDevicePath_Arg_0,
                (EFI_FILE_PROTOCOL **)&EfiOpenFileByDevicePath_Arg_1,
                EfiOpenFileByDevicePath_Arg_2,
                EfiOpenFileByDevicePath_Arg_3
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
            CHAR16 * ShellCreateDirectory_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 ShellCreateDirectory_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(ShellCreateDirectory_Arg_0_choice), (VOID *)&ShellCreateDirectory_Arg_0_choice);
            switch(ShellCreateDirectory_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*ShellCreateDirectory_Arg_0), (VOID *)ShellCreateDirectory_Arg_0);
                    ShellCreateDirectory_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(ShellCreateDirectory_Arg_0);
                    ShellCreateDirectory_Arg_0 = NULL;
                    break;
                }
            }
            
            FirnessSanitizer(TRUE);
            Status = ShellCreateDirectory(
                ShellCreateDirectory_Arg_0,
                &DeleteFile_Arg_0
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->DeleteFile(
        DeleteFile_Arg_0
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called DeleteFileByName.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDeleteFileByName(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * DeleteFileByName_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    
    // Fuzzable Variable Initialization
    UINT8 DeleteFileByName_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(DeleteFileByName_Arg_0_choice), (VOID *)&DeleteFileByName_Arg_0_choice);
    switch(DeleteFileByName_Arg_0_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*DeleteFileByName_Arg_0), (VOID *)DeleteFileByName_Arg_0);
            DeleteFileByName_Arg_0[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(DeleteFileByName_Arg_0);
            DeleteFileByName_Arg_0 = NULL;
            break;
        }
    }
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->DeleteFileByName(
        DeleteFileByName_Arg_0
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetFilePosition.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetFilePosition(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    SHELL_FILE_HANDLE GetFilePosition_Arg_0 = {0};
    
    UINT8* GetFilePosition_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetFilePosition_Arg_0_choice), (VOID *)GetFilePosition_Arg_0_choice);
    switch(*GetFilePosition_Arg_0_choice % 4) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(GetFilePosition_Arg_0), (VOID *)&GetFilePosition_Arg_0);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * ShellOpenFileByName_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            unsigned long long ShellOpenFileByName_Arg_2 = {0};
            UINT64 ShellOpenFileByName_Arg_3 = {0};
            
            // Fuzzable Variable Initialization
            UINT8 ShellOpenFileByName_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_0_choice), (VOID *)&ShellOpenFileByName_Arg_0_choice);
            switch(ShellOpenFileByName_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*ShellOpenFileByName_Arg_0), (VOID *)ShellOpenFileByName_Arg_0);
                    ShellOpenFileByName_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(ShellOpenFileByName_Arg_0);
                    ShellOpenFileByName_Arg_0 = NULL;
                    break;
                }
            }
            
            UINT8* ShellOpenFileByName_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*ShellOpenFileByName_Arg_2_choice), (VOID *)ShellOpenFileByName_Arg_2_choice);
            switch(*ShellOpenFileByName_Arg_2_choice % 7) {
                case 0:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ;
            
                    break;
                }
                case 1:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ;
            
                    break;
                }
                case 2:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ;
            
                    break;
                }
                case 3:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE;
            
                    break;
                }
                case 4:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE;
            
                    break;
                }
                case 5:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ | EFI_FILE_MODE_CREATE;
            
                    break;
                }
                case 6:
                {
                // Fuzzable Variable Initialization
                ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_2), (VOID *)&ShellOpenFileByName_Arg_2);
            
                    break;
                }
            }
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_3), (VOID *)&ShellOpenFileByName_Arg_3);
            ShellOpenFileByName_Arg_3 = ShellOpenFileByName_Arg_3 % (4096 + 1);
            
            FirnessSanitizer(TRUE);
            Status = ShellOpenFileByName(
                ShellOpenFileByName_Arg_0,
                &GetFilePosition_Arg_0,
                ShellOpenFileByName_Arg_2,
                ShellOpenFileByName_Arg_3
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
            EFI_DEVICE_PATH_PROTOCOL * EfiOpenFileByDevicePath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            if (EfiOpenFileByDevicePath_Arg_0 != NULL) {
                EfiOpenFileByDevicePath_Arg_0->Type = 0x7F;
                EfiOpenFileByDevicePath_Arg_0->SubType = 0xFF;
                EfiOpenFileByDevicePath_Arg_0->Length[0] = 4;
                EfiOpenFileByDevicePath_Arg_0->Length[1] = 0;
            }
            UINT64 EfiOpenFileByDevicePath_Arg_2 = {0};
            UINT64 EfiOpenFileByDevicePath_Arg_3 = {0};
            
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiOpenFileByDevicePath_Arg_2), (VOID *)&EfiOpenFileByDevicePath_Arg_2);
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiOpenFileByDevicePath_Arg_3), (VOID *)&EfiOpenFileByDevicePath_Arg_3);
            
            /*
                Output Variable(s)
            */
            EFI_FILE_PROTOCOL * EfiOpenFileByDevicePath_Arg_1 = (EFI_FILE_PROTOCOL *)AllocateZeroPool(sizeof(EFI_FILE_PROTOCOL));
            UINT8* EfiOpenFileByDevicePath_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*EfiOpenFileByDevicePath_Arg_1_OutputChoice), (VOID *)EfiOpenFileByDevicePath_Arg_1_OutputChoice);
            if(*EfiOpenFileByDevicePath_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*EfiOpenFileByDevicePath_Arg_1), (VOID *)EfiOpenFileByDevicePath_Arg_1);
            }
            FirnessSanitizer(TRUE);
            Status = EfiOpenFileByDevicePath(
                (EFI_DEVICE_PATH_PROTOCOL **)&EfiOpenFileByDevicePath_Arg_0,
                (EFI_FILE_PROTOCOL **)&EfiOpenFileByDevicePath_Arg_1,
                EfiOpenFileByDevicePath_Arg_2,
                EfiOpenFileByDevicePath_Arg_3
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
            CHAR16 * ShellCreateDirectory_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 ShellCreateDirectory_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(ShellCreateDirectory_Arg_0_choice), (VOID *)&ShellCreateDirectory_Arg_0_choice);
            switch(ShellCreateDirectory_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*ShellCreateDirectory_Arg_0), (VOID *)ShellCreateDirectory_Arg_0);
                    ShellCreateDirectory_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(ShellCreateDirectory_Arg_0);
                    ShellCreateDirectory_Arg_0 = NULL;
                    break;
                }
            }
            
            FirnessSanitizer(TRUE);
            Status = ShellCreateDirectory(
                ShellCreateDirectory_Arg_0,
                &GetFilePosition_Arg_0
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
    }
    /*
        Output Variable(s)
    */
    UINT64 * GetFilePosition_Arg_1 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    UINT8* GetFilePosition_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetFilePosition_Arg_1_OutputChoice), (VOID *)GetFilePosition_Arg_1_OutputChoice);
    if(*GetFilePosition_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetFilePosition_Arg_1), (VOID *)GetFilePosition_Arg_1);
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetFilePosition(
        GetFilePosition_Arg_0,
        GetFilePosition_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called SetFilePosition.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetFilePosition(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    SHELL_FILE_HANDLE SetFilePosition_Arg_0 = {0};
    UINT64 SetFilePosition_Arg_1 = {0};
    
    UINT8* SetFilePosition_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*SetFilePosition_Arg_0_choice), (VOID *)SetFilePosition_Arg_0_choice);
    switch(*SetFilePosition_Arg_0_choice % 4) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(SetFilePosition_Arg_0), (VOID *)&SetFilePosition_Arg_0);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * ShellOpenFileByName_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            unsigned long long ShellOpenFileByName_Arg_2 = {0};
            UINT64 ShellOpenFileByName_Arg_3 = {0};
            
            // Fuzzable Variable Initialization
            UINT8 ShellOpenFileByName_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_0_choice), (VOID *)&ShellOpenFileByName_Arg_0_choice);
            switch(ShellOpenFileByName_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*ShellOpenFileByName_Arg_0), (VOID *)ShellOpenFileByName_Arg_0);
                    ShellOpenFileByName_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(ShellOpenFileByName_Arg_0);
                    ShellOpenFileByName_Arg_0 = NULL;
                    break;
                }
            }
            
            UINT8* ShellOpenFileByName_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*ShellOpenFileByName_Arg_2_choice), (VOID *)ShellOpenFileByName_Arg_2_choice);
            switch(*ShellOpenFileByName_Arg_2_choice % 7) {
                case 0:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ;
            
                    break;
                }
                case 1:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ;
            
                    break;
                }
                case 2:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ;
            
                    break;
                }
                case 3:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE;
            
                    break;
                }
                case 4:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE;
            
                    break;
                }
                case 5:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ | EFI_FILE_MODE_CREATE;
            
                    break;
                }
                case 6:
                {
                // Fuzzable Variable Initialization
                ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_2), (VOID *)&ShellOpenFileByName_Arg_2);
            
                    break;
                }
            }
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_3), (VOID *)&ShellOpenFileByName_Arg_3);
            ShellOpenFileByName_Arg_3 = ShellOpenFileByName_Arg_3 % (4096 + 1);
            
            FirnessSanitizer(TRUE);
            Status = ShellOpenFileByName(
                ShellOpenFileByName_Arg_0,
                &SetFilePosition_Arg_0,
                ShellOpenFileByName_Arg_2,
                ShellOpenFileByName_Arg_3
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
            EFI_DEVICE_PATH_PROTOCOL * EfiOpenFileByDevicePath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            if (EfiOpenFileByDevicePath_Arg_0 != NULL) {
                EfiOpenFileByDevicePath_Arg_0->Type = 0x7F;
                EfiOpenFileByDevicePath_Arg_0->SubType = 0xFF;
                EfiOpenFileByDevicePath_Arg_0->Length[0] = 4;
                EfiOpenFileByDevicePath_Arg_0->Length[1] = 0;
            }
            UINT64 EfiOpenFileByDevicePath_Arg_2 = {0};
            UINT64 EfiOpenFileByDevicePath_Arg_3 = {0};
            
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiOpenFileByDevicePath_Arg_2), (VOID *)&EfiOpenFileByDevicePath_Arg_2);
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiOpenFileByDevicePath_Arg_3), (VOID *)&EfiOpenFileByDevicePath_Arg_3);
            
            /*
                Output Variable(s)
            */
            EFI_FILE_PROTOCOL * EfiOpenFileByDevicePath_Arg_1 = (EFI_FILE_PROTOCOL *)AllocateZeroPool(sizeof(EFI_FILE_PROTOCOL));
            UINT8* EfiOpenFileByDevicePath_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*EfiOpenFileByDevicePath_Arg_1_OutputChoice), (VOID *)EfiOpenFileByDevicePath_Arg_1_OutputChoice);
            if(*EfiOpenFileByDevicePath_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*EfiOpenFileByDevicePath_Arg_1), (VOID *)EfiOpenFileByDevicePath_Arg_1);
            }
            FirnessSanitizer(TRUE);
            Status = EfiOpenFileByDevicePath(
                (EFI_DEVICE_PATH_PROTOCOL **)&EfiOpenFileByDevicePath_Arg_0,
                (EFI_FILE_PROTOCOL **)&EfiOpenFileByDevicePath_Arg_1,
                EfiOpenFileByDevicePath_Arg_2,
                EfiOpenFileByDevicePath_Arg_3
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
            CHAR16 * ShellCreateDirectory_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 ShellCreateDirectory_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(ShellCreateDirectory_Arg_0_choice), (VOID *)&ShellCreateDirectory_Arg_0_choice);
            switch(ShellCreateDirectory_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*ShellCreateDirectory_Arg_0), (VOID *)ShellCreateDirectory_Arg_0);
                    ShellCreateDirectory_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(ShellCreateDirectory_Arg_0);
                    ShellCreateDirectory_Arg_0 = NULL;
                    break;
                }
            }
            
            FirnessSanitizer(TRUE);
            Status = ShellCreateDirectory(
                ShellCreateDirectory_Arg_0,
                &SetFilePosition_Arg_0
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetFilePosition_Arg_1), (VOID *)&SetFilePosition_Arg_1);
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->SetFilePosition(
        SetFilePosition_Arg_0,
        SetFilePosition_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called FlushFile.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFlushFile(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    SHELL_FILE_HANDLE FlushFile_Arg_0 = {0};
    
    UINT8* FlushFile_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*FlushFile_Arg_0_choice), (VOID *)FlushFile_Arg_0_choice);
    switch(*FlushFile_Arg_0_choice % 4) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(FlushFile_Arg_0), (VOID *)&FlushFile_Arg_0);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * ShellOpenFileByName_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            unsigned long long ShellOpenFileByName_Arg_2 = {0};
            UINT64 ShellOpenFileByName_Arg_3 = {0};
            
            // Fuzzable Variable Initialization
            UINT8 ShellOpenFileByName_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_0_choice), (VOID *)&ShellOpenFileByName_Arg_0_choice);
            switch(ShellOpenFileByName_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*ShellOpenFileByName_Arg_0), (VOID *)ShellOpenFileByName_Arg_0);
                    ShellOpenFileByName_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(ShellOpenFileByName_Arg_0);
                    ShellOpenFileByName_Arg_0 = NULL;
                    break;
                }
            }
            
            UINT8* ShellOpenFileByName_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*ShellOpenFileByName_Arg_2_choice), (VOID *)ShellOpenFileByName_Arg_2_choice);
            switch(*ShellOpenFileByName_Arg_2_choice % 7) {
                case 0:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ;
            
                    break;
                }
                case 1:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ;
            
                    break;
                }
                case 2:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ;
            
                    break;
                }
                case 3:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE;
            
                    break;
                }
                case 4:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE;
            
                    break;
                }
                case 5:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ | EFI_FILE_MODE_CREATE;
            
                    break;
                }
                case 6:
                {
                // Fuzzable Variable Initialization
                ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_2), (VOID *)&ShellOpenFileByName_Arg_2);
            
                    break;
                }
            }
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_3), (VOID *)&ShellOpenFileByName_Arg_3);
            ShellOpenFileByName_Arg_3 = ShellOpenFileByName_Arg_3 % (4096 + 1);
            
            FirnessSanitizer(TRUE);
            Status = ShellOpenFileByName(
                ShellOpenFileByName_Arg_0,
                &FlushFile_Arg_0,
                ShellOpenFileByName_Arg_2,
                ShellOpenFileByName_Arg_3
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
            EFI_DEVICE_PATH_PROTOCOL * EfiOpenFileByDevicePath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            if (EfiOpenFileByDevicePath_Arg_0 != NULL) {
                EfiOpenFileByDevicePath_Arg_0->Type = 0x7F;
                EfiOpenFileByDevicePath_Arg_0->SubType = 0xFF;
                EfiOpenFileByDevicePath_Arg_0->Length[0] = 4;
                EfiOpenFileByDevicePath_Arg_0->Length[1] = 0;
            }
            UINT64 EfiOpenFileByDevicePath_Arg_2 = {0};
            UINT64 EfiOpenFileByDevicePath_Arg_3 = {0};
            
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiOpenFileByDevicePath_Arg_2), (VOID *)&EfiOpenFileByDevicePath_Arg_2);
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiOpenFileByDevicePath_Arg_3), (VOID *)&EfiOpenFileByDevicePath_Arg_3);
            
            /*
                Output Variable(s)
            */
            EFI_FILE_PROTOCOL * EfiOpenFileByDevicePath_Arg_1 = (EFI_FILE_PROTOCOL *)AllocateZeroPool(sizeof(EFI_FILE_PROTOCOL));
            UINT8* EfiOpenFileByDevicePath_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*EfiOpenFileByDevicePath_Arg_1_OutputChoice), (VOID *)EfiOpenFileByDevicePath_Arg_1_OutputChoice);
            if(*EfiOpenFileByDevicePath_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*EfiOpenFileByDevicePath_Arg_1), (VOID *)EfiOpenFileByDevicePath_Arg_1);
            }
            FirnessSanitizer(TRUE);
            Status = EfiOpenFileByDevicePath(
                (EFI_DEVICE_PATH_PROTOCOL **)&EfiOpenFileByDevicePath_Arg_0,
                (EFI_FILE_PROTOCOL **)&EfiOpenFileByDevicePath_Arg_1,
                EfiOpenFileByDevicePath_Arg_2,
                EfiOpenFileByDevicePath_Arg_3
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
            CHAR16 * ShellCreateDirectory_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 ShellCreateDirectory_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(ShellCreateDirectory_Arg_0_choice), (VOID *)&ShellCreateDirectory_Arg_0_choice);
            switch(ShellCreateDirectory_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*ShellCreateDirectory_Arg_0), (VOID *)ShellCreateDirectory_Arg_0);
                    ShellCreateDirectory_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(ShellCreateDirectory_Arg_0);
                    ShellCreateDirectory_Arg_0 = NULL;
                    break;
                }
            }
            
            FirnessSanitizer(TRUE);
            Status = ShellCreateDirectory(
                ShellCreateDirectory_Arg_0,
                &FlushFile_Arg_0
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->FlushFile(
        FlushFile_Arg_0
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called FindFiles.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFindFiles(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * FindFiles_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    
    // Fuzzable Variable Initialization
    UINT8 FindFiles_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(FindFiles_Arg_0_choice), (VOID *)&FindFiles_Arg_0_choice);
    switch(FindFiles_Arg_0_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*FindFiles_Arg_0), (VOID *)FindFiles_Arg_0);
            FindFiles_Arg_0[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(FindFiles_Arg_0);
            FindFiles_Arg_0 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_SHELL_FILE_INFO * FindFiles_Arg_1 = (EFI_SHELL_FILE_INFO *)AllocateZeroPool(sizeof(EFI_SHELL_FILE_INFO));
    UINT8* FindFiles_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*FindFiles_Arg_1_OutputChoice), (VOID *)FindFiles_Arg_1_OutputChoice);
    if(*FindFiles_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*FindFiles_Arg_1), (VOID *)FindFiles_Arg_1);
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->FindFiles(
        FindFiles_Arg_0,
        (EFI_SHELL_FILE_INFO * *)&FindFiles_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called FindFilesInDir.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFindFilesInDir(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    SHELL_FILE_HANDLE FindFilesInDir_Arg_0 = {0};
    
    UINT8* FindFilesInDir_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*FindFilesInDir_Arg_0_choice), (VOID *)FindFilesInDir_Arg_0_choice);
    switch(*FindFilesInDir_Arg_0_choice % 4) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(FindFilesInDir_Arg_0), (VOID *)&FindFilesInDir_Arg_0);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * ShellOpenFileByName_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            unsigned long long ShellOpenFileByName_Arg_2 = {0};
            UINT64 ShellOpenFileByName_Arg_3 = {0};
            
            // Fuzzable Variable Initialization
            UINT8 ShellOpenFileByName_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_0_choice), (VOID *)&ShellOpenFileByName_Arg_0_choice);
            switch(ShellOpenFileByName_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*ShellOpenFileByName_Arg_0), (VOID *)ShellOpenFileByName_Arg_0);
                    ShellOpenFileByName_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(ShellOpenFileByName_Arg_0);
                    ShellOpenFileByName_Arg_0 = NULL;
                    break;
                }
            }
            
            UINT8* ShellOpenFileByName_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*ShellOpenFileByName_Arg_2_choice), (VOID *)ShellOpenFileByName_Arg_2_choice);
            switch(*ShellOpenFileByName_Arg_2_choice % 7) {
                case 0:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ;
            
                    break;
                }
                case 1:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ;
            
                    break;
                }
                case 2:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ;
            
                    break;
                }
                case 3:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE;
            
                    break;
                }
                case 4:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE;
            
                    break;
                }
                case 5:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ | EFI_FILE_MODE_CREATE;
            
                    break;
                }
                case 6:
                {
                // Fuzzable Variable Initialization
                ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_2), (VOID *)&ShellOpenFileByName_Arg_2);
            
                    break;
                }
            }
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_3), (VOID *)&ShellOpenFileByName_Arg_3);
            ShellOpenFileByName_Arg_3 = ShellOpenFileByName_Arg_3 % (4096 + 1);
            
            FirnessSanitizer(TRUE);
            Status = ShellOpenFileByName(
                ShellOpenFileByName_Arg_0,
                &FindFilesInDir_Arg_0,
                ShellOpenFileByName_Arg_2,
                ShellOpenFileByName_Arg_3
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
            EFI_DEVICE_PATH_PROTOCOL * EfiOpenFileByDevicePath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            if (EfiOpenFileByDevicePath_Arg_0 != NULL) {
                EfiOpenFileByDevicePath_Arg_0->Type = 0x7F;
                EfiOpenFileByDevicePath_Arg_0->SubType = 0xFF;
                EfiOpenFileByDevicePath_Arg_0->Length[0] = 4;
                EfiOpenFileByDevicePath_Arg_0->Length[1] = 0;
            }
            UINT64 EfiOpenFileByDevicePath_Arg_2 = {0};
            UINT64 EfiOpenFileByDevicePath_Arg_3 = {0};
            
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiOpenFileByDevicePath_Arg_2), (VOID *)&EfiOpenFileByDevicePath_Arg_2);
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiOpenFileByDevicePath_Arg_3), (VOID *)&EfiOpenFileByDevicePath_Arg_3);
            
            /*
                Output Variable(s)
            */
            EFI_FILE_PROTOCOL * EfiOpenFileByDevicePath_Arg_1 = (EFI_FILE_PROTOCOL *)AllocateZeroPool(sizeof(EFI_FILE_PROTOCOL));
            UINT8* EfiOpenFileByDevicePath_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*EfiOpenFileByDevicePath_Arg_1_OutputChoice), (VOID *)EfiOpenFileByDevicePath_Arg_1_OutputChoice);
            if(*EfiOpenFileByDevicePath_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*EfiOpenFileByDevicePath_Arg_1), (VOID *)EfiOpenFileByDevicePath_Arg_1);
            }
            FirnessSanitizer(TRUE);
            Status = EfiOpenFileByDevicePath(
                (EFI_DEVICE_PATH_PROTOCOL **)&EfiOpenFileByDevicePath_Arg_0,
                (EFI_FILE_PROTOCOL **)&EfiOpenFileByDevicePath_Arg_1,
                EfiOpenFileByDevicePath_Arg_2,
                EfiOpenFileByDevicePath_Arg_3
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
            CHAR16 * ShellCreateDirectory_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 ShellCreateDirectory_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(ShellCreateDirectory_Arg_0_choice), (VOID *)&ShellCreateDirectory_Arg_0_choice);
            switch(ShellCreateDirectory_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*ShellCreateDirectory_Arg_0), (VOID *)ShellCreateDirectory_Arg_0);
                    ShellCreateDirectory_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(ShellCreateDirectory_Arg_0);
                    ShellCreateDirectory_Arg_0 = NULL;
                    break;
                }
            }
            
            FirnessSanitizer(TRUE);
            Status = ShellCreateDirectory(
                ShellCreateDirectory_Arg_0,
                &FindFilesInDir_Arg_0
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
    }
    /*
        Output Variable(s)
    */
    EFI_SHELL_FILE_INFO * FindFilesInDir_Arg_1 = (EFI_SHELL_FILE_INFO *)AllocateZeroPool(sizeof(EFI_SHELL_FILE_INFO));
    UINT8* FindFilesInDir_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*FindFilesInDir_Arg_1_OutputChoice), (VOID *)FindFilesInDir_Arg_1_OutputChoice);
    if(*FindFilesInDir_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*FindFilesInDir_Arg_1), (VOID *)FindFilesInDir_Arg_1);
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->FindFilesInDir(
        FindFilesInDir_Arg_0,
        (EFI_SHELL_FILE_INFO * *)&FindFilesInDir_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetFileSize.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetFileSize(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    SHELL_FILE_HANDLE GetFileSize_Arg_0 = {0};
    
    UINT8* GetFileSize_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetFileSize_Arg_0_choice), (VOID *)GetFileSize_Arg_0_choice);
    switch(*GetFileSize_Arg_0_choice % 4) {
        case 0:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(GetFileSize_Arg_0), (VOID *)&GetFileSize_Arg_0);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * ShellOpenFileByName_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            unsigned long long ShellOpenFileByName_Arg_2 = {0};
            UINT64 ShellOpenFileByName_Arg_3 = {0};
            
            // Fuzzable Variable Initialization
            UINT8 ShellOpenFileByName_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_0_choice), (VOID *)&ShellOpenFileByName_Arg_0_choice);
            switch(ShellOpenFileByName_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*ShellOpenFileByName_Arg_0), (VOID *)ShellOpenFileByName_Arg_0);
                    ShellOpenFileByName_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(ShellOpenFileByName_Arg_0);
                    ShellOpenFileByName_Arg_0 = NULL;
                    break;
                }
            }
            
            UINT8* ShellOpenFileByName_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*ShellOpenFileByName_Arg_2_choice), (VOID *)ShellOpenFileByName_Arg_2_choice);
            switch(*ShellOpenFileByName_Arg_2_choice % 7) {
                case 0:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ;
            
                    break;
                }
                case 1:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ;
            
                    break;
                }
                case 2:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ;
            
                    break;
                }
                case 3:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE;
            
                    break;
                }
                case 4:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE;
            
                    break;
                }
                case 5:
                {
                // Constant Variable Initialization
                ShellOpenFileByName_Arg_2 = EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ | EFI_FILE_MODE_CREATE;
            
                    break;
                }
                case 6:
                {
                // Fuzzable Variable Initialization
                ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_2), (VOID *)&ShellOpenFileByName_Arg_2);
            
                    break;
                }
            }
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(ShellOpenFileByName_Arg_3), (VOID *)&ShellOpenFileByName_Arg_3);
            ShellOpenFileByName_Arg_3 = ShellOpenFileByName_Arg_3 % (4096 + 1);
            
            FirnessSanitizer(TRUE);
            Status = ShellOpenFileByName(
                ShellOpenFileByName_Arg_0,
                &GetFileSize_Arg_0,
                ShellOpenFileByName_Arg_2,
                ShellOpenFileByName_Arg_3
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
            EFI_DEVICE_PATH_PROTOCOL * EfiOpenFileByDevicePath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            if (EfiOpenFileByDevicePath_Arg_0 != NULL) {
                EfiOpenFileByDevicePath_Arg_0->Type = 0x7F;
                EfiOpenFileByDevicePath_Arg_0->SubType = 0xFF;
                EfiOpenFileByDevicePath_Arg_0->Length[0] = 4;
                EfiOpenFileByDevicePath_Arg_0->Length[1] = 0;
            }
            UINT64 EfiOpenFileByDevicePath_Arg_2 = {0};
            UINT64 EfiOpenFileByDevicePath_Arg_3 = {0};
            
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiOpenFileByDevicePath_Arg_2), (VOID *)&EfiOpenFileByDevicePath_Arg_2);
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiOpenFileByDevicePath_Arg_3), (VOID *)&EfiOpenFileByDevicePath_Arg_3);
            
            /*
                Output Variable(s)
            */
            EFI_FILE_PROTOCOL * EfiOpenFileByDevicePath_Arg_1 = (EFI_FILE_PROTOCOL *)AllocateZeroPool(sizeof(EFI_FILE_PROTOCOL));
            UINT8* EfiOpenFileByDevicePath_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*EfiOpenFileByDevicePath_Arg_1_OutputChoice), (VOID *)EfiOpenFileByDevicePath_Arg_1_OutputChoice);
            if(*EfiOpenFileByDevicePath_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*EfiOpenFileByDevicePath_Arg_1), (VOID *)EfiOpenFileByDevicePath_Arg_1);
            }
            FirnessSanitizer(TRUE);
            Status = EfiOpenFileByDevicePath(
                (EFI_DEVICE_PATH_PROTOCOL **)&EfiOpenFileByDevicePath_Arg_0,
                (EFI_FILE_PROTOCOL **)&EfiOpenFileByDevicePath_Arg_1,
                EfiOpenFileByDevicePath_Arg_2,
                EfiOpenFileByDevicePath_Arg_3
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
            CHAR16 * ShellCreateDirectory_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 ShellCreateDirectory_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(ShellCreateDirectory_Arg_0_choice), (VOID *)&ShellCreateDirectory_Arg_0_choice);
            switch(ShellCreateDirectory_Arg_0_choice % 2) {
                case 0:
                    ReadBytes(Input, 31 * sizeof(*ShellCreateDirectory_Arg_0), (VOID *)ShellCreateDirectory_Arg_0);
                    ShellCreateDirectory_Arg_0[31] = 0;
                    break;
                case 1:
                {
                    gBS->FreePool(ShellCreateDirectory_Arg_0);
                    ShellCreateDirectory_Arg_0 = NULL;
                    break;
                }
            }
            
            FirnessSanitizer(TRUE);
            Status = ShellCreateDirectory(
                ShellCreateDirectory_Arg_0,
                &GetFileSize_Arg_0
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
    }
    /*
        Output Variable(s)
    */
    UINT64 * GetFileSize_Arg_1 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    UINT8* GetFileSize_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetFileSize_Arg_1_OutputChoice), (VOID *)GetFileSize_Arg_1_OutputChoice);
    if(*GetFileSize_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetFileSize_Arg_1), (VOID *)GetFileSize_Arg_1);
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetFileSize(
        GetFileSize_Arg_0,
        GetFileSize_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called OpenRoot.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzOpenRoot(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * OpenRoot_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    if (OpenRoot_Arg_0 != NULL) {
        OpenRoot_Arg_0->Type = 0x7F;
        OpenRoot_Arg_0->SubType = 0xFF;
        OpenRoot_Arg_0->Length[0] = 4;
        OpenRoot_Arg_0->Length[1] = 0;
    }
    
    UINT8* OpenRoot_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*OpenRoot_Arg_0_choice), (VOID *)OpenRoot_Arg_0_choice);
    switch(*OpenRoot_Arg_0_choice % 4) {
        case 0:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * ChooseFile_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            if (ChooseFile_Arg_0 != NULL) {
                ChooseFile_Arg_0->Type = 0x7F;
                ChooseFile_Arg_0->SubType = 0xFF;
                ChooseFile_Arg_0->Length[0] = 4;
                ChooseFile_Arg_0->Length[1] = 0;
            }
            unsigned short * ChooseFile_Arg_1 = (unsigned short *)AllocateZeroPool(sizeof(unsigned short));
            
            // Generator Struct Variable Initialization
            {
                UINT8 Firness_Type;
                ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
                ChooseFile_Arg_0->Type = Firness_Type;
            }
            {
                UINT8 Firness_SubType;
                ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
                ChooseFile_Arg_0->SubType = Firness_SubType;
            }
            ReadBytes(Input, sizeof(ChooseFile_Arg_0->Length), (VOID *)&(ChooseFile_Arg_0->Length));
            
            // Fuzzable Variable Initialization
            UINT8 ChooseFile_Arg_1_choice = 0;
            ReadBytes(Input, sizeof(ChooseFile_Arg_1_choice), (VOID *)&ChooseFile_Arg_1_choice);
            switch(ChooseFile_Arg_1_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(*ChooseFile_Arg_1), (VOID *)ChooseFile_Arg_1);
                    break;
                case 1:
                {
                    gBS->FreePool(ChooseFile_Arg_1);
                    ChooseFile_Arg_1 = NULL;
                    break;
                }
            }
            
            FirnessSanitizer(TRUE);
            Status = ChooseFile(
                ChooseFile_Arg_0,
                ChooseFile_Arg_1,
                NULL,
                &OpenRoot_Arg_0
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        UINT8 OpenRoot_Arg_0_choice = 0;
        ReadBytes(Input, sizeof(OpenRoot_Arg_0_choice), (VOID *)&OpenRoot_Arg_0_choice);
        switch(OpenRoot_Arg_0_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(*OpenRoot_Arg_0), (VOID *)OpenRoot_Arg_0);
                break;
            case 1:
            {
                gBS->FreePool(OpenRoot_Arg_0);
                OpenRoot_Arg_0 = NULL;
                break;
            }
        }
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_GUID * GetFileDevicePathFromAnyFv_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
            EFI_SECTION_TYPE GetFileDevicePathFromAnyFv_Arg_1 = {0};
            UINTN GetFileDevicePathFromAnyFv_Arg_2 = {0};
            
            // Generator Struct Variable Initialization
            {
                UINT32 Firness_Data1;
                ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
                GetFileDevicePathFromAnyFv_Arg_0->Data1 = Firness_Data1;
            }
            {
                UINT16 Firness_Data2;
                ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
                GetFileDevicePathFromAnyFv_Arg_0->Data2 = Firness_Data2;
            }
            {
                UINT16 Firness_Data3;
                ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
                GetFileDevicePathFromAnyFv_Arg_0->Data3 = Firness_Data3;
            }
            ReadBytes(Input, sizeof(GetFileDevicePathFromAnyFv_Arg_0->Data4), (VOID *)&(GetFileDevicePathFromAnyFv_Arg_0->Data4));
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(GetFileDevicePathFromAnyFv_Arg_1), (VOID *)&GetFileDevicePathFromAnyFv_Arg_1);
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(GetFileDevicePathFromAnyFv_Arg_2), (VOID *)&GetFileDevicePathFromAnyFv_Arg_2);
            
            FirnessSanitizer(TRUE);
            Status = GetFileDevicePathFromAnyFv(
                GetFileDevicePathFromAnyFv_Arg_0,
                GetFileDevicePathFromAnyFv_Arg_1,
                GetFileDevicePathFromAnyFv_Arg_2,
                &OpenRoot_Arg_0
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
        {
            UINT8 Firness_Type;
            ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
            OpenRoot_Arg_0->Type = Firness_Type;
        }
        {
            UINT8 Firness_SubType;
            ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
            OpenRoot_Arg_0->SubType = Firness_SubType;
        }
        ReadBytes(Input, sizeof(OpenRoot_Arg_0->Length), (VOID *)&(OpenRoot_Arg_0->Length));
    
            break;
        }
    }
    /*
        Output Variable(s)
    */
    SHELL_FILE_HANDLE * OpenRoot_Arg_1 = (SHELL_FILE_HANDLE *)AllocateZeroPool(sizeof(SHELL_FILE_HANDLE));
    UINT8* OpenRoot_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*OpenRoot_Arg_1_OutputChoice), (VOID *)OpenRoot_Arg_1_OutputChoice);
    if(*OpenRoot_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*OpenRoot_Arg_1), (VOID *)OpenRoot_Arg_1);
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->OpenRoot(
        OpenRoot_Arg_0,
        OpenRoot_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called OpenRootByHandle.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzOpenRootByHandle(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    SHELL_FILE_HANDLE * OpenRootByHandle_Arg_1 = (SHELL_FILE_HANDLE *)AllocateZeroPool(sizeof(SHELL_FILE_HANDLE));
    UINT8* OpenRootByHandle_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*OpenRootByHandle_Arg_1_OutputChoice), (VOID *)OpenRootByHandle_Arg_1_OutputChoice);
    if(*OpenRootByHandle_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*OpenRootByHandle_Arg_1), (VOID *)OpenRootByHandle_Arg_1);
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->OpenRootByHandle(
        ImageHandle,
        OpenRootByHandle_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called RegisterGuidName.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterGuidName(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * RegisterGuidName_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    CHAR16 * RegisterGuidName_Arg_1 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    
    UINT8* RegisterGuidName_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*RegisterGuidName_Arg_0_choice), (VOID *)RegisterGuidName_Arg_0_choice);
    switch(*RegisterGuidName_Arg_0_choice % 7) {
        case 0:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            Status = NetLibGetSystemGuid(
                RegisterGuidName_Arg_0
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            GUID * CopyGuid_Arg_1 = (GUID *)AllocateZeroPool(sizeof(GUID));
            
            UINT8* CopyGuid_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*CopyGuid_Arg_1_choice), (VOID *)CopyGuid_Arg_1_choice);
            switch(*CopyGuid_Arg_1_choice % 27) {
                case 0:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiAuthenticatedVariableGuid;
            
                    break;
                }
                case 1:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiCallerIdGuid;
            
                    break;
                }
                case 2:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gZeroGuid;
            
                    break;
                }
                case 3:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPcAnsiGuid;
            
                    break;
                }
                case 4:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100Guid;
            
                    break;
                }
                case 5:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100PlusGuid;
            
                    break;
                }
                case 6:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVTUTF8Guid;
            
                    break;
                }
                case 7:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiUartDevicePathGuid;
            
                    break;
                }
                case 8:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSasDevicePathGuid;
            
                    break;
                }
                case 9:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDebugPortProtocolGuid;
            
                    break;
                }
                case 10:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualDiskGuid;
            
                    break;
                }
                case 11:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualCdGuid;
            
                    break;
                }
                case 12:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualDiskGuid;
            
                    break;
                }
                case 13:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualCdGuid;
            
                    break;
                }
                case 14:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoAhciInterfaceGuid;
            
                    break;
                }
                case 15:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocModuleGuid;
            
                    break;
                }
                case 16:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocStackGuid;
            
                    break;
                }
                case 17:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocBspStoreGuid;
            
                    break;
                }
                case 18:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmmVariableProtocolGuid;
            
                    break;
                }
                case 19:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoIdeInterfaceGuid;
            
                    break;
                }
                case 20:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoUfsInterfaceGuid;
            
                    break;
                }
                case 21:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEdkiiDeviceIdentifierTypePciGuid;
            
                    break;
                }
                case 22:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVariableGuid;
            
                    break;
                }
                case 23:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiFirmwareFileSystem2Guid;
            
                    break;
                }
                case 24:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gVarCheckPolicyLibMmiHandlerGuid;
            
                    break;
                }
                case 25:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiGlobalVariableGuid;
            
                    break;
                }
                case 26:
                {
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
            
                    break;
                }
            }
            FirnessSanitizer(TRUE);
            CopyGuid(
                RegisterGuidName_Arg_0,
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
                &RegisterGuidName_Arg_0
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
            
            FirnessSanitizer(TRUE);
            StrToGuid(
                StrToGuid_Arg_0,
                RegisterGuidName_Arg_0
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
            
            FirnessSanitizer(TRUE);
            Status = GetGuidFromStringName(
                GetGuidFromStringName_Arg_0,
                GetGuidFromStringName_Arg_1,
                &RegisterGuidName_Arg_0
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 5:
        {
        // Fuzzable Variable Initialization
        UINT8 RegisterGuidName_Arg_0_choice = 0;
        ReadBytes(Input, sizeof(RegisterGuidName_Arg_0_choice), (VOID *)&RegisterGuidName_Arg_0_choice);
        switch(RegisterGuidName_Arg_0_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(*RegisterGuidName_Arg_0), (VOID *)RegisterGuidName_Arg_0);
                break;
            case 1:
            {
                gBS->FreePool(RegisterGuidName_Arg_0);
                RegisterGuidName_Arg_0 = NULL;
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
            RegisterGuidName_Arg_0->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            RegisterGuidName_Arg_0->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            RegisterGuidName_Arg_0->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(RegisterGuidName_Arg_0->Data4), (VOID *)&(RegisterGuidName_Arg_0->Data4));
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 RegisterGuidName_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(RegisterGuidName_Arg_1_choice), (VOID *)&RegisterGuidName_Arg_1_choice);
    switch(RegisterGuidName_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*RegisterGuidName_Arg_1), (VOID *)RegisterGuidName_Arg_1);
            RegisterGuidName_Arg_1[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(RegisterGuidName_Arg_1);
            RegisterGuidName_Arg_1 = NULL;
            break;
        }
    }
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->RegisterGuidName(
        RegisterGuidName_Arg_0,
        RegisterGuidName_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetGuidName.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetGuidName(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * GetGuidName_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
    UINT8* GetGuidName_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetGuidName_Arg_0_choice), (VOID *)GetGuidName_Arg_0_choice);
    switch(*GetGuidName_Arg_0_choice % 6) {
        case 0:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            Status = NetLibGetSystemGuid(
                GetGuidName_Arg_0
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            GUID * CopyGuid_Arg_1 = (GUID *)AllocateZeroPool(sizeof(GUID));
            
            UINT8* CopyGuid_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*CopyGuid_Arg_1_choice), (VOID *)CopyGuid_Arg_1_choice);
            switch(*CopyGuid_Arg_1_choice % 27) {
                case 0:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiAuthenticatedVariableGuid;
            
                    break;
                }
                case 1:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiCallerIdGuid;
            
                    break;
                }
                case 2:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gZeroGuid;
            
                    break;
                }
                case 3:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPcAnsiGuid;
            
                    break;
                }
                case 4:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100Guid;
            
                    break;
                }
                case 5:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100PlusGuid;
            
                    break;
                }
                case 6:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVTUTF8Guid;
            
                    break;
                }
                case 7:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiUartDevicePathGuid;
            
                    break;
                }
                case 8:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSasDevicePathGuid;
            
                    break;
                }
                case 9:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDebugPortProtocolGuid;
            
                    break;
                }
                case 10:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualDiskGuid;
            
                    break;
                }
                case 11:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualCdGuid;
            
                    break;
                }
                case 12:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualDiskGuid;
            
                    break;
                }
                case 13:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualCdGuid;
            
                    break;
                }
                case 14:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoAhciInterfaceGuid;
            
                    break;
                }
                case 15:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocModuleGuid;
            
                    break;
                }
                case 16:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocStackGuid;
            
                    break;
                }
                case 17:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocBspStoreGuid;
            
                    break;
                }
                case 18:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmmVariableProtocolGuid;
            
                    break;
                }
                case 19:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoIdeInterfaceGuid;
            
                    break;
                }
                case 20:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoUfsInterfaceGuid;
            
                    break;
                }
                case 21:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEdkiiDeviceIdentifierTypePciGuid;
            
                    break;
                }
                case 22:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVariableGuid;
            
                    break;
                }
                case 23:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiFirmwareFileSystem2Guid;
            
                    break;
                }
                case 24:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gVarCheckPolicyLibMmiHandlerGuid;
            
                    break;
                }
                case 25:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiGlobalVariableGuid;
            
                    break;
                }
                case 26:
                {
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
            
                    break;
                }
            }
            FirnessSanitizer(TRUE);
            CopyGuid(
                GetGuidName_Arg_0,
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
                &GetGuidName_Arg_0
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
            
            FirnessSanitizer(TRUE);
            StrToGuid(
                StrToGuid_Arg_0,
                GetGuidName_Arg_0
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 4:
        {
        // Fuzzable Variable Initialization
        UINT8 GetGuidName_Arg_0_choice = 0;
        ReadBytes(Input, sizeof(GetGuidName_Arg_0_choice), (VOID *)&GetGuidName_Arg_0_choice);
        switch(GetGuidName_Arg_0_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(*GetGuidName_Arg_0), (VOID *)GetGuidName_Arg_0);
                break;
            case 1:
            {
                gBS->FreePool(GetGuidName_Arg_0);
                GetGuidName_Arg_0 = NULL;
                break;
            }
        }
    
            break;
        }
        case 5:
        {
        // Generator Struct Variable Initialization
        {
            UINT32 Firness_Data1;
            ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
            GetGuidName_Arg_0->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            GetGuidName_Arg_0->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            GetGuidName_Arg_0->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(GetGuidName_Arg_0->Data4), (VOID *)&(GetGuidName_Arg_0->Data4));
    
            break;
        }
    }
    /*
        Output Variable(s)
    */
    CONST CHAR16 * GetGuidName_Arg_1 = (CONST CHAR16 *)AllocateZeroPool(32 * sizeof(CONST CHAR16));
    UINT8* GetGuidName_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetGuidName_Arg_1_OutputChoice), (VOID *)GetGuidName_Arg_1_OutputChoice);
    if(*GetGuidName_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetGuidName_Arg_1), (VOID *)GetGuidName_Arg_1);
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetGuidName(
        GetGuidName_Arg_0,
        (CONST CHAR16 * *)&GetGuidName_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetGuidFromName.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetGuidFromName(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * GetGuidFromName_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    
    // Fuzzable Variable Initialization
    UINT8 GetGuidFromName_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(GetGuidFromName_Arg_0_choice), (VOID *)&GetGuidFromName_Arg_0_choice);
    switch(GetGuidFromName_Arg_0_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*GetGuidFromName_Arg_0), (VOID *)GetGuidFromName_Arg_0);
            GetGuidFromName_Arg_0[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(GetGuidFromName_Arg_0);
            GetGuidFromName_Arg_0 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_GUID * GetGuidFromName_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINT8* GetGuidFromName_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetGuidFromName_Arg_1_OutputChoice), (VOID *)GetGuidFromName_Arg_1_OutputChoice);
    if(*GetGuidFromName_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetGuidFromName_Arg_1), (VOID *)GetGuidFromName_Arg_1);
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetGuidFromName(
        GetGuidFromName_Arg_0,
        GetGuidFromName_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetEnvEx.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetEnvEx(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SHELL_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * GetEnvEx_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    
    // Fuzzable Variable Initialization
    UINT8 GetEnvEx_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(GetEnvEx_Arg_0_choice), (VOID *)&GetEnvEx_Arg_0_choice);
    switch(GetEnvEx_Arg_0_choice % 2) {
        case 0:
            ReadBytes(Input, 31 * sizeof(*GetEnvEx_Arg_0), (VOID *)GetEnvEx_Arg_0);
            GetEnvEx_Arg_0[31] = 0;
            break;
        case 1:
        {
            gBS->FreePool(GetEnvEx_Arg_0);
            GetEnvEx_Arg_0 = NULL;
            break;
        }
    }
    
    FirnessSanitizer(TRUE);
    ProtocolVariable->GetEnvEx(
        GetEnvEx_Arg_0,
        NULL
    );
    FirnessSanitizer(FALSE);
    return Status;
}

