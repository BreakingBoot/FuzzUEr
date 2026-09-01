#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called GetDevicePathSize.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetDevicePathSize(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DEVICE_PATH_UTILITIES_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDevicePathUtilitiesProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * GetDevicePathSize_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    
    UINT8* GetDevicePathSize_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetDevicePathSize_Arg_0_choice), (VOID *)GetDevicePathSize_Arg_0_choice);
    switch(*GetDevicePathSize_Arg_0_choice % 3) {
        case 0:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * ChooseFile_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
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
                    ReadBytes(Input, sizeof(ChooseFile_Arg_1), (VOID *)ChooseFile_Arg_1);
                    break;
                case 1:
                {
                    gBS->FreePool(ChooseFile_Arg_1);
                    ChooseFile_Arg_1 = NULL;
                    break;
                }
            }
            
            Status = ChooseFile(
                ChooseFile_Arg_0,
                ChooseFile_Arg_1,
                NULL,
                &GetDevicePathSize_Arg_0
            );
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_GUID * GetFileDevicePathFromAnyFv_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
            EFI_SECTION_TYPE GetFileDevicePathFromAnyFv_Arg_1 = 0;
            UINTN GetFileDevicePathFromAnyFv_Arg_2 = 0;
            
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
            
            Status = GetFileDevicePathFromAnyFv(
                GetFileDevicePathFromAnyFv_Arg_0,
                GetFileDevicePathFromAnyFv_Arg_1,
                GetFileDevicePathFromAnyFv_Arg_2,
                &GetDevicePathSize_Arg_0
            );
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
        {
            UINT8 Firness_Type;
            ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
            GetDevicePathSize_Arg_0->Type = Firness_Type;
        }
        {
            UINT8 Firness_SubType;
            ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
            GetDevicePathSize_Arg_0->SubType = Firness_SubType;
        }
        ReadBytes(Input, sizeof(GetDevicePathSize_Arg_0->Length), (VOID *)&(GetDevicePathSize_Arg_0->Length));
    
            break;
        }
    }
    ProtocolVariable->GetDevicePathSize(
        GetDevicePathSize_Arg_0
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called DuplicateDevicePath.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDuplicateDevicePath(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DEVICE_PATH_UTILITIES_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDevicePathUtilitiesProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * DuplicateDevicePath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    
    UINT8* DuplicateDevicePath_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(DuplicateDevicePath_Arg_0_choice), (VOID *)DuplicateDevicePath_Arg_0_choice);
    switch(*DuplicateDevicePath_Arg_0_choice % 4) {
        case 0:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * ChooseFile_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
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
                    ReadBytes(Input, sizeof(ChooseFile_Arg_1), (VOID *)ChooseFile_Arg_1);
                    break;
                case 1:
                {
                    gBS->FreePool(ChooseFile_Arg_1);
                    ChooseFile_Arg_1 = NULL;
                    break;
                }
            }
            
            Status = ChooseFile(
                ChooseFile_Arg_0,
                ChooseFile_Arg_1,
                NULL,
                &DuplicateDevicePath_Arg_0
            );
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * GetGopDevicePath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            
            // Generator Struct Variable Initialization
            {
                UINT8 Firness_Type;
                ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
                GetGopDevicePath_Arg_0->Type = Firness_Type;
            }
            {
                UINT8 Firness_SubType;
                ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
                GetGopDevicePath_Arg_0->SubType = Firness_SubType;
            }
            ReadBytes(Input, sizeof(GetGopDevicePath_Arg_0->Length), (VOID *)&(GetGopDevicePath_Arg_0->Length));
            
            Status = GetGopDevicePath(
                GetGopDevicePath_Arg_0,
                &DuplicateDevicePath_Arg_0
            );
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_GUID * GetFileDevicePathFromAnyFv_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
            EFI_SECTION_TYPE GetFileDevicePathFromAnyFv_Arg_1 = 0;
            UINTN GetFileDevicePathFromAnyFv_Arg_2 = 0;
            
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
            
            Status = GetFileDevicePathFromAnyFv(
                GetFileDevicePathFromAnyFv_Arg_0,
                GetFileDevicePathFromAnyFv_Arg_1,
                GetFileDevicePathFromAnyFv_Arg_2,
                &DuplicateDevicePath_Arg_0
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
        {
            UINT8 Firness_Type;
            ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
            DuplicateDevicePath_Arg_0->Type = Firness_Type;
        }
        {
            UINT8 Firness_SubType;
            ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
            DuplicateDevicePath_Arg_0->SubType = Firness_SubType;
        }
        ReadBytes(Input, sizeof(DuplicateDevicePath_Arg_0->Length), (VOID *)&(DuplicateDevicePath_Arg_0->Length));
    
            break;
        }
    }
    Status = ProtocolVariable->DuplicateDevicePath(
        DuplicateDevicePath_Arg_0
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called AppendDevicePath.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAppendDevicePath(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DEVICE_PATH_UTILITIES_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDevicePathUtilitiesProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * AppendDevicePath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    EFI_DEVICE_PATH_PROTOCOL * AppendDevicePath_Arg_1 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    
    UINT8* AppendDevicePath_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(AppendDevicePath_Arg_0_choice), (VOID *)AppendDevicePath_Arg_0_choice);
    switch(*AppendDevicePath_Arg_0_choice % 3) {
        case 0:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * ChooseFile_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
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
                    ReadBytes(Input, sizeof(ChooseFile_Arg_1), (VOID *)ChooseFile_Arg_1);
                    break;
                case 1:
                {
                    gBS->FreePool(ChooseFile_Arg_1);
                    ChooseFile_Arg_1 = NULL;
                    break;
                }
            }
            
            Status = ChooseFile(
                ChooseFile_Arg_0,
                ChooseFile_Arg_1,
                NULL,
                &AppendDevicePath_Arg_0
            );
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_GUID * GetFileDevicePathFromAnyFv_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
            EFI_SECTION_TYPE GetFileDevicePathFromAnyFv_Arg_1 = 0;
            UINTN GetFileDevicePathFromAnyFv_Arg_2 = 0;
            
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
            
            Status = GetFileDevicePathFromAnyFv(
                GetFileDevicePathFromAnyFv_Arg_0,
                GetFileDevicePathFromAnyFv_Arg_1,
                GetFileDevicePathFromAnyFv_Arg_2,
                &AppendDevicePath_Arg_0
            );
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
        {
            UINT8 Firness_Type;
            ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
            AppendDevicePath_Arg_0->Type = Firness_Type;
        }
        {
            UINT8 Firness_SubType;
            ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
            AppendDevicePath_Arg_0->SubType = Firness_SubType;
        }
        ReadBytes(Input, sizeof(AppendDevicePath_Arg_0->Length), (VOID *)&(AppendDevicePath_Arg_0->Length));
    
            break;
        }
    }
    // Generator Struct Variable Initialization
    {
        UINT8 Firness_Type;
        ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
        AppendDevicePath_Arg_1->Type = Firness_Type;
    }
    {
        UINT8 Firness_SubType;
        ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
        AppendDevicePath_Arg_1->SubType = Firness_SubType;
    }
    ReadBytes(Input, sizeof(AppendDevicePath_Arg_1->Length), (VOID *)&(AppendDevicePath_Arg_1->Length));
    
    Status = ProtocolVariable->AppendDevicePath(
        AppendDevicePath_Arg_0,
        AppendDevicePath_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called AppendDeviceNode.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAppendDeviceNode(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DEVICE_PATH_UTILITIES_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDevicePathUtilitiesProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * AppendDeviceNode_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    EFI_DEVICE_PATH_PROTOCOL * AppendDeviceNode_Arg_1 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    
    UINT8* AppendDeviceNode_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(AppendDeviceNode_Arg_0_choice), (VOID *)AppendDeviceNode_Arg_0_choice);
    switch(*AppendDeviceNode_Arg_0_choice % 4) {
        case 0:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * ChooseFile_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
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
                    ReadBytes(Input, sizeof(ChooseFile_Arg_1), (VOID *)ChooseFile_Arg_1);
                    break;
                case 1:
                {
                    gBS->FreePool(ChooseFile_Arg_1);
                    ChooseFile_Arg_1 = NULL;
                    break;
                }
            }
            
            Status = ChooseFile(
                ChooseFile_Arg_0,
                ChooseFile_Arg_1,
                NULL,
                &AppendDeviceNode_Arg_0
            );
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * GetGopDevicePath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            
            // Generator Struct Variable Initialization
            {
                UINT8 Firness_Type;
                ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
                GetGopDevicePath_Arg_0->Type = Firness_Type;
            }
            {
                UINT8 Firness_SubType;
                ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
                GetGopDevicePath_Arg_0->SubType = Firness_SubType;
            }
            ReadBytes(Input, sizeof(GetGopDevicePath_Arg_0->Length), (VOID *)&(GetGopDevicePath_Arg_0->Length));
            
            Status = GetGopDevicePath(
                GetGopDevicePath_Arg_0,
                &AppendDeviceNode_Arg_0
            );
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_GUID * GetFileDevicePathFromAnyFv_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
            EFI_SECTION_TYPE GetFileDevicePathFromAnyFv_Arg_1 = 0;
            UINTN GetFileDevicePathFromAnyFv_Arg_2 = 0;
            
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
            
            Status = GetFileDevicePathFromAnyFv(
                GetFileDevicePathFromAnyFv_Arg_0,
                GetFileDevicePathFromAnyFv_Arg_1,
                GetFileDevicePathFromAnyFv_Arg_2,
                &AppendDeviceNode_Arg_0
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
        {
            UINT8 Firness_Type;
            ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
            AppendDeviceNode_Arg_0->Type = Firness_Type;
        }
        {
            UINT8 Firness_SubType;
            ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
            AppendDeviceNode_Arg_0->SubType = Firness_SubType;
        }
        ReadBytes(Input, sizeof(AppendDeviceNode_Arg_0->Length), (VOID *)&(AppendDeviceNode_Arg_0->Length));
    
            break;
        }
    }
    // Generator Struct Variable Initialization
    {
        UINT8 Firness_Type;
        ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
        AppendDeviceNode_Arg_1->Type = Firness_Type;
    }
    {
        UINT8 Firness_SubType;
        ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
        AppendDeviceNode_Arg_1->SubType = Firness_SubType;
    }
    ReadBytes(Input, sizeof(AppendDeviceNode_Arg_1->Length), (VOID *)&(AppendDeviceNode_Arg_1->Length));
    
    Status = ProtocolVariable->AppendDeviceNode(
        AppendDeviceNode_Arg_0,
        AppendDeviceNode_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called AppendDevicePathInstance.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAppendDevicePathInstance(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DEVICE_PATH_UTILITIES_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDevicePathUtilitiesProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * AppendDevicePathInstance_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    EFI_DEVICE_PATH_PROTOCOL * AppendDevicePathInstance_Arg_1 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    
    UINT8* AppendDevicePathInstance_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(AppendDevicePathInstance_Arg_0_choice), (VOID *)AppendDevicePathInstance_Arg_0_choice);
    switch(*AppendDevicePathInstance_Arg_0_choice % 4) {
        case 0:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * ChooseFile_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
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
                    ReadBytes(Input, sizeof(ChooseFile_Arg_1), (VOID *)ChooseFile_Arg_1);
                    break;
                case 1:
                {
                    gBS->FreePool(ChooseFile_Arg_1);
                    ChooseFile_Arg_1 = NULL;
                    break;
                }
            }
            
            Status = ChooseFile(
                ChooseFile_Arg_0,
                ChooseFile_Arg_1,
                NULL,
                &AppendDevicePathInstance_Arg_0
            );
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * GetGopDevicePath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            
            // Generator Struct Variable Initialization
            {
                UINT8 Firness_Type;
                ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
                GetGopDevicePath_Arg_0->Type = Firness_Type;
            }
            {
                UINT8 Firness_SubType;
                ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
                GetGopDevicePath_Arg_0->SubType = Firness_SubType;
            }
            ReadBytes(Input, sizeof(GetGopDevicePath_Arg_0->Length), (VOID *)&(GetGopDevicePath_Arg_0->Length));
            
            Status = GetGopDevicePath(
                GetGopDevicePath_Arg_0,
                &AppendDevicePathInstance_Arg_0
            );
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_GUID * GetFileDevicePathFromAnyFv_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
            EFI_SECTION_TYPE GetFileDevicePathFromAnyFv_Arg_1 = 0;
            UINTN GetFileDevicePathFromAnyFv_Arg_2 = 0;
            
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
            
            Status = GetFileDevicePathFromAnyFv(
                GetFileDevicePathFromAnyFv_Arg_0,
                GetFileDevicePathFromAnyFv_Arg_1,
                GetFileDevicePathFromAnyFv_Arg_2,
                &AppendDevicePathInstance_Arg_0
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
        {
            UINT8 Firness_Type;
            ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
            AppendDevicePathInstance_Arg_0->Type = Firness_Type;
        }
        {
            UINT8 Firness_SubType;
            ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
            AppendDevicePathInstance_Arg_0->SubType = Firness_SubType;
        }
        ReadBytes(Input, sizeof(AppendDevicePathInstance_Arg_0->Length), (VOID *)&(AppendDevicePathInstance_Arg_0->Length));
    
            break;
        }
    }
    // Generator Struct Variable Initialization
    {
        UINT8 Firness_Type;
        ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
        AppendDevicePathInstance_Arg_1->Type = Firness_Type;
    }
    {
        UINT8 Firness_SubType;
        ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
        AppendDevicePathInstance_Arg_1->SubType = Firness_SubType;
    }
    ReadBytes(Input, sizeof(AppendDevicePathInstance_Arg_1->Length), (VOID *)&(AppendDevicePathInstance_Arg_1->Length));
    
    Status = ProtocolVariable->AppendDevicePathInstance(
        AppendDevicePathInstance_Arg_0,
        AppendDevicePathInstance_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetNextDevicePathInstance.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetNextDevicePathInstance(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DEVICE_PATH_UTILITIES_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDevicePathUtilitiesProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * * GetNextDevicePathInstance_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL * *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    
    
    /*
        Output Variable(s)
    */
    UINTN * GetNextDevicePathInstance_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetNextDevicePathInstance_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetNextDevicePathInstance_Arg_1_OutputChoice), (VOID *)GetNextDevicePathInstance_Arg_1_OutputChoice);
    if(*GetNextDevicePathInstance_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetNextDevicePathInstance_Arg_1), (VOID *)GetNextDevicePathInstance_Arg_1);
    }
    Status = ProtocolVariable->GetNextDevicePathInstance(
        &GetNextDevicePathInstance_Arg_0,
        GetNextDevicePathInstance_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called IsDevicePathMultiInstance.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzIsDevicePathMultiInstance(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DEVICE_PATH_UTILITIES_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDevicePathUtilitiesProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * IsDevicePathMultiInstance_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
    
    UINT8* IsDevicePathMultiInstance_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(IsDevicePathMultiInstance_Arg_0_choice), (VOID *)IsDevicePathMultiInstance_Arg_0_choice);
    switch(*IsDevicePathMultiInstance_Arg_0_choice % 4) {
        case 0:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * ChooseFile_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
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
                    ReadBytes(Input, sizeof(ChooseFile_Arg_1), (VOID *)ChooseFile_Arg_1);
                    break;
                case 1:
                {
                    gBS->FreePool(ChooseFile_Arg_1);
                    ChooseFile_Arg_1 = NULL;
                    break;
                }
            }
            
            Status = ChooseFile(
                ChooseFile_Arg_0,
                ChooseFile_Arg_1,
                NULL,
                &IsDevicePathMultiInstance_Arg_0
            );
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * GetGopDevicePath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            
            // Generator Struct Variable Initialization
            {
                UINT8 Firness_Type;
                ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
                GetGopDevicePath_Arg_0->Type = Firness_Type;
            }
            {
                UINT8 Firness_SubType;
                ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
                GetGopDevicePath_Arg_0->SubType = Firness_SubType;
            }
            ReadBytes(Input, sizeof(GetGopDevicePath_Arg_0->Length), (VOID *)&(GetGopDevicePath_Arg_0->Length));
            
            Status = GetGopDevicePath(
                GetGopDevicePath_Arg_0,
                &IsDevicePathMultiInstance_Arg_0
            );
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_GUID * GetFileDevicePathFromAnyFv_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
            EFI_SECTION_TYPE GetFileDevicePathFromAnyFv_Arg_1 = 0;
            UINTN GetFileDevicePathFromAnyFv_Arg_2 = 0;
            
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
            
            Status = GetFileDevicePathFromAnyFv(
                GetFileDevicePathFromAnyFv_Arg_0,
                GetFileDevicePathFromAnyFv_Arg_1,
                GetFileDevicePathFromAnyFv_Arg_2,
                &IsDevicePathMultiInstance_Arg_0
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
        {
            UINT8 Firness_Type;
            ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
            IsDevicePathMultiInstance_Arg_0->Type = Firness_Type;
        }
        {
            UINT8 Firness_SubType;
            ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
            IsDevicePathMultiInstance_Arg_0->SubType = Firness_SubType;
        }
        ReadBytes(Input, sizeof(IsDevicePathMultiInstance_Arg_0->Length), (VOID *)&(IsDevicePathMultiInstance_Arg_0->Length));
    
            break;
        }
    }
    ProtocolVariable->IsDevicePathMultiInstance(
        IsDevicePathMultiInstance_Arg_0
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called CreateDeviceNode.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzCreateDeviceNode(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DEVICE_PATH_UTILITIES_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDevicePathUtilitiesProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 CreateDeviceNode_Arg_0 = 0;
    UINT8 CreateDeviceNode_Arg_1 = 0;
    UINT16 CreateDeviceNode_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(CreateDeviceNode_Arg_0), (VOID *)&CreateDeviceNode_Arg_0);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(CreateDeviceNode_Arg_1), (VOID *)&CreateDeviceNode_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(CreateDeviceNode_Arg_2), (VOID *)&CreateDeviceNode_Arg_2);
    
    Status = ProtocolVariable->CreateDeviceNode(
        CreateDeviceNode_Arg_0,
        CreateDeviceNode_Arg_1,
        CreateDeviceNode_Arg_2
    );
    return Status;
}

