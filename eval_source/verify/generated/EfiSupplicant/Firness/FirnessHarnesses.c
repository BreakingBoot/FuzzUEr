#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called BuildResponsePacket.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzBuildResponsePacket(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SUPPLICANT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSupplicantProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * BuildResponsePacket_Arg_4 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    UINT8 BuildResponsePacket_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(BuildResponsePacket_Arg_4_choice), (VOID *)&BuildResponsePacket_Arg_4_choice);
    switch(BuildResponsePacket_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(BuildResponsePacket_Arg_4), (VOID *)BuildResponsePacket_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(BuildResponsePacket_Arg_4);
            BuildResponsePacket_Arg_4 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    UINT8 * BuildResponsePacket_Arg_3 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT8* BuildResponsePacket_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(BuildResponsePacket_Arg_3_OutputChoice), (VOID *)BuildResponsePacket_Arg_3_OutputChoice);
    if(*BuildResponsePacket_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*BuildResponsePacket_Arg_3), (VOID *)BuildResponsePacket_Arg_3);
    }
    Status = ProtocolVariable->BuildResponsePacket(
        ProtocolVariable,
        NULL,
        (UINTN){0},
        BuildResponsePacket_Arg_3,
        BuildResponsePacket_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ProcessPacket.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzProcessPacket(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SUPPLICANT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSupplicantProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_SUPPLICANT_FRAGMENT_DATA * * ProcessPacket_Arg_1 = (EFI_SUPPLICANT_FRAGMENT_DATA * *)AllocateZeroPool(sizeof(EFI_SUPPLICANT_FRAGMENT_DATA));
    UINT32 * ProcessPacket_Arg_2 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    
    
    // Fuzzable Variable Initialization
    UINT8 ProcessPacket_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(ProcessPacket_Arg_2_choice), (VOID *)&ProcessPacket_Arg_2_choice);
    switch(ProcessPacket_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(ProcessPacket_Arg_2), (VOID *)ProcessPacket_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(ProcessPacket_Arg_2);
            ProcessPacket_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->ProcessPacket(
        ProtocolVariable,
        &ProcessPacket_Arg_1,
        ProcessPacket_Arg_2,
        (EFI_SUPPLICANT_CRYPT_MODE){0}
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetData.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SUPPLICANT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSupplicantProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  SetData_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN SetData_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    UINT8 SetData_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(SetData_Arg_2_choice), (VOID *)&SetData_Arg_2_choice);
    switch(SetData_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetData_Arg_2), (VOID *)SetData_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(SetData_Arg_2);
            SetData_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetData_Arg_3), (VOID *)&SetData_Arg_3);
    
    Status = ProtocolVariable->SetData(
        ProtocolVariable,
        (EFI_SUPPLICANT_DATA_TYPE){0},
        (VOID *)SetData_Arg_2,
        SetData_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetData.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SUPPLICANT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSupplicantProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * GetData_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    UINT8 GetData_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(GetData_Arg_3_choice), (VOID *)&GetData_Arg_3_choice);
    switch(GetData_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetData_Arg_3), (VOID *)GetData_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(GetData_Arg_3);
            GetData_Arg_3 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetData(
        ProtocolVariable,
        (EFI_SUPPLICANT_DATA_TYPE){0},
        NULL,
        GetData_Arg_3
    );
    return Status;
}

