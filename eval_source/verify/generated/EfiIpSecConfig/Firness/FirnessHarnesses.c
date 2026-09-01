#include "FirnessHarnesses.h"

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
    EFI_IPSEC_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIpSecConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  SetData_Arg_3 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    UINT8 SetData_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(SetData_Arg_3_choice), (VOID *)&SetData_Arg_3_choice);
    switch(SetData_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetData_Arg_3), (VOID *)SetData_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(SetData_Arg_3);
            SetData_Arg_3 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->SetData(
        ProtocolVariable,
        (EFI_IPSEC_CONFIG_DATA_TYPE){0},
        NULL,
        (VOID *)SetData_Arg_3,
        NULL
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
    EFI_IPSEC_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIpSecConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
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
    
    /*
        Output Variable(s)
    */
    UINTN*  GetData_Arg_4 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT8* GetData_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetData_Arg_4_OutputChoice), (VOID *)GetData_Arg_4_OutputChoice);
    if(*GetData_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetData_Arg_4), (VOID *)GetData_Arg_4);
    }
    Status = ProtocolVariable->GetData(
        ProtocolVariable,
        (EFI_IPSEC_CONFIG_DATA_TYPE){0},
        NULL,
        GetData_Arg_3,
        (VOID *)GetData_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetNextSelector.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetNextSelector(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_IPSEC_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIpSecConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * GetNextSelector_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    EFI_IPSEC_CONFIG_SELECTOR * GetNextSelector_Arg_3 = (EFI_IPSEC_CONFIG_SELECTOR *)AllocateZeroPool(sizeof(EFI_IPSEC_CONFIG_SELECTOR));
    
    // Fuzzable Variable Initialization
    UINT8 GetNextSelector_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetNextSelector_Arg_2_choice), (VOID *)&GetNextSelector_Arg_2_choice);
    switch(GetNextSelector_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetNextSelector_Arg_2), (VOID *)GetNextSelector_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(GetNextSelector_Arg_2);
            GetNextSelector_Arg_2 = NULL;
            break;
        }
    }
    
    
    Status = ProtocolVariable->GetNextSelector(
        ProtocolVariable,
        (EFI_IPSEC_CONFIG_DATA_TYPE){0},
        GetNextSelector_Arg_2,
        GetNextSelector_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RegisterDataNotify.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterDataNotify(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_IPSEC_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIpSecConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_EVENT RegisterDataNotify_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RegisterDataNotify_Arg_2), (VOID *)&RegisterDataNotify_Arg_2);
    
    Status = ProtocolVariable->RegisterDataNotify(
        ProtocolVariable,
        (EFI_IPSEC_CONFIG_DATA_TYPE){0},
        RegisterDataNotify_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UnregisterDataNotify.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUnregisterDataNotify(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_IPSEC_CONFIG_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIpSecConfigProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_EVENT UnregisterDataNotify_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UnregisterDataNotify_Arg_2), (VOID *)&UnregisterDataNotify_Arg_2);
    
    Status = ProtocolVariable->UnregisterDataNotify(
        ProtocolVariable,
        (EFI_IPSEC_CONFIG_DATA_TYPE){0},
        UnregisterDataNotify_Arg_2
    );
    return Status;
}

