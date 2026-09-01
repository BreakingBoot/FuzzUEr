#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the Protocols service
    called GetEsrtEntry.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetEsrtEntry(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    ESRT_MANAGEMENT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEsrtManagementProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * GetEsrtEntry_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    EFI_SYSTEM_RESOURCE_ENTRY * GetEsrtEntry_Arg_1 = (EFI_SYSTEM_RESOURCE_ENTRY *)AllocateZeroPool(sizeof(EFI_SYSTEM_RESOURCE_ENTRY));
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        GetEsrtEntry_Arg_0->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        GetEsrtEntry_Arg_0->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        GetEsrtEntry_Arg_0->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(GetEsrtEntry_Arg_0->Data4), (VOID *)&(GetEsrtEntry_Arg_0->Data4));
    
    
    Status = ProtocolVariable->GetEsrtEntry(
        GetEsrtEntry_Arg_0,
        GetEsrtEntry_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called UpdateEsrtEntry.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUpdateEsrtEntry(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    ESRT_MANAGEMENT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEsrtManagementProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->UpdateEsrtEntry(
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called RegisterEsrtEntry.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterEsrtEntry(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    ESRT_MANAGEMENT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEsrtManagementProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->RegisterEsrtEntry(
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called UnRegisterEsrtEntry.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUnRegisterEsrtEntry(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    ESRT_MANAGEMENT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEsrtManagementProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * UnRegisterEsrtEntry_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        UnRegisterEsrtEntry_Arg_0->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        UnRegisterEsrtEntry_Arg_0->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        UnRegisterEsrtEntry_Arg_0->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(UnRegisterEsrtEntry_Arg_0->Data4), (VOID *)&(UnRegisterEsrtEntry_Arg_0->Data4));
    
    Status = ProtocolVariable->UnRegisterEsrtEntry(
        UnRegisterEsrtEntry_Arg_0
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called SyncEsrtFmp.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSyncEsrtFmp(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    ESRT_MANAGEMENT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEsrtManagementProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->SyncEsrtFmp(
    );
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called LockEsrtRepository.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzLockEsrtRepository(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    ESRT_MANAGEMENT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEsrtManagementProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->LockEsrtRepository(
    );
    return Status;
}

