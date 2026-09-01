#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called GetNetworkInterfaceList.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetNetworkInterfaceList(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_REDFISH_DISCOVER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiRedfishDiscoverProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINTN * GetNetworkInterfaceList_Arg_2 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetNetworkInterfaceList_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetNetworkInterfaceList_Arg_2_OutputChoice), (VOID *)GetNetworkInterfaceList_Arg_2_OutputChoice);
    if(*GetNetworkInterfaceList_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetNetworkInterfaceList_Arg_2), (VOID *)GetNetworkInterfaceList_Arg_2);
    }
    EFI_REDFISH_DISCOVER_NETWORK_INTERFACE * * GetNetworkInterfaceList_Arg_3 = (EFI_REDFISH_DISCOVER_NETWORK_INTERFACE * *)AllocateZeroPool(sizeof(EFI_REDFISH_DISCOVER_NETWORK_INTERFACE));
    UINT8* GetNetworkInterfaceList_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetNetworkInterfaceList_Arg_3_OutputChoice), (VOID *)GetNetworkInterfaceList_Arg_3_OutputChoice);
    if(*GetNetworkInterfaceList_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetNetworkInterfaceList_Arg_3), (VOID *)GetNetworkInterfaceList_Arg_3);
    }
    Status = ProtocolVariable->GetNetworkInterfaceList(
        ProtocolVariable,
        ImageHandle,
        GetNetworkInterfaceList_Arg_2,
        &GetNetworkInterfaceList_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called AcquireRedfishService.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAcquireRedfishService(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_REDFISH_DISCOVER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiRedfishDiscoverProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->AcquireRedfishService(
        ProtocolVariable,
        ImageHandle,
        NULL,
        (EFI_REDFISH_DISCOVER_FLAG){0},
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called AbortAcquireRedfishService.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAbortAcquireRedfishService(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_REDFISH_DISCOVER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiRedfishDiscoverProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->AbortAcquireRedfishService(
        ProtocolVariable,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ReleaseRedfishService.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzReleaseRedfishService(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_REDFISH_DISCOVER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiRedfishDiscoverProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->ReleaseRedfishService(
        ProtocolVariable,
        NULL
    );
    return Status;
}

