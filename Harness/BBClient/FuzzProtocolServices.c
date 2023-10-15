#include "FuzzProtocolServices.h"

EFI_STATUS
EFIAPI
FuzzProtocolServices(
    IN INPUT_BUFFER *Input
)
{
    DEBUG((DEBUG_ERROR, "FUZZING: Protocols\n"));
    EFI_STATUS Status = EFI_SUCCESS;
    UINTN ProtocolService;
    ReadInput(Input, 1, &ProtocolService);
    switch(ProtocolService%12)
    {
        case LOCATE_PROTOCOL:
            Status = FuzzLocateProtocol(Input);
            break;
        case OPEN_PROTOCOL:
            Status = FuzzOpenProtocol(Input);
            break;
        case CLOSE_PROTOCOL:
            Status = FuzzCloseProtocol(Input);
            break;
        case HANDLE_PROTOCOL:
            Status = FuzzHandleProtocol(Input);
            break;
        case OPEN_PROTOCOL_INFORMATION:
            Status = FuzzOpenProtocolInformation(Input);
            break;
        case PROTOCOLS_PER_HANDLE:
            Status = FuzzProtocolsPerHandle(Input);
            break;
        case LOCATE_HANDLE_BUFFER:
            Status = FuzzLocateHandleBuffer(Input);
            break;
        case INSTALL_PROTOCOL_INTERFACE:
            Status = FuzzInstallProtocolInterface(Input);
            break;
        case REINSTALL_PROTOCOL_INTERFACE:
            Status = FuzzReinstallProtocolInterface(Input);
            break;
        case UNINSTALL_PROTOCOL_INTERFACE:
            Status = FuzzUninstallProtocolInterface(Input);
            break;
        case INSTALL_MULTIPLE_PROTOCOL_INTERFACES:
            Status = FuzzInstallMultipleProtocolInterfaces(Input);
            break;
        case UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES:
            Status = FuzzUninstallMultipleProtocolInterfaces(Input);
            break;
    }
    return Status;
}

EFI_STATUS
EFIAPI
FuzzLocateProtocol(
    IN INPUT_BUFFER *Input
)
{
    DEBUG((DEBUG_ERROR, "FUZZING: LocateProtocol\n"));
    EFI_STATUS Status = EFI_SUCCESS;
    UINTN Temp;
    ReadInput(Input, 2, &Temp);
    EFI_GUID* ProtocolGuid = ProtocolGuidList[Temp%(sizeof(ProtocolGuidList)/sizeof(ProtocolGuidList[0]))];

    Status = gBS->LocateProtocol(ProtocolGuid, NULL, (VOID**)&list[Temp%(sizeof(ProtocolGuidList)/sizeof(ProtocolGuidList[0]))]);

    return Status;
}

EFI_STATUS
EFIAPI
FuzzOpenProtocol(
    IN INPUT_BUFFER *Input
)
{
    DEBUG((DEBUG_ERROR, "FUZZING: OpenProtocol\n"));
    EFI_STATUS Status = EFI_SUCCESS;
    // UINTN Temp;
    // UINT32 Attribute;
    // ReadInput(Input, 1, &Temp);
    // Attribute = ProtocolAttributes[Temp%(sizeof(ProtocolAttributes)/sizeof(ProtocolAttributes[0]))];
    // ReadInput(Input, 2, &Temp);
    // EFI_GUID* ProtocolGuid = ProtocolGuidList[Temp%(sizeof(ProtocolGuidList)/sizeof(ProtocolGuidList[0]))];
    //VOID *ProtocolInterface = ProtocolList[Temp%(sizeof(ProtocolList)/sizeof(ProtocolList[0]))];

    //Status = gBS->OpenProtocol(UserHandle, &ProtocolGuid, ProtocolInterface, ImageHandle, ControllerHandle, Attribute);

    /*
    switch(GetAttribute%6)
    {
        case 0:
            Attribute = EFI_OPEN_PROTOCOL_GET_PROTOCOL;
            break;
        case 1:
            Attribute = EFI_OPEN_PROTOCOL_BY_DRIVER;
            break;
        case 2:
            Attribute = EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER;
            break;
        case 3:
            Attribute = EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL;
            break;
        case 4:
            Attribute = EFI_OPEN_PROTOCOL_TEST_PROTOCOL;
            break;
        case 5:
            Attribute = EFI_OPEN_PROTOCOL_EXCLUSIVE;
            break;
    }
    */
    return Status;
}

EFI_STATUS
EFIAPI
FuzzCloseProtocol(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    return Status;
}

EFI_STATUS
EFIAPI
FuzzHandleProtocol(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    return Status;
}

EFI_STATUS
EFIAPI
FuzzOpenProtocolInformation(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    return Status;
}

EFI_STATUS
EFIAPI
FuzzProtocolsPerHandle(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    return Status;
}

EFI_STATUS
EFIAPI
FuzzLocateHandleBuffer(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    return Status;
}

EFI_STATUS
EFIAPI
FuzzInstallProtocolInterface(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    return Status;
}

EFI_STATUS
EFIAPI
FuzzReinstallProtocolInterface(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    return Status;
}

EFI_STATUS
EFIAPI
FuzzUninstallProtocolInterface(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    return Status;
}

EFI_STATUS
EFIAPI
FuzzInstallMultipleProtocolInterfaces(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    return Status;
}

EFI_STATUS
EFIAPI
FuzzUninstallMultipleProtocolInterfaces(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    return Status;
}