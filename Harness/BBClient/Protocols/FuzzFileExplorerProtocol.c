#include "FuzzFileExplorerProtocol.h"

EFI_STATUS
EFIAPI
FuzzFileExplorerProtocol(
    IN INPUT_BUFFER* Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: FileExplorerProtocol\n"));
    Status = FuzzChooseFile(Input);

    return Status;
}

EFI_STATUS
EFIAPI
FuzzChooseFile(
    IN INPUT_BUFFER* Input
)
{
    EFI_STATUS Status = EFI_STATUS;
    DEBUG((DEBUG_ERROR, "FUZZING: ChooseFile\n"));
    EFI_DEVICE_PATH_PROTOCOL  *File;
    EFI_FILE_EXPLORER_PROTOCOL *FileExplorerProtocol;

    CHOOSE_HANDLER Handler = NULL;
    UINTN HandleChoice = 0;
    ReadInput(Input, 1, &HandleChoice);
    switch(HandleChoice%10)
    {
        case 0:
            Handler = CreateBootOptionFromFile;
            break;
        case 1:
            Handler = CreateDriverOptionFromFile;
            break;
        case 2:
            Handler = UpdateCAFromFile;
            break;
        case 3:
            Handler = BootFromFile;
            break;
        case 4:
            Handler = UpdatePKFromFile;
            break;
        case 5:
            Handler = UpdateKEKFromFile;
            break;
        case 6:
            Handler = UpdateDBFromFile;
            break;
        case 7:
            Handler = UpdateDBXFromFile;
            break;
        case 8:
            Handler = UpdateDBTFromFile;
            break;
    }

    CHAR16 *FileType = NULL;
    UINTN Type = 0;
    ReadInput(Input, 1, &Type);
    if(Type%2)
    {
        FileType = L".efi";
    }

    gBS->LocateProtocol(&gEfiFileExplorerProtocolGuid, NULL, (VOID *)&FileExplorerProtocol);
    Status = FileExplorerProtocol->ChooseFile(NULL, FileType, Handler, &File);

    return Status;
}

