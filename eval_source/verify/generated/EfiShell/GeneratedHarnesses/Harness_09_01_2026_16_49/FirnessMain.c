#include "FirnessHarnesses.h"
#include "FirnessBackend.h"

INPUT_BUFFER Input;

extern VOID AsanSetFuzzingActive(BOOLEAN Active) __attribute__((weak));

__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FirnessMain (
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable
) {
    EFI_STATUS Status = EFI_SUCCESS;

    UINTN MaxInputSize = 0x1000;
    UINT8 *buffer = (UINT8 *)AllocatePages(EFI_SIZE_TO_PAGES(MaxInputSize));
    UINTN InputSize = MaxInputSize;

    if (buffer == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }

    HARNESS_START(buffer, &InputSize);

    if (AsanSetFuzzingActive != NULL) {
        AsanSetFuzzingActive(TRUE);
    }

    Input.Buffer = buffer;
    Input.Length = InputSize;

    UINT8 SequenceLength = 0;
    UINTN Step = 0;
    UINTN Steps = 0;
    ReadBytes(&Input, sizeof(SequenceLength), (VOID *)&SequenceLength);
    Steps = (UINTN)(SequenceLength % 8) + 1;

    for (Step = 0; Step < Steps; Step++) {
        UINT8 DriverChoice = 0;
        if (Step > 0 && Input.Length == 0) {
            break;
        }
        ReadBytes(&Input, sizeof(DriverChoice), (VOID *)&DriverChoice);
        switch(DriverChoice%43)
        {
            case 0:
                Status = FuzzDisablePageBreak(&Input, SystemTable, ImageHandle);
                break;
            case 1:
                Status = FuzzGetPageBreak(&Input, SystemTable, ImageHandle);
                break;
            case 2:
                Status = FuzzRemoveDupInFileList(&Input, SystemTable, ImageHandle);
                break;
            case 3:
                Status = FuzzExecute(&Input, SystemTable, ImageHandle);
                break;
            case 4:
                Status = FuzzGetEnv(&Input, SystemTable, ImageHandle);
                break;
            case 5:
                Status = FuzzSetEnv(&Input, SystemTable, ImageHandle);
                break;
            case 6:
                Status = FuzzGetAlias(&Input, SystemTable, ImageHandle);
                break;
            case 7:
                Status = FuzzSetAlias(&Input, SystemTable, ImageHandle);
                break;
            case 8:
                Status = FuzzGetHelpText(&Input, SystemTable, ImageHandle);
                break;
            case 9:
                Status = FuzzGetDevicePathFromMap(&Input, SystemTable, ImageHandle);
                break;
            case 10:
                Status = FuzzGetMapFromDevicePath(&Input, SystemTable, ImageHandle);
                break;
            case 11:
                Status = FuzzGetDevicePathFromFilePath(&Input, SystemTable, ImageHandle);
                break;
            case 12:
                Status = FuzzGetFilePathFromDevicePath(&Input, SystemTable, ImageHandle);
                break;
            case 13:
                Status = FuzzSetMap(&Input, SystemTable, ImageHandle);
                break;
            case 14:
                Status = FuzzGetCurDir(&Input, SystemTable, ImageHandle);
                break;
            case 15:
                Status = FuzzSetCurDir(&Input, SystemTable, ImageHandle);
                break;
            case 16:
                Status = FuzzOpenFileList(&Input, SystemTable, ImageHandle);
                break;
            case 17:
                Status = FuzzFreeFileList(&Input, SystemTable, ImageHandle);
                break;
            case 18:
                Status = FuzzBatchIsActive(&Input, SystemTable, ImageHandle);
                break;
            case 19:
                Status = FuzzIsRootShell(&Input, SystemTable, ImageHandle);
                break;
            case 20:
                Status = FuzzEnablePageBreak(&Input, SystemTable, ImageHandle);
                break;
            case 21:
                Status = FuzzGetDeviceName(&Input, SystemTable, ImageHandle);
                break;
            case 22:
                Status = FuzzGetFileInfo(&Input, SystemTable, ImageHandle);
                break;
            case 23:
                Status = FuzzSetFileInfo(&Input, SystemTable, ImageHandle);
                break;
            case 24:
                Status = FuzzOpenFileByName(&Input, SystemTable, ImageHandle);
                break;
            case 25:
                Status = FuzzCloseFile(&Input, SystemTable, ImageHandle);
                break;
            case 26:
                Status = FuzzCreateFile(&Input, SystemTable, ImageHandle);
                break;
            case 27:
                Status = FuzzReadFile(&Input, SystemTable, ImageHandle);
                break;
            case 28:
                Status = FuzzWriteFile(&Input, SystemTable, ImageHandle);
                break;
            case 29:
                Status = FuzzDeleteFile(&Input, SystemTable, ImageHandle);
                break;
            case 30:
                Status = FuzzDeleteFileByName(&Input, SystemTable, ImageHandle);
                break;
            case 31:
                Status = FuzzGetFilePosition(&Input, SystemTable, ImageHandle);
                break;
            case 32:
                Status = FuzzSetFilePosition(&Input, SystemTable, ImageHandle);
                break;
            case 33:
                Status = FuzzFlushFile(&Input, SystemTable, ImageHandle);
                break;
            case 34:
                Status = FuzzFindFiles(&Input, SystemTable, ImageHandle);
                break;
            case 35:
                Status = FuzzFindFilesInDir(&Input, SystemTable, ImageHandle);
                break;
            case 36:
                Status = FuzzGetFileSize(&Input, SystemTable, ImageHandle);
                break;
            case 37:
                Status = FuzzOpenRoot(&Input, SystemTable, ImageHandle);
                break;
            case 38:
                Status = FuzzOpenRootByHandle(&Input, SystemTable, ImageHandle);
                break;
            case 39:
                Status = FuzzRegisterGuidName(&Input, SystemTable, ImageHandle);
                break;
            case 40:
                Status = FuzzGetGuidName(&Input, SystemTable, ImageHandle);
                break;
            case 41:
                Status = FuzzGetGuidFromName(&Input, SystemTable, ImageHandle);
                break;
            case 42:
                Status = FuzzGetEnvEx(&Input, SystemTable, ImageHandle);
                break;
        }
    }

    HARNESS_STOP();

    return Status;
}
