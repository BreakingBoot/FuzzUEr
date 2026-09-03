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
        AsanSetFuzzingActive(FALSE);
    }

    Input.Buffer = buffer;
    Input.Length = InputSize;

    UINT8 SequenceLength = 0;
    UINTN Step = 0;
    UINTN Steps = 0;
    ReadBytes(&Input, sizeof(SequenceLength), (VOID *)&SequenceLength);
    Steps = (UINTN)(SequenceLength % 8) + 1;

    UINTN Choices = 20;
    for (Step = 0; Step < Steps; Step++) {
        UINT8 DriverChoice = 0;
        if (Step > 0 && Input.Length == 0) {
            break;
        }
        ReadBytes(&Input, sizeof(DriverChoice), (VOID *)&DriverChoice);
        Choices = (Step == 0) ? 3 : 20;
        switch(DriverChoice % Choices)
        {
            case 0:
                Status = FuzzRegisterPackageNotify(&Input, SystemTable, ImageHandle);
                break;
            case 1:
                Status = FuzzSetKeyboardLayout(&Input, SystemTable, ImageHandle);
                break;
            case 2:
                Status = FuzzSetString(&Input, SystemTable, ImageHandle);
                break;
            case 3:
                Status = FuzzExportPackageLists(&Input, SystemTable, ImageHandle);
                break;
            case 4:
                Status = FuzzGetPackageListHandle(&Input, SystemTable, ImageHandle);
                break;
            case 5:
                Status = FuzzUnregisterPackageNotify(&Input, SystemTable, ImageHandle);
                break;
            case 6:
                Status = FuzzGetKeyboardLayout(&Input, SystemTable, ImageHandle);
                break;
            case 7:
                Status = FuzzNewPackageList(&Input, SystemTable, ImageHandle);
                break;
            case 8:
                Status = FuzzRemovePackageList(&Input, SystemTable, ImageHandle);
                break;
            case 9:
                Status = FuzzListPackageLists(&Input, SystemTable, ImageHandle);
                break;
            case 10:
                Status = FuzzUpdatePackageList(&Input, SystemTable, ImageHandle);
                break;
            case 11:
                Status = FuzzNewString(&Input, SystemTable, ImageHandle);
                break;
            case 12:
                Status = FuzzGetString(&Input, SystemTable, ImageHandle);
                break;
            case 13:
                Status = FuzzGetLanguages(&Input, SystemTable, ImageHandle);
                break;
            case 14:
                Status = FuzzStringToImage(&Input, SystemTable, ImageHandle);
                break;
            case 15:
                Status = FuzzGetGlyph(&Input, SystemTable, ImageHandle);
                break;
            case 16:
                Status = FuzzFindKeyboardLayouts(&Input, SystemTable, ImageHandle);
                break;
            case 17:
                Status = FuzzGetSecondaryLanguages(&Input, SystemTable, ImageHandle);
                break;
            case 18:
                Status = FuzzStringIdToImage(&Input, SystemTable, ImageHandle);
                break;
            case 19:
                Status = FuzzGetFontInfo(&Input, SystemTable, ImageHandle);
                break;
        }
    }

    HARNESS_STOP();

    return Status;
}
