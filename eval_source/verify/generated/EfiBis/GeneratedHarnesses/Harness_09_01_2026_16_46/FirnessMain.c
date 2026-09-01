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
        switch(DriverChoice%10)
        {
            case 0:
                Status = FuzzInitialize(&Input, SystemTable, ImageHandle);
                break;
            case 1:
                Status = FuzzShutdown(&Input, SystemTable, ImageHandle);
                break;
            case 2:
                Status = FuzzFree(&Input, SystemTable, ImageHandle);
                break;
            case 3:
                Status = FuzzGetBootObjectAuthorizationCertificate(&Input, SystemTable, ImageHandle);
                break;
            case 4:
                Status = FuzzGetBootObjectAuthorizationCheckFlag(&Input, SystemTable, ImageHandle);
                break;
            case 5:
                Status = FuzzGetBootObjectAuthorizationUpdateToken(&Input, SystemTable, ImageHandle);
                break;
            case 6:
                Status = FuzzGetSignatureInfo(&Input, SystemTable, ImageHandle);
                break;
            case 7:
                Status = FuzzUpdateBootObjectAuthorization(&Input, SystemTable, ImageHandle);
                break;
            case 8:
                Status = FuzzVerifyBootObject(&Input, SystemTable, ImageHandle);
                break;
            case 9:
                Status = FuzzVerifyObjectWithCredential(&Input, SystemTable, ImageHandle);
                break;
        }
    }

    HARNESS_STOP();

    return Status;
}
