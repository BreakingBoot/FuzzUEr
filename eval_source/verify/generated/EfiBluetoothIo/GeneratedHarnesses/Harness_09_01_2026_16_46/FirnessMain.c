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
        switch(DriverChoice%11)
        {
            case 0:
                Status = FuzzGetDeviceInfo(&Input, SystemTable, ImageHandle);
                break;
            case 1:
                Status = FuzzGetSdpInfo(&Input, SystemTable, ImageHandle);
                break;
            case 2:
                Status = FuzzL2CapRawSend(&Input, SystemTable, ImageHandle);
                break;
            case 3:
                Status = FuzzL2CapRawReceive(&Input, SystemTable, ImageHandle);
                break;
            case 4:
                Status = FuzzL2CapRawAsyncReceive(&Input, SystemTable, ImageHandle);
                break;
            case 5:
                Status = FuzzL2CapSend(&Input, SystemTable, ImageHandle);
                break;
            case 6:
                Status = FuzzL2CapReceive(&Input, SystemTable, ImageHandle);
                break;
            case 7:
                Status = FuzzL2CapAsyncReceive(&Input, SystemTable, ImageHandle);
                break;
            case 8:
                Status = FuzzL2CapConnect(&Input, SystemTable, ImageHandle);
                break;
            case 9:
                Status = FuzzL2CapDisconnect(&Input, SystemTable, ImageHandle);
                break;
            case 10:
                Status = FuzzL2CapRegisterService(&Input, SystemTable, ImageHandle);
                break;
        }
    }

    HARNESS_STOP();

    return Status;
}
