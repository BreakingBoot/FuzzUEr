#include "FuzzLoadImage.h"

EFI_STATUS
EFIAPI
FuzzLoadImage(
    IN INPUT_BUFFER *Input,
    IN EFI_HANDLE ParentImageHandle)
{
    /*
    if(Argc < 6)
    {
        Print(L"Need 5 Arguments for LoadImage\n");
    }
    */
    BOOLEAN BootPolicy;
    UINT8 tmp = 0;
    ReadInput(Input, 1, &tmp);
    BootPolicy = tmp%2;
    /*
    if(StrDecimalToUintn(Argv[3]))
    {
        Print(L"Entered IF\n");
        //VOID *SourceBuffer = ;
    }
    */

    VOID *SourceBuffer = NULL;
    UINT8* SourceSize = AllocatePool(sizeof(SourceSize)*8);
    ReadInput(Input, 8, SourceSize);
    UINT8* DriverSize = AllocatePool(sizeof(DriverSize)*8);
    ReadInput(Input, 8, DriverSize);
    // Create an empty DriverEntry
    // EFI_CORE_DRIVER_ENTRY *DriverEntry;
    // File GUID for SampleDriver
    EFI_GUID DriverName = {0xFE3542FE, 0xC1D3, 0x4EF8, {0x65, 0x7C, 0x80, 0x48, 0x60, 0x6F, 0xF6, 0x71}};
    EFI_STATUS Status;
    EFI_PEI_HOB_POINTERS HobFv;
    EFI_PEI_HOB_POINTERS DriverEntry;
    EFI_FIRMWARE_VOLUME2_PROTOCOL *Fv;
    EFI_HANDLE FvHandle;
    UINTN BufferSize;
    EFI_HANDLE *ImageHandle = NULL;

    // Link the empty DriverEntry to a Driver on in the HOB list
    // The drivers parameters will be modified to meet those
    // of the user input parameters

    BufferSize = sizeof(EFI_FIRMWARE_VOLUME2_PROTOCOL);
    Print(L"Current BufferSize = %d\n", BufferSize);
    Status = gBS->LocateHandle(
        ByProtocol,
        &gEfiFirmwareVolume2ProtocolGuid,
        NULL,
        &BufferSize,
        &FvHandle);
    if (EFI_ERROR(Status))
    {
        //
        // If no more notification events exit
        //
        Print(L"Required BufferSize = %d\n", BufferSize);
        Print(L"Couldn't Locate Handle: %r\n", Status);
        return Status;
    }
    Status = gBS->HandleProtocol(FvHandle, &gEfiFirmwareVolume2ProtocolGuid, (VOID **)&Fv);

    HobFv.Raw = GetHobList();

    // Loop through all of the HOBs until the Sample Driver is found
    while ((HobFv.Raw = GetNextHob(EFI_HOB_TYPE_FV, HobFv.Raw)) != NULL)
    {
        // Check if the Driver name and the FV name match
        if (CompareGuid(&DriverName, &HobFv.FirmwareVolume2->FileName) /* &&
              CompareGuid(FvNameGuid, &HobFv.FirmwareVolume2->FvName)*/
        )
        {
            // if you found the Driver you were looking for
            // save it to the DriverEntry and break the loop
            DriverEntry = HobFv;
            break;
        }
        HobFv.Raw = GET_NEXT_HOB(HobFv);
    }

    // Modify the Sample Driver to match the user input parameters
    // Like Driver size
    DriverEntry.FirmwareVolume->Length = *(UINTN *)DriverSize;

    // Run the CoreLoadImage to load the modified Driver to fuzz
    // the service
    Status = gBS->LoadImage(BootPolicy,
                            ParentImageHandle,
                            CoreFvToDevicePath(Fv, FvHandle, &DriverName),
                            SourceBuffer,
                            *(UINTN *)SourceSize,
                            ImageHandle);

    return Status;
}
