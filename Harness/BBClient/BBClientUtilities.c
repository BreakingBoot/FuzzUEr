#include "BBClientUtilities.h"

LIST_ENTRY  mDiscoveredList = INITIALIZE_LIST_HEAD_VARIABLE (mDiscoveredList);

typedef struct
{
    MEDIA_FW_VOL_FILEPATH_DEVICE_PATH File;
    EFI_DEVICE_PATH_PROTOCOL End;
} FV_FILEPATH_DEVICE_PATH;

FV_FILEPATH_DEVICE_PATH mFvDevicePath;

// Help Menu to display correct format and available services to fuzz
EFI_STATUS
EFIAPI
HelpMenu()
{
    Print(L"Usage: BBClient.efi <Function to Fuzz> [Parameters for function] \n \
          <Functions to Fuzz>: 0 - ProcessFirmwareVolume\n \
                               1 - CloseEvent\n \
                               2 - LoadImage\n \
                               3 - SmmHarden\n \
                               4 - Example1\n \
                               ");
    return EFI_SUCCESS;
}

VOID
EFIAPI
ReadInput(
    IN INPUT_BUFFER *InputBuffer,
    IN UINTN NumBytes,
    OUT UINT8 *Buffer)
{
    if(InputBuffer == NULL || Buffer == NULL)
    {
        return;
    }
    //CHAR16* tmp = AllocateRuntimeZeroPool(sizeof(*tmp)*NumBytes);
    for(UINTN i = 0; i < NumBytes; i++)
    {
        ReadByte(InputBuffer, Buffer + i);
    }
}

VOID
EFIAPI
ReadByte(
    IN INPUT_BUFFER *InputBuffer,
    OUT UINT8 *Buffer)
{
    if (InputBuffer->Length > 0 )
    {
        CopyMem(Buffer, InputBuffer->Buffer, 1);
        InputBuffer->Buffer ++;
        InputBuffer->Length --;
        
    }
    else
    {
        ZeroMem(Buffer, 1);
    }
}

UINTN
EFIAPI
Strlen(
    IN CHAR16 *Buffer)
{
    UINTN count = 0;
    while (Buffer[count])
    {
        count++;
    }

    return count;
}

EFI_DEVICE_PATH_PROTOCOL *
CoreFvToDevicePath(
    IN EFI_FIRMWARE_VOLUME2_PROTOCOL *Fv,
    IN EFI_HANDLE FvHandle,
    IN EFI_GUID *DriverName)
{
    EFI_STATUS Status;
    EFI_DEVICE_PATH_PROTOCOL *FvDevicePath;
    EFI_DEVICE_PATH_PROTOCOL *FileNameDevicePath;

    //
    // Remember the device path of the FV
    //
    Status = gBS->HandleProtocol(FvHandle, &gEfiDevicePathProtocolGuid, (VOID **)&FvDevicePath);
    if (EFI_ERROR(Status))
    {
        FileNameDevicePath = NULL;
    }
    else
    {
        //
        // Build a device path to the file in the FV to pass into gBS->LoadImage
        //
        EfiInitializeFwVolDevicepathNode(&mFvDevicePath.File, DriverName);
        SetDevicePathEndNode(&mFvDevicePath.End);

        FileNameDevicePath = AppendDevicePath(
            FvDevicePath,
            (EFI_DEVICE_PATH_PROTOCOL *)&mFvDevicePath);
    }

    return FileNameDevicePath;
}
/*
EFI_DEVICE_PATH_PROTOCOL *
DevicePathFromHandle (
   EFI_HANDLE                      Handle
  )
{
  EFI_DEVICE_PATH_PROTOCOL  *DevicePath;
  EFI_STATUS                Status;

  Status = gBS->HandleProtocol (
                  Handle,
                  &gEfiDevicePathProtocolGuid,
                  (VOID *) &DevicePath
                  );
  if (EFI_ERROR (Status)) {
    DevicePath = NULL;
  }
  return DevicePath;
}
*/

UINT16
FvBufCalculateSum16(
    IN UINT16 *Buffer,
    IN UINTN Size)
{
    UINTN Index;
    UINT16 Sum;

    Sum = 0;

    //
    // Perform the word sum for buffer
    //
    for (Index = 0; Index < Size; Index++)
    {
        Sum = (UINT16)(Sum + Buffer[Index]);
    }

    return (UINT16)Sum;
}

UINT16
FvBufCalculateChecksum16(
    IN UINT16 *Buffer,
    IN UINTN Size)
{
    return (UINT16)(0x10000 - FvBufCalculateSum16(Buffer, Size));
}

EFI_FIRMWARE_VOLUME_HEADER
EFIAPI
CreateDummyFirmwareVolume(
    IN EFI_FVB_ATTRIBUTES_2 InputAttributes,
    IN UINT64 InputLength,
    IN UINT32 NumBlocks,
    IN UINT32 BlockLength)
{
    EFI_FIRMWARE_VOLUME_HEADER FwHeader;
    EFI_PEI_HOB_POINTERS FvHob;
    EFI_FIRMWARE_VOLUME_HEADER *FwHeaderNormal;
    FvHob.Raw = GetHobList();
    FvHob.Raw = GetNextHob(EFI_HOB_TYPE_FV, FvHob.Raw);
    FwHeaderNormal = (EFI_FIRMWARE_VOLUME_HEADER *)(UINTN)((EFI_PHYSICAL_ADDRESS)(UINTN)FvHob.FirmwareVolume->BaseAddress);

    EFI_GUID Guid = FwHeaderNormal->FileSystemGuid;
    // FW Header Info
    // COMPLETED
    EFI_FV_BLOCK_MAP_ENTRY InitialBlockMap;
    InitialBlockMap.Length = MAX_UINT32;
    InitialBlockMap.NumBlocks = MAX_UINT32;
    EFI_FV_BLOCK_MAP_ENTRY BlockMap;
    BlockMap.Length = BlockLength;
    BlockMap.NumBlocks = NumBlocks;
    EFI_FV_BLOCK_MAP_ENTRY EmptyBlock;
    EmptyBlock.Length = 0;
    EmptyBlock.NumBlocks = 0;
    UINT64 FvLength = InputLength;
    UINT32 Signature = EFI_FVH_SIGNATURE;
    EFI_FVB_ATTRIBUTES_2 Attributes = InputAttributes;
    UINT8 Reserved = 0;
    UINT8 Revision = EFI_FVH_REVISION;
    UINT16 HeaderLength = (UINT16)(((UINTN) & (FwHeader)) - (UINTN)InputLength);
    DEBUG((DEBUG_ERROR, "FUZZING: Checksum\n"));
    UINT16 Checksum = FvBufCalculateChecksum16((UINT16 *)&FwHeader, HeaderLength / sizeof(UINT16));
    EFI_GUID FileSystemGuid = Guid;

    // INCOMPLETED
    UINT16 ExtHeaderOffset = 0; // May need to change

    DEBUG((DEBUG_ERROR, "FUZZING: There\n"));
    gBS->SetMem(&(FwHeader.ZeroVector), 16, 0);
    FwHeader.FileSystemGuid = FileSystemGuid;
    FwHeader.FvLength = FvLength;
    FwHeader.Signature = Signature;
    FwHeader.Attributes = Attributes;
    FwHeader.HeaderLength = HeaderLength;
    FwHeader.Checksum = Checksum;
    FwHeader.ExtHeaderOffset = ExtHeaderOffset;
    FwHeader.Reserved[0] = Reserved;
    FwHeader.Revision = Revision;

    FwHeader.BlockMap[0] = InitialBlockMap;
    FwHeader.BlockMap[1] = BlockMap;
    FwHeader.BlockMap[2] = EmptyBlock;
    return FwHeader;
}


EFI_STATUS
EFIAPI
CreateDummyEvent(
    IN INPUT_BUFFER *Input,
    OUT EFI_EVENT *DummyEvent
)
{
    UINT8 UserType = 0;
    ReadInput(Input, 8, &UserType);
    UINT8 UserTpl = 0;
    ReadInput(Input, 8, &UserTpl);

    EFI_STATUS Status;
    UINT32 Type;
    EFI_TPL NotifyTpl;
    EFI_EVENT_NOTIFY NotifyFunction; // Optional
    VOID *NotifyContext;             // Optional

    //
    // Set the values for the DummyEvent to create
    //
    // Random Notify Type
    switch (UserType % 8)
    {
    case 0:
        Type = EVT_TIMER | EVT_NOTIFY_SIGNAL;
        break;
    case 1:
        Type = EVT_TIMER;
        break;
    case 2:
        Type = EVT_NOTIFY_WAIT;
        break;
    case 3:
        Type = EVT_NOTIFY_SIGNAL;
        break;
    case 4:
        Type = EVT_SIGNAL_EXIT_BOOT_SERVICES;
        break;
    case 5:
        Type = EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE;
        break;
    case 6:
        Type = 0x00000000;
        break;
    case 7:
        Type = EVT_TIMER | EVT_NOTIFY_WAIT;
        break;
    }
    // Needs to be of type TPL_APPLICATION, TPL_CALLBACK, and TPL_NOTIFY
    switch(UserTpl%3)
    {
        case 0:
            NotifyTpl = TPL_APPLICATION;
            break;
        case 1:
            NotifyTpl = TPL_CALLBACK;
            break;
        case 2:
            NotifyTpl = TPL_NOTIFY;
            break;
    }
    //NotifyTpl = (EFI_TPL)UserTpl;
    // Set as NULL but can be set to a custom value
    NotifyFunction = EfiEventEmptyFunction;
    NotifyContext = NULL;
    DEBUG((DEBUG_ERROR, "FUZZING: CreateEvent(\n"));
    DEBUG((DEBUG_ERROR, "                     Type = 0x%x,\n", Type));
    DEBUG((DEBUG_ERROR, "                     NotifyTpl = %r,\n", NotifyTpl));
    DEBUG((DEBUG_ERROR, "                     NotifyFunction = %d,\n", NotifyFunction));
    DEBUG((DEBUG_ERROR, "                     NotifyContext = %d)\n", NotifyContext));
    Status = gBS->CreateEvent(Type, NotifyTpl, NotifyFunction, NotifyContext, DummyEvent);
    return Status;
}