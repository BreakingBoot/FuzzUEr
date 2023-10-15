#include "FuzzProcessFirmwareVolume.h"

EFI_STATUS
EFIAPI
FuzzProcessFirmwareVolume(
    IN INPUT_BUFFER *Input)
{
    EFI_STATUS Status = EFI_SUCCESS;
    // EFI_FIRMWARE_VOLUME_HEADER *FwHeader;
    EFI_HANDLE FvProtocolHandle;
    /*
    if(Argc != 6)
          {
            Print(L"Need 5 Arguments for ProcessFirmwareImage\n");
            Print(L"BBClient.efi 0 <InputLength> <InputAttributes> <NumBlocks> <BlockLength>\n");
            Print(L"    <InputLength>     : Firmware Volume Image Length\n");
            Print(L"    <InputAttributes> : Specific FV attributes\n");
            Print(L"    <NumBlocks>       : Number of Blocks for FV BlockMap\n");
            Print(L"    <BlockLength>     : Length of each Block in the BlockMap\n");
            break;
          }
      */
    UINT8* temp = AllocatePool(sizeof(UINTN));
    UINTN InputLength;
    ReadInput(Input, 8, temp);
    InputLength = *(UINTN *)temp;
    EFI_FVB_ATTRIBUTES_2 InputAttributes;
    ReadInput(Input, 8, temp);
    InputAttributes = (EFI_FVB_ATTRIBUTES_2)*(UINTN *)temp;
    UINT32 NumBlocks;
    ReadInput(Input, 4, temp);
    NumBlocks = *(UINT32 *)temp;
    UINT32 BlockLength;
    ReadInput(Input, 4, temp);
    BlockLength = *(UINT32 *)temp;

    EFI_FIRMWARE_VOLUME_HEADER FwHeader;
    EFI_PEI_HOB_POINTERS FvHob;
    EFI_FIRMWARE_VOLUME_HEADER *FwHeaderNormal;
    FvHob.Raw = GetHobList();
    FvHob.Raw = GetNextHob(EFI_HOB_TYPE_FV, FvHob.Raw);
    FwHeaderNormal = (EFI_FIRMWARE_VOLUME_HEADER *)(UINTN)((EFI_PHYSICAL_ADDRESS)(UINTN)FvHob.FirmwareVolume->BaseAddress);

    EFI_GUID Guid = FwHeaderNormal->FileSystemGuid;
    // FW Header Info
    // COMPLETED
    EFI_FV_BLOCK_MAP_ENTRY InitialBlockMap;// = AllocateZeroPool(sizeof(EFI_FV_BLOCK_MAP_ENTRY)*5);
    InitialBlockMap.Length = BlockLength;
    InitialBlockMap.NumBlocks = NumBlocks;
    EFI_FV_BLOCK_MAP_ENTRY BlockMap;
    //BlockMap.Length = BlockLength;
    //BlockMap.NumBlocks = NumBlocks;
    BlockMap.Length = MAX_UINT32;
    BlockMap.NumBlocks = MAX_UINT32;
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
    UINT16 ExtHeaderOffset = 0; // May need to change

    // Set All of the information in the FW Volume header
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
    //*FwHeader = CreateDummyFirmwareVolume(InputAttributes, InputLength, NumBlocks, BlockLength);
    /*
    DEBUG ((DEBUG_ERROR, "FUZZING: ZeroVector - %d\n", FwHeader->ZeroVector[0]));
    DEBUG ((DEBUG_ERROR, "FUZZING: FileSystemGuid - %x\n", FwHeader->FileSystemGuid));
    DEBUG ((DEBUG_ERROR, "FUZZING: FvLength - %d\n", FwHeader->FvLength));
    DEBUG ((DEBUG_ERROR, "FUZZING: Signature - %d\n", FwHeader->Signature));
    DEBUG ((DEBUG_ERROR, "FUZZING: Attributes - %d\n", FwHeader->Attributes));
    DEBUG ((DEBUG_ERROR, "FUZZING: HeaderLength - %d\n", FwHeader->HeaderLength));
    DEBUG ((DEBUG_ERROR, "FUZZING: Checksum - %d\n", FwHeader->Checksum));
    DEBUG ((DEBUG_ERROR, "FUZZING: ExtHeaderOffset - %d\n", FwHeader->ExtHeaderOffset));
    DEBUG ((DEBUG_ERROR, "FUZZING: Reserved - %d\n", FwHeader->Reserved[0]));
    DEBUG ((DEBUG_ERROR, "FUZZING: Revision - %d\n", FwHeader->Revision));
    DEBUG ((DEBUG_ERROR, "FUZZING: BlockMap(NumBlocks) - %ld\n", FwHeader->BlockMap[0].NumBlocks));
    DEBUG ((DEBUG_ERROR, "FUZZING: BlockMap(Length) - %ld\n", BlockLength));
    DEBUG ((DEBUG_ERROR, "FUZZING: BlockMap(NumBlocks) - %d\n", NumBlocks));
    DEBUG ((DEBUG_ERROR, "FUZZING: BlockMap(Length) - %d\n", FwHeader->BlockMap[1].Length));
    */
    Status = gDS->ProcessFirmwareVolume((VOID *)&FwHeader, FwHeader.FvLength, &FvProtocolHandle);

    return Status;
}