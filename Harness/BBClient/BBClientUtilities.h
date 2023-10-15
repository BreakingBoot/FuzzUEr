#ifndef _BBCLIENTUTILITIES_H_
#define _BBCLIENTUTILITIES_H_

#include "BBClient.h"

extern LIST_ENTRY  mDiscoveredList;
//extern UINT32 AllVariableAttributes[] = {EFI_VARIABLE_NON_VOLATILE, EFI_VARIABLE_BOOTSERVICE_ACCESS, EFI_VARIABLE_RUNTIME_ACCESS, EFI_VARIABLE_HARDWARE_ERROR_RECORD, EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS, EFI_VARIABLE_APPEND_WRITE};

typedef struct {
  EFI_GUID     *ProtocolGuid;
  VOID         **Protocol;
  EFI_EVENT    Event;
  VOID         *Registration;
  BOOLEAN      Present;
} EFI_CORE_PROTOCOL_NOTIFY_ENTRY;

//
// DXE Dispatcher Data structures
//

#define KNOWN_HANDLE_SIGNATURE  SIGNATURE_32('k','n','o','w')
typedef struct {
  UINTN         Signature;
  LIST_ENTRY    Link;           // mFvHandleList
  EFI_HANDLE    Handle;
  EFI_GUID      FvNameGuid;
} KNOWN_HANDLE;

#define EFI_CORE_DRIVER_ENTRY_SIGNATURE  SIGNATURE_32('d','r','v','r')
typedef struct {
  UINTN                            Signature;
  LIST_ENTRY                       Link;            // mDriverList

  LIST_ENTRY                       ScheduledLink;   // mScheduledQueue

  EFI_HANDLE                       FvHandle;
  EFI_GUID                         FileName;
  EFI_DEVICE_PATH_PROTOCOL         *FvFileDevicePath;
  EFI_FIRMWARE_VOLUME2_PROTOCOL    *Fv;

  VOID                             *Depex;
  UINTN                            DepexSize;

  BOOLEAN                          Before;
  BOOLEAN                          After;
  EFI_GUID                         BeforeAfterGuid;

  BOOLEAN                          Dependent;
  BOOLEAN                          Unrequested;
  BOOLEAN                          Scheduled;
  BOOLEAN                          Untrusted;
  BOOLEAN                          Initialized;
  BOOLEAN                          DepexProtocolError;

  EFI_HANDLE                       ImageHandle;
  BOOLEAN                          IsFvImage;
} EFI_CORE_DRIVER_ENTRY;

//
// The data structure of GCD memory map entry
//
#define EFI_GCD_MAP_SIGNATURE  SIGNATURE_32('g','c','d','m')
typedef struct {
  UINTN                   Signature;
  LIST_ENTRY              Link;
  EFI_PHYSICAL_ADDRESS    BaseAddress;
  UINT64                  EndAddress;
  UINT64                  Capabilities;
  UINT64                  Attributes;
  EFI_GCD_MEMORY_TYPE     GcdMemoryType;
  EFI_GCD_IO_TYPE         GcdIoType;
  EFI_HANDLE              ImageHandle;
  EFI_HANDLE              DeviceHandle;
} EFI_GCD_MAP_ENTRY;


typedef struct {
  UINT8 *Buffer;
  UINTN Length;
} INPUT_BUFFER;

VOID
EFIAPI
ReadByte(
    IN INPUT_BUFFER *InputBuffer,
    OUT UINT8 *Buffer);

UINT16
FvBufCalculateChecksum16 (
  IN UINT16       *Buffer,
  IN UINTN        Size
  );


UINT16
FvBufCalculateSum16 (
  IN UINT16       *Buffer,
  IN UINTN        Size
  );

EFI_DEVICE_PATH_PROTOCOL *
CoreFvToDevicePath (
  IN  EFI_FIRMWARE_VOLUME2_PROTOCOL  *Fv,
  IN  EFI_HANDLE                     FvHandle,
  IN  EFI_GUID                       *DriverName
  );

VOID
EFIAPI
ReadInput(
  IN INPUT_BUFFER *InputBuffer,
  IN UINTN NumBytes,
  OUT UINT8 *Buffer
);

UINTN
EFIAPI
Strlen(
    IN CHAR16 *Buffer
);

EFI_STATUS
EFIAPI
HelpMenu ();

EFI_FIRMWARE_VOLUME_HEADER
EFIAPI
CreateDummyFirmwareVolume(
    IN EFI_FVB_ATTRIBUTES_2 InputAttributes,
    IN UINT64 InputLength,
    IN UINT32 NumBlocks,
    IN UINT32 BlockLength
);

EFI_STATUS
EFIAPI
CreateDummyEvent(
    IN INPUT_BUFFER *Input,
    OUT EFI_EVENT *DummyEvent
);

#endif