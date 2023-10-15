#ifndef _FUZZPROCESSFIRMWAREVOLUME_H_
#define _FUZZPROCESSFIRMWAREVOLUME_H_

#include "BBClientUtilities.h"

EFI_STATUS
EFIAPI
FuzzProcessFirmwareVolume(
    IN INPUT_BUFFER *Input
);

typedef struct {
  UINTN    Base;
  UINTN    Length;
} LBA_CACHE;

#endif