#ifndef _FUZZFILEEXPLORERPROTOCOL_H_
#define _FUZZFILEEXPLORERPROTOCOL_H_

#include "../BBClientUtilities.h"


EFI_STATUS
EFIAPI
FuzzFileExplorerProtocol(
    IN INPUT_BUFFER* Input
);

EFI_STATUS
EFIAPI
FuzzChooseFile(
    IN INPUT_BUFFER* Input
);

#endif