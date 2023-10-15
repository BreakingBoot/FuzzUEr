#ifndef _FUZZLOADIMAGE_H_
#define _FUZZLOADIMAGE_H_

#include "BBClientUtilities.h"

EFI_STATUS
EFIAPI
FuzzLoadImage(
    IN INPUT_BUFFER *Input,
    IN EFI_HANDLE ParentImageHandle
);

#endif