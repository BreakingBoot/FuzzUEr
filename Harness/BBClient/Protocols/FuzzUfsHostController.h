#ifndef _FUZZUFSHOSTCONTROLLER_H_
#define _FUZZUFSHOSTCONTROLLER_H_

#include "../BBClientUtilities.h"

#define GET_UFS_HC_MMIO_BAR 0
#define ALLOCATE_BUFFER 1
#define FREE_BUFFER 2
#define MAP 3
#define UNMAP 4
#define FLUSH 5
#define MMIO_READ 6
#define MMIO_WRITE 7

EFI_STATUS
EFIAPI
FuzzUfsHostController(
    IN INPUT_BUFFER* Input
);

EFI_STATUS
EFIAPI
FuzzGetUfsHcMmioBar(
    IN INPUT_BUFFER* Input
);


EFI_STATUS
EFIAPI
FuzzAllocateBuffer(
    IN INPUT_BUFFER* Input
);

EFI_STATUS
EFIAPI
FuzzFreeBuffer(
    IN INPUT_BUFFER* Input
);


EFI_STATUS
EFIAPI
FuzzMap(
    IN INPUT_BUFFER* Input
);

EFI_STATUS
EFIAPI
FuzzUnmap(
    IN INPUT_BUFFER* Input
);


EFI_STATUS
EFIAPI
FuzzFlush(
    IN INPUT_BUFFER* Input
);

EFI_STATUS
EFIAPI
FuzzRead(
    IN INPUT_BUFFER* Input
);


EFI_STATUS
EFIAPI
FuzzWrite(
    IN INPUT_BUFFER* Input
);

#endif