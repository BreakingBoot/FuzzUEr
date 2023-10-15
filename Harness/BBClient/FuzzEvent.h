#ifndef _FUZZEVENT_H_
#define _FUZZEVENT_H_

#include "BBClientUtilities.h"

#define CLOSE_EVENT 0
#define CREATE_EVENT 1
#define SIGNAL_EVENT 2
#define CHECK_EVENT 3
#define WAIT_FOR_EVENT 4
#define CREATE_EVENT_EX 5

EFI_STATUS
EFIAPI
FuzzEvent(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzCloseEvent(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzCreateEvent(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzSignalEvent(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzCheckEvent(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzWaitForEvent(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzCreateEventEx(
    IN INPUT_BUFFER *Input
);

#endif