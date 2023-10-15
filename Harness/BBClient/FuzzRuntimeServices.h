#ifndef _FUZZRUNTIMESERVICES_H_
#define _FUZZRUNTIMESERVICES_H_

#include "BBClientUtilities.h"

#define GET_TIME 0
#define SET_TIME 1
#define GET_WAKEUP_TIME 2
#define SET_WAKEUP_TIME 3
#define SET_VIRTUAL_ADDRESS_MAP 4
#define CONVERT_POINTER 5
#define GET_VARIABLE 6
#define SET_VARIABLE 7
#define GET_NEXT_VARIABLE_NAME 8
#define GET_NEXT_HIGH_MONOTONIC_COUNT 9
#define RESET_SYSTEM 10
#define UPDATE_CAPSULE 11
#define QUERY_CAPSULE_CAPABILITIES 12
#define QUERY_VARIABLE_INFO 13

EFI_STATUS
EFI_API
FuzzRuntimeServices(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzGetTime(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzSetTime(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzGetWakeupTime(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzSetWakeupTime(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzSetVirtualAddressMap(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzConvertPointer(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzGetVariable(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzSetVariable(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzGetNextVariableName(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzGetNextHighMonotonicCount(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzResetSystem(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzUpdateCapsule(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzQueryCapsuleCapabilities(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzQueryVariableInfo(
    IN INPUT_BUFFER *Input
);

#endif