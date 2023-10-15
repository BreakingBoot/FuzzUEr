#ifndef _FUZZMEMORY_H_
#define _FUZZMEMORY_H_

#include "Uefi/UefiSpec.h"
#include "BBClientUtilities.h"

#define ADD_MEMORY_SPACE 0
#define ALLOCATE_MEMORY_SPACE 1
#define FREE_MEMORY_SPACE 2
#define REMOVE_MEMORY_SPACE 3
#define GET_MEMORY_SPACE_DESCRIPTOR 4
#define SET_MEMORY_SPACE_ATTRIBUTES 5
#define GET_MEMORY_SPACE_MAP 6
#define SET_MEMORY_SPACE_CAPABILITIES 7
#define ALLOCATE_PAGES 8
#define FREE_PAGES 9
#define GET_MEMORY_MAP 10
#define ALLOCATE_POOL 11
#define FREE_POOL 12
#define COPY_MEM 13
#define SET_MEM 14

EFI_STATUS
EFIAPI
FuzzMemory(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzAddMemorySpace(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzAllocateMemorySpace(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzFreeMemorySpace(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzRemoveMemorySpace(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzGetMemorySpaceDescriptor(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzSetMemorySpaceAttributes(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzGetMemorySpaceMap(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzSetMemorySpaceCapabilities(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzAllocatePages(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzFreePages(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzGetMemoryMap(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzAllocatePool(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzFreePool(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzCopyMem(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzSetMem(
    IN INPUT_BUFFER *Input
);

#endif