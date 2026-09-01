#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called BiosBaseAddress.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzBiosBaseAddress(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_LEGACY_SPI_FLASH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiLegacySpiFlashProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 BiosBaseAddress_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(BiosBaseAddress_Arg_1), (VOID *)&BiosBaseAddress_Arg_1);
    
    Status = ProtocolVariable->BiosBaseAddress(
        ProtocolVariable,
        BiosBaseAddress_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ClearSpiProtect.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzClearSpiProtect(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_LEGACY_SPI_FLASH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiLegacySpiFlashProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->ClearSpiProtect(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called IsRangeProtected.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzIsRangeProtected(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_LEGACY_SPI_FLASH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiLegacySpiFlashProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 IsRangeProtected_Arg_1 = 0;
    UINT32 IsRangeProtected_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(IsRangeProtected_Arg_1), (VOID *)&IsRangeProtected_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(IsRangeProtected_Arg_2), (VOID *)&IsRangeProtected_Arg_2);
    
    ProtocolVariable->IsRangeProtected(
        ProtocolVariable,
        IsRangeProtected_Arg_1,
        IsRangeProtected_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ProtectNextRange.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzProtectNextRange(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_LEGACY_SPI_FLASH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiLegacySpiFlashProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 ProtectNextRange_Arg_1 = 0;
    UINT32 ProtectNextRange_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ProtectNextRange_Arg_1), (VOID *)&ProtectNextRange_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ProtectNextRange_Arg_2), (VOID *)&ProtectNextRange_Arg_2);
    
    Status = ProtocolVariable->ProtectNextRange(
        ProtocolVariable,
        ProtectNextRange_Arg_1,
        ProtectNextRange_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called LockController.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzLockController(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_LEGACY_SPI_FLASH_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiLegacySpiFlashProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->LockController(
        ProtocolVariable
    );
    return Status;
}

