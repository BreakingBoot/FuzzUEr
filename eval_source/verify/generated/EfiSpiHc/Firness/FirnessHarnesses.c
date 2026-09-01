#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called ChipSelect.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzChipSelect(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SPI_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSpiHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN ChipSelect_Arg_2 = FALSE;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ChipSelect_Arg_2), (VOID *)&ChipSelect_Arg_2);
    
    Status = ProtocolVariable->ChipSelect(
        ProtocolVariable,
        NULL,
        ChipSelect_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Clock.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzClock(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SPI_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSpiHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 * Clock_Arg_2 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    
    // Fuzzable Variable Initialization
    UINT8 Clock_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(Clock_Arg_2_choice), (VOID *)&Clock_Arg_2_choice);
    switch(Clock_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Clock_Arg_2), (VOID *)Clock_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(Clock_Arg_2);
            Clock_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->Clock(
        ProtocolVariable,
        NULL,
        Clock_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Transaction.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzTransaction(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SPI_HC_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSpiHcProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Transaction(
        ProtocolVariable,
        NULL
    );
    return Status;
}

