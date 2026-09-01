#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called SCardConnect.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSCardConnect(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMART_CARD_READER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmartCardReaderProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 SCardConnect_Arg_1 = 0;
    UINT32 SCardConnect_Arg_2 = 0;
    UINT32 SCardConnect_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SCardConnect_Arg_1), (VOID *)&SCardConnect_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SCardConnect_Arg_2), (VOID *)&SCardConnect_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SCardConnect_Arg_3), (VOID *)&SCardConnect_Arg_3);
    
    /*
        Output Variable(s)
    */
    UINT32 * SCardConnect_Arg_4 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT8* SCardConnect_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SCardConnect_Arg_4_OutputChoice), (VOID *)SCardConnect_Arg_4_OutputChoice);
    if(*SCardConnect_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*SCardConnect_Arg_4), (VOID *)SCardConnect_Arg_4);
    }
    Status = ProtocolVariable->SCardConnect(
        ProtocolVariable,
        SCardConnect_Arg_1,
        SCardConnect_Arg_2,
        SCardConnect_Arg_3,
        SCardConnect_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SCardDisconnect.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSCardDisconnect(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMART_CARD_READER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmartCardReaderProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 SCardDisconnect_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SCardDisconnect_Arg_1), (VOID *)&SCardDisconnect_Arg_1);
    
    Status = ProtocolVariable->SCardDisconnect(
        ProtocolVariable,
        SCardDisconnect_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SCardStatus.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSCardStatus(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMART_CARD_READER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmartCardReaderProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->SCardStatus(
        ProtocolVariable,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SCardTransmit.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSCardTransmit(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMART_CARD_READER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmartCardReaderProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 * SCardTransmit_Arg_1 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINTN SCardTransmit_Arg_2 = 0;
    UINTN * SCardTransmit_Arg_4 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    UINT8 SCardTransmit_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(SCardTransmit_Arg_1_choice), (VOID *)&SCardTransmit_Arg_1_choice);
    switch(SCardTransmit_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SCardTransmit_Arg_1), (VOID *)SCardTransmit_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(SCardTransmit_Arg_1);
            SCardTransmit_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SCardTransmit_Arg_2), (VOID *)&SCardTransmit_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 SCardTransmit_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(SCardTransmit_Arg_4_choice), (VOID *)&SCardTransmit_Arg_4_choice);
    switch(SCardTransmit_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SCardTransmit_Arg_4), (VOID *)SCardTransmit_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(SCardTransmit_Arg_4);
            SCardTransmit_Arg_4 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    UINT8 * SCardTransmit_Arg_3 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT8* SCardTransmit_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SCardTransmit_Arg_3_OutputChoice), (VOID *)SCardTransmit_Arg_3_OutputChoice);
    if(*SCardTransmit_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*SCardTransmit_Arg_3), (VOID *)SCardTransmit_Arg_3);
    }
    Status = ProtocolVariable->SCardTransmit(
        ProtocolVariable,
        SCardTransmit_Arg_1,
        SCardTransmit_Arg_2,
        SCardTransmit_Arg_3,
        SCardTransmit_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SCardControl.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSCardControl(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMART_CARD_READER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmartCardReaderProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 SCardControl_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SCardControl_Arg_1), (VOID *)&SCardControl_Arg_1);
    
    Status = ProtocolVariable->SCardControl(
        ProtocolVariable,
        SCardControl_Arg_1,
        NULL,
        (UINTN){0},
        NULL,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SCardGetAttrib.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSCardGetAttrib(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMART_CARD_READER_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmartCardReaderProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 SCardGetAttrib_Arg_1 = 0;
    UINTN * SCardGetAttrib_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SCardGetAttrib_Arg_1), (VOID *)&SCardGetAttrib_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 SCardGetAttrib_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(SCardGetAttrib_Arg_3_choice), (VOID *)&SCardGetAttrib_Arg_3_choice);
    switch(SCardGetAttrib_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SCardGetAttrib_Arg_3), (VOID *)SCardGetAttrib_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(SCardGetAttrib_Arg_3);
            SCardGetAttrib_Arg_3 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    UINT8 * SCardGetAttrib_Arg_2 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT8* SCardGetAttrib_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SCardGetAttrib_Arg_2_OutputChoice), (VOID *)SCardGetAttrib_Arg_2_OutputChoice);
    if(*SCardGetAttrib_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*SCardGetAttrib_Arg_2), (VOID *)SCardGetAttrib_Arg_2);
    }
    Status = ProtocolVariable->SCardGetAttrib(
        ProtocolVariable,
        SCardGetAttrib_Arg_1,
        SCardGetAttrib_Arg_2,
        SCardGetAttrib_Arg_3
    );
    return Status;
}

