#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called GetNumberOfProcessors.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetNumberOfProcessors(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MM_MP_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMmMpProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINTN * GetNumberOfProcessors_Arg_1 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    UINT8* GetNumberOfProcessors_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetNumberOfProcessors_Arg_1_OutputChoice), (VOID *)GetNumberOfProcessors_Arg_1_OutputChoice);
    if(*GetNumberOfProcessors_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetNumberOfProcessors_Arg_1), (VOID *)GetNumberOfProcessors_Arg_1);
    }
    Status = ProtocolVariable->GetNumberOfProcessors(
        ProtocolVariable,
        GetNumberOfProcessors_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called DispatchProcedure.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDispatchProcedure(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MM_MP_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMmMpProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN DispatchProcedure_Arg_2 = 0;
    UINTN DispatchProcedure_Arg_3 = 0;
    UINTN*  DispatchProcedure_Arg_4 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    MM_COMPLETION * DispatchProcedure_Arg_5 = (MM_COMPLETION *)AllocateZeroPool(sizeof(MM_COMPLETION));
    EFI_STATUS * DispatchProcedure_Arg_6 = (EFI_STATUS *)AllocateZeroPool(sizeof(EFI_STATUS));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(DispatchProcedure_Arg_2), (VOID *)&DispatchProcedure_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(DispatchProcedure_Arg_3), (VOID *)&DispatchProcedure_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 DispatchProcedure_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(DispatchProcedure_Arg_4_choice), (VOID *)&DispatchProcedure_Arg_4_choice);
    switch(DispatchProcedure_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(DispatchProcedure_Arg_4), (VOID *)DispatchProcedure_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(DispatchProcedure_Arg_4);
            DispatchProcedure_Arg_4 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 DispatchProcedure_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(DispatchProcedure_Arg_5_choice), (VOID *)&DispatchProcedure_Arg_5_choice);
    switch(DispatchProcedure_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(DispatchProcedure_Arg_5), (VOID *)DispatchProcedure_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(DispatchProcedure_Arg_5);
            DispatchProcedure_Arg_5 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 DispatchProcedure_Arg_6_choice = 0;
    ReadBytes(Input, sizeof(DispatchProcedure_Arg_6_choice), (VOID *)&DispatchProcedure_Arg_6_choice);
    switch(DispatchProcedure_Arg_6_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(DispatchProcedure_Arg_6), (VOID *)DispatchProcedure_Arg_6);
            break;
        case 1:
        {
            gBS->FreePool(DispatchProcedure_Arg_6);
            DispatchProcedure_Arg_6 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->DispatchProcedure(
        ProtocolVariable,
        (EFI_AP_PROCEDURE2){0},
        DispatchProcedure_Arg_2,
        DispatchProcedure_Arg_3,
        (void *)DispatchProcedure_Arg_4,
        DispatchProcedure_Arg_5,
        DispatchProcedure_Arg_6
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called BroadcastProcedure.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzBroadcastProcedure(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MM_MP_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMmMpProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN BroadcastProcedure_Arg_2 = 0;
    UINTN*  BroadcastProcedure_Arg_3 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    MM_COMPLETION * BroadcastProcedure_Arg_4 = (MM_COMPLETION *)AllocateZeroPool(sizeof(MM_COMPLETION));
    EFI_STATUS * BroadcastProcedure_Arg_5 = (EFI_STATUS *)AllocateZeroPool(sizeof(EFI_STATUS));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(BroadcastProcedure_Arg_2), (VOID *)&BroadcastProcedure_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 BroadcastProcedure_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(BroadcastProcedure_Arg_3_choice), (VOID *)&BroadcastProcedure_Arg_3_choice);
    switch(BroadcastProcedure_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(BroadcastProcedure_Arg_3), (VOID *)BroadcastProcedure_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(BroadcastProcedure_Arg_3);
            BroadcastProcedure_Arg_3 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 BroadcastProcedure_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(BroadcastProcedure_Arg_4_choice), (VOID *)&BroadcastProcedure_Arg_4_choice);
    switch(BroadcastProcedure_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(BroadcastProcedure_Arg_4), (VOID *)BroadcastProcedure_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(BroadcastProcedure_Arg_4);
            BroadcastProcedure_Arg_4 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 BroadcastProcedure_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(BroadcastProcedure_Arg_5_choice), (VOID *)&BroadcastProcedure_Arg_5_choice);
    switch(BroadcastProcedure_Arg_5_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(BroadcastProcedure_Arg_5), (VOID *)BroadcastProcedure_Arg_5);
            break;
        case 1:
        {
            gBS->FreePool(BroadcastProcedure_Arg_5);
            BroadcastProcedure_Arg_5 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->BroadcastProcedure(
        ProtocolVariable,
        (EFI_AP_PROCEDURE2){0},
        BroadcastProcedure_Arg_2,
        (void *)BroadcastProcedure_Arg_3,
        BroadcastProcedure_Arg_4,
        BroadcastProcedure_Arg_5
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetStartupProcedure.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetStartupProcedure(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MM_MP_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMmMpProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  SetStartupProcedure_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    // Fuzzable Variable Initialization
    UINT8 SetStartupProcedure_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(SetStartupProcedure_Arg_2_choice), (VOID *)&SetStartupProcedure_Arg_2_choice);
    switch(SetStartupProcedure_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetStartupProcedure_Arg_2), (VOID *)SetStartupProcedure_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(SetStartupProcedure_Arg_2);
            SetStartupProcedure_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->SetStartupProcedure(
        ProtocolVariable,
        (EFI_AP_PROCEDURE){0},
        (void *)SetStartupProcedure_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called WaitForProcedure.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzWaitForProcedure(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MM_MP_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMmMpProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    MM_COMPLETION WaitForProcedure_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(WaitForProcedure_Arg_1), (VOID *)&WaitForProcedure_Arg_1);
    
    Status = ProtocolVariable->WaitForProcedure(
        ProtocolVariable,
        WaitForProcedure_Arg_1
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called CheckForProcedure.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzCheckForProcedure(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_MM_MP_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiMmMpProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    MM_COMPLETION CheckForProcedure_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(CheckForProcedure_Arg_1), (VOID *)&CheckForProcedure_Arg_1);
    
    Status = ProtocolVariable->CheckForProcedure(
        ProtocolVariable,
        CheckForProcedure_Arg_1
    );
    return Status;
}

