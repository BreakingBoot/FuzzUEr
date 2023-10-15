#include "FuzzRuntimeServices.h"


EFI_STATUS
EFI_API
FuzzRuntimeServices(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: RuntimeServices\n"));
    UINTN RuntimeService = 0;
    ReadInput(Input, 2, &RuntimeService);
    switch(RuntimeService%13)
    {
        case GET_TIME:
            Status = FuzzGetTime(Input);
            break;
        case SET_TIME:
            Status = FuzzSetTime(Input);
            break;
        case GET_WAKEUP_TIME:
            Status = FuzzGetWakeupTime(Input);
            break;
        case SET_WAKEUP_TIME:
            Status = FuzzSetWakeupTime(Input);
            break;
        case SET_VIRTUAL_ADDRESS_MAP:
            Status = FuzzSetVirtualAddressMap(Input);
            break;
        case CONVERT_POINTER:
            Status = FuzzConvertPointer(Input);
            break;
        case GET_VARIABLE:
            Status = FuzzGetVariable(Input);
            break;
        case SET_VARIABLE:
            Status = FuzzSetVariable(Input);
            break;
        case GET_NEXT_VARIABLE_NAME:
            Status = FuzzGetNextVariableName(Input);
            break;
        case GET_NEXT_HIGH_MONOTONIC_COUNT:
            Status = FuzzGetNextHighMonotonicCount(Input);
            break;
        case RESET_SYSTEM:
            Status = FuzzResetSystem(Input);
            break;
        case UPDATE_CAPSULE:
            Status = FuzzUpdateCapsule(Input);
            break;
        case QUERY_CAPSULE_CAPABILITIES:
            Status = FuzzQueryCapsuleCapabilities(Input);
            break;
        case QUERY_VARIABLE_INFO:
            Status = FuzzQueryVariableInfo(Input);
            break;
    }

    return Status;
}

EFI_STATUS
EFIAPI
FuzzGetTime(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: GetTime\n"));
    EFI_TIME Time;
    EFI_TIME_CAPABILITIES Capabilities;

    Status = gRT->GetTime(&Time, &Capabilities);
    return Status;
}

EFI_STATUS
EFIAPI
FuzzSetTime(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: SetTime\n"));
    EFI_TIME Time;
    ReadInput(Input, sizeof(Time.Year), &Time.Year);
    ReadInput(Input, sizeof(Time.Month), &Time.Month);
    ReadInput(Input, sizeof(Time.Day), &Time.Day);
    ReadInput(Input, sizeof(Time.Hour), &Time.Hour);
    ReadInput(Input, sizeof(Time.Minute), &Time.Minute);
    ReadInput(Input, sizeof(Time.Second), &Time.Second);

    Status = gRT->SetTime(&Time);


    return Status;
}

EFI_STATUS
EFIAPI
FuzzGetWakeupTime(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: GetWakeupTime\n"));
    BOOLEAN Enabled;
    BOOLEAN Pending;
    EFI_TIME Time;

    Status = gRT->GetWakeupTime(&Enabled, &Pending, &Time);

    return Status;
}

EFI_STATUS
EFIAPI
FuzzSetWakeupTime(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: SetWakeupTime\n"));
    EFI_TIME Time;
    ReadInput(Input, sizeof(Time.Year), &Time.Year);
    ReadInput(Input, sizeof(Time.Month), &Time.Month);
    ReadInput(Input, sizeof(Time.Day), &Time.Day);
    ReadInput(Input, sizeof(Time.Hour), &Time.Hour);
    ReadInput(Input, sizeof(Time.Minute), &Time.Minute);
    ReadInput(Input, sizeof(Time.Second), &Time.Second);
    BOOLEAN Enabled;
    UINTN Choice = 0;
    ReadInput(Input, 1, &Choice);
    if(Choice%2)
    {
        Enabled = TRUE;
    }
    else
    {
        Enabled = FALSE;
    }

    Status = gRT->SetWakeupTime(Enabled, &Time);

    return Status;
}

EFI_STATUS
EFIAPI
FuzzSetVirtualAddressMap(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: SetVirtualAddressMap\n"));
    // Can't Implement

    return Status;
}

EFI_STATUS
EFIAPI
FuzzConvertPointer(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: ConvertPointer\n"));
    // Can't Implement

    return Status;
}

EFI_STATUS
EFIAPI
FuzzGetVariable(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: GetVariable\n"));
    VarName = Variables[];
    VarGuid = VariableGuids[];
    DataSize;
    Data;

    Status = gRT->GetVariable(
                        VarName,
                        VarGuid,
                        NULL,
                        DataSize,
                        Data
                    );

    return Status;
}

EFI_STATUS
EFIAPI
FuzzSetVariable(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: SetVariable\n"));
    VarName = Variables[];
    VarGuid = VariableGuids[];
    DataSize;
    Data;
    Status = gRT->SetVariable(
                        VarName,
                        VarGuid,
                        Attributes,
                        DataSize,
                        Data
                    );

    return Status;
}

EFI_STATUS
EFIAPI
FuzzGetNextVariableName(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: GetNextVariableName\n"));

    Status = gRT->GetNextVariableName(
                                    NameSize,
                                    VarName,
                                    VarGuid
                                );

    return Status;
}

EFI_STATUS
EFIAPI
FuzzGetNextHighMonotonicCount(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: GetNextHighMonotonicCount\n"));
    UINT32 Count;

    Status = gRT->GetNextHighMonotonicCount(&Count);

    return Status;
}

EFI_STATUS
EFIAPI
FuzzResetSystem(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: ResetSystem\n"));
    // Can't Implement

    return Status;
}

EFI_STATUS
EFIAPI
FuzzUpdateCapsule(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: UpdateCapsule\n"));
    EFI_CAPSULE_HEADER Capsule;
    UINTN Count;
    EFI_CAPSULE_BLOCK_DESCRIPTOR *Blocks = NULL;

    Status = gRT->UpdateCapsule(
                                Capsule,
                                Count,
                                (UINTN)Blocks
                            );

    return Status;
}

EFI_STATUS
EFIAPI
FuzzQueryCapsuleCapabilities(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: QueryCapsuleCapabilities\n"));
    EFI_CAPSULE_HEADER Capsule;
    UINTN CapsuleCount = 0;
    ReadInput(Input, 2, &CapsuleCount);
    UINTN64 MaxCapsuleSize;
    EFI_RESET_TYPE Type;

    Status = gRT->QueryCapsuleCapabilities(
                                            Capsule,
                                            CapsuleCount,
                                            &MaxCapsuleSize,
                                            &Type
                                        );

    return Status;
}

EFI_STATUS
EFIAPI
FuzzQueryVariableInfo(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: QueryVariableInfo\n"));
    UINT32 Attributes = EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_NON_VOLATILE;
    UINT64 MaximumVariableStorageSize;
    UINT64 RemainingVariableStorageSize;
    UINT64 MaximumVariableSize;

    Status = gRT->QueryVariableInfo(
                                    Attributes,
                                    &MaximumVariableStorageSize,
                                    &RemainingVariableStorageSize,
                                    &MaximumVariableSize
                                );

    return Status;
}