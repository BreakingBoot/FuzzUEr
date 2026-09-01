#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called MemoryTestInit.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzMemoryTestInit(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_GENERIC_MEMORY_TEST_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiGenericMemTestProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    BOOLEAN * MemoryTestInit_Arg_2 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
    UINT8* MemoryTestInit_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(MemoryTestInit_Arg_2_OutputChoice), (VOID *)MemoryTestInit_Arg_2_OutputChoice);
    if(*MemoryTestInit_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*MemoryTestInit_Arg_2), (VOID *)MemoryTestInit_Arg_2);
    }
    Status = ProtocolVariable->MemoryTestInit(
        ProtocolVariable,
        (EXTENDMEM_COVERAGE_LEVEL){0},
        MemoryTestInit_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called PerformMemoryTest.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzPerformMemoryTest(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_GENERIC_MEMORY_TEST_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiGenericMemTestProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN PerformMemoryTest_Arg_4 = FALSE;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PerformMemoryTest_Arg_4), (VOID *)&PerformMemoryTest_Arg_4);
    
    /*
        Output Variable(s)
    */
    UINT64 * PerformMemoryTest_Arg_1 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    UINT8* PerformMemoryTest_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(PerformMemoryTest_Arg_1_OutputChoice), (VOID *)PerformMemoryTest_Arg_1_OutputChoice);
    if(*PerformMemoryTest_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*PerformMemoryTest_Arg_1), (VOID *)PerformMemoryTest_Arg_1);
    }
    UINT64 * PerformMemoryTest_Arg_2 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    UINT8* PerformMemoryTest_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(PerformMemoryTest_Arg_2_OutputChoice), (VOID *)PerformMemoryTest_Arg_2_OutputChoice);
    if(*PerformMemoryTest_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*PerformMemoryTest_Arg_2), (VOID *)PerformMemoryTest_Arg_2);
    }
    BOOLEAN * PerformMemoryTest_Arg_3 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
    UINT8* PerformMemoryTest_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(PerformMemoryTest_Arg_3_OutputChoice), (VOID *)PerformMemoryTest_Arg_3_OutputChoice);
    if(*PerformMemoryTest_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*PerformMemoryTest_Arg_3), (VOID *)PerformMemoryTest_Arg_3);
    }
    Status = ProtocolVariable->PerformMemoryTest(
        ProtocolVariable,
        PerformMemoryTest_Arg_1,
        PerformMemoryTest_Arg_2,
        PerformMemoryTest_Arg_3,
        PerformMemoryTest_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Finished.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFinished(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_GENERIC_MEMORY_TEST_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiGenericMemTestProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = ProtocolVariable->Finished(
        ProtocolVariable
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called CompatibleRangeTest.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzCompatibleRangeTest(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_GENERIC_MEMORY_TEST_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiGenericMemTestProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PHYSICAL_ADDRESS CompatibleRangeTest_Arg_1 = 0;
    UINT64 CompatibleRangeTest_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(CompatibleRangeTest_Arg_1), (VOID *)&CompatibleRangeTest_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(CompatibleRangeTest_Arg_2), (VOID *)&CompatibleRangeTest_Arg_2);
    
    Status = ProtocolVariable->CompatibleRangeTest(
        ProtocolVariable,
        CompatibleRangeTest_Arg_1,
        CompatibleRangeTest_Arg_2
    );
    return Status;
}

