#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called Identify.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzIdentify(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DISK_INFO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDiskInfoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  Identify_Arg_1 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT32 * Identify_Arg_2 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    
    // Fuzzable Variable Initialization
    UINT8 Identify_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(Identify_Arg_1_choice), (VOID *)&Identify_Arg_1_choice);
    switch(Identify_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Identify_Arg_1), (VOID *)Identify_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(Identify_Arg_1);
            Identify_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 Identify_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(Identify_Arg_2_choice), (VOID *)&Identify_Arg_2_choice);
    switch(Identify_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Identify_Arg_2), (VOID *)Identify_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(Identify_Arg_2);
            Identify_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->Identify(
        ProtocolVariable,
        (void *)Identify_Arg_1,
        Identify_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Inquiry.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzInquiry(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DISK_INFO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDiskInfoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  Inquiry_Arg_1 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT32 * Inquiry_Arg_2 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    
    // Fuzzable Variable Initialization
    UINT8 Inquiry_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(Inquiry_Arg_1_choice), (VOID *)&Inquiry_Arg_1_choice);
    switch(Inquiry_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Inquiry_Arg_1), (VOID *)Inquiry_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(Inquiry_Arg_1);
            Inquiry_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 Inquiry_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(Inquiry_Arg_2_choice), (VOID *)&Inquiry_Arg_2_choice);
    switch(Inquiry_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(Inquiry_Arg_2), (VOID *)Inquiry_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(Inquiry_Arg_2);
            Inquiry_Arg_2 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->Inquiry(
        ProtocolVariable,
        (void *)Inquiry_Arg_1,
        Inquiry_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SenseData.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSenseData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DISK_INFO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDiskInfoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  SenseData_Arg_1 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT32 * SenseData_Arg_2 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    
    // Fuzzable Variable Initialization
    UINT8 SenseData_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(SenseData_Arg_1_choice), (VOID *)&SenseData_Arg_1_choice);
    switch(SenseData_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SenseData_Arg_1), (VOID *)SenseData_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(SenseData_Arg_1);
            SenseData_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 SenseData_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(SenseData_Arg_2_choice), (VOID *)&SenseData_Arg_2_choice);
    switch(SenseData_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SenseData_Arg_2), (VOID *)SenseData_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(SenseData_Arg_2);
            SenseData_Arg_2 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    UINT8 * SenseData_Arg_3 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT8* SenseData_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SenseData_Arg_3_OutputChoice), (VOID *)SenseData_Arg_3_OutputChoice);
    if(*SenseData_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*SenseData_Arg_3), (VOID *)SenseData_Arg_3);
    }
    Status = ProtocolVariable->SenseData(
        ProtocolVariable,
        (void *)SenseData_Arg_1,
        SenseData_Arg_2,
        SenseData_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called WhichIde.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzWhichIde(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DISK_INFO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDiskInfoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    UINT32 * WhichIde_Arg_1 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT8* WhichIde_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(WhichIde_Arg_1_OutputChoice), (VOID *)WhichIde_Arg_1_OutputChoice);
    if(*WhichIde_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*WhichIde_Arg_1), (VOID *)WhichIde_Arg_1);
    }
    UINT32 * WhichIde_Arg_2 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    UINT8* WhichIde_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(WhichIde_Arg_2_OutputChoice), (VOID *)WhichIde_Arg_2_OutputChoice);
    if(*WhichIde_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*WhichIde_Arg_2), (VOID *)WhichIde_Arg_2);
    }
    Status = ProtocolVariable->WhichIde(
        ProtocolVariable,
        WhichIde_Arg_1,
        WhichIde_Arg_2
    );
    return Status;
}

