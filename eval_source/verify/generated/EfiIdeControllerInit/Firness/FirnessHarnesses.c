#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called SubmitData.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSubmitData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_IDE_CONTROLLER_INIT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIdeControllerInitProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 SubmitData_Arg_1 = 0;
    UINT8 SubmitData_Arg_2 = 0;
    EFI_IDENTIFY_DATA * SubmitData_Arg_3 = (EFI_IDENTIFY_DATA *)AllocateZeroPool(sizeof(EFI_IDENTIFY_DATA));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SubmitData_Arg_1), (VOID *)&SubmitData_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SubmitData_Arg_2), (VOID *)&SubmitData_Arg_2);
    
    // Generator Struct Variable Initialization
    {
        EFI_ATA_IDENTIFY_DATA Firness_AtaData;
        ReadBytes(Input, sizeof(Firness_AtaData), (VOID *)&Firness_AtaData);
        SubmitData_Arg_3->AtaData = Firness_AtaData;
    }
    {
        EFI_ATAPI_IDENTIFY_DATA Firness_AtapiData;
        ReadBytes(Input, sizeof(Firness_AtapiData), (VOID *)&Firness_AtapiData);
        SubmitData_Arg_3->AtapiData = Firness_AtapiData;
    }
    
    Status = ProtocolVariable->SubmitData(
        ProtocolVariable,
        SubmitData_Arg_1,
        SubmitData_Arg_2,
        SubmitData_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called CalculateMode.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzCalculateMode(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_IDE_CONTROLLER_INIT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIdeControllerInitProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 CalculateMode_Arg_1 = 0;
    UINT8 CalculateMode_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(CalculateMode_Arg_1), (VOID *)&CalculateMode_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(CalculateMode_Arg_2), (VOID *)&CalculateMode_Arg_2);
    
    /*
        Output Variable(s)
    */
    EFI_ATA_COLLECTIVE_MODE * CalculateMode_Arg_3 = (EFI_ATA_COLLECTIVE_MODE *)AllocateZeroPool(sizeof(EFI_ATA_COLLECTIVE_MODE));
    UINT8* CalculateMode_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(CalculateMode_Arg_3_OutputChoice), (VOID *)CalculateMode_Arg_3_OutputChoice);
    if(*CalculateMode_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*CalculateMode_Arg_3), (VOID *)CalculateMode_Arg_3);
    }
    Status = ProtocolVariable->CalculateMode(
        ProtocolVariable,
        CalculateMode_Arg_1,
        CalculateMode_Arg_2,
        (EFI_ATA_COLLECTIVE_MODE **)&CalculateMode_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetTiming.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetTiming(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_IDE_CONTROLLER_INIT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIdeControllerInitProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 SetTiming_Arg_1 = 0;
    UINT8 SetTiming_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetTiming_Arg_1), (VOID *)&SetTiming_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetTiming_Arg_2), (VOID *)&SetTiming_Arg_2);
    
    Status = ProtocolVariable->SetTiming(
        ProtocolVariable,
        SetTiming_Arg_1,
        SetTiming_Arg_2,
        NULL
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called NotifyPhase.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzNotifyPhase(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_IDE_CONTROLLER_INIT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIdeControllerInitProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_IDE_CONTROLLER_ENUM_PHASE NotifyPhase_Arg_1 = 0;
    UINT8 NotifyPhase_Arg_2 = 0;
    
    // Constant Variable Initialization
    UINT8* NotifyPhase_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(NotifyPhase_Arg_1_choice), (VOID *)NotifyPhase_Arg_1_choice);
    switch(*NotifyPhase_Arg_1_choice % 9) {
        case 0:
            NotifyPhase_Arg_1 = EfiIdeAfterChannelEnumeration;
            break;
        case 1:
            NotifyPhase_Arg_1 = EfiIdeAfterChannelReset;
            break;
        case 2:
            NotifyPhase_Arg_1 = EfiIdeBeforeChannelEnumeration;
            break;
        case 3:
            NotifyPhase_Arg_1 = EfiIdeBeforeChannelReset;
            break;
        case 4:
            NotifyPhase_Arg_1 = EfiIdeBusAfterDevicePresenceDetection;
            break;
        case 5:
            NotifyPhase_Arg_1 = EfiIdeBusBeforeDevicePresenceDetection;
            break;
        case 6:
            NotifyPhase_Arg_1 = EfiIdeBusPhaseMaximum;
            break;
        case 7:
            NotifyPhase_Arg_1 = EfiIdeResetMode;
            break;
        case 8:
            ReadBytes(Input, sizeof(NotifyPhase_Arg_1), (VOID *)&NotifyPhase_Arg_1);
            break;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(NotifyPhase_Arg_2), (VOID *)&NotifyPhase_Arg_2);
    
    Status = ProtocolVariable->NotifyPhase(
        ProtocolVariable,
        NotifyPhase_Arg_1,
        NotifyPhase_Arg_2
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetChannelInfo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetChannelInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_IDE_CONTROLLER_INIT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIdeControllerInitProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 GetChannelInfo_Arg_1 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetChannelInfo_Arg_1), (VOID *)&GetChannelInfo_Arg_1);
    
    /*
        Output Variable(s)
    */
    BOOLEAN * GetChannelInfo_Arg_2 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
    UINT8* GetChannelInfo_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetChannelInfo_Arg_2_OutputChoice), (VOID *)GetChannelInfo_Arg_2_OutputChoice);
    if(*GetChannelInfo_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetChannelInfo_Arg_2), (VOID *)GetChannelInfo_Arg_2);
    }
    UINT8 * GetChannelInfo_Arg_3 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINT8* GetChannelInfo_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetChannelInfo_Arg_3_OutputChoice), (VOID *)GetChannelInfo_Arg_3_OutputChoice);
    if(*GetChannelInfo_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetChannelInfo_Arg_3), (VOID *)GetChannelInfo_Arg_3);
    }
    Status = ProtocolVariable->GetChannelInfo(
        ProtocolVariable,
        GetChannelInfo_Arg_1,
        GetChannelInfo_Arg_2,
        GetChannelInfo_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called DisqualifyMode.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDisqualifyMode(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_IDE_CONTROLLER_INIT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiIdeControllerInitProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 DisqualifyMode_Arg_1 = 0;
    UINT8 DisqualifyMode_Arg_2 = 0;
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(DisqualifyMode_Arg_1), (VOID *)&DisqualifyMode_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(DisqualifyMode_Arg_2), (VOID *)&DisqualifyMode_Arg_2);
    
    Status = ProtocolVariable->DisqualifyMode(
        ProtocolVariable,
        DisqualifyMode_Arg_1,
        DisqualifyMode_Arg_2,
        NULL
    );
    return Status;
}

