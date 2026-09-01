#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called SetSessionData.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetSessionData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_TLS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTlsProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_TLS_SESSION_DATA_TYPE SetSessionData_Arg_1 = 0;
    UINTN*  SetSessionData_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN SetSessionData_Arg_3 = 0;
    
    // Constant Variable Initialization
    UINT8* SetSessionData_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SetSessionData_Arg_1_choice), (VOID *)SetSessionData_Arg_1_choice);
    switch(*SetSessionData_Arg_1_choice % 14) {
        case 0:
            SetSessionData_Arg_1 = EfiTlsCipherList;
            break;
        case 1:
            SetSessionData_Arg_1 = EfiTlsClientRandom;
            break;
        case 2:
            SetSessionData_Arg_1 = EfiTlsCompressionMethod;
            break;
        case 3:
            SetSessionData_Arg_1 = EfiTlsConnectionEnd;
            break;
        case 4:
            SetSessionData_Arg_1 = EfiTlsExtensionData;
            break;
        case 5:
            SetSessionData_Arg_1 = EfiTlsKeyMaterial;
            break;
        case 6:
            SetSessionData_Arg_1 = EfiTlsServerRandom;
            break;
        case 7:
            SetSessionData_Arg_1 = EfiTlsSessionDataTypeMaximum;
            break;
        case 8:
            SetSessionData_Arg_1 = EfiTlsSessionID;
            break;
        case 9:
            SetSessionData_Arg_1 = EfiTlsSessionState;
            break;
        case 10:
            SetSessionData_Arg_1 = EfiTlsVerifyHost;
            break;
        case 11:
            SetSessionData_Arg_1 = EfiTlsVerifyMethod;
            break;
        case 12:
            SetSessionData_Arg_1 = EfiTlsVersion;
            break;
        case 13:
            ReadBytes(Input, sizeof(SetSessionData_Arg_1), (VOID *)&SetSessionData_Arg_1);
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 SetSessionData_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(SetSessionData_Arg_2_choice), (VOID *)&SetSessionData_Arg_2_choice);
    switch(SetSessionData_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetSessionData_Arg_2), (VOID *)SetSessionData_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(SetSessionData_Arg_2);
            SetSessionData_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetSessionData_Arg_3), (VOID *)&SetSessionData_Arg_3);
    
    Status = ProtocolVariable->SetSessionData(
        ProtocolVariable,
        SetSessionData_Arg_1,
        (void *)SetSessionData_Arg_2,
        SetSessionData_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called BuildResponsePacket.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzBuildResponsePacket(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_TLS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTlsProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 * BuildResponsePacket_Arg_1 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINTN BuildResponsePacket_Arg_2 = 0;
    UINT8 * BuildResponsePacket_Arg_3 = (UINT8 *)AllocateZeroPool(sizeof(UINT8));
    UINTN * BuildResponsePacket_Arg_4 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Fuzzable Variable Initialization
    UINT8 BuildResponsePacket_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(BuildResponsePacket_Arg_1_choice), (VOID *)&BuildResponsePacket_Arg_1_choice);
    switch(BuildResponsePacket_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(BuildResponsePacket_Arg_1), (VOID *)BuildResponsePacket_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(BuildResponsePacket_Arg_1);
            BuildResponsePacket_Arg_1 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(BuildResponsePacket_Arg_2), (VOID *)&BuildResponsePacket_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 BuildResponsePacket_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(BuildResponsePacket_Arg_3_choice), (VOID *)&BuildResponsePacket_Arg_3_choice);
    switch(BuildResponsePacket_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(BuildResponsePacket_Arg_3), (VOID *)BuildResponsePacket_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(BuildResponsePacket_Arg_3);
            BuildResponsePacket_Arg_3 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 BuildResponsePacket_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(BuildResponsePacket_Arg_4_choice), (VOID *)&BuildResponsePacket_Arg_4_choice);
    switch(BuildResponsePacket_Arg_4_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(BuildResponsePacket_Arg_4), (VOID *)BuildResponsePacket_Arg_4);
            break;
        case 1:
        {
            gBS->FreePool(BuildResponsePacket_Arg_4);
            BuildResponsePacket_Arg_4 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->BuildResponsePacket(
        ProtocolVariable,
        BuildResponsePacket_Arg_1,
        BuildResponsePacket_Arg_2,
        BuildResponsePacket_Arg_3,
        BuildResponsePacket_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetSessionData.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetSessionData(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_TLS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTlsProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_TLS_SESSION_DATA_TYPE GetSessionData_Arg_1 = 0;
    UINTN*  GetSessionData_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN * GetSessionData_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
    
    // Constant Variable Initialization
    UINT8* GetSessionData_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(GetSessionData_Arg_1_choice), (VOID *)GetSessionData_Arg_1_choice);
    switch(*GetSessionData_Arg_1_choice % 14) {
        case 0:
            GetSessionData_Arg_1 = EfiTlsCipherList;
            break;
        case 1:
            GetSessionData_Arg_1 = EfiTlsClientRandom;
            break;
        case 2:
            GetSessionData_Arg_1 = EfiTlsCompressionMethod;
            break;
        case 3:
            GetSessionData_Arg_1 = EfiTlsConnectionEnd;
            break;
        case 4:
            GetSessionData_Arg_1 = EfiTlsExtensionData;
            break;
        case 5:
            GetSessionData_Arg_1 = EfiTlsKeyMaterial;
            break;
        case 6:
            GetSessionData_Arg_1 = EfiTlsServerRandom;
            break;
        case 7:
            GetSessionData_Arg_1 = EfiTlsSessionDataTypeMaximum;
            break;
        case 8:
            GetSessionData_Arg_1 = EfiTlsSessionID;
            break;
        case 9:
            GetSessionData_Arg_1 = EfiTlsSessionState;
            break;
        case 10:
            GetSessionData_Arg_1 = EfiTlsVerifyHost;
            break;
        case 11:
            GetSessionData_Arg_1 = EfiTlsVerifyMethod;
            break;
        case 12:
            GetSessionData_Arg_1 = EfiTlsVersion;
            break;
        case 13:
            ReadBytes(Input, sizeof(GetSessionData_Arg_1), (VOID *)&GetSessionData_Arg_1);
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetSessionData_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetSessionData_Arg_2_choice), (VOID *)&GetSessionData_Arg_2_choice);
    switch(GetSessionData_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetSessionData_Arg_2), (VOID *)GetSessionData_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(GetSessionData_Arg_2);
            GetSessionData_Arg_2 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetSessionData_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(GetSessionData_Arg_3_choice), (VOID *)&GetSessionData_Arg_3_choice);
    switch(GetSessionData_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(GetSessionData_Arg_3), (VOID *)GetSessionData_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(GetSessionData_Arg_3);
            GetSessionData_Arg_3 = NULL;
            break;
        }
    }
    
    Status = ProtocolVariable->GetSessionData(
        ProtocolVariable,
        GetSessionData_Arg_1,
        (void *)GetSessionData_Arg_2,
        GetSessionData_Arg_3
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ProcessPacket.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzProcessPacket(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_TLS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiTlsProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 * ProcessPacket_Arg_2 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    EFI_TLS_CRYPT_MODE ProcessPacket_Arg_3 = 0;
    
    // Fuzzable Variable Initialization
    UINT8 ProcessPacket_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(ProcessPacket_Arg_2_choice), (VOID *)&ProcessPacket_Arg_2_choice);
    switch(ProcessPacket_Arg_2_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(ProcessPacket_Arg_2), (VOID *)ProcessPacket_Arg_2);
            break;
        case 1:
        {
            gBS->FreePool(ProcessPacket_Arg_2);
            ProcessPacket_Arg_2 = NULL;
            break;
        }
    }
    
    // Constant Variable Initialization
    UINT8* ProcessPacket_Arg_3_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ProcessPacket_Arg_3_choice), (VOID *)ProcessPacket_Arg_3_choice);
    switch(*ProcessPacket_Arg_3_choice % 3) {
        case 0:
            ProcessPacket_Arg_3 = EfiTlsDecrypt;
            break;
        case 1:
            ProcessPacket_Arg_3 = EfiTlsEncrypt;
            break;
        case 2:
            ReadBytes(Input, sizeof(ProcessPacket_Arg_3), (VOID *)&ProcessPacket_Arg_3);
            break;
    }
    
    Status = ProtocolVariable->ProcessPacket(
        ProtocolVariable,
        NULL,
        ProcessPacket_Arg_2,
        ProcessPacket_Arg_3
    );
    return Status;
}

