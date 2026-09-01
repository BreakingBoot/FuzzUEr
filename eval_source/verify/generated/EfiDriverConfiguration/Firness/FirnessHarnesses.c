#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called SetOptions.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetOptions(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DRIVER_CONFIGURATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDriverConfigurationProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  SetOptions_Arg_1 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINTN*  SetOptions_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    CHAR8 * SetOptions_Arg_3 = (CHAR8 *)AllocateZeroPool(sizeof(CHAR8));
    
    // Fuzzable Variable Initialization
    UINT8 SetOptions_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(SetOptions_Arg_1_choice), (VOID *)&SetOptions_Arg_1_choice);
    switch(SetOptions_Arg_1_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetOptions_Arg_1), (VOID *)SetOptions_Arg_1);
            break;
        case 1:
        {
            gBS->FreePool(SetOptions_Arg_1);
            SetOptions_Arg_1 = NULL;
            break;
        }
    }
    
    UINT8* SetOptions_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SetOptions_Arg_2_choice), (VOID *)SetOptions_Arg_2_choice);
    switch(*SetOptions_Arg_2_choice % 6) {
        case 0:
        {
        // Fuzzable Variable Initialization
        UINT8 SetOptions_Arg_2_choice = 0;
        ReadBytes(Input, sizeof(SetOptions_Arg_2_choice), (VOID *)&SetOptions_Arg_2_choice);
        switch(SetOptions_Arg_2_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(SetOptions_Arg_2), (VOID *)SetOptions_Arg_2);
                break;
            case 1:
            {
                gBS->FreePool(SetOptions_Arg_2);
                SetOptions_Arg_2 = NULL;
                break;
            }
        }
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            UINTN*  SerializeVariablesNewInstanceFromBuffer_Arg_1 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
            UINTN SerializeVariablesNewInstanceFromBuffer_Arg_2 = 0;
            
            // Fuzzable Variable Initialization
            UINT8 SerializeVariablesNewInstanceFromBuffer_Arg_1_choice = 0;
            ReadBytes(Input, sizeof(SerializeVariablesNewInstanceFromBuffer_Arg_1_choice), (VOID *)&SerializeVariablesNewInstanceFromBuffer_Arg_1_choice);
            switch(SerializeVariablesNewInstanceFromBuffer_Arg_1_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(SerializeVariablesNewInstanceFromBuffer_Arg_1), (VOID *)SerializeVariablesNewInstanceFromBuffer_Arg_1);
                    break;
                case 1:
                {
                    gBS->FreePool(SerializeVariablesNewInstanceFromBuffer_Arg_1);
                    SerializeVariablesNewInstanceFromBuffer_Arg_1 = NULL;
                    break;
                }
            }
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(SerializeVariablesNewInstanceFromBuffer_Arg_2), (VOID *)&SerializeVariablesNewInstanceFromBuffer_Arg_2);
            
            /*
                Output Variable(s)
            */
            EFI_HANDLE * SerializeVariablesNewInstanceFromBuffer_Arg_0 = (EFI_HANDLE *)AllocateZeroPool(sizeof(EFI_HANDLE));
            UINT8* SerializeVariablesNewInstanceFromBuffer_Arg_0_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(SerializeVariablesNewInstanceFromBuffer_Arg_0_OutputChoice), (VOID *)SerializeVariablesNewInstanceFromBuffer_Arg_0_OutputChoice);
            if(*SerializeVariablesNewInstanceFromBuffer_Arg_0_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*SerializeVariablesNewInstanceFromBuffer_Arg_0), (VOID *)SerializeVariablesNewInstanceFromBuffer_Arg_0);
            }
            SerializeVariablesNewInstanceFromBuffer(
                SerializeVariablesNewInstanceFromBuffer_Arg_0,
                (void *)SerializeVariablesNewInstanceFromBuffer_Arg_1,
                SerializeVariablesNewInstanceFromBuffer_Arg_2
            );
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            /*
                Output Variable(s)
            */
            EFI_HANDLE * SerializeVariablesNewInstance_Arg_0 = (EFI_HANDLE *)AllocateZeroPool(sizeof(EFI_HANDLE));
            UINT8* SerializeVariablesNewInstance_Arg_0_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(SerializeVariablesNewInstance_Arg_0_OutputChoice), (VOID *)SerializeVariablesNewInstance_Arg_0_OutputChoice);
            if(*SerializeVariablesNewInstance_Arg_0_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*SerializeVariablesNewInstance_Arg_0), (VOID *)SerializeVariablesNewInstance_Arg_0);
            }
            SerializeVariablesNewInstance(
                SerializeVariablesNewInstance_Arg_0
            );
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            UINTN ParseHandleDatabaseByRelationship_Arg_2 = 0;
            UINTN * ParseHandleDatabaseByRelationship_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
            
            UINT8* ParseHandleDatabaseByRelationship_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(ParseHandleDatabaseByRelationship_Arg_2_choice), (VOID *)ParseHandleDatabaseByRelationship_Arg_2_choice);
            switch(*ParseHandleDatabaseByRelationship_Arg_2_choice % 2) {
                case 0:
                {
                // Constant Variable Initialization
                ParseHandleDatabaseByRelationship_Arg_2 = HR_DRIVER_BINDING_HANDLE | HR_DEVICE_DRIVER;
            
                    break;
                }
                case 1:
                {
                // Fuzzable Variable Initialization
                ReadBytes(Input, sizeof(ParseHandleDatabaseByRelationship_Arg_2), (VOID *)&ParseHandleDatabaseByRelationship_Arg_2);
            
                    break;
                }
            }
            // Fuzzable Variable Initialization
            UINT8 ParseHandleDatabaseByRelationship_Arg_3_choice = 0;
            ReadBytes(Input, sizeof(ParseHandleDatabaseByRelationship_Arg_3_choice), (VOID *)&ParseHandleDatabaseByRelationship_Arg_3_choice);
            switch(ParseHandleDatabaseByRelationship_Arg_3_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(ParseHandleDatabaseByRelationship_Arg_3), (VOID *)ParseHandleDatabaseByRelationship_Arg_3);
                    break;
                case 1:
                {
                    gBS->FreePool(ParseHandleDatabaseByRelationship_Arg_3);
                    ParseHandleDatabaseByRelationship_Arg_3 = NULL;
                    break;
                }
            }
            
            /*
                Output Variable(s)
            */
            EFI_HANDLE * ParseHandleDatabaseByRelationship_Arg_4 = (EFI_HANDLE *)AllocateZeroPool(sizeof(EFI_HANDLE));
            UINT8* ParseHandleDatabaseByRelationship_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(ParseHandleDatabaseByRelationship_Arg_4_OutputChoice), (VOID *)ParseHandleDatabaseByRelationship_Arg_4_OutputChoice);
            if(*ParseHandleDatabaseByRelationship_Arg_4_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*ParseHandleDatabaseByRelationship_Arg_4), (VOID *)ParseHandleDatabaseByRelationship_Arg_4);
            }
            Status = ParseHandleDatabaseByRelationship(
                ImageHandle,
                ImageHandle,
                ParseHandleDatabaseByRelationship_Arg_2,
                ParseHandleDatabaseByRelationship_Arg_3,
                (EFI_HANDLE **)&ParseHandleDatabaseByRelationship_Arg_4
            );
    
            break;
        }
        case 4:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * LibGetFileHandleFromDevicePath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            
            // Generator Struct Variable Initialization
            {
                UINT8 Firness_Type;
                ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
                LibGetFileHandleFromDevicePath_Arg_0->Type = Firness_Type;
            }
            {
                UINT8 Firness_SubType;
                ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
                LibGetFileHandleFromDevicePath_Arg_0->SubType = Firness_SubType;
            }
            ReadBytes(Input, sizeof(LibGetFileHandleFromDevicePath_Arg_0->Length), (VOID *)&(LibGetFileHandleFromDevicePath_Arg_0->Length));
            
            /*
                Output Variable(s)
            */
            EFI_FILE_HANDLE * LibGetFileHandleFromDevicePath_Arg_1 = (EFI_FILE_HANDLE *)AllocateZeroPool(sizeof(EFI_FILE_HANDLE));
            UINT8* LibGetFileHandleFromDevicePath_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(LibGetFileHandleFromDevicePath_Arg_1_OutputChoice), (VOID *)LibGetFileHandleFromDevicePath_Arg_1_OutputChoice);
            if(*LibGetFileHandleFromDevicePath_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*LibGetFileHandleFromDevicePath_Arg_1), (VOID *)LibGetFileHandleFromDevicePath_Arg_1);
            }
            CHAR16 * LibGetFileHandleFromDevicePath_Arg_2 = (CHAR16 *)AllocateZeroPool(sizeof(CHAR16));
            UINT8* LibGetFileHandleFromDevicePath_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(LibGetFileHandleFromDevicePath_Arg_2_OutputChoice), (VOID *)LibGetFileHandleFromDevicePath_Arg_2_OutputChoice);
            if(*LibGetFileHandleFromDevicePath_Arg_2_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*LibGetFileHandleFromDevicePath_Arg_2), (VOID *)LibGetFileHandleFromDevicePath_Arg_2);
            }
            EFI_HANDLE * LibGetFileHandleFromDevicePath_Arg_3 = (EFI_HANDLE *)AllocateZeroPool(sizeof(EFI_HANDLE));
            UINT8* LibGetFileHandleFromDevicePath_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(LibGetFileHandleFromDevicePath_Arg_3_OutputChoice), (VOID *)LibGetFileHandleFromDevicePath_Arg_3_OutputChoice);
            if(*LibGetFileHandleFromDevicePath_Arg_3_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*LibGetFileHandleFromDevicePath_Arg_3), (VOID *)LibGetFileHandleFromDevicePath_Arg_3);
            }
            Status = LibGetFileHandleFromDevicePath(
                LibGetFileHandleFromDevicePath_Arg_0,
                LibGetFileHandleFromDevicePath_Arg_1,
                (CHAR16 **)&LibGetFileHandleFromDevicePath_Arg_2,
                LibGetFileHandleFromDevicePath_Arg_3
            );
    
            break;
        }
        case 5:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * EfiBootManagerConnectDevicePath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(sizeof(EFI_DEVICE_PATH_PROTOCOL));
            
            // Generator Struct Variable Initialization
            {
                UINT8 Firness_Type;
                ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
                EfiBootManagerConnectDevicePath_Arg_0->Type = Firness_Type;
            }
            {
                UINT8 Firness_SubType;
                ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
                EfiBootManagerConnectDevicePath_Arg_0->SubType = Firness_SubType;
            }
            ReadBytes(Input, sizeof(EfiBootManagerConnectDevicePath_Arg_0->Length), (VOID *)&(EfiBootManagerConnectDevicePath_Arg_0->Length));
            
            /*
                Output Variable(s)
            */
            EFI_HANDLE * EfiBootManagerConnectDevicePath_Arg_1 = (EFI_HANDLE *)AllocateZeroPool(sizeof(EFI_HANDLE));
            UINT8* EfiBootManagerConnectDevicePath_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(EfiBootManagerConnectDevicePath_Arg_1_OutputChoice), (VOID *)EfiBootManagerConnectDevicePath_Arg_1_OutputChoice);
            if(*EfiBootManagerConnectDevicePath_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*EfiBootManagerConnectDevicePath_Arg_1), (VOID *)EfiBootManagerConnectDevicePath_Arg_1);
            }
            Status = EfiBootManagerConnectDevicePath(
                EfiBootManagerConnectDevicePath_Arg_0,
                EfiBootManagerConnectDevicePath_Arg_1
            );
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 SetOptions_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(SetOptions_Arg_3_choice), (VOID *)&SetOptions_Arg_3_choice);
    switch(SetOptions_Arg_3_choice % 2) {
        case 0:
            ReadBytes(Input, sizeof(SetOptions_Arg_3), (VOID *)SetOptions_Arg_3);
            break;
        case 1:
        {
            gBS->FreePool(SetOptions_Arg_3);
            SetOptions_Arg_3 = NULL;
            break;
        }
    }
    
    /*
        Output Variable(s)
    */
    EFI_DRIVER_CONFIGURATION_ACTION_REQUIRED * SetOptions_Arg_4 = (EFI_DRIVER_CONFIGURATION_ACTION_REQUIRED *)AllocateZeroPool(sizeof(EFI_DRIVER_CONFIGURATION_ACTION_REQUIRED));
    UINT8* SetOptions_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(SetOptions_Arg_4_OutputChoice), (VOID *)SetOptions_Arg_4_OutputChoice);
    if(*SetOptions_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*SetOptions_Arg_4), (VOID *)SetOptions_Arg_4);
    }
    Status = ProtocolVariable->SetOptions(
        ProtocolVariable,
        (void *)SetOptions_Arg_1,
        (void *)SetOptions_Arg_2,
        SetOptions_Arg_3,
        SetOptions_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ForceDefaults.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzForceDefaults(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DRIVER_CONFIGURATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDriverConfigurationProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  ForceDefaults_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    UINT32 ForceDefaults_Arg_3 = 0;
    
    UINT8* ForceDefaults_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ForceDefaults_Arg_2_choice), (VOID *)ForceDefaults_Arg_2_choice);
    switch(*ForceDefaults_Arg_2_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        UINT8 ForceDefaults_Arg_2_choice = 0;
        ReadBytes(Input, sizeof(ForceDefaults_Arg_2_choice), (VOID *)&ForceDefaults_Arg_2_choice);
        switch(ForceDefaults_Arg_2_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(ForceDefaults_Arg_2), (VOID *)ForceDefaults_Arg_2);
                break;
            case 1:
            {
                gBS->FreePool(ForceDefaults_Arg_2);
                ForceDefaults_Arg_2 = NULL;
                break;
            }
        }
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            UINTN ParseHandleDatabaseByRelationship_Arg_2 = 0;
            UINTN * ParseHandleDatabaseByRelationship_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
            
            UINT8* ParseHandleDatabaseByRelationship_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(ParseHandleDatabaseByRelationship_Arg_2_choice), (VOID *)ParseHandleDatabaseByRelationship_Arg_2_choice);
            switch(*ParseHandleDatabaseByRelationship_Arg_2_choice % 2) {
                case 0:
                {
                // Constant Variable Initialization
                ParseHandleDatabaseByRelationship_Arg_2 = HR_DRIVER_BINDING_HANDLE | HR_DEVICE_DRIVER;
            
                    break;
                }
                case 1:
                {
                // Fuzzable Variable Initialization
                ReadBytes(Input, sizeof(ParseHandleDatabaseByRelationship_Arg_2), (VOID *)&ParseHandleDatabaseByRelationship_Arg_2);
            
                    break;
                }
            }
            // Fuzzable Variable Initialization
            UINT8 ParseHandleDatabaseByRelationship_Arg_3_choice = 0;
            ReadBytes(Input, sizeof(ParseHandleDatabaseByRelationship_Arg_3_choice), (VOID *)&ParseHandleDatabaseByRelationship_Arg_3_choice);
            switch(ParseHandleDatabaseByRelationship_Arg_3_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(ParseHandleDatabaseByRelationship_Arg_3), (VOID *)ParseHandleDatabaseByRelationship_Arg_3);
                    break;
                case 1:
                {
                    gBS->FreePool(ParseHandleDatabaseByRelationship_Arg_3);
                    ParseHandleDatabaseByRelationship_Arg_3 = NULL;
                    break;
                }
            }
            
            /*
                Output Variable(s)
            */
            EFI_HANDLE * ParseHandleDatabaseByRelationship_Arg_4 = (EFI_HANDLE *)AllocateZeroPool(sizeof(EFI_HANDLE));
            UINT8* ParseHandleDatabaseByRelationship_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(ParseHandleDatabaseByRelationship_Arg_4_OutputChoice), (VOID *)ParseHandleDatabaseByRelationship_Arg_4_OutputChoice);
            if(*ParseHandleDatabaseByRelationship_Arg_4_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*ParseHandleDatabaseByRelationship_Arg_4), (VOID *)ParseHandleDatabaseByRelationship_Arg_4);
            }
            Status = ParseHandleDatabaseByRelationship(
                ImageHandle,
                ImageHandle,
                ParseHandleDatabaseByRelationship_Arg_2,
                ParseHandleDatabaseByRelationship_Arg_3,
                (EFI_HANDLE **)&ParseHandleDatabaseByRelationship_Arg_4
            );
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ForceDefaults_Arg_3), (VOID *)&ForceDefaults_Arg_3);
    
    /*
        Output Variable(s)
    */
    EFI_DRIVER_CONFIGURATION_ACTION_REQUIRED * ForceDefaults_Arg_4 = (EFI_DRIVER_CONFIGURATION_ACTION_REQUIRED *)AllocateZeroPool(sizeof(EFI_DRIVER_CONFIGURATION_ACTION_REQUIRED));
    UINT8* ForceDefaults_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(ForceDefaults_Arg_4_OutputChoice), (VOID *)ForceDefaults_Arg_4_OutputChoice);
    if(*ForceDefaults_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ForceDefaults_Arg_4), (VOID *)ForceDefaults_Arg_4);
    }
    Status = ProtocolVariable->ForceDefaults(
        ProtocolVariable,
        ImageHandle,
        (void *)ForceDefaults_Arg_2,
        ForceDefaults_Arg_3,
        ForceDefaults_Arg_4
    );
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called OptionsValid.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzOptionsValid(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DRIVER_CONFIGURATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDriverConfigurationProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  OptionsValid_Arg_2 = (UINTN* )AllocateZeroPool(sizeof(UINTN ));
    
    UINT8* OptionsValid_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(OptionsValid_Arg_2_choice), (VOID *)OptionsValid_Arg_2_choice);
    switch(*OptionsValid_Arg_2_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        UINT8 OptionsValid_Arg_2_choice = 0;
        ReadBytes(Input, sizeof(OptionsValid_Arg_2_choice), (VOID *)&OptionsValid_Arg_2_choice);
        switch(OptionsValid_Arg_2_choice % 2) {
            case 0:
                ReadBytes(Input, sizeof(OptionsValid_Arg_2), (VOID *)OptionsValid_Arg_2);
                break;
            case 1:
            {
                gBS->FreePool(OptionsValid_Arg_2);
                OptionsValid_Arg_2 = NULL;
                break;
            }
        }
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            UINTN ParseHandleDatabaseByRelationship_Arg_2 = 0;
            UINTN * ParseHandleDatabaseByRelationship_Arg_3 = (UINTN *)AllocateZeroPool(sizeof(UINTN));
            
            UINT8* ParseHandleDatabaseByRelationship_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(ParseHandleDatabaseByRelationship_Arg_2_choice), (VOID *)ParseHandleDatabaseByRelationship_Arg_2_choice);
            switch(*ParseHandleDatabaseByRelationship_Arg_2_choice % 2) {
                case 0:
                {
                // Constant Variable Initialization
                ParseHandleDatabaseByRelationship_Arg_2 = HR_DRIVER_BINDING_HANDLE | HR_DEVICE_DRIVER;
            
                    break;
                }
                case 1:
                {
                // Fuzzable Variable Initialization
                ReadBytes(Input, sizeof(ParseHandleDatabaseByRelationship_Arg_2), (VOID *)&ParseHandleDatabaseByRelationship_Arg_2);
            
                    break;
                }
            }
            // Fuzzable Variable Initialization
            UINT8 ParseHandleDatabaseByRelationship_Arg_3_choice = 0;
            ReadBytes(Input, sizeof(ParseHandleDatabaseByRelationship_Arg_3_choice), (VOID *)&ParseHandleDatabaseByRelationship_Arg_3_choice);
            switch(ParseHandleDatabaseByRelationship_Arg_3_choice % 2) {
                case 0:
                    ReadBytes(Input, sizeof(ParseHandleDatabaseByRelationship_Arg_3), (VOID *)ParseHandleDatabaseByRelationship_Arg_3);
                    break;
                case 1:
                {
                    gBS->FreePool(ParseHandleDatabaseByRelationship_Arg_3);
                    ParseHandleDatabaseByRelationship_Arg_3 = NULL;
                    break;
                }
            }
            
            /*
                Output Variable(s)
            */
            EFI_HANDLE * ParseHandleDatabaseByRelationship_Arg_4 = (EFI_HANDLE *)AllocateZeroPool(sizeof(EFI_HANDLE));
            UINT8* ParseHandleDatabaseByRelationship_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(ParseHandleDatabaseByRelationship_Arg_4_OutputChoice), (VOID *)ParseHandleDatabaseByRelationship_Arg_4_OutputChoice);
            if(*ParseHandleDatabaseByRelationship_Arg_4_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*ParseHandleDatabaseByRelationship_Arg_4), (VOID *)ParseHandleDatabaseByRelationship_Arg_4);
            }
            Status = ParseHandleDatabaseByRelationship(
                ImageHandle,
                ImageHandle,
                ParseHandleDatabaseByRelationship_Arg_2,
                ParseHandleDatabaseByRelationship_Arg_3,
                (EFI_HANDLE **)&ParseHandleDatabaseByRelationship_Arg_4
            );
    
            break;
        }
    }
    Status = ProtocolVariable->OptionsValid(
        ProtocolVariable,
        ImageHandle,
        (void *)OptionsValid_Arg_2
    );
    return Status;
}

