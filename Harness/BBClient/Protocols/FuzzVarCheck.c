#include "FuzzVarCheck.h"

#define REGISTER_SET_VARIABLE_CHECK_HANDLER 0
#define VARIABLE_PROPERTY_SET 1
#define VARIABLE_PROPERTY_GET 2

EFI_STATUS
EFIAPI
FuzzVarCheck(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: VarCheck\n"));
    UINTN VariableChoice = 0;
    ReadInput(Input, 1, &VariableChoice);

    switch(VariableChoice%3)
    {
        case REGISTER_SET_VARIABLE_CHECK_HANDLER:
            Status = FuzzRegisterSetVariableCheckHandler(Input);
            break;
        case VARIABLE_PROPERTY_SET:
            Status = FuzzVariablePropertySet(Input);
            break;
        case VARIABLE_PROPERTY_GET:
            Status = FuzzVariablePropertyGet(Input);
            break;
    }

    return Status;
}

EFI_STATUS
EFIAPI
FuzzRegisterSetVariableCheckHandler(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: RegisterSetVariableCheckHandler\n"));
    EDKII_VAR_CHECK_PROTOCOL *VarCheckProtocol;
    gBS->LocateProtocol(&gEdkiiVarCheckProtocolGuid, NULL, (VOID **)&VarCheckProtocol);
    VAR_CHECK_SET_VARIABLE_CHECK_HANDLER Handler;
    UINTN HandlerChoice = 0;
    ReadInput(Input, 1, &HandlerChoice);
    switch(HandlerChoice%5)
    {
        case 0:
            Handler = SetVariableCheckHandlerPcd;
            break;
        case 1:
            Handler = SetVariableCheckHandlerMor;
            break;
        case 3:
            Handler = ValidateSetVariable;
            break;
        case 4:
            Handler = SetVariableCheckHandlerHii;
            break;
        case 5:
            Handler = SetVariableCheckHandlerUefiDefined;
            break;
    }

    Status = VarCheckProtocol->RegisterSetVariableCheckHandler(Handler);

    return Status;
}

EFI_STATUS
EFIAPI
FuzzVariablePropertySet(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: VariablePropertySet\n"));
    EDKII_VAR_CHECK_PROTOCOL *VarCheckProtocol;
    gBS->LocateProtocol(&gEdkiiVarCheckProtocolGuid, NULL, (VOID **)&VarCheckProtocol);

    UINTN Index = 0;
    ReadInput(Input, sizeof(Index), &Index);

    UINTN VariableChoice = 0;
    ReadInput(Input, 1, &VariableChoice);

    switch(VariableChoice%4)
    {
        case 0:
            Index = Index%(sizeof (mGlobalVariableList)/sizeof (mGlobalVariableList[0]));
            Status = VarCheckProtocol->VariablePropertySet(mGlobalVariableList[Index].Name, 
                                                            &gEfiGlobalVariableGuid, 
                                                            &mGlobalVariableList[Index].VariableProperty);
            break;
        case 1:
            Index = Index%(sizeof (mGlobalVariableList2)/sizeof (mGlobalVariableList2[0]));
            Status = VarCheckProtocol->VariablePropertySet(mGlobalVariableList2[Index].Name,
                                                            &gEfiGlobalVariableGuid,
                                                            &mGlobalVariableList2[Index].VariableProperty);
            break;
        case 2:
            Index = Index%(sizeof (mImageSecurityVariableList)/sizeof (mImageSecurityVariableList[0]));
            Status = VarCheckProtocol->VariablePropertySet(mImageSecurityVariableList[Index].Name,
                                                            &gEfiImageSecurityDatabaseGuid,
                                                            &mImageSecurityVariableList[Index].VariableProperty);
            break;
        case 3:
            Status = VarCheckProtocol->VariablePropertySet(mHwErrRecVariable.Name,
                                                            &gEfiHardwareErrorVariableGuid,
                                                            &mHwErrRecVariable.VariableProperty);
            break;
    }

    return Status;
}

EFI_STATUS
EFIAPI
FuzzVariablePropertyGet(
    IN INPUT_BUFFER *Input
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    DEBUG((DEBUG_ERROR, "FUZZING: VariablePropertyGet\n"));
    EDKII_VAR_CHECK_PROTOCOL *VarCheckProtocol;
    gBS->LocateProtocol(&gEdkiiVarCheckProtocolGuid, NULL, (VOID **)&VarCheckProtocol);

    VAR_CHECK_VARIABLE_PROPERTY  VarCheckProperty;

    UINTN Index = 0;
    ReadInput(Input, sizeof(Index), &Index);

    UINTN VariableChoice = 0;
    ReadInput(Input, 1, &VariableChoice);

    switch(VariableChoice%4)
    {
        case 0:
            Index = Index%(sizeof (mGlobalVariableList)/sizeof (mGlobalVariableList[0]));
            Status = VarCheckProtocol->VariablePropertySet(mGlobalVariableList[Index].Name, 
                                                            &gEfiGlobalVariableGuid, 
                                                            &VarCheckProperty);
            break;
        case 1:
            Index = Index%(sizeof (mGlobalVariableList2)/sizeof (mGlobalVariableList2[0]));
            Status = VarCheckProtocol->VariablePropertySet(mGlobalVariableList2[Index].Name,
                                                            &gEfiGlobalVariableGuid,
                                                            &VarCheckProperty);
            break;
        case 2:
            Index = Index%(sizeof (mImageSecurityVariableList)/sizeof (mImageSecurityVariableList[0]));
            Status = VarCheckProtocol->VariablePropertySet(mImageSecurityVariableList[Index].Name,
                                                            &gEfiImageSecurityDatabaseGuid,
                                                            &VarCheckProperty);
            break;
        case 3:
            Status = VarCheckProtocol->VariablePropertySet(mHwErrRecVariable.Name,
                                                            &gEfiHardwareErrorVariableGuid,
                                                            &VarCheckProperty);
            break;
    }

    return Status;
}
