#include "FuzzEvent.h"

EFI_STATUS
EFIAPI
FuzzEvent(
    IN INPUT_BUFFER *Input
)
{
    DEBUG((DEBUG_ERROR, "FUZZING: Events\n"));
    EFI_STATUS Status = EFI_SUCCESS;
    UINT8 EventService = 0;
    ReadInput(Input, 1, &EventService);
    switch(EventService%6)
    {
        case CLOSE_EVENT:
            Status = FuzzCloseEvent(Input);
            break;
        case CREATE_EVENT:
            Status = FuzzCreateEvent(Input);
            break;
        case SIGNAL_EVENT:
            Status = FuzzSignalEvent(Input);
            break;
        case CHECK_EVENT:
            Status = FuzzCheckEvent(Input);
            break;
        case WAIT_FOR_EVENT:
            Status = FuzzWaitForEvent(Input);
            break;
        case CREATE_EVENT_EX:
            Status = FuzzCreateEventEx(Input);
            break;
    }
    return Status;
}


EFI_STATUS
EFIAPI
FuzzCloseEvent(
    IN INPUT_BUFFER *Input
)
{
    /*
    if(Argc != 4)
        {
          Print(L"Need 2 Arguments for CloseEvent\n");
          Print(L"BBClient.efi 1 <EventType> <NotifyTPL>\n");
          Print(L"    <EventType> : The type of event to be created\n");
          Print(L"    <NotifyTPL> : The task priority level of the event\n");
          break;
        }
    */
    DEBUG((DEBUG_ERROR, "FUZZING: CloseEvent\n"));
    EFI_STATUS Status;
    EFI_EVENT DummyEvent;
    CreateDummyEvent(Input, &DummyEvent);
    Status = gBS->CloseEvent(DummyEvent);
    
    return Status;
}

EFI_STATUS
EFIAPI
FuzzCreateEvent(
    IN INPUT_BUFFER *Input
)
{
    /*
    if(Argc != 4)
        {
          Print(L"Need 2 Arguments for CloseEvent\n");
          Print(L"BBClient.efi 1 <EventType> <NotifyTPL>\n");
          Print(L"    <EventType> : The type of event to be created\n");
          Print(L"    <NotifyTPL> : The task priority level of the event\n");
          break;
        }
    */
    UINT8 UserType = 0;
    ReadInput(Input, 8, &UserType);
    UINT8 UserTpl = 0;
    ReadInput(Input, 8, &UserTpl);
    DEBUG((DEBUG_ERROR, "FUZZING: CreateEvent\n"));

    EFI_STATUS Status;
    EFI_EVENT DummyEvent;
    UINT32 Type;
    EFI_TPL NotifyTpl;
    EFI_EVENT_NOTIFY NotifyFunction; // Optional
    VOID *NotifyContext;             // Optional

    //
    // Set the values for the DummyEvent to create
    //
    // Random Notify Type
    switch (UserType % 8)
    {
    case 0:
        Type = EVT_TIMER | EVT_NOTIFY_SIGNAL;
        break;
    case 1:
        Type = EVT_TIMER;
        break;
    case 2:
        Type = EVT_NOTIFY_WAIT;
        break;
    case 3:
        Type = EVT_NOTIFY_SIGNAL;
        break;
    case 4:
        Type = EVT_SIGNAL_EXIT_BOOT_SERVICES;
        break;
    case 5:
        Type = EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE;
        break;
    case 6:
        Type = 0x00000000;
        break;
    case 7:
        Type = EVT_TIMER | EVT_NOTIFY_WAIT;
        break;
    }
    // Needs to be of type TPL_APPLICATION, TPL_CALLBACK, and TPL_NOTIFY
    switch(UserTpl%3)
    {
        case 0:
            NotifyTpl = TPL_APPLICATION;
            break;
        case 1:
            NotifyTpl = TPL_CALLBACK;
            break;
        case 2:
            NotifyTpl = TPL_NOTIFY;
            break;
    }
    //NotifyTpl = (EFI_TPL)UserTpl;
    // Set as NULL but can be set to a custom value
    NotifyFunction = EfiEventEmptyFunction;
    NotifyContext = NULL;
    DEBUG((DEBUG_ERROR, "FUZZING: CreateEvent(\n"));
    DEBUG((DEBUG_ERROR, "                     Type = 0x%x,\n", Type));
    DEBUG((DEBUG_ERROR, "                     NotifyTpl = %r,\n", NotifyTpl));
    DEBUG((DEBUG_ERROR, "                     NotifyFunction = %r,\n", NotifyFunction));
    DEBUG((DEBUG_ERROR, "                     NotifyContext = %d)\n", NotifyContext));
    Status = gBS->CreateEvent(Type, NotifyTpl, NotifyFunction, NotifyContext, &DummyEvent);
    if (EFI_ERROR(Status))
    {
        DEBUG((DEBUG_ERROR, "Couldn't Create DummyEvent of Type: %x with a Status: %r\n", Type, Status));
    }

    return Status;
}

EFI_STATUS
EFIAPI
FuzzSignalEvent(
    IN INPUT_BUFFER *Input
)
{
    DEBUG((DEBUG_ERROR, "FUZZING: SignalEvent\n"));
    EFI_STATUS Status;
    EFI_EVENT DummyEvent;
    CreateDummyEvent(Input, &DummyEvent);
    Status = gBS->SignalEvent(DummyEvent);
    return Status;
}

EFI_STATUS
EFIAPI
FuzzCheckEvent(
    IN INPUT_BUFFER *Input
)
{
    DEBUG((DEBUG_ERROR, "FUZZING: CheckEvent\n"));
    EFI_STATUS Status;
    EFI_EVENT DummyEvent;
    CreateDummyEvent(Input, &DummyEvent);
    Status = gBS->CheckEvent(DummyEvent);
    return Status;
}

EFI_STATUS
EFIAPI
FuzzWaitForEvent(
    IN INPUT_BUFFER *Input
)
{
    // IN Number of Events
    // IN EFI_EVENTS *DummyEvents
    // OUT UINTN* Index
    DEBUG((DEBUG_ERROR, "FUZZING: WaitForEvent\n"));
    EFI_STATUS Status;
    UINTN NumberOfEvents = 1;
    UINTN Index;
    //ReadInput(Input, 8, &NumberOfEvents);
    //NumberOfEvents = StrDecimalToUintn((CHAR16 *)&NumberOfEvents);
    EFI_EVENT DummyEvents[NumberOfEvents];// = AllocatePool(NumberOfEvents*sizeof(EFI_EVENT));
    DEBUG((DEBUG_ERROR, "%d\n", NumberOfEvents));
    for(UINTN i = 0; i < NumberOfEvents; i++)
    {
        DEBUG((DEBUG_ERROR, "%d\n", i));
        CreateDummyEvent(Input, &DummyEvents[i]);
    }
    Status = gBS->WaitForEvent(NumberOfEvents, DummyEvents, &Index);
    return Status;
}

EFI_STATUS
EFIAPI
FuzzCreateEventEx(
    IN INPUT_BUFFER *Input
)
{
    UINT8 UserType = 0;
    ReadInput(Input, 8, &UserType);

    UINT8 UserTpl = 0;
    ReadInput(Input, 8, &UserTpl);
    DEBUG((DEBUG_ERROR, "FUZZING: CreateEvent\n"));

    EFI_STATUS Status;
    EFI_EVENT DummyEvent;
    UINT32 Type;
    EFI_TPL NotifyTpl;
    EFI_EVENT_NOTIFY NotifyFunction; // Optional
    VOID *NotifyContext;             // Optional

    //
    // Set the values for the DummyEvent to create
    //
    // Random Notify Type
    switch (UserType % 8)
    {
    case 0:
        Type = EVT_TIMER | EVT_NOTIFY_SIGNAL;
        break;
    case 1:
        Type = EVT_TIMER;
        break;
    case 2:
        Type = EVT_NOTIFY_WAIT;
        break;
    case 3:
        Type = EVT_NOTIFY_SIGNAL;
        break;
    case 4:
        Type = EVT_SIGNAL_EXIT_BOOT_SERVICES;
        break;
    case 5:
        Type = EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE;
        break;
    case 6:
        Type = 0x00000000;
        break;
    case 7:
        Type = EVT_TIMER | EVT_NOTIFY_WAIT;
        break;
    }
    // Needs to be of type TPL_APPLICATION, TPL_CALLBACK, and TPL_NOTIFY
    switch(UserTpl%3)
    {
        case 0:
            NotifyTpl = TPL_APPLICATION;
            break;
        case 1:
            NotifyTpl = TPL_CALLBACK;
            break;
        case 2:
            NotifyTpl = TPL_NOTIFY;
            break;
    }
    //NotifyTpl = (EFI_TPL)UserTpl;
    // Set as NULL but can be set to a custom value
    NotifyFunction = EfiEventEmptyFunction;
    NotifyContext = NULL;
    DEBUG((DEBUG_ERROR, "FUZZING: CreateEvent(\n"));
    DEBUG((DEBUG_ERROR, "                     Type = 0x%x,\n", Type));
    DEBUG((DEBUG_ERROR, "                     NotifyTpl = %r,\n", NotifyTpl));
    DEBUG((DEBUG_ERROR, "                     NotifyFunction = %r,\n", NotifyFunction));
    DEBUG((DEBUG_ERROR, "                     NotifyContext = %d)\n", NotifyContext));
    Status = gBS->CreateEventEx(Type, NotifyTpl, NotifyFunction, NotifyContext, NULL, &DummyEvent);
    if (EFI_ERROR(Status))
    {
        DEBUG((DEBUG_ERROR, "Couldn't Create DummyEvent of Type: %x with a Status: %r\n", Type, Status));
    }

    return Status;
}