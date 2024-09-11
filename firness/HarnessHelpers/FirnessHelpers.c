#include "FirnessHelpers.h"



/**
  Duplicate a string.

  @param  Src  The string to be duplicated.

**/
CHAR16 *
EFIAPI
StrDuplicate (
  IN CHAR16  *Src
  )
{
  CHAR16  *Dest;
  UINTN   Size;

  Size = (StrLen (Src) + 1) * sizeof (CHAR16);
  Dest = AllocateZeroPool (Size);
  if (Dest != NULL) {
    CopyMem (Dest, Src, Size);
  }

  return Dest;
}

__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
ReadBytes(
  IN INPUT_BUFFER *inputBuffer, 
  IN UINTN numBytes, 
  OUT VOID *outputBuffer
  )
{
  // Check for valid input
  if (inputBuffer == NULL || outputBuffer == NULL) 
  {
    return EFI_ABORTED;
  }

  // Determine the actual number of bytes to extract
  UINTN actualBytes = (inputBuffer->Length - numBytes >= 0) ? numBytes : inputBuffer->Length;

  // Copy the bytes from the input buffer to the output buffer
  CopyMem((UINT8*)outputBuffer, inputBuffer->Buffer, actualBytes);

  // Update the input buffer to remove the extracted bytes
  inputBuffer += actualBytes;
  inputBuffer->Length -= actualBytes;

  return EFI_SUCCESS;
}