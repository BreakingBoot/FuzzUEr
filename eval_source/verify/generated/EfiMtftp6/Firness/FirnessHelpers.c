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

  if (inputBuffer->Buffer == NULL)
  {
    inputBuffer->Length = 0;
  }

  // Determine the actual number of bytes to extract. Both operands are UINTN, so
  // "Length - numBytes >= 0" would always be true and over-read a short buffer.
  UINTN actualBytes = (inputBuffer->Length >= numBytes) ? numBytes : inputBuffer->Length;

  // Bytes the input cannot supply are zero, per the contract in FirnessHelpers.h
  SetMem(outputBuffer, numBytes, 0);

  // Copy the bytes from the input buffer to the output buffer
  if (actualBytes > 0)
  {
    CopyMem((UINT8*)outputBuffer, inputBuffer->Buffer, actualBytes);
  }

  // Update the input buffer to remove the extracted bytes. Advance the cursor inside
  // the buffer; advancing inputBuffer itself walks the struct pointer off its object.
  inputBuffer->Buffer += actualBytes;
  inputBuffer->Length -= actualBytes;

  return EFI_SUCCESS;
}