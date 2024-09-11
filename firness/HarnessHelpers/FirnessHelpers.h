#ifndef __FIRNESS_HELPERS_H__
#define __FIRNESS_HELPERS_H__

#include "FirnessIncludes.h"
typedef struct {
  UINT8 *Buffer;
  UINTN Length;
} INPUT_BUFFER;

// Read in a specified number of bytes from the input buffer
// and copy them to the output buffer. The input buffer is
// updated to remove the extracted bytes. If the input buffer
// does not contain enough bytes, the output buffer is filled
// with zeros. The output buffer is allocated by this function
// and must be freed by the caller. The output buffer can be any
// type of buffer which is why it is a void pointer.
EFI_STATUS
EFIAPI
ReadBytes(
  IN INPUT_BUFFER *inputBuffer, 
  IN UINTN numBytes, 
  OUT VOID *outputBuffer
  );

/**
  Duplicate a string.

  @param  Src  The string to be duplicated.

**/
CHAR16 *
EFIAPI
StrDuplicate (
  IN CHAR16  *Src
  );

#endif