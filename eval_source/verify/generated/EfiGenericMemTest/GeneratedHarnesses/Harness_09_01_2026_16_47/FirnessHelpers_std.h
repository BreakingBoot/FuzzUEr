#pragma once
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <uchar.h>

typedef struct {
  uint8_t *Buffer;
  uint64_t Length;
} INPUT_BUFFER;

typedef struct {
  uint32_t  Data1;
  uint16_t  Data2;
  uint16_t  Data3;
  uint8_t   Data4[8];
} EFI_GUID;

static void ReadByte(
    INPUT_BUFFER *InputBuffer,
    void *Buffer)
{
    if (InputBuffer->Length > 0) {
        *(unsigned char *)Buffer = *(unsigned char *)InputBuffer->Buffer;
        InputBuffer->Buffer++;
        InputBuffer->Length--;
    } else {
        memset(Buffer, 0, 1);
    }
}


static void ReadBytes(
    INPUT_BUFFER *InputBuffer,
    uint64_t NumBytes,
    void *Buffer)
{
    if (InputBuffer == NULL || Buffer == NULL) {
        return;
    }

    for (uint64_t i = 0; i < NumBytes; i++) {
        ReadByte(InputBuffer, (unsigned char *)Buffer + i);
    }
}

static size_t read_byte_file(const char* filename, void* buffer, size_t buffer_size) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        return 0;
    }

    size_t bytes_read = fread(buffer, 1, buffer_size, file);
    fclose(file);

    return bytes_read;
}