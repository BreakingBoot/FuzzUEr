/** @file
  The debug support routines for AddressSanitizer(ASan) enabling.

  Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials                          
  are licensed and made available under the terms and conditions of the BSD License         
  which accompanies this distribution.  The full text of the license may be found at        
  http://opensource.org/licenses/bsd-license.php.                                            

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,                     
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.             

**/

//
// Local constant definitions
//
#define CONFIG_PORT0        0x2E
#define INDEX_PORT0         0x2E
#define DATA_PORT0          0x2F

#define COM_BASE_ADDR       0x03f8
#define LSR_OFFSET          0x05
#define LCR_OFFSET          0x03
#define DIV_MSB             0x01
#define DIV_LSB             0

#define TRANSMIT_READY_BIT  0x020

#define BAUD_RATE_DIVISOR   115200

#define DATA_BITS           3 // 0 - 5 bits / 1 - 6 bits
                              // 2 - 7 bits / 3 - 8 bits
#define STOP_BIT            1 // 0 - 1 stop bit
                              // 1 - mutiple bits depending on the databits
#define PARITY_BITS         0 // 0 - None / 1 enables parity
#define BREAK_BIT           0 // 0 - No break
#define DLAB_BIT            1 // 0 - Divisor Latch Disabled
                              // 1 - Divisor Latch Enabled
                              

UINT8
EFIAPI
Asan_IoWrite8 (
  IN      UINTN                     Port,
  IN      UINT8                     Value
  )
{
  __asm__ __volatile__ ("outb %b0,%w1" : : "a" (Value), "d" ((UINT16)Port));
  return Value;;
}

UINT8
EFIAPI
Asan_IoRead8 (
  IN      UINTN                     Port
  )
{
  UINT8   Data;

  __asm__ __volatile__ ("inb %w1,%b0" : "=a" (Data) : "d" ((UINT16)Port));
  return Data;
}

VOID
SendByte(
  IN UINT8 Byte
  )
/*++

  Routine Description:
    Send byte data to COM

  Arguments:
    Byte - Byte data

  Returns:
    None

--*/
{
  UINT8 Buffer8;

  do {
    //
    // read the ready signal to see if the serial port is
    // ready for the next byte
    //
    Buffer8 = Asan_IoRead8 (COM_BASE_ADDR + LSR_OFFSET);

    //
    // Loop until the serial port is ready for the next byte
    //
  } while ((Buffer8 & TRANSMIT_READY_BIT) == 0);

  Asan_IoWrite8 (COM_BASE_ADDR, Byte);

  return ;
}
int gSerialOutputSwitch = 1;
//
// Usage sample: SerialOutput ("\nUEFI Boot\n");
//
VOID
SerialOutput(
  IN  CONST CHAR8      *String
  )
/*++

  Routine Description:
    Send string data to COM

  Arguments:
    String - String data

  Returns:
    None

--*/
{
  if (gSerialOutputSwitch == 0) return;
  
  UINT8  *Buffer;

  //
  // first make data usable
  //
  Buffer = (UINT8 *)String;

  //
  // now send data one byte at a time until the string hits the end of string
  // or we hit the max number of characters
  //
  while (*Buffer) {
    //
    // replace "\n" with "\r\n"
    //
    if (*Buffer == '\n') {
      SendByte('\r');
    }
    SendByte (*Buffer);

    //
    // move Data pointer to the next byte
    //
    Buffer++;
  }

  return ;
}

//
// Usage sample: SerialOutput ("\nUEFI Boot\n");
//
VOID
SerialOutput2(
  IN  CONST CHAR8      *String
  )
/*++

  Routine Description:
    Send string data to COM

  Arguments:
    String - String data

  Returns:
    None

--*/
{

  UINT8  *Buffer;

  //
  // first make data usable
  //
  Buffer = (UINT8 *)String;

  //
  // now send data one byte at a time until the string hits the end of string
  // or we hit the max number of characters
  //
  while (*Buffer) {
    //
    // replace "\n" with "\r\n"
    //
    if (*Buffer == '\n') {
      SendByte('\r');
    }
    SendByte (*Buffer);

    //
    // move Data pointer to the next byte
    //
    Buffer++;
  }

  return ;

}

//edk2-fork\CryptoPkg\Library\IntrinsicLib\MemoryIntrinsics.c
void * Intrinsic_memset (void *dest, char ch, unsigned int count)
{
  //
  // NOTE: Here we use one base implementation for memset, instead of the direct
  //       optimized SetMem() wrapper. Because the IntrinsicLib has to be built 
  //       without whole program optimization option, and there will be some 
  //       potential register usage errors when calling other optimized codes.
  //

  //
  // Declare the local variables that actually move the data elements as
  // volatile to prevent the optimizer from replacing this function with
  // the intrinsic memset()
  //
  volatile UINT8  *Pointer;

  Pointer = (UINT8 *)dest;
  while (count-- != 0) {
    *(Pointer++) = ch;
  }
  
  return dest;
}


//MdePkg\Library\BaseMemoryLib\CopyMem.c
/**
  Copy Length bytes from Source to Destination.

  @param  DestinationBuffer The target of the copy request.
  @param  SourceBuffer      The place to copy from.
  @param  Length            The number of bytes to copy.

  @return Destination

**/
VOID *
EFIAPI
Intrinsic_CopyMem (
  OUT     VOID                      *DestinationBuffer,
  IN      CONST VOID                *SourceBuffer,
  IN      UINTN                     Length
  )
{
  //
  // Declare the local variables that actually move the data elements as
  // volatile to prevent the optimizer from replacing this function with
  // the intrinsic memcpy()
  //
  volatile UINT8                    *Destination8;
  CONST UINT8                       *Source8;
  volatile UINT32                   *Destination32;
  CONST UINT32                      *Source32;
  volatile UINT64                   *Destination64;
  CONST UINT64                      *Source64;
  UINTN                             Alignment;

  if ((((UINTN)DestinationBuffer & 0x7) == 0) && (((UINTN)SourceBuffer & 0x7) == 0) && (Length >= 8)) {
    if (SourceBuffer > DestinationBuffer) {
      Destination64 = (UINT64*)DestinationBuffer;
      Source64 = (CONST UINT64*)SourceBuffer;
      while (Length >= 8) {
        *(Destination64++) = *(Source64++);
        Length -= 8;
      }

      // Finish if there are still some bytes to copy
      Destination8 = (UINT8*)Destination64;
      Source8 = (CONST UINT8*)Source64;
      while (Length-- != 0) {
        *(Destination8++) = *(Source8++);
      }
    } else if (SourceBuffer < DestinationBuffer) {
      Destination64 = (UINT64*)((UINTN)DestinationBuffer + Length);
      Source64 = (CONST UINT64*)((UINTN)SourceBuffer + Length);

      // Destination64 and Source64 were aligned on a 64-bit boundary
      // but if length is not a multiple of 8 bytes then they won't be
      // anymore.

      Alignment = Length & 0x7;
      if (Alignment != 0) {
        Destination8 = (UINT8*)Destination64;
        Source8 = (CONST UINT8*)Source64;

        while (Alignment-- != 0) {
          *(--Destination8) = *(--Source8);
          --Length;
        }
        Destination64 = (UINT64*)Destination8;
        Source64 = (CONST UINT64*)Source8;
      }

      while (Length > 0) {
        *(--Destination64) = *(--Source64);
        Length -= 8;
      }
    }
  } else if ((((UINTN)DestinationBuffer & 0x3) == 0) && (((UINTN)SourceBuffer & 0x3) == 0) && (Length >= 4)) {
    if (SourceBuffer > DestinationBuffer) {
      Destination32 = (UINT32*)DestinationBuffer;
      Source32 = (CONST UINT32*)SourceBuffer;
      while (Length >= 4) {
        *(Destination32++) = *(Source32++);
        Length -= 4;
      }

      // Finish if there are still some bytes to copy
      Destination8 = (UINT8*)Destination32;
      Source8 = (CONST UINT8*)Source32;
      while (Length-- != 0) {
        *(Destination8++) = *(Source8++);
      }
    } else if (SourceBuffer < DestinationBuffer) {
      Destination32 = (UINT32*)((UINTN)DestinationBuffer + Length);
      Source32 = (CONST UINT32*)((UINTN)SourceBuffer + Length);

      // Destination32 and Source32 were aligned on a 32-bit boundary
      // but if length is not a multiple of 4 bytes then they won't be
      // anymore.

      Alignment = Length & 0x3;
      if (Alignment != 0) {
        Destination8 = (UINT8*)Destination32;
        Source8 = (CONST UINT8*)Source32;

        while (Alignment-- != 0) {
          *(--Destination8) = *(--Source8);
          --Length;
        }
        Destination32 = (UINT32*)Destination8;
        Source32 = (CONST UINT32*)Source8;
      }

      while (Length > 0) {
        *(--Destination32) = *(--Source32);
        Length -= 4;
      }
    }
  } else {
    if (SourceBuffer > DestinationBuffer) {
      Destination8 = (UINT8*)DestinationBuffer;
      Source8 = (CONST UINT8*)SourceBuffer;
      while (Length-- != 0) {
        *(Destination8++) = *(Source8++);
      }
    } else if (SourceBuffer < DestinationBuffer) {
      Destination8 = (UINT8*)DestinationBuffer + (Length - 1);
      Source8 = (CONST UINT8*)SourceBuffer + (Length - 1);
      while (Length-- != 0) {
        *(Destination8--) = *(Source8--);
      }
    }
  }
  return DestinationBuffer;
}


//
// Usage sample: Assume NumStr[19] is input
//
//CHAR8 NumStr[19]={0}; // '0x0123456789abcdef'
VOID
Num2Str64bit(
  IN  UINT64 Number,
  IN  CHAR8* NumStr
  )
{
  int i, val;
  
  NumStr[0] = '0';
  NumStr[1] = 'x';
  for (i =17; i>= 2; i--){
    val = Number & 0xF;
    if (val < 0xa){
      NumStr[i] = val + '0';
    }else{
      NumStr[i] = val - 0xa + 'A';
    }

    Number = Number>> 4;
  }
  NumStr[18] = 0;
  return ;
}
// '0x01234567'
VOID
Num2Str32bit(
  IN  UINT32 Number,
  IN  CHAR8* NumStr
  )
{
  int i, val;
  NumStr[0] = '0';
  NumStr[1] = 'x';
  for (i =9; i>= 2; i--){
    val = Number & 0xF;
    if (val < 0xa){
      NumStr[i] = val + '0';
    }else{
      NumStr[i] = val - 0xa + 'A';
    }

    Number = Number>> 4;
  }
  NumStr[10] = 0;
  return ;
}
// '0x0123'
VOID
Num2Str16bit(
  IN  UINT16 Number,
  IN  CHAR8* NumStr
  )
{
  int i, val;
  NumStr[0] = '0';
  NumStr[1] = 'x';
  for (i =5; i>= 2; i--){
    val = Number & 0xF;
    if (val < 0xa){
      NumStr[i] = val + '0';
    }else{
      NumStr[i] = val - 0xa + 'A';
    }

    Number = Number>> 4;
  }
  NumStr[6] = 0;
  return ;
}
// '0x01'
VOID
Num2Str8bit(
  IN  UINT8 Number,
  IN  CHAR8* NumStr
  )
{
  int i, val;
  NumStr[0] = '0';
  NumStr[1] = 'x';
  for (i =3; i>= 2; i--){
    val = Number & 0xF;
    if (val < 0xa){
      NumStr[i] = val + '0';
    }else{
      NumStr[i] = val - 0xa + 'A';
    }

    Number = Number>> 4;
  }
  NumStr[4] = 0;
  return ;
}