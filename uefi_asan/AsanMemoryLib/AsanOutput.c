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
AsanIoWrite8 (
  IN      UINTN                     Port,
  IN      UINT8                     Value
  )
{
  __asm__ __volatile__ ("outb %b0,%w1" : : "a" (Value), "d" ((UINT16)Port));
  return Value;;
}

UINT8
EFIAPI
AsanIoRead8 (
  IN      UINTN                     Port
  )
{
  UINT8   Data;

  __asm__ __volatile__ ("inb %w1,%b0" : "=a" (Data) : "d" ((UINT16)Port));
  return Data;
}

VOID
Sendbyte(
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
    Buffer8 = AsanIoRead8 (COM_BASE_ADDR + LSR_OFFSET);

    //
    // Loop until the serial port is ready for the next byte
    //
  } while ((Buffer8 & TRANSMIT_READY_BIT) == 0);

  AsanIoWrite8 (COM_BASE_ADDR, Byte);

  return ;
}


//
// Usage sample: SerialOutput ("\nUEFI Boot\n");
//
VOID
SerialOut(
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
      Sendbyte('\r');
    }
    Sendbyte (*Buffer);

    //
    // move Data pointer to the next byte
    //
    Buffer++;
  }

  return ;
}


//
// Usage sample: Assume NumStr[19] is input
//
//CHAR8 NumStr[19]={0}; // '0x0123456789abcdef'
VOID
NumStr64bit(
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