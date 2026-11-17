#!/usr/bin/env python3
"""Read the ACPI Boot Graphics Resource Table and classify the image it points at.

This is the operating-system half of the BootLogo2 use-after-free reproducer. It is
strictly read-only: it opens files under /sys and, only if asked, /dev/mem. It writes
nothing, anywhere.

What it is for. BootGraphicsResourceTableDxe builds the BGRT's image from
mLogoBltBuffer (BootGraphicsResourceTableDxe.c:484) and publishes the result as
ImageAddress (:503). Run the UEFI reproducer, let the firmware reach ReadyToBoot once
more, and whatever the use-after-free left in mLogoBltBuffer is what lands in that
table -- which the OS then reads. This tool says what arrived.

Where the bytes come from, in order of preference:

  /sys/firmware/acpi/bgrt/image
      The kernel's own copy. drivers/firmware/efi/efi-bgrt.c copies the image out of
      firmware memory early in boot, before EfiBootServicesData is reclaimed, which is
      the only reason the bytes are still readable at all: TranslateGopBltToBmp
      allocates the BMP with AllocateZeroPool, so it lives in EfiBootServicesData and
      the OS is entitled to reuse that memory. If this file exists, prefer it -- it is
      literally "what the OS read from the firmware".

  /sys/firmware/acpi/tables/BGRT + /dev/mem
      The raw table, with the image fetched from the physical address it names. Needs
      root and a kernel without CONFIG_STRICT_DEVMEM. The bytes may already have been
      overwritten by the OS, for the reason above, so a mismatch here proves nothing.

usage:
  sudo ./read-bgrt.py                 # classify, 64 bytes of hex
  sudo ./read-bgrt.py --bytes 256
  sudo ./read-bgrt.py --save bgrt.bmp # keep the image for the record
  sudo ./read-bgrt.py --devmem        # force the raw table + /dev/mem path
"""

import argparse
import os
import struct
import sys

SYS_BGRT = "/sys/firmware/acpi/bgrt"
SYS_TABLE = "/sys/firmware/acpi/tables/BGRT"

POOL_FREE_POISON = 0xAF

# The value range of PATTERN_BYTE() in BootLogo2Uaf.c, which is 0x21 + (offset & 0x3F).
# The offsets themselves are not usable on this side of the BLT-to-BMP conversion; see
# classify() for why.
PATTERN_LOW = 0x21
PATTERN_HIGH = 0x60


def read_file(path, binary=True):
    mode = "rb" if binary else "r"
    with open(path, mode) as handle:
        return handle.read()


def parse_table(blob):
    """BGRT per ACPI 5.0: 36-byte description header then the fields below."""
    if len(blob) < 56:
        raise ValueError("BGRT is %d bytes, expected at least 56" % len(blob))
    signature = blob[0:4].decode("ascii", "replace")
    length, = struct.unpack_from("<I", blob, 4)
    oem = blob[10:16].decode("ascii", "replace")
    version, status, image_type = struct.unpack_from("<HBB", blob, 36)
    image_address, = struct.unpack_from("<Q", blob, 40)
    offset_x, offset_y = struct.unpack_from("<II", blob, 48)
    return {
        "signature": signature,
        "length": length,
        "oem": oem,
        "version": version,
        "status": status,
        "image_type": image_type,
        "image_address": image_address,
        "offset_x": offset_x,
        "offset_y": offset_y,
    }


def parse_bmp(blob):
    if len(blob) < 54 or blob[0:2] != b"BM":
        return None
    size, = struct.unpack_from("<I", blob, 2)
    image_offset, = struct.unpack_from("<I", blob, 10)
    width, height = struct.unpack_from("<ii", blob, 18)
    bpp, = struct.unpack_from("<H", blob, 28)
    return {
        "size": size,
        "image_offset": image_offset,
        "width": width,
        "height": height,
        "bpp": bpp,
    }


def hexdump(blob, count, indent="  "):
    out = []
    for base in range(0, min(count, len(blob)), 16):
        chunk = blob[base:base + 16]
        out.append("%s+%04x: %s" % (indent, base, " ".join("%02x" % b for b in chunk)))
    return "\n".join(out)


def classify(pixels, count):
    """Say what the first `count` bytes of the image data are."""
    sample = pixels[:count]
    if not sample:
        return "no image data to classify"

    if all(b == POOL_FREE_POISON for b in sample):
        return (
            "every one of the first %d bytes is 0x%02x.\n"
            "    That is PcdDebugClearMemoryValue, the byte DxeCore writes over a pool\n"
            "    block in CoreFreePoolI. Freed firmware heap has reached an ACPI table\n"
            "    this OS reads." % (len(sample), POOL_FREE_POISON)
        )

    poison = sum(1 for b in sample if b == POOL_FREE_POISON)
    if poison * 2 > len(sample):
        return (
            "%d of the first %d bytes are 0x%02x (the pool free poison), mixed with\n"
            "    other content -- consistent with part of a freed block arriving here."
            % (poison, len(sample), POOL_FREE_POISON)
        )

    # No pattern comparison beyond this point, on purpose.
    #
    # TranslateGopBltToBmp drops the Reserved byte of every EFI_GRAPHICS_OUTPUT_BLT_PIXEL
    # and writes the rows bottom-up, so the reproducer's 64-byte-period pattern does not
    # survive into the BMP at the same offsets. A byte-for-byte pattern match here would
    # be meaningless, and a "matches for N bytes" count reads as evidence when it is not.
    # A single repeated byte does survive both transformations, which is why the free
    # poison above is the only thing this classifies.
    #
    # Whether the pattern made it into the driver's buffer at all is decided inside the
    # firmware, by the UEFI reproducer, which reads the buffer directly.
    in_pattern_range = sum(1 for b in sample if PATTERN_LOW <= b <= PATTERN_HIGH)
    return (
        "not the pool free poison (%d of the first %d bytes are 0x%02x). %d of them fall\n"
        "    in the pattern's value range 0x%02x..0x%02x, which is suggestive and not proof:\n"
        "    the BLT-to-BMP conversion drops a byte per pixel and flips the row order, so\n"
        "    the pattern cannot be matched offset for offset here. Most likely this is the\n"
        "    platform's own logo -- run the UEFI reproducer first, then let the firmware\n"
        "    reach ReadyToBoot once more. Its own VERDICT line is the authoritative one."
        % (poison, len(sample), POOL_FREE_POISON, in_pattern_range,
           PATTERN_LOW, PATTERN_HIGH)
    )


def from_sysfs():
    if not os.path.isdir(SYS_BGRT):
        return None
    fields = {}
    for name in ("version", "status", "type", "xoffset", "yoffset"):
        path = os.path.join(SYS_BGRT, name)
        try:
            fields[name] = int(read_file(path, binary=False).strip())
        except (OSError, ValueError):
            fields[name] = None
    image_path = os.path.join(SYS_BGRT, "image")
    try:
        image = read_file(image_path)
    except OSError as error:
        print("note: %s: %s" % (image_path, error))
        image = b""
    return fields, image


def from_devmem(table):
    address = table["image_address"]
    if address == 0:
        raise ValueError("the table's ImageAddress is 0 -- no image is published")
    # The BMP header comes first; read it, then the rest of the declared size.
    with open("/dev/mem", "rb") as mem:
        mem.seek(address)
        head = mem.read(54)
        bmp = parse_bmp(head)
        if bmp is None:
            raise ValueError(
                "no 'BM' signature at 0x%x -- either the OS has already reused this\n"
                "memory (it is EfiBootServicesData) or /dev/mem is restricted" % address
            )
        size = min(bmp["size"], 64 * 1024 * 1024)
        mem.seek(address)
        return mem.read(size)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bytes", type=int, default=64,
                        help="how many bytes of image data to dump and classify")
    parser.add_argument("--save", metavar="FILE",
                        help="write the image out as a .bmp for the record")
    parser.add_argument("--devmem", action="store_true",
                        help="ignore /sys/firmware/acpi/bgrt and use the raw table")
    args = parser.parse_args()

    table = None
    if os.path.exists(SYS_TABLE):
        try:
            table = parse_table(read_file(SYS_TABLE))
        except (OSError, ValueError) as error:
            print("note: %s: %s" % (SYS_TABLE, error))
    else:
        print("note: %s does not exist" % SYS_TABLE)

    if table:
        print("BGRT table (%s):" % SYS_TABLE)
        print("  signature     %s" % table["signature"])
        print("  length        %d" % table["length"])
        print("  oem id        %s" % table["oem"])
        print("  version       %d" % table["version"])
        print("  status        0x%02x (bit0 = image valid)" % table["status"])
        print("  image type    %d (0 = bitmap)" % table["image_type"])
        print("  image address 0x%016x" % table["image_address"])
        print("  offset        (%d, %d)" % (table["offset_x"], table["offset_y"]))
        print()

    image = b""
    source = None
    if not args.devmem:
        sysfs = from_sysfs()
        if sysfs is not None:
            fields, image = sysfs
            source = os.path.join(SYS_BGRT, "image")
            print("kernel's own copy (%s):" % SYS_BGRT)
            print("  version %s  status %s  type %s  offset (%s, %s)  image %d bytes"
                  % (fields["version"], fields["status"], fields["type"],
                     fields["xoffset"], fields["yoffset"], len(image)))
            print()

    if not image:
        if table is None:
            print("no BGRT at all: this machine's firmware published no boot graphics table.")
            return 2
        try:
            image = from_devmem(table)
            source = "/dev/mem at 0x%016x" % table["image_address"]
        except (OSError, ValueError) as error:
            print("could not read the image: %s" % error)
            if os.geteuid() != 0:
                print("(run as root)")
            return 2

    bmp = parse_bmp(image)
    if bmp is None:
        print("the image does not start with a BMP header; raw bytes from %s:" % source)
        print(hexdump(image, args.bytes))
        return 1

    print("image from %s:" % source)
    print("  BMP %dx%d, %d bpp, %d bytes, pixel data at +0x%x"
          % (bmp["width"], bmp["height"], bmp["bpp"], bmp["size"], bmp["image_offset"]))

    pixels = image[bmp["image_offset"]:]
    print("  pixel data (a BMP stores rows bottom-up, so this is the last row first):")
    print(hexdump(pixels, args.bytes, indent="    "))
    print()
    print("  VERDICT: %s" % classify(pixels, args.bytes))

    if args.save:
        with open(args.save, "wb") as handle:
            handle.write(image)
        print()
        print("image written to %s" % args.save)

    return 0


if __name__ == "__main__":
    sys.exit(main())
