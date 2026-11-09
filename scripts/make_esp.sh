#!/bin/bash
# Build a FAT image holding one UEFI application on the removable media path.
#
# QEMU can serve a directory as a virtual FAT disk (-drive file=fat:rw:<dir>), and
# scripts/qemu_smoke.sh does exactly that against a distribution QEMU. The QEMU that
# libafl_qemu builds is configured without the vvfat block driver, so under the fuzzer
# that same argument fails with "Unknown protocol 'fat'". A real image works under both.
#
# Name the output .qcow2 and it is converted after the FAT is laid down. That matters
# under the fuzzer: QEMU's snapshots need every writable block device to support them, and
# a raw disk does not -- "Device 'ide0-hd0' is writable but does not support snapshots",
# after which the emulator cannot restore between iterations.
#
# Pass --empty in place of the application to lay down a formatted ESP with nothing on
# it. The dxe harness timing needs that: the harness is a DXE_DRIVER linked into OVMF's
# own firmware volume and dispatched before BDS, so there is no Firness.efi to copy and
# nothing ever launches a boot option -- but the fuzzer still needs a writable qcow2
# device for the reasons above. An empty ESP is the honest way to say "no application
# here"; a placeholder binary would boot and confuse the narration.
#
# usage: make_esp.sh <Firness.efi|--empty> <out.img|out.qcow2> [size_mb]
set -eu

EFI=${1:?usage: make_esp.sh <Firness.efi|--empty> <out.img> [size_mb]}
OUT=${2:?usage: make_esp.sh <Firness.efi|--empty> <out.img> [size_mb]}
SIZE_MB=${3:-64}

EMPTY=0
if [ "$EFI" = "--empty" ]; then
    EMPTY=1
else
    [ -f "$EFI" ] || { echo "no such file: $EFI"; exit 2; }
fi
for tool in mkfs.vfat mmd mcopy; do
    command -v "$tool" >/dev/null || { echo "missing $tool -- install dosfstools and mtools"; exit 2; }
done

# an image smaller than the application cannot hold it, and mkfs will not say so
if [ "$EMPTY" = 0 ]; then
    need=$(( ($(stat -c %s "$EFI") / 1048576) + 8 ))
    if [ "$SIZE_MB" -lt "$need" ]; then
        SIZE_MB=$need
    fi
fi

case "$OUT" in
    *.qcow2) RAW="$OUT.raw"; QCOW=1 ;;
    *)       RAW="$OUT";     QCOW=0 ;;
esac

rm -f "$OUT" "$RAW"
truncate -s "${SIZE_MB}M" "$RAW"
mkfs.vfat -n FIRNESS "$RAW" >/dev/null
mmd -i "$RAW" ::/EFI ::/EFI/BOOT
if [ "$EMPTY" = 0 ]; then
    mcopy -i "$RAW" "$EFI" ::/EFI/BOOT/BOOTX64.EFI

    # prove it landed, rather than trusting a silent mcopy
    if ! mdir -i "$RAW" ::/EFI/BOOT | grep -qi 'BOOTX64'; then
        echo "BOOTX64.EFI is not in the image"
        exit 1
    fi
else
    # And prove the opposite, so an --empty that silently picked up a stale BOOTX64 from
    # a reused raw file is caught here rather than looking like a dxe harness that ran.
    if mdir -i "$RAW" ::/EFI/BOOT | grep -qi 'BOOTX64'; then
        echo "--empty was asked for but BOOTX64.EFI is in the image"
        exit 1
    fi
fi

if [ "$QCOW" = 1 ]; then
    command -v qemu-img >/dev/null || { echo "missing qemu-img -- install qemu-utils"; exit 2; }
    qemu-img convert -f raw -O qcow2 "$RAW" "$OUT"
    rm -f "$RAW"
fi
if [ "$EMPTY" = 0 ]; then
    echo "$OUT: ${SIZE_MB}M, EFI/BOOT/BOOTX64.EFI from $EFI"
else
    echo "$OUT: ${SIZE_MB}M, empty ESP (no boot application -- dxe harness timing)"
fi
