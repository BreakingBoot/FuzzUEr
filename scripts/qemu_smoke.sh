#!/bin/bash
# Boot a generated harness under stock QEMU with OVMF and say what the guest did.
#
# This is the cheap half of the QEMU backend: it proves the harness loads and reaches
# HARNESS_START without needing the LibAFL host fuzzer built. The two backends give
# opposite, unambiguous answers, which is what makes it a test rather than a demo:
#
#   --backend none  the harness runs to completion and BDS moves on to the next boot
#                   option. No exception.
#   --backend qemu  the four magic bytes 0f 3a f2 66 are not an x86 instruction, so
#                   stock QEMU raises #UD at the HARNESS_START site. The dump names
#                   Firness.dll and carries the hypercall arguments in registers:
#                   RAX = 0 (START_VIRT), RDI = input buffer, RSI = 0x1000 (max len).
#                   Under qemu-libafl-bridge that same instruction is decoded instead.
#
# A #UD from the "none" build, or none from the "qemu" build, means the backend
# selection never reached the compiler -- see FirnessBackend.h.
set -u

EFI=${1:-}
OVMF_CODE=${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE.fd}
OVMF_VARS=${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS.fd}
TIMEOUT=${TIMEOUT:-90}

if [ -z "$EFI" ] || [ ! -f "$EFI" ]; then
    echo "usage: $0 <path to Firness.efi>   (OVMF_CODE/OVMF_VARS/TIMEOUT override paths)"
    exit 2
fi
for f in "$OVMF_CODE" "$OVMF_VARS"; do
    [ -f "$f" ] || { echo "missing $f -- install the ovmf package"; exit 2; }
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# the removable media path, so OVMF starts it with no shell and no startup.nsh
mkdir -p "$WORK/esp/EFI/BOOT"
cp "$EFI" "$WORK/esp/EFI/BOOT/BOOTX64.EFI"
cp "$OVMF_VARS" "$WORK/vars.fd"

# -smp 1 and the override OVMF names itself: against QEMU 6.2 its PlatformCpuCountBugCheck
# asserts in Platform.c(520) before any driver runs. -debugcon because OVMF writes DEBUG
# there, not to serial.
timeout "$TIMEOUT" qemu-system-x86_64 -machine q35 -m 2048 -no-reboot -smp 1 \
    -fw_cfg name=opt/org.tianocore/X-Cpuhp-Bugcheck-Override,string=yes \
    -debugcon file:"$WORK/debug.log" -global isa-debugcon.iobase=0x402 \
    -drive if=pflash,format=raw,unit=0,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,unit=1,file="$WORK/vars.fd" \
    -drive file=fat:rw:"$WORK/esp",format=raw,if=ide \
    -serial file:"$WORK/serial.log" -display none >/dev/null 2>&1

cat "$WORK/serial.log" "$WORK/debug.log" 2>/dev/null | tr -d '\r' > "$WORK/serial.txt"
started=$(grep -c 'BdsDxe: starting Boot' "$WORK/serial.txt")
ud=$(grep -c 'Exception Type - 06(#UD' "$WORK/serial.txt")
in_harness=$(grep -c 'Firness.dll' "$WORK/serial.txt")

echo "boot options started : $started"
echo "harness image named  : $in_harness"
echo "#UD exceptions       : $ud"
if [ "$ud" -gt 0 ]; then
    grep -A3 'Exception Type - 06(#UD' "$WORK/serial.txt" | head -4
    grep 'Find image based on IP' "$WORK/serial.txt" | head -1
fi

if [ "$started" -eq 0 ]; then
    echo "RESULT: the harness never started -- OVMF did not reach the boot option"
    exit 1
fi
if [ "$ud" -gt 0 ] && [ "$in_harness" -gt 0 ]; then
    echo "RESULT: reached HARNESS_START in the harness (libafl-qemu backend, no host attached)"
    exit 0
fi
if [ "$ud" -eq 0 ]; then
    echo "RESULT: ran to completion with no magic instruction (none backend)"
    exit 0
fi
echo "RESULT: #UD outside the harness -- not the backend magic"
exit 1
