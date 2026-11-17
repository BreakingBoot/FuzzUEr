#!/bin/bash
# Boot BootLogo2Uaf.efi under QEMU with OVMF and print what it decided.
#
# The ESP is laid down by this project's scripts/make_esp.sh -- the same removable-media
# path the fuzzer's harness uses. One short boot, no fuzzer, no snapshotting.
#
# The use-after-free itself needs nothing but the one run: BDS launches
# EFI/BOOT/BOOTX64.EFI and the application reaches a verdict before it returns.
#
# The OS-visible half needs a second ReadyToBoot, because BgrtReadyToBootEventNotify is
# the only thing that turns mLogoBltBuffer into the BGRT, and BDS already signalled
# ReadyToBoot once before this application was launched. Two ways to get one:
#
#   REPUBLISH=1 (the default here)  the ESP carries a \BL2UAF.RTB marker and the
#       application signals ReadyToBoot itself, so the whole chain is visible in this
#       single run. It re-runs every ReadyToBoot notification in the firmware; the
#       varstore below is a throwaway copy, so nothing persists. See the README before
#       doing this on hardware.
#
#   REPUBLISH=0  nothing is signalled. The firmware reaches ReadyToBoot again by itself
#       the moment it launches the next boot option, and a startup.nsh is on the ESP so a
#       firmware whose next option is the UEFI shell runs the application a second time
#       and reads the table back. Debian's OVMF does NOT do that: its next boot option is
#       UiApp, which signals ReadyToBoot (so the table IS rebuilt) and then sits in the
#       setup menu, where nothing reads it back. Measured on
#       /usr/share/OVMF/OVMF_CODE_4M.fd, QEMU 6.2.
#
# usage:
#   ./run-qemu.sh <BootLogo2Uaf.efi> [out-dir]
#
# env:
#   OVMF_CODE  default /usr/share/OVMF/OVMF_CODE_4M.fd
#   OVMF_VARS  default /usr/share/OVMF/OVMF_VARS_4M.fd
#   REPUBLISH  1 (default) to place the \BL2UAF.RTB marker, 0 to leave it out
#   TIMEOUT    seconds, default 180
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)

EFI=${1:?usage: run-qemu.sh <BootLogo2Uaf.efi> [out-dir]}
OUT=${2:-$HERE/qemu-out}
OVMF_CODE=${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}
OVMF_VARS=${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}
REPUBLISH=${REPUBLISH:-1}
TIMEOUT=${TIMEOUT:-180}

[ -f "$EFI" ] || { echo "no such file: $EFI"; exit 2; }
for f in "$OVMF_CODE" "$OVMF_VARS"; do
    [ -f "$f" ] || { echo "missing $f"; exit 2; }
done
command -v qemu-system-x86_64 >/dev/null || { echo "missing qemu-system-x86_64"; exit 2; }
command -v mcopy >/dev/null || { echo "missing mcopy -- install mtools"; exit 2; }

rm -rf "$OUT"
mkdir -p "$OUT"

# The project's own ESP builder, so the media layout is the one the rest of the repo uses.
"$REPO/scripts/make_esp.sh" "$EFI" "$OUT/esp.img" 64 >/dev/null

printf 'echo -off\r\necho startup.nsh: second run\r\nfs0:\r\ncd \\EFI\\BOOT\r\nBOOTX64.EFI\r\nreset -s\r\n' > "$OUT/startup.nsh"
mcopy -i "$OUT/esp.img" "$OUT/startup.nsh" ::/startup.nsh

if [ "$REPUBLISH" = 1 ]; then
    printf 'signal ReadyToBoot after the use-after-free\n' > "$OUT/BL2UAF.RTB"
    mcopy -i "$OUT/esp.img" "$OUT/BL2UAF.RTB" ::/BL2UAF.RTB
fi

cp "$OVMF_VARS" "$OUT/vars.fd"

# -smp 1 and the cpuhp override: against QEMU 6.2 OVMF's PlatformCpuCountBugCheck asserts
# in Platform.c(520) before any driver runs. -debugcon because OVMF writes its DEBUG
# stream to the ISA debug port; AsanLib writes its reports to COM1, which is -serial.
set +e
timeout "$TIMEOUT" qemu-system-x86_64 -machine q35 -m 2048 -no-reboot -smp 1 \
    -fw_cfg name=opt/org.tianocore/X-Cpuhp-Bugcheck-Override,string=yes \
    -debugcon file:"$OUT/debugcon.log" -global isa-debugcon.iobase=0x402 \
    -drive if=pflash,format=raw,unit=0,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,unit=1,file="$OUT/vars.fd" \
    -drive file="$OUT/esp.img",format=raw,if=ide \
    -serial file:"$OUT/serial.log" -display none >"$OUT/qemu.log" 2>&1
RC=$?
set -e

tr -d '\r' < "$OUT/serial.log" > "$OUT/serial.txt" 2>/dev/null || true
mcopy -n -i "$OUT/esp.img" ::/bootlogo2-uaf.log "$OUT/bootlogo2-uaf.log" 2>/dev/null || true
if [ -f "$OUT/bootlogo2-uaf.log" ]; then
    tr -d '\r' < "$OUT/bootlogo2-uaf.log" > "$OUT/report.txt"
fi

echo "qemu exit        : $RC (124 = timeout)"
echo "firmware         : $OVMF_CODE"
echo "\\BL2UAF.RTB      : $([ "$REPUBLISH" = 1 ] && echo 'present (ReadyToBoot is re-signalled)' || echo 'absent')"
echo "output           : $OUT"
echo

if [ -f "$OUT/report.txt" ]; then
    echo "--- report from the guest (\\bootlogo2-uaf.log) ----------------------"
    cat "$OUT/report.txt"
else
    echo "the guest wrote no \\bootlogo2-uaf.log -- falling back to the serial stream"
    cat "$OUT/serial.txt" 2>/dev/null | tail -80
fi

echo
echo "--- ASan reports -------------------------------------------------"
# AsanEmitReport writes two lines per finding: "[ASan] ERROR: Invalid memory access:
# address ..., size ..., is_write ..., ip ..." and then "bug_descr=<class> in file: <path>
# at line: <ip>". On this project's instrumented OVMF they arrive on COM1; the firmware's
# own DEBUG stream, which is where the module attribution is printed, goes to the ISA
# debug port. Both are searched, because which one carries the report depends on how the
# firmware was built -- a build flag has moved it before.
for f in "$OUT/serial.txt" "$OUT/debugcon.log"; do
    [ -s "$f" ] || continue
    if grep -q 'ASan\] ERROR\|bug_descr=' "$f"; then
        echo "in $(basename "$f"):"
        grep -n 'ASan\] ERROR\|bug_descr=' "$f"
    fi
done
if ! grep -qs 'ASan\] ERROR\|bug_descr=' "$OUT/serial.txt" "$OUT/debugcon.log"; then
    echo "none (this firmware is not an instrumented build, or nothing was detected)"
fi

echo
echo "--- exceptions -----------------------------------------------------"
grep -c 'Exception Type' "$OUT/serial.txt" "$OUT/debugcon.log" 2>/dev/null || true

if [ -f "$OUT/report.txt" ]; then
    grep -E '^VERDICT:' "$OUT/report.txt" || true
fi
