#!/bin/bash
# Fuzz a generated harness under LibAFL-QEMU.
#
# The pieces and why they are what they are:
#   * the harness must be generated with --backend qemu, so it emits the libafl custom
#     instruction instead of the tsffs CPUID and is built without the sanitizers, which
#     need a shadow region OVMF does not publish;
#   * it is delivered as EFI/BOOT/BOOTX64.EFI inside a qcow2, so OVMF starts it over the
#     removable media path with no shell, no startup.nsh and no console input;
#   * both OVMF pflash images are read-only, because QEMU will not snapshot a writable
#     one, and the snapshot is what every iteration after the first restores from.
#
# scripts/qemu_smoke.sh is the cheaper check that the harness reaches HARNESS_START.
set -eu

EFI=${1:?usage: qemu_fuzz.sh <Firness.efi> [seconds]}
SECONDS_TO_RUN=${2:-600}

FUZZER=${FIRNESS_FUZZER:-./target/release/firness_qemu}
WORK=${FIRNESS_WORK:-/work/firness_qemu}
ESP=${FIRNESS_ESP:-$WORK/esp.qcow2}
MAKE_ESP=${MAKE_ESP:-$(dirname "$0")/make_esp.sh}

[ -x "$FUZZER" ] || { echo "no fuzzer at $FUZZER -- cargo build --release in Harness/qemu_fuzzer"; exit 2; }

"$MAKE_ESP" "$EFI" "$ESP" 64

mkdir -p "$WORK/corpus" "$WORK/crashes"
# an empty corpus makes the fuzzer exit with "No entries in corpus", which reads as a
# broken target rather than a missing seed
if [ -z "$(ls -A "$WORK/corpus" 2>/dev/null)" ]; then
    head -c 64 /dev/urandom > "$WORK/corpus/seed"
fi

export FIRNESS_ESP="$ESP"
export FIRNESS_CORPUS="$WORK/corpus"
export FIRNESS_CRASHES="$WORK/crashes"
export FIRNESS_SERIAL="${FIRNESS_SERIAL:-$WORK/serial.log}"

echo "fuzzing $EFI for ${SECONDS_TO_RUN}s; crashes land in $WORK/crashes"
timeout "$SECONDS_TO_RUN" "$FUZZER" 2>&1 | tee "$WORK/run.txt" | grep -aE 'Heartbeat|Objective' || true

echo
echo "--- result ---"
grep -a 'CLIENT' "$WORK/run.txt" | tail -1 || echo "no heartbeat: the harness never reached HARNESS_START"
echo "solutions: $(ls -1 "$WORK/crashes" 2>/dev/null | wc -l)"
