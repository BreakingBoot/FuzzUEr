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

# The emulator is linked into the fuzzer, so it has no data directory and resolves its
# rom path relative to the working directory. Run this script from anywhere else and it
# dies with "no QEMU rom directory holds kvmvapic.bin". Find the bridge checkout's
# pc-bios rather than making the caller know where cargo put it.
if [ -z "${FIRNESS_QEMU_BIOS_DIR:-}" ]; then
    for d in "$(dirname "$FUZZER")/qemu-libafl-bridge/pc-bios" \
             /work/qemu-libafl-bridge/pc-bios \
             "$(dirname "$FUZZER")/pc-bios"; do
        [ -f "$d/kvmvapic.bin" ] && { export FIRNESS_QEMU_BIOS_DIR="$d"; break; }
    done
fi
[ -n "${FIRNESS_QEMU_BIOS_DIR:-}" ] || echo "warning: no pc-bios found; set FIRNESS_QEMU_BIOS_DIR"

# The firmware has to be the instrumented build, or ASan never runs and the campaign
# reports crashes and timeouts only. The fuzzer defaults to the distribution OVMF.
[ -n "${FIRNESS_OVMF_CODE:-}" ] || echo "warning: FIRNESS_OVMF_CODE unset -- using the distribution OVMF, which has no ASan"

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
last=$(grep -a 'CLIENT' "$WORK/run.txt" | tail -1)
if [ -z "$last" ]; then
    echo "no heartbeat: the harness never reached HARNESS_START"
    echo "  serial log: $FIRNESS_SERIAL"
    exit 1
fi
echo "$last"

# The fuzzer's own objectives counter, not a file count: LibAFL's OnDiskCorpus writes a
# lock file and a .metadata file beside each solution, and flushes the corpus into this
# directory at shutdown, so "how many files are here" reports solutions that did not
# happen. Take the number from the last heartbeat instead.
objectives=$(printf '%s' "$last" | sed -n 's/.*objectives: \([0-9]*\).*/\1/p')
echo "objectives: ${objectives:-unknown}"
if [ "${objectives:-0}" -gt 0 ] 2>/dev/null; then
    echo "  inputs in $WORK/crashes (ignore the dot files, they are LibAFL's own)"
fi
