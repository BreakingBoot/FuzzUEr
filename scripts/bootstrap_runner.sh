#!/usr/bin/env bash
#
# Make a machine able to run scripts/fuzz_edk2.py.
#
#   scripts/bootstrap_runner.sh
#
# Idempotent: every step checks for its own output first, so a runner that already has the
# images does nothing and the workflow's first step costs seconds. Nothing here is fast on
# a cold machine -- the base image builds LLVM 15 from source and installs Simics, and the
# fuzzer builds QEMU -- which is exactly why it is separate from the run and why the check
# comes before the work.
#
# It does NOT build the firmware. That belongs to the version under test and fuzz_edk2.py
# builds it per ref.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO="$PWD"

have_image() { docker image inspect "$1" >/dev/null 2>&1; }
say() { printf '\n=== %s ===\n' "$*"; }

FORCE="${BOOTSTRAP_FORCE:-}"

# --- the submodules the images are built from ------------------------------------------
# A checkout without them produces an image with an empty /workspace/harness_generator,
# and every campaign then fails inside the container with no reference to the checkout.
say 'submodules'
for m in firness uefi_asan tsffs; do
    if [ ! -e "$m/.git" ] && [ -z "$(ls -A "$m" 2>/dev/null || true)" ]; then
        echo "  $m is empty, fetching"
        git submodule update --init --depth=1 "$m"
    else
        echo "  $m present"
    fi
done

# --- the toolchain image ----------------------------------------------------------------
say 'fuzzuer-base'
if have_image fuzzuer-base:latest && [ -z "$FORCE" ]; then
    echo '  present'
else
    echo '  building (LLVM 15 from source and the Simics packages; this takes hours)'
    docker build -t fuzzuer-base:latest -f Dockerfile "$REPO"
fi

# --- the LibAFL-QEMU fuzzer -------------------------------------------------------------
# qemustage/ is not tracked: it holds a 130 MB binary and the pc-bios tree that the
# emulator inside it needs. Building it here is what lets a clean clone reach a campaign.
say 'qemustage'
if [ -x qemustage/firness_qemu ] && [ -d qemustage/pc-bios ] && [ -z "$FORCE" ]; then
    echo "  present ($(du -sh qemustage/firness_qemu | cut -f1) fuzzer, \
$(ls qemustage/pc-bios | wc -l) rom files)"
else
    echo '  building the fuzzer (clones and builds qemu-libafl-bridge)'
    docker build -t fuzzuer-fuzzer:latest -f fuzzer.Dockerfile "$REPO"
    mkdir -p qemustage
    cid=$(docker create fuzzuer-fuzzer:latest)
    trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT
    docker cp "$cid:/workspace/qemu_fuzzer/target/release/firness_qemu" qemustage/
    # libafl_qemu clones the bridge under the target directory; ask the image where it put
    # it rather than assuming, since the path moves with the crate version
    roms=$(docker run --rm --entrypoint bash fuzzuer-fuzzer:latest -c \
        'find /workspace/qemu_fuzzer/target/release -maxdepth 3 -type d -name pc-bios | head -1')
    [ -n "$roms" ] || { echo '  no pc-bios in the build output' >&2; exit 1; }
    rm -rf qemustage/pc-bios
    docker cp "$cid:$roms" qemustage/pc-bios
    docker rm -f "$cid" >/dev/null
    trap - EXIT
    chmod +x qemustage/firness_qemu
    echo "  staged $(du -sh qemustage/firness_qemu | cut -f1) fuzzer and \
$(ls qemustage/pc-bios | wc -l) rom files"
fi

# --- the campaign base image ------------------------------------------------------------
say 'fuzzuer-ci'
if have_image fuzzuer-ci:latest && [ -z "$FORCE" ]; then
    echo '  present'
else
    docker build -t fuzzuer-ci:latest -f ci.Dockerfile "$REPO"
fi

# --- the container fuzz_edk2.py builds firmware in ---------------------------------------
say 'builder container'
if [ -n "$(docker ps -q --filter name=^fwbuild-stack$)" ] && [ -z "$FORCE" ]; then
    echo '  fwbuild-stack is up'
else
    docker rm -f fwbuild-stack >/dev/null 2>&1 || true
    docker run -d --name fwbuild-stack fuzzuer-base:latest sleep infinity >/dev/null
    echo '  fwbuild-stack started'
fi

# --- where the refs come from -------------------------------------------------------------
say 'edk2 remotes'
if [ -d eval_source/edk2/.git ] || [ -f eval_source/edk2/.git ]; then
    git -C eval_source/edk2 remote add tianocore https://github.com/tianocore/edk2.git \
        2>/dev/null || true
    echo "  tianocore -> $(git -C eval_source/edk2 remote get-url tianocore)"
else
    echo '  eval_source/edk2 is not checked out; fuzz_edk2.py needs it for the port' >&2
    exit 1
fi

say 'ready'
echo "  python3 scripts/fuzz_edk2.py --ref edk2-stable202505"
