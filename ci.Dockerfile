# The campaign base image for an unattended run.
#
# fuzzuer-cur and fuzzuer-qemu cannot be built on a machine that has only cloned this
# repository: they COPY ckptstage/, fwstage/ and qemustage/, none of which is tracked --
# ckptstage and fwstage are Simics artefacts, a booted checkpoint and a board firmware,
# which a QEMU run never touches. This image carries only what a QEMU campaign needs, so
# a runner can build it from a clean checkout once qemustage/ has been produced.
#
# It deliberately ships no edk2 tree and no firmware. scripts/fuzz_edk2.py layers the
# version under test on top, and a campaign that somehow ran against this image directly
# stops at firness.py's "no OVMF_CODE at /workspace/qemu_fw/OVMF_CODE.fd" rather than
# quietly booting someone else's firmware.
FROM fuzzuer-base:latest
RUN apt-get update && apt-get install --yes --no-install-recommends \
      mtools qemu-utils qemu-system-x86 \
    && rm -rf /var/lib/apt/lists/*
COPY ./firness/harness_generator /workspace/harness_generator
COPY ./firness/HarnessHelpers /workspace/HarnessHelpers

# The analyzer, rebuilt from this repository's source rather than inherited.
#
# fuzzuer-base carries both the analyzer source tree and a firness binary built when that
# image was made -- which on the current base is 2026-08-27. The line above ships the
# generator's Python, so a change to the Python took effect and a change to the C++ did
# not, and nothing said so. Run 42299962707 is what that looks like from the outside:
# smi-call-edges.json simply was not in the campaign directory, because the binary that
# ran predated the pass that writes it, while the Python half of the same commit ran and
# crashed the generator.
#
# The firness target is already registered in the base's clang-tools-extra CMakeLists and
# its build directory is configured, so this is a link of one target and not an LLVM build.
COPY ./firness/firness /workspace/llvm-15.0.7/clang-tools-extra/firness/firness
COPY ./firness/CMakeLists.txt /workspace/llvm-15.0.7/clang-tools-extra/firness/CMakeLists.txt
RUN cd /workspace/llvm-15.0.7/build \
    && cmake . >/dev/null \
    && ninja firness \
    && /workspace/llvm-15.0.7/build/bin/firness --help >/dev/null 2>&1 \
    ; test -x /workspace/llvm-15.0.7/build/bin/firness
COPY ./scripts /workspace/scripts/
COPY ./scripts/firness.py /workspace/
COPY ./uefi_asan /workspace/uefi_asan/
COPY ./qemustage/firness_qemu /workspace/qemu_fuzzer/target/release/firness_qemu
COPY ./qemustage/pc-bios /workspace/qemu_fuzzer/target/release/qemu-libafl-bridge/pc-bios
RUN chmod +x /workspace/qemu_fuzzer/target/release/firness_qemu
