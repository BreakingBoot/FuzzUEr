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
COPY ./scripts /workspace/scripts/
COPY ./scripts/firness.py /workspace/
COPY ./uefi_asan /workspace/uefi_asan/
COPY ./qemustage/firness_qemu /workspace/qemu_fuzzer/target/release/firness_qemu
COPY ./qemustage/pc-bios /workspace/qemu_fuzzer/target/release/qemu-libafl-bridge/pc-bios
RUN chmod +x /workspace/qemu_fuzzer/target/release/firness_qemu
