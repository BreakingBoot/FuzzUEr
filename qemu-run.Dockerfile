# The image a QEMU-backend campaign runs in: everything fuzzuer-cur has, plus the LibAFL
# fuzzer, the roms its embedded emulator cannot find on its own, and the instrumented
# firmware. Without that firmware the fuzzer falls back to the distribution OVMF, which
# has no sanitizer in it, and the campaign reports crashes and timeouts only.
FROM fuzzuer-cur:latest
RUN apt-get update && apt-get install --yes --no-install-recommends \
      mtools qemu-utils \
    && rm -rf /var/lib/apt/lists/*
COPY ./qemustage/firness_qemu /workspace/qemu_fuzzer/target/release/firness_qemu
COPY ./qemustage/pc-bios /workspace/qemu_fuzzer/target/release/qemu-libafl-bridge/pc-bios
COPY ./qemustage/qemu_fw /workspace/qemu_fw
# The SMM build, for an SMI harness: SMRAM has to exist before PiSmmIpl publishes
# anything, so the machine needs smm=on and the firmware needs SMM_REQUIRE.
COPY ./qemustage/qemu_fw_smm /workspace/qemu_fw_smm
RUN chmod +x /workspace/qemu_fuzzer/target/release/firness_qemu
