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
RUN chmod +x /workspace/qemu_fuzzer/target/release/firness_qemu
