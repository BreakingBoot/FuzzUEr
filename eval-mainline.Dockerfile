# A campaign image whose harness build tree is mainline edk2.
#
# The firmware and the harness have to come from the same edk2. fuzzuer-cur ships the fork
# tree at /workspace/tmp/edk2 and firness.py builds Firness.efi there; pairing that harness
# with mainline firmware produced an application that BDS started and that then emitted
# nothing at all -- no constructor output, no HARNESS_START -- so the fuzzer waited through
# the whole budget for a handshake that never came and reported zero executions.
FROM fuzzuer-cur:latest
# The ESP builder shells out to mmd. fuzzuer-cur does not carry mtools -- qemu-run
# installs it -- so a campaign here generates and compiles a harness, reaches
# run_qemu_fuzzer, and stops at "could not build the ESP: missing mmd".
RUN apt-get update && apt-get install --yes --no-install-recommends \
      mtools dosfstools qemu-utils \
    && rm -rf /var/lib/apt/lists/*
RUN rm -rf /workspace/tmp/edk2
COPY ./mlstage/edk2 /workspace/tmp/edk2
COPY ./qemustage/firness_qemu /workspace/qemu_fuzzer/target/release/firness_qemu
COPY ./qemustage/pc-bios /workspace/qemu_fuzzer/target/release/qemu-libafl-bridge/pc-bios
COPY ./qemustage/qemu_fw /workspace/qemu_fw
# BaseTools ships as C sources; the campaign builds the harness with GenFw and friends, and
# without these the build stops at "Unable to find the real 'GenFw'" and the campaign reports
# a harness that did not compile.
RUN make -C /workspace/tmp/edk2/BaseTools -j8 >/tmp/basetools.log 2>&1 \
    && test -x /workspace/tmp/edk2/BaseTools/Source/C/bin/GenFw
RUN chmod +x /workspace/qemu_fuzzer/target/release/firness_qemu
