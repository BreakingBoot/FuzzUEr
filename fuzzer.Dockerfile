# Builds the LibAFL-QEMU fuzzer.
#
# Kept apart from the campaign image for two reasons. It needs a QEMU build environment --
# meson, glib, pixman -- that nothing else here wants in the final image; and libafl_qemu
# clones qemu-libafl-bridge at a revision pinned inside the crate and builds it, which is
# the better part of an hour. The result is one binary and a pc-bios directory, which
# scripts/bootstrap_runner.sh lifts out into qemustage/ for the campaign images to copy.
FROM fuzzuer-base:latest
RUN apt-get update && apt-get install --yes --no-install-recommends \
      meson ninja-build libglib2.0-dev libpixman-1-dev libslirp-dev \
      python3-venv python3-pip flex bison \
    && rm -rf /var/lib/apt/lists/*
# libafl's vharness builds through cmake and asks for 3.23. Ubuntu 22.04, which the base
# image is, ships 3.22.1, and the build ends in a Rust panic from the cmake crate quoting
# "CMake 3.23 or higher is required". The wheel is the least invasive way to a newer one.
RUN pip3 install --no-cache-dir 'cmake>=3.28' && cmake --version
COPY ./Harness/qemu_fuzzer /workspace/qemu_fuzzer
WORKDIR /workspace/qemu_fuzzer
RUN cargo build --release && test -x target/release/firness_qemu
