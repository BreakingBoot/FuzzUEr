# Use an official Fedora 35 as a parent image
FROM fedora:38

# Set environment variables to non-interactive (this prevents some prompts)
ENV DEBIAN_FRONTEND=non-interactive

# Set timezone.
ENV TZ=UTC

ENV GCC_MAJOR_VERSION=10

WORKDIR /llvm-source

# Run package updates and install packages
RUN dnf -y update \
    && dnf install -y \
        @development-tools \
        cmake \
        z3-devel \
        unzip \
        zlib-devel \
        git \
        python3 \
        python3-pip \
        ninja-build \
        json-devel \
        wget \
        cryptsetup \
        sudo \
        libuuid-devel \
        lcov \
        nasm \
        acpica-tools \
        virtualenv \
        dtc \
        mono-devel \
        bear \
        ca-certificates && \
    dnf install -y \
        gcc \
        g++ && \
    dnf upgrade -y && \
    dnf clean all


# Download clang
RUN wget -q https://github.com/llvm/llvm-project/archive/refs/tags/llvmorg-15.0.7.zip \
    && unzip llvmorg-15.0.7.zip \
    && rm llvmorg-15.0.7.zip \
    && mv llvm-project-llvmorg-15.0.7 llvm-15.0.7

# Set toolchains prefix
ENV GCC5_AARCH64_PREFIX /usr/bin/aarch64-linux-gnu-
ENV GCC5_ARM_PREFIX     /usr/bin/arm-linux-gnueabi-
ENV GCC5_RISCV64_PREFIX /usr/bin/riscv64-linux-gnu-

# Setup and compile it
RUN cd llvm-15.0.7 \
    && mkdir build \
    && cd build \
    && cmake -G Ninja ../llvm -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra;lld;llvm" -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_RTTI=ON \
    && ninja -j4

ENV PATH /llvm-source/llvm-15.0.7/build/bin:$PATH

COPY analyze.sh /llvm-source
COPY ./ /llvm-source/llvm-15.0.7/clang-tools-extra/firness
COPY ./harness_generator /llvm-source/harness_generator
COPY ./HarnessHelpers /llvm-source/HarnessHelpers

RUN /llvm-source/llvm-15.0.7/clang-tools-extra/firness/patch.sh \
    && cd llvm-15.0.7/build \
    && ninja -j4

# Set the default shell command
COPY ./pipeline_analysis.sh /llvm-source/pipeline_analysis.sh
ENTRYPOINT ["/bin/sh"]
