FROM ubuntu:22.04

# Suppresses a debconf error during apt-get install.
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /workspace
# Download links can be obtained from:
# https://lemcenter.intel.com/productDownload/?Product=256660e5-a404-4390-b436-f64324d94959
ENV PUBLIC_SIMICS_PKGS_URL="https://registrationcenter-download.intel.com/akdlm/IRC_NAS/ead79ef5-28b5-48c7-8d1f-3cde7760798f/simics-6-packages-2024-05-linux64.ispm"
ENV PUBLIC_SIMICS_ISPM_URL="https://registrationcenter-download.intel.com/akdlm/IRC_NAS/ead79ef5-28b5-48c7-8d1f-3cde7760798f/intel-simics-package-manager-1.8.3-linux64.tar.gz"
ENV PUBLIC_SIMICS_PACKAGE_VERSION_1000="6.0.185"
ENV SIMICS_BASE="/workspace/simics/simics-${PUBLIC_SIMICS_PACKAGE_VERSION_1000}/"
# Add cargo and ispm to the path
ENV PATH="/root/.cargo/bin:/workspace/simics/ispm:${PATH}"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install local dependencies:
# - Libraries and dependencies for SIMICS and ISPM
# - Libraries and dependencies for building a sample UEFI application
# - Tools for creating a CRAFF image to load into a model
# - Python, including checkers/linters
# - Rust (will be on the PATH due to the ENV command above)
# Set timezone.
ENV TZ=UTC

ENV GCC_MAJOR_VERSION=12

# Install and update the package list
RUN apt-get update && \
    apt-get install --yes --no-install-recommends \
        software-properties-common \
        apt-utils \
        cryptsetup \
        apt-transport-https \
        sudo \
        wget \
        clang \
        llvm \
        clang-tools \
        cmake \
        cups \
        curl \
        dosfstools \
        unzip \
        libjsoncpp-dev \
        bear \
        build-essential \
        uuid-dev \
        git \
        lcov \
        nasm \
        acpica-tools \
        virtualenv \
        device-tree-compiler \
        mono-devel \
        python3\
        python3-pip \
        python3-venv \
        locales \
        gnupg \
        ca-certificates \
        ninja-build && \
    apt-get install --yes --no-install-recommends \
        g++-${GCC_MAJOR_VERSION} gcc-${GCC_MAJOR_VERSION} \
        g++-${GCC_MAJOR_VERSION}-x86-64-linux-gnux32 gcc-${GCC_MAJOR_VERSION}-x86-64-linux-gnux32 \
        g++-${GCC_MAJOR_VERSION}-aarch64-linux-gnu gcc-${GCC_MAJOR_VERSION}-aarch64-linux-gnu \
        g++-${GCC_MAJOR_VERSION}-riscv64-linux-gnu gcc-${GCC_MAJOR_VERSION}-riscv64-linux-gnu \
        g++-${GCC_MAJOR_VERSION}-arm-linux-gnueabi gcc-${GCC_MAJOR_VERSION}-arm-linux-gnueabi \
        g++-${GCC_MAJOR_VERSION}-arm-linux-gnueabihf gcc-${GCC_MAJOR_VERSION}-arm-linux-gnueabihf && \
    python3 -m pip install --no-cache-dir \
        black==23.10.1 \
        flake8==6.1.0 \
        isort==5.12.0 \
        mypy==1.6.1 \
        pylint==3.0.2 \
        matplotlib==3.8.3 \
        fuzzywuzzy==0.18.0 \
        networkx==3.1 \
        pydot==1.4.2 && \
    curl https://sh.rustup.rs -sSf | bash -s -- -y --default-toolchain nightly


RUN \
    update-alternatives \
      --install /usr/bin/python python /usr/bin/python3.10 1 &&\
    update-alternatives \
      --install /usr/bin/python3 python3 /usr/bin/python3.10 1 &&\
    update-alternatives \
      --install /usr/bin/gcc gcc /usr/bin/gcc-${GCC_MAJOR_VERSION} 100 \
      --slave /usr/bin/g++ g++ /usr/bin/g++-${GCC_MAJOR_VERSION} \
      --slave /usr/bin/gcc-ar gcc-ar /usr/bin/gcc-ar-${GCC_MAJOR_VERSION} \
      --slave /usr/bin/gcc-nm gcc-nm /usr/bin/gcc-nm-${GCC_MAJOR_VERSION} \
      --slave /usr/bin/gcc-ranlib gcc-ranlib /usr/bin/gcc-ranlib-${GCC_MAJOR_VERSION} \
      --slave /usr/bin/gcov gcov /usr/bin/gcov-${GCC_MAJOR_VERSION} && \
    update-alternatives \
      --install /usr/bin/cpp cpp /usr/bin/cpp-${GCC_MAJOR_VERSION} 100 && \
    update-alternatives \
      --install /usr/bin/aarch64-linux-gnu-gcc aarch64-linux-gnu-gcc /usr/bin/aarch64-linux-gnu-gcc-${GCC_MAJOR_VERSION} 100 \
      --slave /usr/bin/aarch64-linux-gnu-g++ aarch64-linux-gnu-g++ /usr/bin/aarch64-linux-gnu-g++-${GCC_MAJOR_VERSION} \
      --slave /usr/bin/aarch64-linux-gnu-gcc-ar aarch64-linux-gnu-gcc-ar /usr/bin/aarch64-linux-gnu-gcc-ar-${GCC_MAJOR_VERSION} \
      --slave /usr/bin/aarch64-linux-gnu-gcc-nm aarch64-linux-gnu-gcc-nm /usr/bin/aarch64-linux-gnu-gcc-nm-${GCC_MAJOR_VERSION} \
      --slave /usr/bin/aarch64-linux-gnu-gcc-ranlib aarch64-linux-gnu-gcc-ranlib /usr/bin/aarch64-linux-gnu-gcc-ranlib-${GCC_MAJOR_VERSION} \
      --slave /usr/bin/aarch64-linux-gnu-gcov aarch64-linux-gnu-gcov /usr/bin/aarch64-linux-gnu-gcov-${GCC_MAJOR_VERSION} && \
    update-alternatives \
      --install /usr/bin/aarch64-linux-gnu-cpp aarch64-linux-gnu-cpp /usr/bin/aarch64-linux-gnu-cpp-${GCC_MAJOR_VERSION} 100 && \
    update-alternatives \
      --install /usr/bin/arm-linux-gnueabi-gcc arm-linux-gnueabi-gcc /usr/bin/arm-linux-gnueabi-gcc-${GCC_MAJOR_VERSION} 100 \
      --slave /usr/bin/arm-linux-gnueabi-g++ arm-linux-gnueabi-g++ /usr/bin/arm-linux-gnueabi-g++-${GCC_MAJOR_VERSION} \
      --slave /usr/bin/arm-linux-gnueabi-gcc-ar arm-linux-gnueabi-gcc-ar /usr/bin/arm-linux-gnueabi-gcc-ar-${GCC_MAJOR_VERSION} \
      --slave /usr/bin/arm-linux-gnueabi-gcc-nm arm-linux-gnueabi-gcc-nm /usr/bin/arm-linux-gnueabi-gcc-nm-${GCC_MAJOR_VERSION} \
      --slave /usr/bin/arm-linux-gnueabi-gcc-ranlib arm-linux-gnueabi-gcc-ranlib /usr/bin/arm-linux-gnueabi-gcc-ranlib-${GCC_MAJOR_VERSION} \
      --slave /usr/bin/arm-linux-gnueabi-gcov arm-linux-gnueabi-gcov /usr/bin/arm-linux-gnueabi-gcov-${GCC_MAJOR_VERSION} && \
    update-alternatives \
      --install /usr/bin/arm-linux-gnueabi-cpp arm-linux-gnueabi-cpp /usr/bin/arm-linux-gnueabi-cpp-${GCC_MAJOR_VERSION} 100 && \
    update-alternatives \
      --install /usr/bin/riscv64-linux-gnu-gcc riscv64-linux-gnu-gcc /usr/bin/riscv64-linux-gnu-gcc-${GCC_MAJOR_VERSION} 100 \
      --slave /usr/bin/riscv64-linux-gnu-g++ riscv64-linux-gnu-g++ /usr/bin/riscv64-linux-gnu-g++-${GCC_MAJOR_VERSION} \
      --slave /usr/bin/riscv64-linux-gnu-gcc-ar riscv64-linux-gnu-gcc-ar /usr/bin/riscv64-linux-gnu-gcc-ar-${GCC_MAJOR_VERSION} \
      --slave /usr/bin/riscv64-linux-gnu-gcc-nm riscv64-linux-gnu-gcc-nm /usr/bin/riscv64-linux-gnu-gcc-nm-${GCC_MAJOR_VERSION} \
      --slave /usr/bin/riscv64-linux-gnu-gcc-ranlib riscv64-linux-gnu-gcc-ranlib /usr/bin/riscv64-linux-gnu-gcc-ranlib-${GCC_MAJOR_VERSION} \
      --slave /usr/bin/riscv64-linux-gnu-gcov riscv64-linux-gnu-gcov /usr/bin/riscv64-linux-gnu-gcov-${GCC_MAJOR_VERSION} && \
    update-alternatives \
      --install /usr/bin/riscv64-linux-gnu-cpp riscv64-linux-gnu-cpp /usr/bin/riscv64-linux-gnu-cpp-${GCC_MAJOR_VERSION} 100

# Set toolchains prefix
ENV GCC5_AARCH64_PREFIX /usr/bin/aarch64-linux-gnu-
ENV GCC5_ARM_PREFIX     /usr/bin/arm-linux-gnueabi-
ENV GCC5_RISCV64_PREFIX /usr/bin/riscv64-linux-gnu-

# Set the locale
RUN sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && \
    locale-gen
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

RUN wget -q https://github.com/llvm/llvm-project/archive/refs/tags/llvmorg-15.0.7.zip \
    && unzip llvmorg-15.0.7.zip \
    && rm llvmorg-15.0.7.zip \
    && mv llvm-project-llvmorg-15.0.7 llvm-15.0.7

# Setup and compile it
RUN cd llvm-15.0.7 \
    && mkdir build \
    && cd build \
    && cmake -G Ninja ../llvm -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra;lld;llvm" -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_RTTI=ON \
    && ninja -j4

ENV PATH /workspace/llvm-15.0.7/build/bin:$PATH

COPY ./firness/pipeline_analysis.sh /workspace/analyze.sh
COPY ./firness /workspace/llvm-15.0.7/clang-tools-extra/firness
COPY ./firness/harness_generator /workspace/harness_generator
COPY ./firness/HarnessHelpers /workspace/HarnessHelpers

RUN apt-get install -y nlohmann-json3-dev

RUN /workspace/llvm-15.0.7/clang-tools-extra/firness/patch.sh \
    && cd llvm-15.0.7/build \
    && ninja -j4


# Download and install public SIMICS. This installs all the public packages as well as the
# ispm SIMICS package and project manager. ISPM will be on the path due to the ENV command
# above
RUN mkdir -p /workspace/simics/ispm/ && \
    curl --noproxy '*.intel.com' -L -o /workspace/simics/ispm.tar.gz "${PUBLIC_SIMICS_ISPM_URL}" && \
    curl --noproxy '*.intel.com' -L -o /workspace/simics/simics.ispm "${PUBLIC_SIMICS_PKGS_URL}" && \
    tar -C /workspace/simics/ispm --strip-components=1 \
        -xf /workspace/simics/ispm.tar.gz && \
    ispm settings install-dir /workspace/simics && \
    ispm packages --install-bundle /workspace/simics/simics.ispm --non-interactive \
        --trust-insecure-packages && \
    rm /workspace/simics/ispm.tar.gz /workspace/simics/simics.ispm && \
    rm -rf /workspace/simics-6-packages/

# Copy the local repository into the workspace
COPY ./tsffs /workspace/tsffs/

WORKDIR /workspace/tsffs/

# Build the project by initializing it as a project associated with the local SIMICS installation
# and building the module using the build script. Then, install the built TSFFS SIMICS
# package into the local SIMICS installation for use.
RUN cargo install --path simics-rs/cargo-simics-build && \
    cargo simics-build -r && \
    ispm packages \
        -i target/release/*-linux64.ispm \
        --non-interactive --trust-insecure-packages

WORKDIR /workspace/projects/example/

COPY ./Harness/hardware.yml /workspace/simics/simics-qsp-x86-6.0.73/targets/qsp-x86/
COPY ./Harness/qsp-uefi-custom.target.yml /workspace/simics/simics-qsp-x86-6.0.73/targets/qsp-x86/
COPY ./Harness/qsp-uefi-custom.target.yml.include /workspace/simics/simics-qsp-x86-6.0.73/targets/qsp-x86/
COPY ./Harness/fuzz.simics /workspace/projects/example/
COPY ./Harness/minimal_boot_disk.craff /workspace/projects/example/

# Create an example project with:
# - SIMICS Base (1000)
# - QSP X86 (2096)
# - QSP CPU (8112)
# - Crypto Engine (1030) [only necessary because it is required by Golden Cove]
# - TSFFS Fuzzer (31337)
# - A SIMICS script that configures the fuzzer for the example and starts fuzzing it
RUN ispm projects /workspace/projects/example/ --create \
    1000-latest \
    2096-latest \
    8112-latest \
    1030-latest \
    31337-latest --ignore-existing-files --non-interactive 

WORKDIR /workspace/

COPY ./scripts /workspace/scripts/
COPY ./uefi_asan /workspace/uefi_asan/
COPY ./scripts/firness.py /workspace/