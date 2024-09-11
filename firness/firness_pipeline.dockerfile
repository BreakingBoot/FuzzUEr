# Use an official Ubuntu 22.04 as a parent image
FROM ubuntu:22.04

# Set environment variables to non-interactive (this prevents some prompts)
ENV DEBIAN_FRONTEND=non-interactive

# Set timezone.
ENV TZ=UTC

ENV GCC_MAJOR_VERSION=12

WORKDIR /llvm-source

# Run package updates and install packages
RUN apt-get update \
    && apt-get install --yes --no-install-recommends\
        build-essential \
        make \
        cmake \
        z3 \
        unzip \
        zlib1g-dev \
        git \
        python3 \
        python3-pip \
        ninja-build \
        nlohmann-json3-dev \
        wget \
        software-properties-common \
        apt-utils \
        cryptsetup \
        apt-transport-https \
        sudo \
        uuid-dev \
        lcov \
        nasm \
        acpica-tools \
        virtualenv \
        device-tree-compiler \
        mono-devel \
        python3-venv \
        locales \
        gnupg \
        bear \
        ca-certificates && \
    apt-get install --yes --no-install-recommends \
        g++-${GCC_MAJOR_VERSION} gcc-${GCC_MAJOR_VERSION} \
        g++-${GCC_MAJOR_VERSION}-x86-64-linux-gnux32 gcc-${GCC_MAJOR_VERSION}-x86-64-linux-gnux32 \
        g++-${GCC_MAJOR_VERSION}-aarch64-linux-gnu gcc-${GCC_MAJOR_VERSION}-aarch64-linux-gnu \
        g++-${GCC_MAJOR_VERSION}-riscv64-linux-gnu gcc-${GCC_MAJOR_VERSION}-riscv64-linux-gnu \
        g++-${GCC_MAJOR_VERSION}-arm-linux-gnueabi gcc-${GCC_MAJOR_VERSION}-arm-linux-gnueabi \
        g++-${GCC_MAJOR_VERSION}-arm-linux-gnueabihf gcc-${GCC_MAJOR_VERSION}-arm-linux-gnueabihf && \
    apt-get upgrade -y && \
    apt-get clean &&\
    rm -rf /var/lib/apt/lists/*

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

# Download clang
RUN wget -q https://github.com/llvm/llvm-project/archive/refs/tags/llvmorg-15.0.7.zip \
    && unzip llvmorg-15.0.7.zip \
    && rm llvmorg-15.0.7.zip \
    && mv llvm-project-llvmorg-15.0.7 llvm-15.0.7

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

# RUN git clone https://github.com/tianocore/edk2.git \
#     && cd edk2 \
#     && git submodule update --init --recursive \
#     && make -C BaseTools
#     #&& /bin/bash -c "source edksetup.sh && bear -- build -p OvmfPkg/OvmfPkgX64.dsc -t CLANGPDB -a X64"
#     #&& bear -- build -p OvmfPkg/OvmfPkgX64.dsc -t CLANGPDB -a X64

# Set the default shell command
# ENV EDK2_DOCKER_USER_HOME /llvm-source
# COPY entrypoint.sh /llvm-source/entrypoint
COPY ./pipeline_analysis.sh /llvm-source/pipeline_analysis.sh
# ENTRYPOINT ["/bin/sh"]
ENTRYPOINT ["/llvm-source/pipeline_analysis.sh"]
