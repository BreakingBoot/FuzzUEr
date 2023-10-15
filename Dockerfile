FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y \
    apt-utils \
    fusefat \
    wget \
    tar \
    python3 \
    git \
    acpica-tools \
    python3-distutils \
    uuid-dev \
    nasm \
    python-is-python3 \
    gcc-multilib \
    make \
    g++ \
    lcov \
    curl \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libgtk-3-0 \
    libgbm1 \
    libasound2

WORKDIR /FuzzUEr

# COPY Harness/ /FuzzUEr/Harness
# COPY run.sh /FuzzUEr

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH /root/.cargo/bin:$PATH
RUN cargo new --bin /tmp/rust-test \
    && cargo run --manifest-path /tmp/rust-test/Cargo.toml

# Download Simics
RUN mkdir Downloads/ \
    && curl -L -o /FuzzUEr/Downloads/intel-simics-package-manager-1.7.5-linux64.tar.gz \
        https://registrationcenter-download.intel.com/akdlm/IRC_NAS/881ee76a-c24d-41c0-af13-5d89b2a857ff/intel-simics-package-manager-1.7.5-linux64.tar.gz \
    && curl -L -o /FuzzUEr/Downloads/simics-6-packages-2023-31-linux64.ispm \
        https://registrationcenter-download.intel.com/akdlm/IRC_NAS/881ee76a-c24d-41c0-af13-5d89b2a857ff/simics-6-packages-2023-31-linux64.ispm

# Install Simics
RUN mkdir -p simics/ispm \
    && tar -C /FuzzUEr/simics/ispm --strip-components=1 \
        -xvf /FuzzUEr/Downloads/intel-simics-package-manager-1.7.5-linux64.tar.gz \
    && /FuzzUEr/simics/ispm/ispm packages \
        --install-dir /FuzzUEr/simics \
        --install-bundle /FuzzUEr/Downloads/simics-6-packages-2023-31-linux64.ispm \
        --non-interactive

ENV SIMICS_HOME /FuzzUEr/simics/

# Build the fuzzer
RUN git clone https://github.com/intel/tsffs.git \
    && cd tsffs \
    && echo "SIMICS_HOME=/FuzzUEr/simics/" > .env \
    && cargo build --features=6.0.169

# sudo docker build -t tsffs-image .
# sudo docker run -it -v ./:/FuzzUEr/Harness/ tsffs-image