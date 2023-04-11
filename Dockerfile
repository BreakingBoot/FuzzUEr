FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y apt-utils fusefat wget tar python3 git acpica-tools python3-distutils uuid-dev nasm python-is-python3 gcc-multilib make g++ lcov

WORKDIR /FuzzUEr

COPY . .

RUN ./setup.sh
RUN ./compile.sh