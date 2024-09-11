#!/bin/bash

edk2_dir=/input/edk2
input_file=/input/input.txt
output_dir=/output

ls -al $output_dir

# Create output_dir/tmp directory if it doesn't exist
output_tmp_dir="$output_dir/tmp"
if [[ ! -d $output_tmp_dir ]]; then
    mkdir -p $output_tmp_dir
    if [[ $? -ne 0 ]]; then
        echo "Failed to create directory $output_tmp_dir"
        exit 1
    fi
fi

cd $edk2_dir && \
make -C BaseTools && \
source edksetup.sh && \
bear -- build -p OvmfPkg/OvmfPkgX64.dsc -a X64 -t CLANGDWARF
firness -p $edk2_dir -o $output_tmp_dir -i $input_file dummyfile # For compilation database
cd /llvm-source/harness_generator && \
python3 main.py