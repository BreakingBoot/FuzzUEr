#!/bin/bash

build_dir=/llvm-source/llvm-15.0.7/build
edk2_dir=/input/edk2
input_file=/input/input.txt
output_dir=/output


# Ensure that two arguments are provided
if [[ $# == 3 ]]; then
    input_file=$1
    output_dir=$2
    edk2_dir=$3
fi

# Create output_dir/tmp directory if it doesn't exist
output_tmp_dir="$output_dir/tmp"
if [[ ! -d $output_tmp_dir ]]; then
    mkdir -p $output_tmp_dir
    if [[ $? -ne 0 ]]; then
        echo "Failed to create directory $output_tmp_dir"
        exit 1
    fi
fi


# Run ninja
cd $build_dir && ninja

# Check the exit status of ninja
if [[ $? -eq 0 ]]; then
    # If ninja succeeded, run firness
    firness -p $edk2_dir -o $output_tmp_dir -i $input_file dummyfile # For compilation database
else
    # If ninja failed, print an error message
    echo "ninja failed, not running firness"
    exit 1
fi