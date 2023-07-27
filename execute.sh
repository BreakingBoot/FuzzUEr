#!/bin/bash

# Check if an argument is provided
if [ $# -eq 0 ]; then
  echo "Please provide an argument."
  exit 1
fi

# Check if the argument is an integer
if ! [[ $1 =~ ^-?[0-9]+$ ]]; then
  echo "Please provide an integer."
  exit 1
fi

# Check if the argument is greater than or equal to 0 and less than 5
if [ $1 -lt 0 ] || [ $1 -ge 9 ]; then
  echo "The argument is outside the specified range."
  exit 1
fi

main_dir=$PWD
simics_dir=$main_dir/simics/fuzzer-project

# Folder names
base_folder="$simics_dir/FuzzUEr_logs"
log_folder="$base_folder/logs"
crash_folder="$base_folder/crashes"

# Check if the folders exist and create them if they don't
if [ ! -d "$base_folder" ]; then
    mkdir "$base_folder"
fi

if [ ! -d "$log_folder" ]; then
    mkdir "$log_folder"
fi

if [ ! -d "$crash_folder" ]; then
    mkdir "$crash_folder"
fi

# Mock-up get_name function
get_name() {
    case "$1" in
        0) echo "ProcessFirmwareVolume" ;;
        1) echo "Event" ;;
        2) echo "LoadImage" ;;
        3) echo "SmmHarden" ;;
        4) echo "Example" ;;
        5) echo "Memory" ;;
        6) echo "Unknown" ;;
        7) echo "Protocol" ;;
        8) echo "Demo1" ;;
    esac
}

# Check if directory exists
log_dir_exist() {
    if [ -d "$1" ]; then
        return 0  # exists and is a directory
    else
        return 1  # does not exist, or it's not a directory
    fi
}

# Create directory if it doesn't exist
create_log_dir() {
    if ! log_dir_exist "$1"; then
        mkdir -p "$1"
    fi
}

init_log() {
    dir_name="$log_folder/$(get_name "$1")"
    create_log_dir "$dir_name"
    
    dir_name="$crash_folder/$(get_name "$1")"
    create_log_dir "$dir_name"
}

init_log $1

main_dir=$PWD
simics_dir=$main_dir/simics/fuzzer-project

# run the fuzzer
cd $simics_dir
$main_dir/AFLplusplus/afl-fuzz -i testcases/ -o fuzz_output1/ -t 100000 -- ./afl-wrapper $1 @@
