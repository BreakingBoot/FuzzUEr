#!/bin/bash

main_dir=$PWD
simics_dir=$main_dir/simics/fuzzer-project
# Create a snapshot of the FW at the EFI Shell
cd $simics_dir
./simics -no-win -batch-mode targets/qsp-x86/qsp-modern-core.simics -e "run-seconds seconds = 30" -e "write-configuration shell-restore.conf"

# run the fuzzer
$main_dir/AFLplusplus/afl-fuzz -i testcases/ -o testrun/ -n -t 100000 -- ./afl-wrapper @@
