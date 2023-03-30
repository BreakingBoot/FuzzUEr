#!/bin/bash

main_dir=$PWD
simics_dir=$main_dir/simics/fuzzer-project

# run the fuzzer
cd $simics_dir
$main_dir/AFLplusplus/afl-fuzz -i testcases/ -o testrun/ -n -t 100000 -- ./afl-wrapper @@
