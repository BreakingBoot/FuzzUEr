#!/bin/bash

# install libraries
./install_libraries.sh

# setup the program
./setup.sh 

# compile
./compile.sh 

# fuzz UEFI
./execute.sh 
