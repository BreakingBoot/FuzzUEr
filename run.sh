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
if [ $1 -lt 0 ] || [ $1 -ge 5 ]; then
  echo "The argument is outside the specified range."
  exit 1
fi

# install libraries
./install_libraries.sh

# setup the program
./setup.sh 

# compile
./compile.sh 

# fuzz UEFI
./execute.sh $1
