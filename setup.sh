#!/bin/bash

main_dir=$PWD
# these are the remote branches to pull from
folder_name="src"
PAT="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"
repo_url="https://$PAT@github.com/BreakingBoot"
edk2_url="edk2-fuzzuer"
fsp_url="FSP"
edk2_platforms_url="edk2-platforms-fuzzuer"
edk2_non_osi_url="edk2-non-osi"

# create the folder if it doesn't exist and clone the repos
# otherwise make sure the git repos are install and up to date
if [ ! -d "$folder_name" ]; then
    mkdir "$folder_name"
fi

# get all of the necessary repos from github
cd "$folder_name"
git clone "$repo_url/$edk2_url" "edk2"
cd "edk2" && git submodule update --init --recursive
cd ..
git clone "$repo_url/$fsp_url"
cd "$fsp_url" && git submodule update --init --recursive
cd ..
git clone "$repo_url/$edk2_platforms_url" "edk2-platforms"
cd "edk2-platforms" && git submodule update --init --recursive
cd ..
git clone "$repo_url/$edk2_non_osi_url"
cd "$edk2_non_osi_url" && git submodule update --init --recursive
cd $main_dir
git clone -b "lcov-bitmap" "https://github.com/cglosner/AFLplusplus"
cd $main_dir

# download simics and install it
mkdir simics
cd simics

wget https://registrationcenter-download.intel.com/akdlm/IRC_NAS/708028d9-b710-45ea-baab-3b9c78c32cfc/intel-simics-package-manager-1.5.3-linux64.tar.gz
tar -xzf intel-simics-package-manager-1.5.3-linux64.tar.gz

wget https://registrationcenter-download.intel.com/akdlm/IRC_NAS/1f756747-b5ca-47d7-85b5-23cb3141fd4a/simics-6-packages-2022-49-linux64.ispm

cd $main_dir

cd "simics/intel-simics-package-manager-1.5.3"
./ispm packages --install-bundle ../simics-6-packages-2022-49-linux64.ispm --install-dir $main_dir/simics/ -y

cd $main_dir
