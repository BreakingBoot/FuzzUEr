#!/bin/bash

current_dir=$PWD
simics_dir="src/edk2-platforms/Platform/Intel/"

# compile the code
cd "src/edk2"
make -C "BaseTools" && source edksetup.sh && cd $current_dir/$simics_dir && python build_bios.py -p BoardX58Ich10 -t GCC5
cd $current_dir

# create a simics project
cd "$current_dir/simics/intel-simics-package-manager-1.5.3"
./ispm packages --install-bundle $current_dir/simics/simics-6-packages-2022-49-linux64.ispm --install-dir $current_dir/simics/ --create-project $current_dir/simics/fuzzer-project -y
cd $current_dir

# copy it to the necessary directory
cp src/Build/SimicsOpenBoardPkg/BoardX58Ich10/DEBUG_GCC5/FV/BOARDX58ICH10.fd simics/simics-qsp-x86-6.0.65/targets/qsp-x86/images/

# create a virtual disk and copy the apps to it
dd if=/dev/zero of=VHD.vhd bs=1M count=1200
mkfs -t fat VHD.vhd 
mkdir /tmp/VHD
sudo mount -o loop VHD.vhd /tmp/VHD
sudo cp src/Build/SimicsOpenBoardPkg/BoardX58Ich10/DEBUG_GCC5/X64/BBClient.efi /tmp/VHD
sudo cp src/Build/SimicsOpenBoardPkg/BoardX58Ich10/DEBUG_GCC5/X64/Exploit.efi /tmp/VHD
sudo cp src/Build/SimicsOpenBoardPkg/BoardX58Ich10/DEBUG_GCC5/X64/Example1_App.efi /tmp/VHD
sudo umount /tmp/VHD
cp VHD.vhd simics/simics-qsp-x86-6.0.65/targets/qsp-x86/images/
sudo -i
echo core >/proc/sys/kernel/core_pattern
exit

# patch the scripts
patch -p0 < modified-FV.patch

# copy the additional scripts from the main dir to simics project
cd $current_dir
cp afl-wrapper.c afl-simics-linker.py simics/fuzzer-project
cp -R testcases simics/fuzzer-project

cd simics/fuzzer-project
gcc afl-wrapper.c -o afl-wrapper
mkdir fuzz_output

# Create a snapshot of the FW at the EFI Shell
./simics -no-win -batch-mode targets/qsp-x86/qsp-modern-core.simics -e "run-seconds seconds = 30" -e "board.software.delete-tracker" -e "board.software.insert-tracker tracker = uefi_fw_tracker_comp" -e "write-configuration shell-restore.conf"


cd $current_dir

cd "AFLplusplus"
make all
