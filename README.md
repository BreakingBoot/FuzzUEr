# FuzzUEr
This is the tool is designed for setting up and Fuzzing the EDK2 firmware, specifically the BoardX58Ich10 board via Simics. The code here is responsible for automating downloading, installing, compiling, and executing the UEFI firmware on Simics.

## Overview
This repo is responsible for fuzzing the EDK2 UEFI through the use of a harness driver that is reposible for creating well formed inputs to pass to other drivers. The fuzzing is done by using AFL and plmbing it into Simics.

The custom drivers and applications that are needed are included here in this repo, but the custom internal driver responsible for creating the well formed input is called the BBClient.

Currently, the input in plumbed into Simics through the use of both `afl-simics-linker.py` and `afl-wrapper.c`. Where `afl-simics-linker.py` uses the simics API to handle directly dealing with simics while `afl-wrapper.c` just handles reading the input from afl and processes it for simics. The coverage isn't perfect matching because Simics provides and LCOV tracefile which provides line numbers and whether they have been reached or not. Therefore, the modified AFL program handles reading the tracfile and roughly mapping the line coverage to edge coverage.

Reporting crashes is also done roughly (for now), breakpoints are set in Simics anytime the word "FAILED" is seen on ther serial console, so anytime a breakpoint is reached a SIGABRT signal is sent to AFL to handle properly reporting a crash. TODO: Add a breakpoint on a function that can be called naturally like `CpuDeadLoop` or `DXE_ASSERT`.

## Stucture
The important bash scripts that are included are:

* `install_libraries.sh`: It is responsible for downloading all of the needed libraries via `sudo apt install`.
* `setup.sh`: It is responsible for downloading and "setting up" all of the required libraries and additional tools, like Simics and EDK2.
* `compile.sh`: This compiles the EDK2 for Simics and the custom AFL repo, and it also copies all of the necessary files to where they need to be so it can be run with `execute.sh`.
* `execute.sh`: This scripts creates a checkpoint or "snapshot" within Simics within the UEFI shell to optimize the fuzzing process and then runs the custom `afl-fuzz` on it.
* `run.sh`: It puts all of the scripts together and makes it easy to run all of the commands.

All of these steps can be done at the same time by running the run.sh script, but if you are adding additional functionality or running into issues because you are testing this code in a different environment it may be useful to run the scripts one at a time so you know where the problem is happening.

Debug statements are included throughout the code to provide useful information, and these are stored in a file called `log.txt`. TODO: by adding the -D flag when running the scripts the debug statements will be displayed on in the terminal too.

## Execution

Once this repository has been downloaded, all you will need to do is run the following command:
```
./run.sh <service to fuzz>
Example for ProcessFirmwareVolume service:
./run.sh 0
```

Currently, the following services are supported:
```
0 : ProcessFirmwareVolume
1 : Events
    - CreateEvent
    - WaitForEvent
    - SignalEvent
    - CloseEvent
    - CheckEvent
    - CreateEventEx
2 : LoadImage
3 : SmmHarden
4 : Example1
    - SetLockPin
    - WriteDataWrapper
    - WriteData
    - ReadData
5 : MemoryServices
    - AddMemorySpace
    - AllocateMemorySpace
    - FreeMemorySpace
    - RemoveMemorySpace
    - GetMemorySpaceDescriptor
    - SetMemorySpaceAttributes
    - GetMemorySpaceMap
    - SetMemorySpaceCapabilities
    - GetMemoryMap
    - AllocatePages
    - FreePages
    - AllocatePool
    - FreePool
    - CopyMem
    - SetMem
6 : ProtocolServcices
    - InstallProtocolInterface
    - ReinstallProtocolInterface
    - UninstallProtocolInterface
    - HandleProtocol
    - RegisterProtocolNotify
    - OpenProtocol
    - CloseProtocol
    - OpenProtocolInformation
    - ProtocolsPerHandle
    - LocateProtocol
    - InstallMultipleProtocolInterfaces
    - UninstallMultipleProtocolInterfaces
7 : Protocols
8 : Demo1Challenge
    - GetAccessVariable
    - SetAccessVariable
    - BobProtocol
    - AliceProtocol
    - ValidateAccessKey
    - GenerateAccessKey
9 : RuntimeServices
    - GetTime
    - SetTime
    - GetWakeupTime
    - SetWakeupTime
    - SetVirtualAddressMap
    - ConvertPointer
    - GetVariable
    - GetNextVariableName
    - SetVariable
    - GetAccessVariable
    - SetAccessVariable
    - GetNextHighMonotonicCount
    - ResetSystem
    - UpdateCapsule
    - QueryCapsuleCapabilities
    - QueryVariableInfo
```

The code for the added examples and for the BBClient harness can be found [here](https://github.com/BreakingBoot/edk2/tree/fuzzuer).

Limitations:
- Currently, this is being tested on an Ubuntu 22.04 LTS VM

## Docker

It has been modified to now use a docker as well. By following these steps:

1. Pull this repo
2. Run `docker build -t <name> .`
3. To execute fuzzer use:
    ```
    docker run -it --rm <name>
    ./execute.sh <servce #>
    ```
4. If this is your first time running it you will need to execute the following on the host machine as root:
    ```
    echo core >/proc/sys/kernel/core_pattern

    cd /sys/devices/system/cpu
    echo performance | tee cpu*/cpufreq/scaling_governor
    ```

This will allow you to fuzz it on any platform that can run docker.
