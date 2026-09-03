# The image the campaigns actually run in: current generator and scripts on top of the
# unchanged LLVM build, with the sanitizer sources and the firmware they produce.
FROM fuzzuer-base:latest
COPY ./firness/harness_generator /workspace/harness_generator
COPY ./firness/HarnessHelpers /workspace/HarnessHelpers
COPY ./scripts /workspace/scripts/
COPY ./scripts/firness.py /workspace/
COPY ./uefi_asan /workspace/uefi_asan/
COPY ./fwstage/AsanLib /workspace/tmp/edk2/MdeModulePkg/Library/AsanLib
COPY ./fwstage/AsanMemoryLib /workspace/tmp/edk2/MdePkg/Library/AsanMemoryLib
COPY ./fwstage/AsanMemoryLibRepStr /workspace/tmp/edk2/MdePkg/Library/AsanMemoryLibRepStr
COPY ./fwstage/BOARDX58ICH10.repo2.fd /workspace/tmp/Build/SimicsOpenBoardPkg/BoardX58Ich10/DEBUG_CLANGSAN/FV/BOARDX58ICH10.fd
# reproduce.simics never made it into the base image, so --reproduce could not run and
# a saved solution could not be replayed. fuzz.simics ships here too so a change to it
# does not need the base rebuilt.
COPY ./Harness/fuzz.simics /workspace/projects/example/
COPY ./Harness/reproduce.simics /workspace/projects/example/
COPY ./Harness/snapshot.simics /workspace/projects/example/
COPY ./Harness/fuzz_snapshot.simics /workspace/projects/example/
# The booted checkpoint, so a campaign restores the machine at the shell (12s) instead of
# booting to it (516s). It is stamped with the firmware it was captured from; firness.py
# falls back to a normal boot if that no longer matches.
COPY ./ckptstage/booted.ckpt /workspace/projects/example/booted.ckpt
COPY ./ckptstage/booted.ckpt.firmware /workspace/projects/example/booted.ckpt.firmware
