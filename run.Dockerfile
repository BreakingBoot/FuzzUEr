# The image the campaigns actually run in: current generator and scripts on top of the
# unchanged LLVM build, with the sanitizer sources and the firmware they produce.
FROM fuzzuer-base:latest
COPY ./firness/harness_generator /workspace/harness_generator
COPY ./firness/HarnessHelpers /workspace/HarnessHelpers
COPY ./scripts /workspace/scripts/
COPY ./scripts/firness.py /workspace/
COPY ./uefi_asan /workspace/uefi_asan/
# From uefi_asan, which is now kept in step with eval_source/edk2. There used to be a
# third copy under fwstage/ and it had drifted 310 lines behind, so the firmware was
# built from the submodule while the harness image linked the old sanitizer -- a report
# raised inside Firness.efi carried none of the detail the same code emitted from a
# driver. eval_source/ is excluded from the build context, so uefi_asan is the copy that
# can actually be shipped to the daemon; keeping it current is what makes the porting
# instructions in the README deliver the sanitizer this tree actually uses.
COPY ./uefi_asan/AsanLib /workspace/tmp/edk2/MdeModulePkg/Library/AsanLib
COPY ./uefi_asan/AsanMemoryLib /workspace/tmp/edk2/MdePkg/Library/AsanMemoryLib
COPY ./uefi_asan/AsanMemoryLibRepStr /workspace/tmp/edk2/MdePkg/Library/AsanMemoryLibRepStr
COPY ./fwstage/BOARDX58ICH10.repo2.fd /workspace/tmp/Build/SimicsOpenBoardPkg/BoardX58Ich10/DEBUG_CLANGSAN/FV/BOARDX58ICH10.fd
# reproduce.simics never made it into the base image, so --reproduce could not run and
# a saved solution could not be replayed. fuzz.simics ships here too so a change to it
# does not need the base rebuilt.
# fuzz.simics does run-python-file "absorb_unmapped.py" at line 17. Without it every
# campaign dies before the harness with "not found in the Simics search path", which
# reads as a firmware that will not boot.
COPY ./Harness/absorb_unmapped.py /workspace/projects/example/
COPY ./Harness/fuzz.simics /workspace/projects/example/
COPY ./Harness/reproduce.simics /workspace/projects/example/
COPY ./Harness/snapshot.simics /workspace/projects/example/
COPY ./Harness/fuzz_snapshot.simics /workspace/projects/example/
# The booted checkpoint, so a campaign restores the machine at the shell (12s) instead of
# booting to it (516s). It is stamped with the firmware it was captured from; firness.py
# falls back to a normal boot if that no longer matches.
COPY ./ckptstage/booted.ckpt /workspace/projects/example/booted.ckpt
COPY ./ckptstage/booted.ckpt.firmware /workspace/projects/example/booted.ckpt.firmware
