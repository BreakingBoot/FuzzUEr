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
