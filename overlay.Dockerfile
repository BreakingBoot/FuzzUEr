# Refresh a built fuzzuer image with the current sources without repeating the LLVM build.
# The clang tool is unchanged, so only the python generator, the harness helpers, the
# scripts and the sanitizer sources need to move.
FROM fuzzuer-base:latest
COPY ./firness/harness_generator /workspace/harness_generator
COPY ./firness/HarnessHelpers /workspace/HarnessHelpers
COPY ./scripts /workspace/scripts/
COPY ./scripts/firness.py /workspace/
COPY ./uefi_asan /workspace/uefi_asan/
