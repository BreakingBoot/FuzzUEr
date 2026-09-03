# The same run image with the page-poisoning firmware, to test whether poisoning freed
# pages finds anything the pool-only instrumentation misses.
FROM fuzzuer-run:latest
COPY ./fwstage/BOARDX58ICH10.pages.fd /workspace/tmp/Build/SimicsOpenBoardPkg/BoardX58Ich10/DEBUG_CLANGSAN/FV/BOARDX58ICH10.fd
COPY ./fwstage/Page.c /workspace/tmp/edk2/MdeModulePkg/Core/Dxe/Mem/Page.c
