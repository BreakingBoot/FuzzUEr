# The Simics campaign image running mainline edk2. Same generator and scripts as
# fuzzuer-cur, with the BoardX58Ich10 firmware built against edk2-stable202608 and
# edk2-platforms master instead of the 2023/2024 pins.
FROM fuzzuer-cur:latest
COPY ./fwstage/BOARDX58ICH10.mainline.fd /workspace/tmp/Build/SimicsOpenBoardPkg/BoardX58Ich10/DEBUG_CLANGSAN/FV/BOARDX58ICH10.fd
