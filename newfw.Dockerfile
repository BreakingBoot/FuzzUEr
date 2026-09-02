# Refresh the built firmware and the sanitizer sources in an existing image. The campaigns
# run firness.py -f, which reuses the prebuilt BOARDX58ICH10.fd rather than rebuilding it,
# so the image has to carry the new one.
FROM fuzzuer-cur:latest
COPY ./fwstage/AsanLib /workspace/tmp/edk2/MdeModulePkg/Library/AsanLib
COPY ./fwstage/AsanMemoryLib /workspace/tmp/edk2/MdePkg/Library/AsanMemoryLib
COPY ./fwstage/AsanMemoryLibRepStr /workspace/tmp/edk2/MdePkg/Library/AsanMemoryLibRepStr
COPY ./fwstage/BOARDX58ICH10.v3.fd /workspace/tmp/Build/SimicsOpenBoardPkg/BoardX58Ich10/DEBUG_CLANGSAN/FV/BOARDX58ICH10.fd
