# The campaign image for the sanitizer's positive control.
#
# firness analyses the tree inside the container, not the one the firmware was built from,
# so a driver that exists only in the build tree is invisible to it: the analysis returns
# "Total Functions: 0" and generation produces an empty harness. The fault driver, its
# protocol header and the DEC that declares its GUID all have to be here too.
FROM fuzzuer-fault:latest
COPY ./faultstage/AsanFaultDxe /workspace/tmp/edk2/MdeModulePkg/Universal/AsanFaultDxe
COPY ./faultstage/Protocol/AsanFault.h /workspace/tmp/edk2/MdePkg/Include/Protocol/AsanFault.h
COPY ./faultstage/MdePkg.dec /workspace/tmp/edk2/MdePkg/MdePkg.dec
