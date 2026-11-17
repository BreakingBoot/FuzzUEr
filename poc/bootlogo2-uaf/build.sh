#!/bin/bash
# Build BootLogo2Uaf.efi.
#
# The module is a normal edk2 UEFI_APPLICATION with its own platform description, so the
# only thing this script does beyond `build` is copy the module into an edk2 workspace
# (edk2 resolves everything relative to WORKSPACE, so the sources have to live under it)
# and, when no local clang/gcc edk2 toolchain is configured, run the build inside this
# project's container image.
#
# usage:
#   EDK2=/path/to/edk2 ./build.sh                     # local toolchain
#   EDK2=/path/to/edk2 DOCKER_IMAGE=bbx-fuzzuer:latest ./build.sh
#
# env:
#   EDK2          edk2 workspace to build in. Required. BaseTools must already be built
#                 there (make -C BaseTools) and Conf/ must exist.
#   TARGET        DEBUG | RELEASE | NOOPT        (default RELEASE)
#   TOOLCHAIN     GCC | GCC5 | CLANGDWARF        (default: whichever of GCC / GCC5 the
#                                                 workspace's Conf/tools_def.txt defines)
#   ARCH          X64 | IA32                     (default X64)
#   DOCKER_IMAGE  if set, the build runs in this image with EDK2 bind mounted at /work
#
# The toolchain tag is detected rather than hard-coded because edk2 renamed it: a release
# branch up to and including edk2-stable202502 defines GCC5, and master defines GCC. A
# wrong tag fails with "error 4000: Not available -- [GCC5] not defined", which reads like
# a missing compiler and is not one.
#
# A maintainer with a working edk2 build environment does not need this script at all:
#
#   cp -r poc/bootlogo2-uaf <edk2>/BootLogo2Uaf
#   cd <edk2> && make -C BaseTools && source edksetup.sh
#   build -a X64 -b RELEASE -t GCC -p BootLogo2Uaf/BootLogo2Uaf.dsc    # GCC5 on a release
#
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
EDK2=${EDK2:?set EDK2 to an edk2 workspace whose BaseTools are built}
TARGET=${TARGET:-RELEASE}
ARCH=${ARCH:-X64}
DOCKER_IMAGE=${DOCKER_IMAGE:-}

[ -d "$EDK2/MdePkg" ] || { echo "$EDK2 is not an edk2 workspace"; exit 2; }
[ -d "$EDK2/MdeModulePkg" ] || { echo "$EDK2 has no MdeModulePkg"; exit 2; }
[ -f "$EDK2/Conf/target.txt" ] || { echo "$EDK2/Conf/target.txt is missing -- run edksetup.sh there once"; exit 2; }
[ -f "$EDK2/Conf/tools_def.txt" ] || { echo "$EDK2/Conf/tools_def.txt is missing -- run edksetup.sh there once"; exit 2; }

if [ -z "${TOOLCHAIN:-}" ]; then
    for tag in GCC GCC5; do
        if grep -q "^\*_${tag}_\*_\*_FAMILY" "$EDK2/Conf/tools_def.txt"; then
            TOOLCHAIN=$tag
            break
        fi
    done
fi
[ -n "${TOOLCHAIN:-}" ] || { echo "neither GCC nor GCC5 is defined in $EDK2/Conf/tools_def.txt"; exit 2; }
echo "toolchain: $TOOLCHAIN  target: $TARGET  arch: $ARCH" >&2

# The module has to be under the workspace, so it is copied rather than referenced.
rm -rf "$EDK2/BootLogo2Uaf"
mkdir -p "$EDK2/BootLogo2Uaf"
cp "$HERE/BootLogo2Uaf.c" "$HERE/BootLogo2Uaf.inf" "$HERE/BootLogo2Uaf.dsc" "$EDK2/BootLogo2Uaf/"

# StackCheckLib and StackCheckFailureHookLib arrived after edk2-stable202502, and
# UefiApplicationEntryPoint consumes StackCheckLib on a tree that has them. The DSC names
# both, so on an older workspace it names two INF paths that are not there -- measured
# absent on edk2-stable202211 and on the EVAL-1 tree, present on master. An earlier version
# of this script asserted in a comment that naming an unresolvable class was harmless
# because build.py "only opens an INF it has to resolve"; that claim was never tested and
# is wrong. Detected rather than assumed, the same way the toolchain tag above is, so one
# DSC builds on both eras and a maintainer on either does not have to edit it.
if [ ! -f "$EDK2/MdePkg/Library/StackCheckLibNull/StackCheckLibNull.inf" ]; then
    echo "note: $EDK2 predates StackCheckLib; dropping the two stack-cookie classes"
    sed -i '/StackCheckLib|/d; /StackCheckFailureHookLib|/d' \
        "$EDK2/BootLogo2Uaf/BootLogo2Uaf.dsc"
fi

BUILD="build -a $ARCH -b $TARGET -t $TOOLCHAIN -p BootLogo2Uaf/BootLogo2Uaf.dsc"
OUT="Build/BootLogo2Uaf/${TARGET}_${TOOLCHAIN}/$ARCH/BootLogo2Uaf.efi"

if [ -n "$DOCKER_IMAGE" ]; then
    docker run --rm --user "$(id -u):$(id -g)" \
        -v "$EDK2":/work -w /work "$DOCKER_IMAGE" bash -lc "
            export WORKSPACE=/work EDK_TOOLS_PATH=/work/BaseTools CONF_PATH=/work/Conf
            source edksetup.sh >/dev/null 2>&1 || true
            $BUILD
        "
else
    # edksetup.sh is not written to survive 'set -u', so it is sourced in a subshell with
    # the strict flags off and only its exported variables are relied on afterwards.
    ( set +eu
      cd "$EDK2"
      export WORKSPACE="$EDK2" EDK_TOOLS_PATH="$EDK2/BaseTools" CONF_PATH="$EDK2/Conf"
      . ./edksetup.sh >/dev/null 2>&1
      set -e
      $BUILD )
fi

[ -f "$EDK2/$OUT" ] || { echo "build reported success but $OUT is missing"; exit 1; }
echo "$EDK2/$OUT"
