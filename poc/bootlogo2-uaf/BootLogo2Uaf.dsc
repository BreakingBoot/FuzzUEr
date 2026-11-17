## @file
#  Standalone platform description for the BootLogo2 use-after-free reproducer.
#
#  Self-contained on purpose: it resolves every library class the application needs so
#  that it can be built against a pristine edk2 checkout without touching a platform DSC.
#  Copy this directory into the root of an edk2 workspace as BootLogo2Uaf/ and build:
#
#    build -a X64 -b RELEASE -t GCC -p BootLogo2Uaf/BootLogo2Uaf.dsc
#
#  The toolchain tag is GCC on edk2 master and GCC5 on a release branch; edk2 renamed it
#  and dropped the old spelling. build.sh detects which one the workspace defines.
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
##

[Defines]
  PLATFORM_NAME                  = BootLogo2Uaf
  PLATFORM_GUID                  = 1D2F3A44-6B58-4C7E-8F91-0A5C3E7B6D20
  PLATFORM_VERSION               = 0.1
  DSC_SPECIFICATION              = 0x00010005
  OUTPUT_DIRECTORY               = Build/BootLogo2Uaf
  SUPPORTED_ARCHITECTURES        = IA32|X64
  BUILD_TARGETS                  = DEBUG|RELEASE|NOOPT
  SKUID_IDENTIFIER               = DEFAULT

[LibraryClasses]
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  CpuLib|MdePkg/Library/BaseCpuLib/BaseCpuLib.inf
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
  DebugPrintErrorLevelLib|MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  IoLib|MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsic.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  RegisterFilterLib|MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf
  #
  # Stack-cookie support. These two classes were introduced after edk2-stable202502 and
  # UefiApplicationEntryPoint consumes StackCheckLib on a tree that has them.
  #
  # ON AN OLDER TREE THESE TWO LINES MUST GO. The INF paths do not exist before that
  # release -- measured absent on edk2-stable202211 and on the EVAL-1 tree, present on
  # master -- and naming an unresolvable path here is not harmless, whatever an earlier
  # version of this comment claimed. build.sh detects the tree and strips them for you; if
  # you are running `build` by hand on a pre-202502 checkout, delete them yourself.
  #
  StackCheckLib|MdePkg/Library/StackCheckLibNull/StackCheckLibNull.inf
  StackCheckFailureHookLib|MdePkg/Library/StackCheckFailureHookLibNull/StackCheckFailureHookLibNull.inf
  SynchronizationLib|MdePkg/Library/BaseSynchronizationLib/BaseSynchronizationLib.inf
  TimerLib|MdePkg/Library/BaseTimerLibNullTemplate/BaseTimerLibNullTemplate.inf
  UefiApplicationEntryPoint|MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf

[Components]
  BootLogo2Uaf/BootLogo2Uaf.inf

[BuildOptions]
  #
  # The reproducer must not be instrumented, even when it is built inside this project's
  # sanitizer-enabled tree. Only the driver's own instrumentation should speak: an ASan
  # report naming this application would say nothing about upstream edk2.
  #
  # SAN_FLAGS is appended after CC_FLAGS by that tree's build_rule.txt, so -fno-sanitize in
  # CC_FLAGS would not win; the flag set has to be replaced here.
  #
  # On a pristine edk2 there is no CLANGSAN tag and no SAN tool code, and build.py only
  # applies a BuildOptions line whose TagName matches the build's -t, so this line is a
  # no-op there. Verified: the RELEASE_GCC build in the README was made with it present.
  #
  *_CLANGSAN_*_SAN_FLAGS == -Wno-frame-address
