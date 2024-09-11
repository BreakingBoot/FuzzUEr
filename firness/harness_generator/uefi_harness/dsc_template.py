from typing import List, Dict
import uuid

default_dsc_libs = [
    "NULL|MdeModulePkg/Library/AsanLib/AsanLib.inf",
    "ArmTrngLib|MdePkg/Library/BaseArmTrngLibNull/BaseArmTrngLibNull.inf",
    "RegisterFilterLib|MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf",
    "CpuLib|MdePkg/Library/BaseCpuLib/BaseCpuLib.inf",
    "SmmCpuRendezvousLib|MdePkg/Library/SmmCpuRendezvousLibNull/SmmCpuRendezvousLibNull.inf",
    "DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf",
    "BaseLib|MdePkg/Library/BaseLib/BaseLib.inf",
    "BaseMemoryLib|MdePkg/Library/AsanMemoryLibRepStr/AsanMemoryLibRepStr.inf",
    "DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf",
    "HobLib|MdePkg/Library/DxeHobLib/DxeHobLib.inf",
    "IoLib|MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsic.inf",
    "MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf",
    "PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf",
    "PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf",
    "SynchronizationLib|MdePkg/Library/BaseSynchronizationLib/BaseSynchronizationLib.inf",
    "UefiApplicationEntryPoint|MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf",
    "UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf",
    "UefiLib|MdePkg/Library/UefiLib/UefiLib.inf",
    "UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf",
    "TimerLib|UefiCpuPkg/Library/CpuTimerLib/BaseCpuTimerLib.inf",
    "DxeServicesTableLib|MdePkg/Library/DxeServicesTableLib/DxeServicesTableLib.inf"
    ]

def gen_firness_dsc(libraries: Dict[str, str]) -> List[str]:
    output = []
    dsc_guid = str(uuid.uuid4()).upper()

    output.append("[Defines]")
    output.append("  PLATFORM_NAME                  = Firness")
    output.append(f'  PLATFORM_GUID                  = {dsc_guid}')
    output.append("  PLATFORM_VERSION               = 0.1")
    output.append("  DSC_SPECIFICATION              = 0x00010005")
    output.append("  OUTPUT_DIRECTORY               = Build/Firness")
    output.append("  SUPPORTED_ARCHITECTURES        = X64")
    output.append("  BUILD_TARGETS                  = DEBUG|RELEASE|NOOPT")
    output.append("  SKUID_IDENTIFIER               = DEFAULT")

    output.append("")
    output.append("[LibraryClasses]")
    # for lib in default_dsc_libs:
    #     output.append(f'  {lib}')
    output.append(f'  NULL|MdeModulePkg/Library/AsanLib/AsanLib.inf')
    for lib, path in libraries.items():
        if "BaseMemoryLib" in lib:
            path = "MdePkg/Library/AsanMemoryLibRepStr/AsanMemoryLibRepStr.inf"
        output.append(f'  {lib}|{path}')
    
    output.append("")
    output.append("[Components]")
    output.append("  Firness/FirnessHarnesses.inf")

    return output