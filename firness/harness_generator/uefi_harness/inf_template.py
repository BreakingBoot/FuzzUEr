from typing import Dict, List

def gen_firness_inf(uuid: str, 
                    driver_guids: List[str], 
                    protocol_guids: List[str],
                    libraries: Dict[str, str]) -> List[str]:
    output = []

    output.append("[Defines]")
    output.append("  INF_VERSION                    = 0x00010005")
    output.append("  BASE_NAME                      = Firness")
    output.append(f'  FILE_GUID                      = {uuid}')
    output.append("  MODULE_TYPE                    = UEFI_APPLICATION")
    output.append("  VERSION_STRING                 = 1.0")
    output.append("  ENTRY_POINT                    = FirnessMain")

    output.append("")
    output.append("#")
    output.append("#  This flag specifies whether HII resource section is generated into PE image.")
    output.append("#")
    output.append("  UEFI_HII_RESOURCE_SECTION      = TRUE")

    output.append("")
    output.append("#")
    output.append("# The following information is for reference only and not required by the build tools.")
    output.append("#")
    output.append("#  VALID_ARCHITECTURES           = IA32 X64 EBC")
    output.append("#")

    output.append("")
    output.append("[Sources]")
    output.append("  FirnessMain.c")
    output.append("  FirnessHarnesses.c")
    output.append("  FirnessHelpers.c")

    output.append("")
    output.append("[Packages]")
    output.append("  MdePkg/MdePkg.dec")
    output.append("  MdeModulePkg/MdeModulePkg.dec")
    output.append("  ShellPkg/ShellPkg.dec")
    output.append("  NetworkPkg/NetworkPkg.dec")
    output.append("  OvmfPkg/OvmfPkg.dec")
    output.append("  UefiCpuPkg/UefiCpuPkg.dec")

    output.append("")
    output.append("[LibraryClasses]")
    for lib in libraries.keys():
        if lib != "NULL":
            output.append(f'  {lib}')

    output.append("")
    output.append("[Guids]")
    for guid in driver_guids:
        output.append(f'  {guid}')

    output.append("")
    output.append("[Protocols]")
    for guid in protocol_guids:
        output.append(f'  {guid}')

    return output