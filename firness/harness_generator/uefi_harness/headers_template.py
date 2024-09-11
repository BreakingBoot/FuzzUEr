from typing import List, Dict
from common.types import FunctionBlock

def harness_includes(includes: List[str]) -> List[str]:
    output = []
    output.append("#ifndef __FIRNESS_INCLUDES__")
    output.append("#define __FIRNESS_INCLUDES__")

    output.append("")
    for include in includes:
        output.append(f"#include <{include}>")

    output.append("")
    output.append("#endif // __FIRNESS_INCLUDES__")

    return output

def harness_header(functions: Dict[str, FunctionBlock],
                   matched_macros: Dict[str, str]) -> List[str]:
    output = []
    output.append("#ifndef __FIRNESS_HARNESSES__")
    output.append("#define __FIRNESS_HARNESSES__")

    output.append("")
    output.append("#include \"FirnessIncludes.h\"")
    output.append("#include \"FirnessHelpers.h\"")
    output.append("")

    for name, value in matched_macros.items():
        output.append(f"#define {name} {value}")
    output.append("")

    for function, _ in functions.items():
        output.append(f"EFI_STATUS")
        output.append(f"EFIAPI")
        output.append(f"Fuzz{function}(")
        output.append(f"    IN INPUT_BUFFER *Input,")
        output.append(f"    IN EFI_SYSTEM_TABLE *SystemTable,")
        output.append(f"    IN EFI_HANDLE *ImageHandle")
        output.append(");")
        output.append("")

    output.append("#endif // __FIRNESS_HARNESSES__")

    return output
