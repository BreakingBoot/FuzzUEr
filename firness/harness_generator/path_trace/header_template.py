from typing import List, Dict
from common.types import FunctionBlock, FieldInfo, convert_types
from common.utils import remove_ref_symbols

def harness_header(includes: List[str], 
                   functions: Dict[str, FunctionBlock],
                   types: Dict[str, List[FieldInfo]],
                   aliases: Dict[str, str]) -> List[str]:
    output = []
    output.append("#ifndef __FIRNESS_HARNESSES__")
    output.append("#define __FIRNESS_HARNESSES__")

    output.append("#include \"FirnessHelpers_std.h\"")

    for type, fields in types.items():
        output.extend(create_structs(type, fields, aliases))
        output.append("")

    for function, _ in functions.items():
        output.append(f"int Fuzz{function}(")
        output.append(f"    INPUT_BUFFER *Input")
        output.append(");")

    output.append("#endif")

    return output

def get_type(arg_type: str, aliases: Dict[str, str]) -> str:
    if remove_ref_symbols(arg_type) in aliases.keys():
        return arg_type.replace(remove_ref_symbols(arg_type), aliases[remove_ref_symbols(arg_type)])
    else:
        return arg_type

# create the structures converted to normal c types
def create_structs(type: str, fields: List[FieldInfo], aliases: Dict[str, str]) -> List[str]:
    output = []
    output.append("typedef struct {")
    for field in fields:
        if get_type(field.type, aliases) in convert_types.keys():
            output.append(f"    {field.type.replace(remove_ref_symbols(field.type), convert_types[get_type(field.type, aliases)])} {field.name};")
        else:
            output.append(f"    uint64_t {field.name};")
    output.append('}' + f" {type};")
    output.append("")

    return output