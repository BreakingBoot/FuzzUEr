from typing import List, Dict
from common.types import FunctionBlock, FieldInfo, Argument, TypeTracker
from common.utils import remove_ref_symbols, remove_quotes, add_indents

def generate_outputs(all_args: Dict[str, List[Argument]],
                    arg_type_list: List[TypeTracker],
                     indent: bool) -> List[str]:
    output = []
    tmp = []
    
    for arg_key, arguments in all_args.items():
        if "OUT" in arguments[0].arg_dir and not "IN" in arguments[0].arg_dir:
            tmp.extend(declare_var(arg_key, arguments, arg_type_list, False))
    
    if len(tmp) > 0:
        output.append("/*")
        output.append("    Output Variable(s)")
        output.append("*/")
        output.extend(tmp)
        output.append("")

    return add_indents(output, indent)


def call_function(function: str, 
                  function_block: FunctionBlock, 
                  services: Dict[str, FunctionBlock], 
                  protocol_variable: str,
                  arg_type_list: List[TypeTracker],                    
                  indent: bool) -> List[str]:
    output = []

    if "protocol" in services[function].service:
        call_prefix = protocol_variable + "->"
    elif "BS" in services[function].service or "Boot" in services[function].service:
        call_prefix = "SystemTable->BootServices->"
    elif "RT" in services[function].service or "Runtime" in services[function].service:
        call_prefix = "SystemTable->RuntimeServices->"
    else:
        call_prefix = ""
    
    output.append(f"printf(\"Status = {call_prefix}{function}\\n\");")

    return add_indents(output, indent)

def add_ptrs(arg_type: str,
             num_ptrs: int) -> str:
    if num_ptrs == 0:
        return arg_type
    else:
        return add_ptrs(f"{arg_type}*", num_ptrs - 1)

def declare_var(arg_key: str, 
                arguments: List[Argument],
                arg_type_list: List[TypeTracker],
                indent: bool) -> List[str]:
    output = []
    if arguments[0].pointer_count > 2:
        if arguments[0].arg_dir == "OUT":
            arg_type = add_ptrs(arguments[0].arg_type, arguments[0].pointer_count-1) if "void" in arguments[0].arg_type.lower() else arguments[0].arg_type
            arg_type_list.append(TypeTracker(arg_type, arg_key, arguments[0].pointer_count))
        else:
            print(f"ERROR: {function} {arg_key} has more than 2 pointers")
            return output
    elif arguments[0].pointer_count == 2:
        arg_type = "uint64_t*" if "void" in arguments[0].arg_type.lower()  else arguments[0].arg_type.replace('**', '*')
        arg_type_list.append(TypeTracker(arg_type, arg_key, 1))
    else:
        arg_type = add_ptrs("uint64_t", arguments[0].pointer_count) if "void" in arguments[0].arg_type.lower() else arguments[0].arg_type
        arg_type_list.append(TypeTracker(arg_type, arg_key, arguments[0].pointer_count))
    if arguments[0].pointer_count > 0:
        output.append(f'printf(\"{arg_type} {arg_key} = NULL;\\n\");')
    else:
        output.append(f"printf(\"{arg_type} {arg_key};\\n\");")
    
    return add_indents(output, indent)

def fuzzable_args(arg: str, 
                  indent: bool) -> List[str]:
    output = []
    output.append("// Fuzzable Variable Initialization")
    output.append(f'uint64_t {arg} = 0;')
    output.append(f"ReadBytes(Input, sizeof({arg}), &{arg});")
    output.append(f'printf(\"{arg} = %lx;\\n\", {arg});')
    
    return add_indents(output, indent)

def generate_inputs(function_block: FunctionBlock, 
                    types: Dict[str, List[FieldInfo]], 
                    services: Dict[str, FunctionBlock], 
                    protocol_variable: str, 
                    generators: Dict[str, FunctionBlock],
                    arg_type_list: List[TypeTracker],
                    indent: bool) -> List[str]:
    output = []
    tmp = []
    for arg_key, arguments in function_block.arguments.items():
        if "IN" in arguments[0].arg_dir:
            tmp.extend(declare_var(arg_key, arguments, arg_type_list, False))

    if len(tmp) > 0:
        output.append("/*")
        output.append("    Input Variable(s)")
        output.append("*/")
        output.extend(tmp)
        output.append("")

    for arg_key, arguments in function_block.arguments.items():
        if "IN" in arguments[0].arg_dir:
            if arguments[0].variable == "__FUZZABLE__":
                output.extend(fuzzable_args(arg_key, False))
            elif "__CONSTANT" in arguments[0].variable or "__ENUM_ARG__" in arguments[0].variable:
                output.extend(constant_args(arg_key, arguments, False))
            elif "__FUNCTION_PTR__" in arguments[0].variable:
                output.extend(function_ptr_args(arg_key, arguments, False))
            elif "EFI_GUID" in arguments[0].arg_type:
                output.extend(guid_args(arg_key, arguments, False))
            elif (
                arguments[0].variable.startswith('__FUZZABLE_')
                and arguments[0].variable.endswith('_STRUCT__')
            ) or "__GENERATOR_FUNCTION__" in arguments[0].variable:
                output.extend(generator_struct_args(function_block.function, arg_key, arguments, types, services, protocol_variable, generators, False))
            output.append("")

    return add_indents(output, indent)


def constant_args(arg_key: str, 
                  arguments: List[Argument],
                  indent: bool) -> List[str]:
    output = []
    output.append("// Constant Variable Initialization")
    output.append(f'uint8_t {arg_key}_choice = 0;')
    output.append(f'ReadBytes(Input, sizeof(uint8_t), &{arg_key}_choice);')
    output.append(f'switch({arg_key}_choice % {len(arguments)})' + ' {')
    for index, argument in enumerate(arguments):
        output.append(f'    case {index}:')
        if argument.usage == "":
            output.append(f'        printf(\"{arg_key} = NULL;\\n\");')
        else:
            output.append(f'        printf(\"{arg_key} = {remove_quotes(argument.usage)};\\n\");')
        output.append(f'        break;')
    output.append('}')

    return add_indents(output, indent)

def function_ptr_args(arg_key: str, 
                      arguments: List[Argument],
                      indent: bool) -> List[str]:
    output = []
    output.append("// Function Pointer Variable Initialization")
    output.append(f'uint8_t {arg_key}_choice = 0;')
    output.append(f'ReadBytes(Input, sizeof(uint8_t), &{arg_key}_choice);')
    output.append(f'switch({arg_key}_choice % {len(arguments)})' + ' {')
    for index, argument in enumerate(arguments):
        output.append(f'    case {index}:')
        output.append(f'        printf(\"{arg_key} = {argument.usage};\");')
        output.append(f'        break;')
    output.append('}')
    
    # VOID* {{ arg_key }};

    return add_indents(output, indent)

def guid_args(arg_key: str, 
              arguments: List[Argument],
              indent: bool) -> List[str]:
    output = []
    output.append("// EFI_GUID Variable Initialization")
    output.append(f'uint8_t {arg_key}_choice = 0;')
    output.append(f'ReadBytes(Input, sizeof(uint8_t), &{arg_key}_choice);')
    output.append(f'switch({arg_key}_choice % {len(arguments)})' + ' {')
    for index, argument in enumerate(arguments):
        output.append(f'    case {index}:')
        output.append(f'        printf(\"{arg_key} = &{argument.variable};\\n\");')
        output.append(f'        break;')
    output.append('}')

    return add_indents(output, indent)

def generator_struct_args(function: str,
                          arg_key: str, 
                          arguments: List[Argument], 
                          types: Dict[str, List[FieldInfo]], 
                          services: Dict[str, FunctionBlock], 
                          protocol_variable: str,
                          generators: Dict[str, FunctionBlock],
                          indent: bool) -> List[str]:
    output = []
    output.append("// Generator Struct Variable Initialization")
    if len(arguments) > 1:
        output.append(f'uint8_t {function}_{arg_key}_choice = 0;')
        output.append(f'ReadBytes(Input, sizeof(uint8_t), &{function}_{arg_key}_choice);')
        output.append(f'switch({function}_{arg_key}_choice % {len(arguments)})' +' {')
        for index, argument in enumerate(arguments):
            output.append(f'    case {index}: ' + '{')
            if argument.variable.startswith('__FUZZABLE_') and argument.variable.endswith('_STRUCT__'):
                output.append(f'        printf(\"{argument.arg_type}\\n\");')
                output.append(f'        {remove_ref_symbols(arguments[0].arg_type)} {function}_{arg_key};')
                for field in types[remove_ref_symbols(argument.arg_type)]:
                    if field.type != "EFI_GUID":
                        output.append(f'        {function}_{arg_key}.{field.name} = 0;')
                    output.append(f'        ReadBytes(Input, sizeof({function}_{arg_key}.{field.name}), &({function}_{arg_key}.{field.name}));')
                    output.append(f'        printf(\"\t{field.name} = %lx;\\n\", {function}_{arg_key}.{field.name});')            # elif "__GENERATOR_FUNCTION__" in argument.variable:
            elif "__GENERATOR_FUNCTION__" in argument.variable:
                generator_outputs = function_body(generators[argument.assignment], services, protocol_variable, generators, types, True)
                for line in generator_outputs:
                    output.append(f'    {line}')
                for generator_arg_key, generator_arguments in generators[argument.assignment].arguments.items():
                    if "OUT" in generator_arguments[0].arg_dir and not "IN" in generator_arguments[0].arg_dir:
                        if argument.arg_type in generator_arguments[0].arg_type:
                            output.append(f'        printf(\"{function}_{arg_key} = {argument.assignment}_{generator_arg_key};\");')
            output.append(f'        break;')
            output.append('    }')
        output.append('}')
    else:
        if arguments[0].variable.startswith('__FUZZABLE_') and arguments[0].variable.endswith('_STRUCT__'):
            output.append(f'printf(\"{arguments[0].arg_type}\\n\");')
            output.append(f'{remove_ref_symbols(arguments[0].arg_type)} {function}_{arg_key};')
            for field in types[remove_ref_symbols(arguments[0].arg_type)]:
                if field.type != "EFI_GUID":
                    output.append(f'{function}_{arg_key}.{field.name} = 0;')
                output.append(f'ReadBytes(Input, sizeof({function}_{arg_key}.{field.name}), &({function}_{arg_key}.{field.name}));')
                output.append(f'printf(\"\t{field.name} = %lx;\\n\", {function}_{arg_key}.{field.name});')
        elif "__GENERATOR_FUNCTION__" in arguments[0].variable:
            output.extend(function_body(generators[arguments[0].assignment], services, protocol_variable, generators, types, False))        

    return add_indents(output, indent)

def function_body(function_block: FunctionBlock, 
                  services: Dict[str, FunctionBlock], 
                  protocol_variable: str, 
                  generators: Dict[str, FunctionBlock], 
                  types: Dict[str, List[FieldInfo]],
                  indent: bool) -> List[str]:
    output = []
    arg_type_list = []
    output.extend(generate_inputs(function_block, types, services, protocol_variable, generators, arg_type_list, False))
    output.extend(generate_outputs(function_block.arguments, arg_type_list, False))
    output.extend(call_function(function_block.function, function_block, services, protocol_variable, arg_type_list, False))

    return add_indents(output, indent)


def harness_generator(services: Dict[str, FunctionBlock], 
                      functions: Dict[str, FunctionBlock], 
                      types: Dict[str, List[FieldInfo]], 
                      aliases: Dict[str, str],
                      generators: Dict[str, FunctionBlock]) -> List[str]:
    # Initialize an empty string to store the generated content
    output = []

    output.append("#include \"FirnessHarnesses_std.h\"")
    output.append("")

    # Iterate through functions and generate harnesses
    for function, function_block in functions.items():
        output.append(f"/*")
        output.append(f"    This is a harness for fuzzing the {services[function].service} service")
        output.append(f"    called {function}.")
        output.append(f"*/")
        output.append(f"int Fuzz{function}(")
        output.append(f"    INPUT_BUFFER *Input")
        output.append(") {")
        output.append(f"    printf(\"Fuzzing {function}...\\n\");")
        output.append(f"    int Status = 0;")
        protocol_variable = ""
        if "protocol" in services[function].service:
            protocol_variable = "ProtocolVariable"
            output.append(f"    printf(\"{function_block['Arg_0'][0].arg_type} {protocol_variable};\\n\");")

        output.extend(function_body(function_block, services, protocol_variable, generators, types, True))

        output.append(f"    return Status;")
        output.append("}")
        output.append("")

    # Print or use the output_string as needed
    return output
