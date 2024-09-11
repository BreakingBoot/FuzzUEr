from typing import List, Dict
import copy
from common.types import FunctionBlock, Argument, TypeTracker, FieldInfo, TypeInfo, EnumDef
from common.utils import add_indents, remove_ref_symbols

aliases_map = {}
enum_map = {}

# this is a function that will return the underlying data type for any function
# so given EFI_PHYSICAL_ADDRESS it will return UINT64 by searching the aliases
# dictionary
def get_type(arg_type: str) -> str:
    if remove_ref_symbols(arg_type) in aliases_map.keys():
        return arg_type.replace(remove_ref_symbols(arg_type), aliases_map[remove_ref_symbols(arg_type)])
    else:
        return arg_type

def set_undefined_constants(arg_type: str) -> str:
    if has_pointer(arg_type):
        return "("+arg_type+")AllocateZeroPool(sizeof(" + remove_ref_symbols(arg_type) + "))"        
    elif "bool" in arg_type.lower():
        return "FALSE"
    else:
        return "0"
        

def generate_outputs(function: str,
                     all_args: Dict[str, List[Argument]],
                     arg_type_list: List[TypeTracker],
                     indent: bool,
                     prefix: str) -> List[str]:
    output = []
    tmp = []
    
    for arg_key, arguments in all_args.items():
        if "OUT" == arguments[0].arg_dir and not arguments[0].variable == '__GEN_INPUT__':
            if prefix != "":
                arg_key = f'{prefix}_{arg_key}'
            tmp.extend(declare_var(function, arg_key, arguments, arg_type_list, False, False, False, False))
            # This is being used to handle the case where the output is a pointer ( so randomly create a pointer)
            tmp.append(f"UINT8* {function}_{arg_key}_OutputChoice = AllocateZeroPool(sizeof(UINT8));")
            tmp.append(f"ReadBytes(Input, sizeof({function}_{arg_key}_OutputChoice), (VOID *){function}_{arg_key}_OutputChoice);")
            tmp.append(f"if(*{function}_{arg_key}_OutputChoice % 2)")
            tmp.append("{")
            if arguments[0].pointer_count > 0:
                tmp.append(f"    ReadBytes(Input, sizeof(*{function}_{arg_key}), (VOID *){function}_{arg_key});")
            else:
                tmp.append(f"    ReadBytes(Input, sizeof({function}_{arg_key}), {function}_{arg_key});")
            tmp.append("}") 
    
    if len(tmp) > 0:
        output.append("/*")
        output.append("    Output Variable(s)")
        output.append("*/")
        output.extend(tmp)
     
    return add_indents(output, indent)


# properly add casts to the arguments based off the difference
# between the argument type and the type tracker type along with
# the pointer count
def cast_arg(function: str, 
             arg_key:str,
             arguments: List[Argument],
             arg_type_list: List[TypeTracker]) -> str:
    
    update_arg = ""
    for arg in arg_type_list:
        if arg.name == arg_key:
            if arg.arg_type != arguments[0].arg_type:
                update_arg += f'({arguments[0].arg_type})'
            if arguments[0].pointer_count > arg.pointer_count:
                update_arg += f'&'
            # elif arg.fuzzable and arg.pointer_count > 0:
            #     update_arg += f'*'
            break
    if arguments[0].variable == '__GEN_INPUT__':
        update_arg += arguments[0].usage
    else:
        update_arg += f'{function}_{arg_key}'

    return update_arg
    

def call_function(function: str, 
                  function_block: FunctionBlock, 
                  services: Dict[str, FunctionBlock], 
                  protocol_variable: str,
                  arg_type_list: List[TypeTracker],                    
                  indent: bool,
                  prefix: str) -> List[str]:
    output = []
    lookup_function = function
    if prefix != "":
        lookup_function = f'{prefix}:{function}'
    if "protocol" in services[lookup_function].service:
        call_prefix = protocol_variable + "->"
    elif "BS" in services[lookup_function].service or "Boot" in services[lookup_function].service:
        call_prefix = "SystemTable->BootServices->"
    elif "RT" in services[lookup_function].service or "Runtime" in services[lookup_function].service:
        call_prefix = "SystemTable->RuntimeServices->"
    elif "DS" in services[lookup_function].service or "DxeServices" in services[lookup_function].service:
        call_prefix = "gDS->"
    else:
        call_prefix = ""
    
    if function_block.return_type == "EFI_STATUS":
        output.append(f"Status = {call_prefix}{function}(")
    else:
        output.append(f"{call_prefix}{function}(")

    for arg_key, arguments in function_block.arguments.items():
        original_arg_key = arg_key
        if prefix != "":
            arg_key = f'{prefix}_{arg_key}'
        if arguments[0].arg_dir == "IN" and arguments[0].variable == "__HANDLE__":
            tmp = f"    ImageHandle,"
        elif arguments[0].arg_dir == "IN" and arguments[0].variable == "__PROTOCOL__":
            tmp = f"    ProtocolVariable,"
        elif arguments[0].arg_dir == "OPTIONAL":
            tmp = f"    NULL,"
        else:
            tmp = f"    {cast_arg(function, arg_key, arguments, arg_type_list)},"
        # if the last iteration remove the comma
        if original_arg_key == list(function_block.arguments.keys())[-1]:
            tmp = tmp[:-1]
        output.append(tmp)
    output.append(f");")

    return add_indents(output, indent)

def add_ptrs(arg_type: str,
             num_ptrs: int) -> str:
    if num_ptrs == 0:
        return arg_type
    else:
        return add_ptrs(f"{arg_type}*", num_ptrs - 1)

def declare_var(function: str,
                arg_key: str, 
                arguments: List[Argument],
                arg_type_list: List[TypeTracker],
                indent: bool,
                fuzzable: bool,
                isStruct: bool,
                random) -> List[str]:
    output = []
    if arguments[0].pointer_count > 2:
        if arguments[0].arg_dir == "OUT":
            arg_type = add_ptrs(arguments[0].arg_type, arguments[0].pointer_count-1) if "void" in arguments[0].arg_type.lower() else arguments[0].arg_type
            arg_type_list.append(TypeTracker(arg_type, arg_key, arguments[0].pointer_count, fuzzable))
        else:
            print(f"ERROR: {function} {arg_key} has more than 2 pointers")
            return output
    elif arguments[0].pointer_count == 2:
        arg_type = "UINTN*" if "void" in arguments[0].arg_type.lower()  else arguments[0].arg_type.replace('**', '*')
        if random:
            arg_type = "UINTN*"
        arg_type_list.append(TypeTracker(arg_type, arg_key, 1, fuzzable))
        # output.append(f'UINT8 *{arg_key}_array = NULL;')
        # output.append(f'ReadBytes(&Input, sizeof({arg_key}_array), &{arg_key}_array);')
        # arg_type = f'{arg_type}[{arg_key}_array[0]]'
    else:
        if random:
            arg_type = "UINTN*"
        elif fuzzable:
            arg_type = "UINTN* " if "void" in arguments[0].arg_type.lower() else f'{(arguments[0].arg_type)}'
        else:
            arg_type = "UINTN* " if "void" in arguments[0].arg_type.lower() else arguments[0].arg_type
        arg_type_list.append(TypeTracker(arg_type, arg_key, arguments[0].pointer_count, fuzzable))
    if (arguments[0].pointer_count > 0 and not "char" in arguments[0].arg_type.lower()) and not "IN" in arguments[0].arg_dir:
        output.append(f'{arg_type} {function}_{arg_key} = ({arg_type})AllocateZeroPool(sizeof({remove_ref_symbols(arg_type)}));')
    else:
        output.append(f"{arg_type} {function}_{arg_key} = {set_undefined_constants(arg_type)};")
        # if fuzzable :
        #     # output.append(f'{arg_type} {function}_{arg_key} = NULL;')
            
        # elif isStruct:
        #     output.append(f'{arg_type} {function}_{arg_key} = AllocateZeroPool(sizeof({remove_ref_symbols(arg_type)}));')
        # else:
        #     output.append(f"{arg_type} {function}_{arg_key} = {set_undefined_constants(arguments[0])};")
    
    return add_indents(output, indent)

def fuzzable_args(function: str,
                  arg: str, 
                  indent: bool,
                  arg_type_list: List[TypeTracker]) -> List[str]:
    output = []
    output.append("// Fuzzable Variable Initialization")
    for arg_type in arg_type_list:
        if arg_type.name == arg:
            if arg_type.pointer_count == 0:
                output.append(f'ReadBytes(Input, sizeof({function}_{arg}), (VOID *)&{function}_{arg});')
                break
            else:
                # output.append(f'ReadBytes(Input, sizeof({function}_{arg}), (VOID *){function}_{arg});')
                # output.append(f'ReadBytes(Input, sizeof({function}_{arg}), (VOID *){function}_{arg});')
                output.append(f'UINT8 {function}_{arg}_choice = 0;')
                output.append(f'ReadBytes(Input, sizeof({function}_{arg}_choice), (VOID *)&{function}_{arg}_choice);')
                output.append(f'switch({function}_{arg}_choice % 2)' + ' {')
                output.append(f'    case 0:')
                output.append(f'        ReadBytes(Input, sizeof({function}_{arg}), (VOID *){function}_{arg});')
                output.append(f'        break;')
                output.append(f'    case 1:')
                output.append('    {')
                output.append(f'        gBS->FreePool({function}_{arg});')
                output.append(f'        {function}_{arg} = NULL;')
                output.append(f'        break;')
                output.append('    }')
                output.append('}')
                break

    # output.append(f'ReadBytes(Input, sizeof({function}_{arg}), (VOID *){function}_{arg});')
    # output.append(f'UINT8 {function}_{arg}_choice = 0;')
    # output.append(f'ReadBytes(Input, sizeof({function}_{arg}_choice), (VOID *)&{function}_{arg}_choice);')
    # output.append(f'switch({function}_{arg}_choice % 2)' + ' {')
    # output.append(f'    case 0:')
    # output.append(f'        ReadBytes(Input, sizeof({function}_{arg}), (VOID *){function}_{arg});')
    # output.append(f'        break;')
    # output.append(f'    case 1:')
    # output.append('    {')
    # output.append(f'        UINTN RandomPointer = 0;')
    # output.append(f'        ReadBytes(Input, sizeof(RandomPointer), (VOID *)&RandomPointer);')
    # for arg_type in arg_type_list:
    #     if arg_type.name == arg:
    #         output.append(f'        {function}_{arg} = ({arg_type.arg_type})RandomPointer;')
    #         break
    # output.append(f'        break;')
    # output.append('    }')
    # output.append('}')
    
    return add_indents(output, indent)

def generate_inputs(function_block: FunctionBlock, 
                    types: Dict[str, TypeInfo], 
                    services: Dict[str, FunctionBlock], 
                    protocol_variable: str, 
                    generators: Dict[str, FunctionBlock],
                    arg_type_list: List[TypeTracker],
                    indent: bool,
                    random: bool,
                    prefix: str) -> List[str]:
    output = []
    tmp = []
    for arg_key, arguments in function_block.arguments.items():
        if "IN" in arguments[0].arg_dir and not arguments[0].variable == "__HANDLE__" and not arguments[0].variable == "__PROTOCOL__":
            is_struct = remove_ref_symbols(arguments[0].arg_type) in types.keys() or aliases_map.get(remove_ref_symbols(arguments[0].arg_type), "") in types.keys()
            if prefix != "":
                arg_key = f'{prefix}_{arg_key}'
            tmp.extend(declare_var(function_block.function, arg_key, arguments, arg_type_list, False, arguments[0].variable == "__FUZZABLE__", is_struct, random))

    if len(tmp) > 0:
        output.append("/*")
        output.append("    Input Variable(s)")
        output.append("*/")
        output.extend(tmp)
        output.append("")

    for arg_key, arguments in function_block.arguments.items():
        if "IN" in arguments[0].arg_dir:
            if prefix != "":
                arg_key = f'{prefix}_{arg_key}'
            total_elements = len(arguments)
            if total_elements > 1:
                output.append(f'UINT8* {function_block.function}_{arg_key}_choice = AllocateZeroPool(sizeof(UINT8));')
                output.append(f'ReadBytes(Input, sizeof({function_block.function}_{arg_key}_choice), (VOID *){function_block.function}_{arg_key}_choice);')
                output.append(f'switch(*{function_block.function}_{arg_key}_choice % {total_elements})' + ' {')
            for arg in arguments:
                if total_elements > 1:
                    output.append(f'    case {arguments.index(arg)}:')
                    output.append('    {')
                if arg.variable == "__FUZZABLE__" or random:
                    output.extend(fuzzable_args(function_block.function, arg_key, total_elements > 1, arg_type_list))
                elif "__CONSTANT" in arg.variable or "__ENUM_ARG__" in arg.variable:
                    output.extend(constant_args(function_block.function, arg_key, arg, total_elements > 1))
                elif "__FUNCTION_PTR__" in arg.variable:
                    output.extend(function_ptr_args(function_block.function, arg_key, arg, total_elements > 1))
                elif "__GUID__" in arg.variable:
                    output.extend(guid_args(function_block.function, arg_key, arg, total_elements > 1))
                elif (
                    arg.variable.startswith('__FUZZABLE_')
                    and arg.variable.endswith('_STRUCT__')
                ) or "__GENERATOR_FUNCTION__" in arg.variable:
                    output.extend(generator_struct_args(function_block.function, arg_key, arg, types, services, protocol_variable, generators, total_elements > 1))
                        
                output.append("")
                if total_elements > 1:
                    output.append(f'        break;')
                    output.append('    }')
            if total_elements > 1:
                output.append('}')

    return add_indents(output, indent)

def constant_args(function: str,
                  arg_key: str, 
                  arg: Argument,
                  indent: bool) -> List[str]:
    output = []
    output.append("// Constant Variable Initialization")
    if arg.variable == "__ENUM_ARG__":
        output.append(f'UINT8* {function}_{arg_key}_choice = AllocateZeroPool(sizeof(UINT8));')
        output.append(f'ReadBytes(Input, sizeof({function}_{arg_key}_choice), (VOID *){function}_{arg_key}_choice);')
        usages = []
        matched_enum = enum_map.get(remove_ref_symbols(arg.arg_type), None)
        if matched_enum is None:
            matched_enum = enum_map.get(remove_ref_symbols(arg.data_type), EnumDef())
        for enum in matched_enum.values:
            tmp = copy.copy(arg)
            tmp.usage = enum
            usages.append(tmp)
        output.append(f'switch(*{function}_{arg_key}_choice % {len(usages)+1})' + ' {')
        for index, argument in enumerate(usages):
            output.append(f'    case {index}:')
            if argument.usage == "":
                output.append(f'        {function}_{arg_key} = {set_undefined_constants(argument)};')
            elif "char" in argument.arg_type.lower():
                output.append(f'        {function}_{arg_key} = StrDuplicate({argument.usage});')
            else:
                output.append(f'        {function}_{arg_key} = {argument.usage};')
            output.append(f'        break;')
        output.append(f'    case {len(usages)}:')
        if has_pointer(arg.arg_type):
            output.append(f'        ReadBytes(Input, sizeof({function}_{arg_key}), (VOID *){function}_{arg_key});')
        else:
            output.append(f'        ReadBytes(Input, sizeof({function}_{arg_key}), (VOID *)&{function}_{arg_key});')
        output.append(f'        break;')
        output.append('}')
    else:
        if arg.usage == "":
            output.append(f'{function}_{arg_key} = {set_undefined_constants(arg)};')
        elif "char" in arg.arg_type.lower():
            output.append(f'{function}_{arg_key} = StrDuplicate({arg.usage});')
        else:
            output.append(f'{function}_{arg_key} = {arg.usage};')

    return add_indents(output, indent)

def function_ptr_args(function:str, 
                      arg_key: str, 
                      arg: Argument,
                      indent: bool) -> List[str]:
    output = []
    output.append("// Function Pointer Variable Initialization")
    output.append(f'{function}_{arg_key} = {arg.usage};')
    
    # VOID* {{ arg_key }};

    return add_indents(output, indent)

def guid_args(function:str, 
              arg_key: str, 
              arg: Argument,
              indent: bool) -> List[str]:
    output = []
    output.append("// EFI_GUID Variable Initialization")
    output.append(f'{function}_{arg_key} = {arg.usage};')

    return add_indents(output, indent)

def has_pointer(arg_type: str) -> bool:
    return arg_type.count('*') > 0

def generator_struct_args(function: str, 
                          arg_key: str, 
                          arg: Argument, 
                          types: Dict[str, TypeInfo], 
                          services: Dict[str, FunctionBlock], 
                          protocol_variable: str,
                          generators: Dict[str, FunctionBlock],
                          indent: bool) -> List[str]:
    output = []
    output.append("// Generator Struct Variable Initialization")
    # if len(arguments) > 1:
    #     output.append(f'UINT8 {function}_{arg_key}_choice = 0;')
    #     output.append(f'ReadBytes(Input, sizeof({function}_{arg_key}_choice), &{function}_{arg_key}_choice);')
    #     output.append(f'switch({function}_{arg_key}_choice % {len(arguments)})' +' {')
    #     for index, argument in enumerate(arguments):
    #         output.append(f'    case {index}: ' + '{')
    #         if argument.variable.startswith('__FUZZABLE_') and argument.variable.endswith('_STRUCT__'):
    #             for field in types[remove_ref_symbols(argument.arg_type)]:
    #                 output.append(f'        ReadBytes(Input, sizeof({function}_{arg_key}->{field.name}), &({function}_{arg_key}->{field.name}));')
    #         elif "__GENERATOR_FUNCTION__" in argument.variable:
    #             generator_outputs = function_body(generators[argument.assignment], services, protocol_variable, generators, types, True)
    #             for line in generator_outputs:
    #                 output.append(f'    {line}')
    #             for generator_arg_key, generator_arguments in generators[argument.assignment].arguments.items():
    #                 if "OUT" in generator_arguments[0].arg_dir and not "IN" in generator_arguments[0].arg_dir:
    #                     if argument.arg_type in generator_arguments[0].arg_type:
    #                         output.append(f'        {function}_{arg_key} = {argument.assignment}_{generator_arg_key};')
    #         output.append(f'        break;')
    #         output.append('    }')
    #     output.append('}')
    # else:
    if arg.variable.startswith('__FUZZABLE_') and arg.variable.endswith('_STRUCT__'):
        struct_type = remove_ref_symbols(arg.arg_type) if len(types.get(remove_ref_symbols(arg.arg_type), TypeInfo()).fields) > 0 else (aliases_map.get(remove_ref_symbols(arg.arg_type), None))
        for field in types[struct_type].fields:
            if not has_pointer(field.type):
                output.append(f'ReadBytes(Input, sizeof({function}_{arg_key}->{field.name}), (VOID *)&({function}_{arg_key}->{field.name}));')
            else:
                output.append(f'ReadBytes(Input, sizeof({function}_{arg_key}->{field.name}), (VOID *)({function}_{arg_key}->{field.name}));')
    elif "__GENERATOR_FUNCTION__" in arg.variable:
        # find the arg in the generator that is OUT and has the same type as the in function_arg_key
        for gen_arg_key, gen_arg in generators[arg.assignment].arguments.items():
            if gen_arg[0].arg_dir == 'OUT' and arg.arg_type == gen_arg[0].arg_type:
                gen_arg[0].variable = "__GEN_INPUT__"
                gen_arg[0].usage = f'{function}_{arg_key}'
                break
        function_name = arg.assignment
        prefix = ""
        if ':' in arg.assignment:
            prefix = arg.assignment.split(':')[0]
            function_name = arg.assignment.split(':')[-1]

        generators[arg.assignment].function = function_name
        services[arg.assignment].function = function_name
        if "protocol" in generators[arg.assignment].service.lower():
            protocol_variable = f'{protocol_variable}_{prefix}'
            output.append(f"    {generators[arg.assignment].arguments['Arg_0'][0].arg_type} {protocol_variable} = NULL;")
            output.append(f'    Status = SystemTable->BootServices->LocateProtocol(&{generators[arg.assignment].arguments["Arg_0"][0].usage}, NULL, (VOID *)&{protocol_variable});')
            output.append('    if (EFI_ERROR(Status)) {')
            output.append('        return Status;')
            output.append('    }')
        output.extend(function_body(generators[arg.assignment], services, protocol_variable, generators, types, indent, False, prefix))        

    return add_indents(output, indent)

def function_body(function_block: FunctionBlock, 
                  services: Dict[str, FunctionBlock], 
                  protocol_variable: str, 
                  generators: Dict[str, FunctionBlock], 
                  types: Dict[str, TypeInfo],
                  indent: bool,
                  random: bool = False,
                  prefix: str = "") -> List[str]:
    output = []
    arg_type_list = []
    output.extend(generate_inputs(function_block, types, services, protocol_variable, generators, arg_type_list, False, random, prefix))
    output.extend(generate_outputs(function_block.function, function_block.arguments, arg_type_list, False, prefix))
    output.extend(call_function(function_block.function, function_block, services, protocol_variable, arg_type_list, False, prefix))

    return add_indents(output, indent)


def harness_generator(services: Dict[str, FunctionBlock], 
                      functions: Dict[str, FunctionBlock], 
                      types: Dict[str, TypeInfo], 
                      generators: Dict[str, FunctionBlock],
                      aliases: Dict[str, str],
                      enums: Dict[str, EnumDef],
                      random: bool = False) -> List[str]:
    aliases_map.update(aliases)
    enum_map.update(enums)
    # Initialize an empty string to store the generated content
    output = []

    output.append("#include \"FirnessHarnesses.h\"")
    output.append("")

    # Iterate through functions and generate harnesses
    for function, function_block in functions.items():
        output.append(f"/*")
        output.append(f"    This is a harness for fuzzing the {services[function].service} service")
        output.append(f"    called {function}.")
        output.append(f"*/")
        output.append(f'__attribute__((no_sanitize("address")))')
        output.append(f"EFI_STATUS")
        output.append(f"EFIAPI")
        output.append(f"Fuzz{function}(")
        output.append(f"    IN INPUT_BUFFER *Input,")
        output.append(f"    IN EFI_SYSTEM_TABLE *SystemTable,")
        output.append(f"    IN EFI_HANDLE *ImageHandle")
        output.append(") {")
        output.append(f"    EFI_STATUS Status = EFI_SUCCESS;")
        protocol_variable = ""
        if "protocol" in services[function].service:
            protocol_variable = "ProtocolVariable"
            output.append(f"    {function_block.arguments['Arg_0'][0].arg_type} {protocol_variable} = NULL;")
            output.append(f'    Status = SystemTable->BootServices->LocateProtocol(&{function_block.arguments["Arg_0"][0].usage}, NULL, (VOID *)&{protocol_variable});')
            output.append('    if (EFI_ERROR(Status)) {')
            output.append('        return Status;')
            output.append('    }')

        output.extend(function_body(function_block, services, protocol_variable, generators, types, True, random))

        output.append(f"    return Status;")
        output.append("}")
        output.append("")

    # Print or use the output_string as needed
    return output







