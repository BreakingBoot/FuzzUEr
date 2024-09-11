import json
import os
import copy
from fuzzywuzzy import fuzz
import math
from collections import defaultdict, Counter
from typing import List, Dict, Tuple, Set
from common.types import FunctionBlock, FieldInfo, TypeInfo, EnumDef, Function, Argument, Macros, scalable_params, services_map, type_defs, known_contant_variables, ignore_constant_keywords, default_includes, default_libraries
from common.utils import remove_ref_symbols, write_data, get_union, is_whitespace, contains_void_star, contains_usage, get_stripped_usage, is_fuzzable, get_intersect, print_function_block
from common.generate_library_map import generate_libmap

current_args_dict = defaultdict(list)
all_includes = set()
total_generators = set()


# Doesn't take into account if multiple function definitions are found with the same
# name but different number of params
def load_generator_declares(json_file: str) -> Dict[str, Tuple[str, str]]:
    try:
        with open(json_file, 'r') as file:
            raw_data = json.load(file)

        function_dict = defaultdict(list)
        for raw_function in raw_data:
            arguments = {
                arg_key: [Argument(**raw_argument)] 
                for arg_key, raw_argument in raw_function.get('Parameters', {}).items()
            }
            function = Function(raw_function.get('Function'), arguments, raw_function.get('ReturnType'),
                                raw_function.get('Service'), raw_function.get('Includes'), raw_function.get('File'))
            function_dict[function.function] = function

        return function_dict
    except Exception as e:
        print(f'ERROR: {e}')
        return {}


def load_include_deps(json_file: str) -> Dict[str, List[str]]:
    try:
        with open(json_file, 'r') as file:
            raw_data = json.load(file)
        include_dict = defaultdict(list)
        for raw_include in raw_data:
            include_dict[raw_include["File"]] = raw_include["Includes"]
        return include_dict
    except Exception as e:
        print(f'ERROR: {e}')
        return {}

# Doesn't take into account if multiple function definitions are found with the same
# name but different number of params
def load_function_declares(json_file: str) -> Dict[str, Tuple[str, str]]:
    try:
        with open(json_file, 'r') as file:
            raw_data = json.load(file)

        function_dict = defaultdict(list)
        for raw_function in raw_data:
            arguments = {
                arg_key: [Argument(**raw_argument)] 
                for arg_key, raw_argument in raw_function.get('Parameters', {}).items()
            }
            function = Function(raw_function.get('Function'), arguments, raw_function.get('ReturnType'),
                                raw_function.get('Service'), raw_function.get('Includes'))
            function_dict[function.function] = function

        return function_dict
    except Exception as e:
        print(f'ERROR: {e}')
        return {}

def load_libmap(edk2_dir: str, output_file: str) -> Dict[str, Dict[str, list]]:
    try:
        return generate_libmap(edk2_dir, output_file)
    except Exception as e:
        print(f'ERROR: {e}')
        return {}

#
# load in the castings
#
def load_castings(json_file: str) -> Dict[str, List[str]]:
    try:
        with open(json_file, 'r') as file:
            raw_data = json.load(file)
        casting_dict = defaultdict(list)
        for raw_casting in raw_data:
            # if the type isn't a scalar, then add it to the casting_dict
            if not any(param.lower() in raw_casting["Type"].lower() for param in scalable_params):
                casts = raw_casting["Casts"]
                for cast in casts:
                    # if the cast isn't a scalar, then add it to the casting_dict
                    if not any(param.lower() in cast.lower() for param in scalable_params):
                        casting_dict[raw_casting["Type"]].append(cast)
        return casting_dict
    except Exception as e:
        print(f'ERROR: {e}')
        return {}


#
# load in the functions to be harnessed
#
def load_functions(function_file: str) -> Dict[str, List[Tuple[str, str]]]:
    # Load in the functions to be harnessed from the txt file
    # They are classified into 3 categories: OtherFunctions, BootServices, and RuntimeServices
    with open(function_file, 'r') as file:
        data = file.readlines()
    function_dict = defaultdict(list)
    current_service = ""
    for line in data:
        if line.strip() != "":
            if line.strip().startswith("["):
                current_service = line.strip().replace("[", "").replace("]", "")
            # if the line is a comment, then skip it
            elif line.strip().startswith("//"):
                continue
            else:
                if ':' in line:
                    function_dict[current_service].append(
                        (line.split(':')[1].strip(), line.split(':')[0].strip()))
                else:
                    function_dict[current_service].append((line.strip(), ""))
    return function_dict


def sort_data(input_data: Dict[str, List[FunctionBlock]],
              harness_functions: Dict[str, List[Tuple[str, str]]],
              best_guess: bool,
              function_decl: Dict[str, Tuple[str, str]]) -> Dict[str, List[FunctionBlock]]:
    
    filtered_data = defaultdict(list)

    if len(input_data) > 0:
        sorted_data = {}
        # Determine the most common number of parameters for each function
        most_common_param_counts = {}
        for function, function_blocks in input_data.items():
            param_counts = Counter(len(fb.arguments) for fb in function_blocks)
            most_common_param_counts[function] = param_counts

        # group the data based on the number of parameters
        # and TODO: add a check for the parameters themselves
        # i.e. if there are multiple functions with the same number of parameters
        # then the arg_dir and arg_type must match
        # Also, if the most common param count isn't at least 50% of the total number of the different param counts
        # then don't keep any of the functions
        for function, param_counts in most_common_param_counts.items():
            if param_counts.most_common(1)[0][1] < math.floor(len(input_data[function]) / 2):
                print(f'WARNING: {function} has too many different parameter counts to be harnessed!!')
                continue
            sorted_data[function] = {}
            if len(param_counts) != 1:
                for function_block in input_data[function]:
                    sorted_data[function].setdefault(
                        len(function_block.arguments), []).append(function_block)
            else:
                sorted_data[function].setdefault(param_counts.most_common(1)[
                                                0][0], []).extend(input_data[function])
                
        
        # now loop through the sorted data and keep the groups of elements that have a corresponding service
        # in the harness_functions dictionary
        for function, arg_num_pairs in sorted_data.items():
            for _, function_blocks in arg_num_pairs.items():
                if not any(function in pair[0] for pairs in harness_functions.values() for pair in pairs):
                    print(f'WARNING: {function} is not in the harness functions list!!')
                    continue
                arg_num_match = False
                for function_block in function_blocks:
                    for key, item in services_map.items():
                        if key in function_block.service or item in function_block.service:
                            for harness_group in harness_functions[services_map[key]]:
                                if function in harness_group:
                                        # print(f'INFO: {function} with {key} parameters has been selected for harnessing!!')
                                        arg_num_match = True
                                        break
                        if arg_num_match:
                            break
                    if arg_num_match:
                        break
                if arg_num_match:
                    filtered_data.setdefault(function, []).extend(function_blocks)
                elif any(function in pair[0] for pair in harness_functions["OtherFunctions"]):
                    filtered_data.setdefault(function, []).extend(function_blocks)
        if best_guess:
            for function, arg_num_pairs in sorted_data.items():
                for _, function_blocks in arg_num_pairs.items():
                    if not any(function in pair[0] for pairs in harness_functions.values() for pair in pairs):
                        continue
                    if function in filtered_data.keys():
                        break
                    filtered_data.setdefault(function, []).extend(function_blocks)
                
    # loop through the filtered data and add the function_decl function if it is not already in the filtered_data
    for function, function_info in function_decl.items():
        if function not in filtered_data.keys():
            if function_info.service == "" or function_info.service is None:
                # search harness_functions for the function
                for key, value in harness_functions.items():
                    if any(function in pair[0] for pair in value):
                        function_info.service = key
                        break
            filtered_data[function].append(FunctionBlock(function_info.arguments, function, 
                                            function_info.service, function_info.includes, function_info.return_type))
            # all_includes.update(function_info.includes)
    return filtered_data

#
# Load in the function call database and perform frequency analysis across
# the function calls to make sure to only keep the function calls that have
# the same type of input args
#
def load_data(json_file: str,
              harness_functions: Dict[str, List[Tuple[str, str]]],
              macros: Dict[str, Macros],
              random: bool,
              best_guess: bool,
              function_decl: Dict[str, Tuple[str, str]]) -> Tuple[Dict[str, List[FunctionBlock]], Dict[str, FunctionBlock]]:

    with open(json_file, 'r') as file:
        raw_data = json.load(file)

    function_dict = defaultdict(list)
    try:
        for raw_function_block in raw_data:
            arguments = {
                arg_key: [Argument(**raw_argument)]
                for arg_key, raw_argument in raw_function_block.get('Arguments', {}).items()
            }
            if random:
                for arg_key, argument in arguments.items():
                    if argument[0].variable in known_contant_variables:
                        argument[0].variable = ""
            function_block = FunctionBlock(arguments, raw_function_block.get(
                'Function'), raw_function_block.get('Service'), raw_function_block.get('Include'), raw_function_block.get('ReturnType'))
            function_dict[function_block.function].append(function_block)
    except Exception as e:
        print(f'ERROR: {e}')

    # Check if there is a single most common number of parameters for each function
    # and if not then take the one which has a service matching the harness_functions.keys()
    # note that if RT is in the service name, then it is a runtime service and BS is a boot service
    filtered_function_dict = sort_data(function_dict, harness_functions, best_guess, function_decl)

    void_star_data_type_counter = defaultdict(Counter)
    function_template = {}

    # Collect data_type statistics for arg_type of "void *"
    for function, function_blocks in filtered_function_dict.items():
        if function not in function_template:
            function_template[function] = function_blocks[0]        
        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                if remove_ref_symbols(function_template[function].arguments.get(arg_key)[0].arg_type) in type_defs.values():
                    for name, type_def in type_defs.items():
                        if type_def == remove_ref_symbols(function_template[function].arguments.get(arg_key)[0].arg_type):
                            function_template[function].arguments.get(
                                arg_key)[0].arg_type = name
                    # function_template[function].arguments.get(
                    #     arg_key)[0].arg_type = argument[0].arg_type
                if argument[0].variable == "__FUNCTION_PTR__":
                    for function_block2 in function_blocks:
                        function_block2.arguments.get(arg_key)[0].variable = "__FUNCTION_PTR__"
                        function_block2.arguments.get(arg_key)[0].data_type = argument[0].arg_type
                if argument[0].assignment in macros.keys():
                    argument[0].usage = macros[argument[0].assignment].name
                    argument[0].assignment = macros[argument[0].assignment].name
                elif argument[0].usage in macros.keys():
                    argument[0].assignment = macros[argument[0].usage].name
                    argument[0].usage = macros[argument[0].usage].name
                if contains_void_star(argument[0].arg_type):
                    void_star_data_type_counter[arg_key].update(
                        [argument[0].data_type])
                # Add a check for the services and if there is no service in the template add it
                if is_whitespace(function_template[function].service) and not is_whitespace(function_block.service):
                    function_template[function].service = function_block.service
            if len(function_block.arguments) > 0:
                if "protocol" in function_block.arguments["Arg_0"][0].arg_type.lower():
                    function_template[function].service = "protocol"
        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                argument[0].arg_type = function_template[function].arguments.get(arg_key)[0].arg_type

    return filtered_function_dict, function_template

def load_generators(json_file: str,
                    macros: Dict[str, Macros]) -> Dict[str, List[FunctionBlock]]:

    if os.stat(json_file).st_size <= 4:
        print("WARNING: No generator functions were captured!!\n")
        return defaultdict(list)
    
    with open(json_file, 'r') as file:
        raw_data = json.load(file)            

    function_dict = defaultdict(list)
    for raw_function_block in raw_data:
        arguments = {
            arg_key: [Argument(**raw_argument)]
            for arg_key, raw_argument in raw_function_block.get('Arguments', {}).items()
        }
        function_block = FunctionBlock(arguments, raw_function_block.get(
            'Function'), raw_function_block.get('Service'), raw_function_block.get('Include'), raw_function_block.get('ReturnType'))
        if function_block.service == "protocol":
            function_dict[f'{remove_ref_symbols(function_block.arguments["Arg_0"][0].arg_type)}:{function_block.function}'].append(function_block)
        else:
            function_dict[function_block.function].append(function_block)

    # Determine the most common number of parameters for each function
    # most_common_param_counts = {}
    # for function, function_blocks in function_dict.items():
    #     param_counts = Counter(len(fb.arguments) for fb in function_blocks)
    #     most_common_param_counts[function] = param_counts.most_common(1)[0][0]

    # # Filter the function_dict to only include FunctionBlock instances with the most common number of parameters
    # filtered_function_dict = {function: [fb for fb in function_blocks if len(fb.arguments) == most_common_param_counts[function]]
    #                           for function, function_blocks in function_dict.items()}
    filtered_function_dict = function_dict

    for function, function_blocks in filtered_function_dict.items():
        for function_block in function_blocks:
            for _, argument in function_block.arguments.items():
                if argument[0].assignment in macros.keys():
                    argument[0].usage = macros[argument[0].assignment].name
                    argument[0].assignment = macros[argument[0].assignment].name
                elif argument[0].usage in macros.keys():
                    argument[0].assignment = macros[argument[0].usage].name
                    argument[0].usage = macros[argument[0].usage].name

    return filtered_function_dict


def load_aliases(json_file: str) -> Dict[str, str]:
    with open(json_file, 'r') as file:
        raw_data = json.load(file)
    return raw_data

#
# Load enums
#
def load_enums(json_file: str) -> Dict[str, EnumDef]:
    with open(json_file, 'r') as file:
        raw_data = json.load(file)
    enum_dict = defaultdict(list)
    for enum in raw_data:
        enum_def = EnumDef(enum["Name"], enum["Values"], enum["File"])
        enum_dict[enum["Name"]] = enum_def
    return enum_dict

#
# Load Macros
#
def load_macros(json_file: str) -> Tuple[Dict[str, Macros], Dict[str, Macros]]:
    with open(json_file, 'r') as file:
        raw_data = json.load(file)
    macros_val = defaultdict()
    macros_name = defaultdict()
    for macro in raw_data:
        macros_val[macro["Value"]] = Macros(**macro)
        macros_name[macro["Name"]] = Macros(**macro)
    return macros_val, macros_name

#
# Load in the type structures
#
def load_types(json_file: str) -> Dict[str, TypeInfo]:
    with open(json_file, 'r') as file:
        data = json.load(file)
    type_data_list = defaultdict(list)
    for type_data_dict in data:
        fields_list = []
        for field_dict in type_data_dict['Fields']:
            field_info = FieldInfo(field_dict['Name'], field_dict['Type'])
            fields_list.append(field_info)
        type_data_list[type_data_dict['TypeName']] = TypeInfo(type_data_dict['TypeName'], fields_list, type_data_dict['File'])
    return type_data_list


def variable_fuzzable(input_data: Dict[str, List[FunctionBlock]],
                      types: Dict[str, TypeInfo],
                      pre_processed_data: Dict[str, FunctionBlock],
                      aliases: Dict[str, str],
                      macros: Dict[str, Macros],
                      random: bool) -> Dict[str, FunctionBlock]:
    # for all of the functionblock argument data_types, check the types structure for the matching type
    # if the type is found and all of the fields are scalars, then add it to the create a new argument
    # and have the variable be __FUZZABLE_STRUCT__ and add it to the list
    contains_fuzzable_struct = defaultdict(lambda: defaultdict(lambda: False))

    # Add a check to not add an argument if the is already an argument of the variable name __FUZZABLE__
    # and a check to make sure that the variable name isn't __FUZZABLE_ARG_STRUCT__
    for function, function_blocks in input_data.items():
        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                added_struct = False
                if len(pre_processed_data[function].arguments.setdefault(arg_key, [])) > 0:
                    if any('__FUZZABLE__' in var.variable or '__ENUM_ARG__' in var.variable or 'EFI_EVENT' in var.arg_type or "void" in remove_ref_symbols(get_underlying_type(var.arg_type, aliases, macros)) for var in pre_processed_data[function].arguments.get(arg_key)):
                        continue

                if argument[0].arg_dir == "IN" and not contains_fuzzable_struct[function][arg_key] and (arg_key not in current_args_dict[function]):
                    if not contains_void_star(argument[0].arg_type):
                        if is_fuzzable(remove_ref_symbols(argument[0].arg_type), aliases, types, 0):
                            struct_arg = Argument(argument[0].arg_dir, argument[0].arg_type, "", argument[0].data_type,
                                                  argument[0].usage, "__FUZZABLE_ARG_STRUCT__", argument[0].potential_outputs)
                            pre_processed_data[function].arguments.setdefault(
                                arg_key, []).append(struct_arg)
                            current_args_dict[function].append(arg_key)
                            added_struct = True
                            contains_fuzzable_struct[function][arg_key] = True
                    if not contains_void_star(argument[0].data_type) and not added_struct:
                        if is_fuzzable(remove_ref_symbols(argument[0].data_type), aliases, types, 0):
                            struct_arg = Argument(argument[0].arg_dir, argument[0].arg_type, "", argument[0].data_type,
                                                  argument[0].usage, "__FUZZABLE_DATA_STRUCT__", argument[0].potential_outputs)
                            pre_processed_data[function].arguments.setdefault(
                                arg_key, []).append(struct_arg)
                            current_args_dict[function].append(arg_key)
                            contains_fuzzable_struct[function][arg_key] = True

    return pre_processed_data

#
# search the enum list for a matching type or assignment/usage
#
def find_enum(argument: Argument, enums: Dict[str, EnumDef]) -> str:
    for enum_name, enum_values in enums.items():
        if argument.arg_type.lower() in enum_name.lower():
            all_includes.add(enum_values.file)
            return enum_name
        elif any(value.lower() in argument.assignment.lower() or value in argument.usage.lower() for value in enum_values.values):
            all_includes.add(enum_values.file)
            return enum_name
    return argument.usage


#
# Filters out any arguments that are not IN and CONSTANT values, but making sure
# to not keep duplicates
#
def collect_known_constants(input_data: Dict[str, List[FunctionBlock]],
                            pre_processed_data: Dict[str, FunctionBlock],
                            macros: Dict[str, Macros],
                            aliases: Dict[str, str],
                            types: Dict[str, TypeInfo],
                            enums: Dict[str, List[str]]) -> Tuple[Dict[str, FunctionBlock], Dict[str, str], set, set]:
    # Keeps track of arg.usage values seen for each function and arg_key
    usage_seen = defaultdict(lambda: defaultdict(list))
    matched_macros = defaultdict(list)
    protocol_guids = set()
    driver_guids = set()

    # Step 1: Collect all arguments
    for function, function_blocks in input_data.items():
        first_sizeof = defaultdict(lambda: True)
        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                if (argument[0].arg_dir == "IN" or argument[0].arg_dir == "IN_OUT") :
                    # only want to add different enums once
                    if argument[0].variable == "__ENUM_ARG__": 
                        argument[0].usage = find_enum(argument[0], enums)
                        if argument[0].usage not in usage_seen[function][arg_key]:
                            pre_processed_data[function].arguments.setdefault(
                                arg_key, []).append(argument[0])
                            # current_args_dict[function].append(arg_key)
                            usage_seen[function][arg_key].append(argument[0].usage)
                    # only want to add EFI_HANDLE once
                    elif ("EFI_HANDLE" in argument[0].arg_type or "EFI_HANDLE" in get_underlying_type(argument[0].arg_type, aliases, macros) ) and usage_seen[function][arg_key] == []:
                        argument[0].variable = "__HANDLE__"
                        pre_processed_data[function].arguments.setdefault(
                            arg_key, []).append(argument[0])
                        # current_args_dict[function].append(arg_key)
                        usage_seen[function][arg_key].append(argument[0].usage)
                    # only need to add one protocol varibale to the harness
                    elif argument[0].variable == "__PROTOCOL__":
                        # if the assignment is LocatedProtocol then find the protocol guid from the assignment:
                        # gBS->LocateProtocol ( &gEfiUnicodeCollation2ProtocolGuid, NULL, (VOID **)&mUnicodeCollation )
                        if "locateprotocol" in argument[0].assignment.lower():
                            try:
                                protocol_guids.add(argument[0].assignment.split('->')[1].split('(')[1].split(',')[0].strip()[1:])
                            except:
                                print(f'ERROR: {function} has a protocol assignment that could not be parsed!!')
                                print(f'ERROR: {argument[0].assignment}')
                        if usage_seen[function][arg_key] == []:
                            pre_processed_data[function].arguments.setdefault(
                                arg_key, []).append(argument[0])
                            # current_args_dict[function].append(arg_key)
                            # save the file that the protocol is defined in
                            all_includes.add(types.get(remove_ref_symbols(argument[0].arg_type), TypeInfo()).file)
                            usage_seen[function][arg_key].append(argument[0].usage)
                    # add all contant values, but only one if its a sizeof(UINTN)
                    elif ("__CONSTANT" in argument[0].variable and "__CONSTANT_" != argument[0].variable) and argument[0].usage not in usage_seen[function][arg_key]:
                        if "__CONSTANT_SIZEOF__" in argument[0].variable:
                            if not first_sizeof[arg_key]:
                                continue
                            else:
                                first_sizeof[arg_key] = False
                        pre_processed_data[function].arguments.setdefault(
                            arg_key, []).append(argument[0])
                        # current_args_dict[function].append(arg_key)
                        usage_seen[function][arg_key].append(argument[0].usage)
                    # check if it is a guid
                    elif 'guid' in argument[0].arg_type.lower() and argument[0].variable.startswith('g') and argument[0].variable.endswith('Guid'):
                        if 'protocolguid' in argument[0].variable.lower():
                            # Add to the protocol_guids set
                            protocol_guids.add(argument[0].variable)
                        else:
                            # Add to the driver_guids set
                            if argument[0].usage != "":
                                driver_guids.add(argument[0].variable)
                        if argument[0].usage not in usage_seen[function][arg_key]:
                            guid_arg = copy.copy(argument[0])
                            guid_arg.variable = "__GUID__"
                            pre_processed_data[function].arguments.setdefault(
                                arg_key, []).append(guid_arg)
                            # current_args_dict[function].append(arg_key)
                            usage_seen[function][arg_key].append(guid_arg.usage)
                    # If there are multiple potential outputs, then add each one this would happen if there was masking
                    elif len(argument[0].potential_outputs) > 1:
                        for argument_value in argument[0].potential_outputs:
                            if not contains_usage(argument_value, usage_seen[function][arg_key], macros, aliases):
                                new_arg = Argument(argument[0].arg_dir, argument[0].arg_type, argument[0].assignment,
                                                   argument[0].data_type, argument_value, argument[0].variable, [])
                                pre_processed_data[function].arguments.setdefault(
                                    arg_key, []).append(new_arg)
                                if argument[0].assignment in macros.keys():
                                    matched_macros[macros[argument[0].assignment]
                                                   .name] = macros[argument[0].assignment].value
                                    all_includes.add(macros[argument[0].assignment].file)
                                # current_args_dict[function].append(arg_key)
                                usage_seen[function][arg_key].append(
                                    get_stripped_usage(argument_value, macros, aliases))
                    # elif not contains_usage(argument[0].usage, usage_seen[function][arg_key], macros, aliases):
                    #     pre_processed_data[function].arguments.setdefault(
                    #         arg_key, []).append(argument[0])
                    #     if argument[0].assignment in macros.keys():
                    #         matched_macros[macros[argument[0].assignment]
                    #                        .name] = macros[argument[0].assignment].value
                    #     current_args_dict[function].append(arg_key)
                    #     usage_seen[function][arg_key].append(get_stripped_usage(
                    #         argument[0].usage, macros, aliases))  # Update the set with the new arg.usage value
    # Step 2: Filter out arguments with less than 3 different values
    for function, function_block in pre_processed_data.items():
        for arg_key, argument in function_block.arguments.items():
            if len(argument) < 3 and (argument[0].variable != "__ENUM_ARG__" and argument[0].variable != "__PROTOCOL__" and argument[0].variable != "__HANDLE__" and argument[0].variable != "__GUID__"):
                for arg in argument:
                    argument.remove(arg)
                # current_args_dict[function].remove(arg_key)
    return pre_processed_data, matched_macros, protocol_guids, driver_guids

def get_underlying_type(data_type: str, 
                        aliases: Dict[str, str], 
                        macros: Dict[str, Macros]) -> str:
    underlying_type = data_type
    while remove_ref_symbols(underlying_type) in aliases.keys() or remove_ref_symbols(underlying_type) in macros.keys():
        if remove_ref_symbols(underlying_type) in aliases.keys():
            underlying_type = aliases[remove_ref_symbols(underlying_type)]
        elif remove_ref_symbols(underlying_type) in macros.keys():
            underlying_type = macros[remove_ref_symbols(underlying_type)].value
    return underlying_type

#
# Get fuzzable saves the arguments that take scalar inputs and also saves void * inputs that vary argument type
# by more than 5 since the assumption is that means the function is most likely manipulating data, not structures
# themselves. There is another exception if both the input argument and expected argument are both void * then
# it will treat is as fuzzable since it is most likely passing in a physical address.
#
def get_directly_fuzzable(input_data: Dict[str, List[FunctionBlock]],
                          pre_processed_data: Dict[str, FunctionBlock],
                          aliases: Dict[str, str],
                          macros: Dict[str, Macros],
                          random: bool) -> Dict[str, FunctionBlock]:

    for function, function_blocks in input_data.items():
        void_star_data_type_counter = defaultdict(Counter)
        only_void_star = {}
        

        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                if not only_void_star.get(arg_key, False):
                    only_void_star[arg_key] = False
                if contains_void_star(argument[0].arg_type) and contains_void_star(argument[0].data_type):
                    only_void_star[arg_key] = True
                elif contains_void_star(argument[0].arg_type) and aliases.get(remove_ref_symbols(argument[0].arg_type), "") == "":
                    only_void_star[arg_key] = True
                elif contains_void_star(argument[0].arg_type):
                    void_star_data_type_counter[arg_key].update(
                        [argument[0].data_type])
                elif contains_void_star(aliases.get(remove_ref_symbols(argument[0].arg_type), "").lower()):
                    void_star_data_type_counter[arg_key].update(
                        [argument[0].data_type])
        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                if (argument[0].arg_dir == "IN" or argument[0].arg_dir == "IN_OUT") and (arg_key not in current_args_dict[function]):
                    arg_type = remove_ref_symbols(argument[0].arg_type)
                    is_scalable = any(param.lower() in arg_type.lower() or param.lower() in get_underlying_type(arg_type, aliases, macros).lower() for param in scalable_params)
                    # if the argument is a fuzzable parameter, then add it to the pre_processed_data
                    if is_scalable:
                        scalable_arg = Argument(
                            argument[0].arg_dir, argument[0].arg_type, "", argument[0].data_type, argument[0].usage, "__FUZZABLE__")
                        current_args_dict[function].append(arg_key)
                        pre_processed_data[function].arguments.setdefault(
                            arg_key, []).append(scalable_arg)
                        continue
                    # if the argument is a void * and the data_type is not a void * and the data_type is not a scalar
                    elif (contains_void_star(argument[0].arg_type) or contains_void_star(aliases.get(remove_ref_symbols(argument[0].arg_type), "").lower())) and (len(void_star_data_type_counter[arg_key]) > math.floor(len(function_blocks)/2) or random):
                        scalable_arg = Argument(
                            argument[0].arg_dir, argument[0].arg_type, "", argument[0].data_type, argument[0].usage, "__FUZZABLE__")
                        current_args_dict[function].append(arg_key)
                        pre_processed_data[function].arguments.setdefault(
                            arg_key, []).append(scalable_arg)
                        continue
                    # if the data type is scalable because the function is expecting a void so no futher an
                    elif any(param.lower() in argument[0].data_type or param.lower() in aliases.get(argument[0].data_type, "").lower() for param in scalable_params) and contains_void_star(argument[0].arg_type):
                        scalable_arg = Argument(
                            argument[0].arg_dir, argument[0].arg_type, "", argument[0].data_type, argument[0].usage, "__FUZZABLE__")
                        current_args_dict[function].append(arg_key)
                        pre_processed_data[function].arguments.setdefault(
                            arg_key, []).append(scalable_arg)
                        continue
                    # if the argument is a void * and the data_type is a void *
                    elif only_void_star[arg_key]:
                        scalable_arg = Argument(
                            argument[0].arg_dir, argument[0].arg_type, "", argument[0].data_type, argument[0].usage, "__FUZZABLE__")
                        current_args_dict[function].append(arg_key)
                        pre_processed_data[function].arguments.setdefault(
                            arg_key, []).append(scalable_arg)
                        continue

    return pre_processed_data


def get_generators(pre_processed_data: Dict[str, FunctionBlock],
                   generators: Dict[str, FunctionBlock],
                   input_data: Dict[str, List[FunctionBlock]],
                   aliases: Dict[str, str],
                   castings: Dict[str, List[str]],
                   types: Dict[str, TypeInfo]) -> Dict[str, FunctionBlock]:
    global total_generators
    matching_generators = {}  # Dictionary to store the matching generators
    for func_name, generator_block in generators.items():
        for argument in generator_block.arguments.values():
            # Check if argument direction is OUT
            if argument[0].arg_dir == "OUT" and not any(param.lower() in argument[0].arg_type.lower() for param in scalable_params):
                # Look for a matching argument in function_template
                for func_temp_name, func_temp_blocks in input_data.items():
                    for func_temp_block in func_temp_blocks:
                        # Check if the function names are similar
                        similar = fuzz.ratio(func_name, func_temp_name)
                        if similar > 65:
                            continue
                        for ft_arg_key, ft_argument in func_temp_block.arguments.items():
                            if not contains_void_star(argument[0].arg_type):
                                # Check if argument types match and the argument is missing from known_inputs
                                if ((remove_ref_symbols(argument[0].arg_type) == remove_ref_symbols(ft_argument[0].arg_type) or remove_ref_symbols(argument[0].arg_type) in castings[remove_ref_symbols(ft_argument[0].arg_type)])and #ft_arg_key not in current_args_dict[func_temp_name] and
                                        ft_argument[0].arg_dir == "IN" and func_name not in matching_generators.setdefault(func_temp_name, [])):
                                    # Add a check to make sure all of the input arguments are fuzzable
                                    all_fuzzable = True
                                    for ft_arg_key2, ft_argument2 in generator_block.arguments.items():
                                        if ft_argument2[0].arg_dir == "IN" and ft_arg_key2 not in current_args_dict[func_temp_name] and ft_argument2[0].variable != "__PROTOCOL__":
                                            if not is_fuzzable(remove_ref_symbols(ft_argument2[0].arg_type), aliases, types, 0) :
                                                all_fuzzable = False
                                                break
                                    # If matching generator is found, add it to the matching_generators dictionary
                                    if all_fuzzable:
                                        total_generators.add(func_name)
                                        matching_generators.setdefault(
                                            func_temp_name, []).append(func_name)
                                        generator_arg = Argument(
                                            ft_argument[0].arg_dir, ft_argument[0].arg_type, func_name, ft_argument[0].data_type, ft_argument[0].usage, "__GENERATOR_FUNCTION__")
                                        # current_args_dict[func_temp_name].append(ft_arg_key)
                                        all_includes.update(generator_block.includes)
                                        pre_processed_data[func_temp_name].arguments.setdefault(
                                            ft_arg_key, []).append(generator_arg)
                                elif ((remove_ref_symbols(argument[0].arg_type) == remove_ref_symbols(ft_argument[0].data_type) or remove_ref_symbols(argument[0].arg_type) in castings[remove_ref_symbols(ft_argument[0].data_type)])and #ft_arg_key not in current_args_dict[func_temp_name] and
                                        ft_argument[0].arg_dir == "IN" and func_name not in matching_generators.setdefault(func_temp_name, [])):
                                    # Add a check to make sure all of the input arguments are fuzzable
                                    all_fuzzable = True
                                    for ft_arg_key2, ft_argument2 in generator_block.arguments.items():
                                        if ft_argument2[0].arg_dir == "IN" and ft_arg_key2 not in current_args_dict[func_temp_name]and ft_argument2[0].variable != "__PROTOCOL__":
                                            if not is_fuzzable(remove_ref_symbols(ft_argument2[0].data_type), aliases, types, 0) :
                                                all_fuzzable = False
                                                break
                                    # If matching generator is found, add it to the matching_generators dictionary
                                    if all_fuzzable:
                                        total_generators.add(func_name)
                                        matching_generators.setdefault(
                                            func_temp_name, []).append(func_name)
                                        generator_arg = Argument(
                                            ft_argument[0].arg_dir, ft_argument[0].arg_type, func_name, ft_argument[0].data_type, ft_argument[0].usage, "__GENERATOR_FUNCTION__")
                                        # current_args_dict[func_temp_name].append(ft_arg_key)
                                        all_includes.update(generator_block.includes)
                                        pre_processed_data[func_temp_name].arguments.setdefault(
                                            ft_arg_key, []).append(generator_arg)
    return pre_processed_data


def write_to_file_output(data: Dict[str, List[FunctionBlock]], file_path: str):
    serializable_data = {}
    for function, function_blocks in data.items():
        serializable_data.setdefault(function, []).extend(
            [function_block.to_dict() for function_block in function_blocks])

    with open(file_path, 'w') as file:
        json.dump(serializable_data, file, indent=4)


def initialize_data(function_template: Dict[str, FunctionBlock]) -> Dict[str, FunctionBlock]:
    initial_data = {}
    current_args_dict.clear()
    for func, func_block in function_template.items():
        initial_data[func] = FunctionBlock(
            {}, func, func_block.service, {}, func_block.return_type)
    return initial_data

# Now add the output variables because we aren't trying to fuzz those necessarily


def add_output_variables(function_template: Dict[str, FunctionBlock],
                         pre_processed_data: Dict[str, FunctionBlock]) -> Dict[str, FunctionBlock]:
    for function, function_block in function_template.items():
        for arg_key, argument in function_block.arguments.items():
            if (argument[0].arg_dir == "OUT" or argument[0].arg_dir == "IN_OUT") and (arg_key not in current_args_dict[function]):
                pre_processed_data[function].arguments.setdefault(
                    arg_key, []).append(argument[0])
                current_args_dict[function].append(arg_key)

    return pre_processed_data


def handle_optional_arguments(pre_processed_data: Dict[str, FunctionBlock]) -> Dict[str, FunctionBlock]:
    for function, function_block in pre_processed_data.items():
        for arg_key, argument in function_block.arguments.items():
            if len(argument) == 0:
                pre_processed_data[function].arguments[arg_key].append(Argument("OPTIONAL", "VOID *", "NULL", "VOID *", "NULL", "__OPTIONAL__"))

    return pre_processed_data

def collect_all_function_arguments(input_data: Dict[str, List[FunctionBlock]],
                                   function_template: Dict[str, FunctionBlock],
                                   types: Dict[str, TypeInfo],
                                   input_generators: Dict[str, FunctionBlock],
                                   aliases: Dict[str, str],
                                   macros: Dict[str, Macros],
                                   enums: Dict[str, List[str]],
                                   casts: Dict[str, List[str]],
                                   random: bool,
                                   harness_functions: Dict[str, List[Tuple[str, str]]]) -> Tuple[Dict[str, FunctionBlock], Dict[str, str], set, set]:
    # Collect all of the arguments to be passed to the template
    pre_processed_data = initialize_data(function_template)
    pre_processed_data = get_intersect(input_data, pre_processed_data)
    matched_macros = {}

    if not random:
        # Step 1: Collect the constant arguments
        pre_processed_data, matched_macros, protocol_guids, driver_guids = collect_known_constants(
            input_data, pre_processed_data, macros, aliases, types, enums)
        print(f'INFO: Collecting known constants complete!!')
    else:
        protocol_guids = set()
        driver_guids = set()

    # Step 2: Collect the fuzzable arguments
    pre_processed_data = get_directly_fuzzable(
        input_data, pre_processed_data, aliases, macros, random)
    print(f'INFO: Collecting directly fuzzable arguments complete!!')

    if not random:
        # Step 3: collect the generator functions
        pre_processed_data = get_generators(
            pre_processed_data, input_generators, input_data, aliases, casts, types)
        print(f'INFO: Collecting generator functions complete!!')

    # Step 4: Collect the fuzzable structs
    pre_processed_data = variable_fuzzable(
        input_data, types, pre_processed_data, aliases, macros, random)
    print(f'INFO: Collecting fuzzable structs complete!!')

    # Step 5: Add the output variables
    pre_processed_data = add_output_variables(
        function_template, pre_processed_data)
    print(f'INFO: Adding output variables complete!!')

    pre_processed_data = handle_optional_arguments(pre_processed_data)  
    print(f'INFO: Handling optional arguments complete!!')          

    # If there are still arguments missing then extend the level for fuzzable structs
    # continue recursively until all arguments have at least one input

    # missing_arg = True
    # while missing_arg:
    #     missing_arg = False
    #     for function, function_block in pre_processed_data.items():
    #         if len(pre_processed_data[function].arguments) < len(function_template[function].arguments):
    #             pre_processed_data = variable_fuzzable(
    #                 input_data, types, pre_processed_data, aliases, random)
    #             missing_arg = True

    # Step 6: add the includes for constants/macro definitions
    for function, function_block in pre_processed_data.items():
        for arg_key, arguments in function_block.arguments.items():
            for arg in arguments:
                if arg.assignment in macros.keys():
                    function_block.includes.append(macros[arg.assignment].file)
                elif arg.usage in macros.keys():
                    function_block.includes.append(macros[arg.usage].file)

    # Step 6: Sort the arguments
    for key, function_block in pre_processed_data.items():
        sorted_arguments = {k: function_block.arguments[k] for k in sorted(
            function_block.arguments.keys())}
        function_block.arguments = sorted_arguments

    # add the protocol to Arg_0 usage
    for function, function_block in pre_processed_data.items():
        for arg_key, argument in function_block.arguments.items():
            if len(argument) > 0 and "protocol" in function_block.service.lower():
                for harness_group, functions in harness_functions.items():
                    if "protocol" in harness_group.lower():
                        for func, guid in functions:
                            if function in func:
                                argument[0].usage = guid
                                break
                break

    return pre_processed_data, matched_macros, protocol_guids, driver_guids


def initialize_generators(input_generators: Dict[str, List[FunctionBlock]]) -> Tuple[Dict[str, FunctionBlock], Dict[str, FunctionBlock]]:
    generators = {}
    generators_template = {}
    current_args_dict.clear()
    for function, function_blocks in input_generators.items():
        if function not in generators.keys():
            generators_template[function] = function_blocks[0]
            generators[function] = FunctionBlock(
                {}, function, function_blocks[0].service, {}, function_blocks[0].return_type)
        elif generators_template[function].service == "":
            generators_template[function].service = function_blocks[0].service
            generators[function].service = function_blocks[0].service
    return generators, generators_template


def remove_unreachable_functions(input_data: Dict[str, FunctionBlock], function_template: Dict[str, FunctionBlock], generator_input_template: Dict[str, Function]) -> Tuple[Dict[str, FunctionBlock], Dict[str, FunctionBlock]]:
    # for all of the generator functions, check if they are reachable from the global scope
    # reachable means that the function is either a protocol or from a library
    # if the function is not reachable then remove it from the input_data and the function_template

    # Step 1: Collect all of the reachable functions
    reachable_functions = set()
    for function, function_block in function_template.items():
        for arg_key, argument in function_block.arguments.items():
            if argument[0].variable == "__PROTOCOL__":
                if function in generator_input_template.keys():
                    if "protocol" in generator_input_template[function].file.lower():
                        reachable_functions.add(function)
                        break
        if function in generator_input_template.keys():
            if "library" in generator_input_template[function].file.lower():
                reachable_functions.add(function)
    
    # Step 2: Remove all of the unreachable functions
    for function in list(input_data.keys()):
        if function not in reachable_functions:
            del input_data[function]
            del function_template[function]
    
    return input_data, function_template

def is_cyclic(data_type: str, types: Dict[str, TypeInfo], aliases: Dict[str, str], macros: Dict[str, Macros], enums: Dict[str, List[str]]) -> bool:
    # check if the data_type is a scalar
    if is_fuzzable(data_type, aliases, types, 0):
        return False
    # check if the data_type is an enum
    # if is_enum(data_type, enums):
    #     return False
    # check if the data_type is a macro
    if data_type in macros.keys():
        return False
    # check if the data_type is a typedef
    if data_type in aliases.keys():
        return is_cyclic(aliases[data_type], types, aliases, macros, enums)
    # check if the data_type is a struct
    if data_type in types.keys():
        for field in types[data_type].fields:
            if data_type.lower() in field.type.lower():
                return True
    return False

def remove_cyclic_dependencies(input_data: Dict[str, FunctionBlock], 
                               function_template: Dict[str, FunctionBlock],
                               aliases: Dict[str, str],
                               macros: Dict[str, Macros],
                               enums: Dict[str, List[str]],
                               types: Dict[str, TypeInfo]) -> Tuple[Dict[str, FunctionBlock], Dict[str, FunctionBlock]]:
    # for all of the generator functions check if any of the arguments are cyclic
    # if the argument is cyclic then remove the function from the input_data and the function_template
    cyclic_functions = set()
    for function, function_block in input_data.items():
        for arg_key, argument in function_block.arguments.items():
            if "ARG_LIST" in argument[0].arg_type:
                print(f'ERROR: {function} has an argument that is an ARG_LIST!!')
                print(is_cyclic(remove_ref_symbols(argument[0].arg_type), types, aliases, macros, enums))
            if is_cyclic(remove_ref_symbols(argument[0].arg_type), types, aliases, macros, enums):
                cyclic_functions.add(function)

    for function in cyclic_functions:
        del input_data[function]
        del function_template[function]

    return input_data, function_template


def analyze_generators(input_generators: Dict[str, List[FunctionBlock]],
                       generator_input_template: Dict[str, Function],
                       input_template: Dict[str, FunctionBlock],
                       aliases: Dict[str, str],
                       macros: Dict[str, Macros],
                       enums: Dict[str, List[str]],
                       types: Dict[str, TypeInfo]) -> Tuple[Dict[str, List[FunctionBlock]], Dict[str, FunctionBlock], Dict[str, FunctionBlock]]:
    # just like for normal functions we want to determine the fuzzable arguments and fuzzable structs
    # for the generator functions
    output_template = input_template.copy()

    # Step 1: Collect the constant arguments
    # generators = collect_known_constants(generators, generators)
    generators, generators_tempalate = initialize_generators(input_generators)
    generators = get_intersect(input_generators, generators)
    generators, matched_macros, protocol_guids, driver_guids = collect_known_constants(
            input_generators, generators, macros, aliases, types, enums)

    # Step 2: Collect the fuzzable arguments
    generators = get_directly_fuzzable(input_generators, generators, aliases, macros, True)

    # Step 3: Collect the fuzzable structs
    generators = variable_fuzzable(
        input_generators, types, generators, aliases, macros, False)

    # Step 4: Add the output variables
    generators = add_output_variables(generators_tempalate, generators)
    generators = handle_optional_arguments(generators)  

    # Step 5: Sort the arguments
    for key, function_block in generators.items():
        sorted_arguments = {k: function_block.arguments[k] for k in sorted(
            function_block.arguments.keys())}
        function_block.arguments = sorted_arguments
    
    # Step 6: remove the generators that are missing arguments from both
    # the input_generators and the generators_template
    incomplete_generators = []
    for function, function_block in generators.items():
        for arg_key, argument in function_block.arguments.items():
            if len(argument) == 0:
                incomplete_generators.append(function)
                break

    for function in incomplete_generators:
        del generators[function]
        del input_generators[function]
        del generators_tempalate[function]

    # Step 7: Combine generators template with the function template
    for function, function_block in generators_tempalate.items():
        if function not in output_template.keys():
            output_template[function] = function_block

    # Step 8: Remove any generator functions that are unreachable from a global scope
    generators, output_template = remove_unreachable_functions(generators, output_template, generator_input_template)

    # Step 9: Remove any generator functions that have cyclic dependencies
    generators, output_template = remove_cyclic_dependencies(generators, output_template, aliases, macros, enums, types)

    return input_generators, generators, output_template

def sanity_check(processed_data: Dict[str, FunctionBlock], harness_functions: Dict[str, List[Tuple[str, str]]]):
    for _, input_functions in harness_functions.items():
        for function, _ in input_functions:
            if function not in processed_data.keys():
                print(f"WARNING: {function} was not able to be harnessed!!")

def cleanup_paths(includes):
    modified_includes = []
    for include in includes:
        if include.endswith(".c"):
            continue
        # Split the path into its components.
        components = include.split("/")
        # Remove the first 3 components.
        include = "/".join(components[-2:])
        if len(components) > 4 and "edk2-platforms" not in components[3].lower():
            if len(include.split("/")) == 2 and "include" in components[-3].lower():
                modified_includes.append(include)
    return modified_includes

def update_inc(includes: List[str], libmap: Dict[str, Dict[str, list]]) -> List[str]:
    for include in includes:
        match = False
        if "library" in include.lower():
            for lib in libmap.keys():
                if lib in include:
                    match = True
            if not match:
                includes.remove(include)
        if "ppi" in include.lower():
            includes.remove(include)
    return includes

def collect_all_lib_deps(libmap: Dict[str, Dict[str, List[str]]], lib: str, collected_deps: Set[str]) -> Set[str]:
    # Add the current library to the set of collected dependencies
    collected_deps.add(lib)
    
    # Iterate over the dependencies of the current library
    if lib in libmap.keys():
        for dep in libmap[lib]["dependencies"]:
            # If the dependency is not yet collected, recursively collect its dependencies
            if dep not in collected_deps:
                collect_all_lib_deps(libmap, dep, collected_deps)
    
    return collected_deps

def collect_all_deps_from_libmap(libraries: List[str], libmap: Dict[str, Dict[str, List[str]]]) -> Set[str]:
    all_libs = set()
    
    # Iterate through each library and collect all of its dependencies recursively
    for lib in libraries:
        for libdef in libmap.keys():
            if lib in libdef:
                all_libs.add(libdef)
                all_libs = collect_all_lib_deps(libmap, libdef, all_libs)
    
    return all_libs


# Function to perform topological sort on the graph
def topological_sort(graph: Dict[str, List[str]]):
    visited = set()
    temp_mark = set()
    sorted_files = []

    def visit(node):
        if node in visited:
            return
        if node in temp_mark:
            return

        temp_mark.add(node)

        for dep in graph.get(node, []):
            visit(dep)

        temp_mark.remove(node)
        visited.add(node)
        sorted_files.append(node)

    for node in graph:
        if node not in visited:
            visit(node)

    return sorted_files[::-1]

def cleanup_include_dep_paths(include_deps: Dict[str, List[str]]):
    modified_includes = dict()
    for include, deps in include_deps.items():
        if include.endswith(".c"):
            continue
        # Split the path into its components.
        components = include.split("/")
        # Remove the first 3 components.
        include = "/".join(components[-2:])
        if len(components) > 4 and "edk2-platforms" not in components[3].lower():
            if len(include.split("/")) == 2 and "include" in components[-3].lower():
                modified_includes[include] = cleanup_paths(deps)
    return modified_includes

# Function to ensure all dependencies are resolved in the correct order
def handle_include_deps(includes: List[str], include_deps: Dict[str, List[str]]) -> List[str]:
    # Cleanup the paths in the include dependencies
    include_deps = cleanup_include_dep_paths(include_deps)

    sorted_graph = topological_sort(include_deps)
    
    # Set to store files that are already included
    included = set()

    # Final ordered list of includes
    ordered_includes = []

    for file in sorted_graph:
        if file in includes and file not in included:
            ordered_includes.append(file)
            included.add(file)

    # reverse the list to ensure that the includes are in the correct order
    ordered_includes.reverse()

    return ordered_includes


def update_libs(libraries: List[str], libmap: Dict[str, Dict[str, list]]) -> Dict[str, str]:
    updated_libs = {}
    tmp_libs = collect_all_deps_from_libmap(libraries, libmap)
    for lib in tmp_libs:
        if lib in libmap.keys():
            updated_libs[lib] = libmap[lib]["path"]

    for lib in libraries:
        if "unittest" in lib.lower():
            del updated_libs[lib]

    return updated_libs

def collect_libraries(includes: List[str]) -> set[str]:
    libraries = set()
    for include in includes:
        lib = include.split("/")[-1]
        lib = lib[:-2]
        if 'Lib' in lib:
            libraries.add(lib)

    return libraries

def natural_sort_key(key):
    # Split the key into a prefix and a numeric suffix
    prefix, suffix = key.split("_", 1)
    return (prefix, int(suffix))

def analyze_data(macro_file: str,
                 enum_file: str,
                 generator_file: str,
                 input_file: str,
                 data_file: str,
                 types_file: str,
                 alias_file: str,
                 cast_file: str,
                 random: bool,
                 harness_folder: str,
                 best_guess: bool,
                 functions: str,
                 generator_decl: str,
                 edk2_dir: str,
                 include_deps_file: str) -> Tuple[Dict[str, FunctionBlock], Dict[str, FunctionBlock], Dict[str, FunctionBlock], Dict[str, List[FieldInfo]], List[str], Dict[str, str], Dict[str, str], Dict[str, str], set, set, Dict[str, List[str]], int]:

    macros_val, macros_name = load_macros(macro_file)
    global total_generators
    cast_map = load_castings(cast_file)
    enum_map = load_enums(enum_file)
    generators = load_generators(generator_file, macros_val)
    harness_functions = load_functions(input_file)
    libmap = load_libmap(edk2_dir, os.path.join('/'.join(data_file.split("/")[:-1]), 'libmap.json'))
    function_declares = load_function_declares(functions)
    generator_declares = load_generator_declares(generator_decl)
    include_deps = load_include_deps(include_deps_file)
    data, function_template = load_data(
        data_file, harness_functions, macros_val, random, best_guess, function_declares)
    types = load_types(types_file)
    aliases = load_aliases(alias_file)
    if not random:
        generators, processed_generators, template = analyze_generators(
            generators, generator_declares, function_template, aliases, macros_name, enum_map, types)
    else:
        processed_generators = {}
        template = function_template

    # These two are treated together because we want to use generators to handle any
    # input argument that isn't either directly fuzzable or of a known input
    # we will primarily use generators to handle the more compilicated structs
    # (i.e. more than one level of integrated structs) and the basic structs
    # that have all scalable fields will be directly generated with random input
    processed_data, matched_macros, protocol_guids, driver_guids = collect_all_function_arguments(
        data, function_template, types, processed_generators, aliases, macros_name, enum_map, cast_map, random, harness_functions)

    # all_includes = get_union(processed_data, processed_generators)
    update_includes = cleanup_paths(all_includes)
    # all_includes = get_union(processed_data, {})
    # all_includes = get_union({}, {})
    collected_includes = list(set(update_includes) | default_includes)
    collected_includes = update_inc(collected_includes, libmap)
    libraries = update_libs(list(collect_libraries(collected_includes) | default_libraries), libmap)
    collected_includes = handle_include_deps(collected_includes, include_deps)
    
    if not random:
        write_data(processed_generators,
                   f'{harness_folder}/processed_generators.json')
    write_data(processed_data, f'{harness_folder}/processed_data.json')

    sanity_check(processed_data, harness_functions)

    # sort the arguments for each function
    for _, function_block in processed_data.items():
        sorted_arguments = {k: function_block.arguments[k] for k in sorted(
            function_block.arguments.keys(), key=natural_sort_key)}
        function_block.arguments = sorted_arguments

    for _, functions in harness_functions.items():
        for _, protocol in functions:
            if protocol == "":
                continue
            protocol_guids.add(protocol)
    return processed_data, processed_generators, template, types, collected_includes, libraries, matched_macros, aliases, driver_guids, protocol_guids, enum_map, len(total_generators)
