import re
import os
import json
from itertools import permutations
from typing import List, Dict, Set
from common.types import FunctionBlock, FieldInfo, Macros, TypeInfo, scalable_params

def is_whitespace(s: str) -> bool:
    if s is None:
        return True
    return len(s.strip()) == 0

def remove_ref_symbols(type_str: str) -> str:
    return re.sub(r" *\*| *&", "", type_str)

def remove_prefix(type: str) -> str:
    return remove_ref_symbols(remove_casts(type))

def remove_quotes(string: str) -> str:
    if string is None:
        return None
    
    return string.replace("\"", "")

def clean_harnesses(clean: bool, dir: str) -> None:
    if clean:
        os.system(f'rm -rf {dir}/GeneratedHarnesses')

def write_sorted_data(sorted_data: Dict[str, Dict[int, List[FunctionBlock]]], filename: str) -> None:
    output_dict = {
        function: {
            arg_num: [function_block.to_dict()
                      for function_block in function_blocks]
            for arg_num, function_blocks in arg_num_pairs.items()
        }
        for function, arg_num_pairs in sorted_data.items()
    }

    with open(filename, 'w') as f:
        json.dump(output_dict, f, indent=4)

# write the template to a file
def write_template(template: Dict[str, FunctionBlock], filename: str) -> None:
    output_dict = {
        function: function_block.to_dict()
        for function, function_block in template.items()
    }

    with open(filename, 'w') as f:
        json.dump(output_dict, f, indent=4)

def add_indents(output: List[str], indent: bool) -> List[str]:
    if not indent:
        return output
    
    indented_output = []
    for line in output:
        indented_output.append(f"    {line}")
    return indented_output

def gen_file(filename: str, output: List[str]):
    with open(filename, 'w') as f:
        f.writelines([line + '\n' for line in output])

def write_data(filtered_args_dict: Dict[str, FunctionBlock], filename: str) -> None:
    output_dict = [function_block.to_dict()
                   for function_block in filtered_args_dict.values()]

    with open(filename, 'w') as f:
        json.dump(output_dict, f, indent=4)

def compile(harness_folder: str):
    os.system(f'clang -w -g -o {harness_folder}/firness_decoder {harness_folder}/FirnessMain_std.c {harness_folder}/FirnessHarnesses_std.c')

#
# This function will ignore the cast statements in the argument usage
#
def ignore_cast(usage: str) -> str:
    return re.sub(r"\(.*?\)", "", usage)

def remove_casts(input_string: str, 
                 aliases: Dict[str, str]) -> str:
    # Define a regular expression pattern to match casts within parentheses
    pattern = r'\(([^()]+)\)'

    # Define a function to replace matched casts with their content
    def replace_cast(match):
        cast_contents = match.group(1)
        check_list = scalable_params
        check_list.extend([alias.lower() for alias in aliases.keys()])
        contains_cast = any(cast in cast_contents.lower() for cast in check_list)
        if contains_cast:
            return ''
        if ' ' in cast_contents:
            return cast_contents
        return ''

    # Use re.sub() to replace the matched casts with their content
    result = re.sub(pattern, replace_cast, input_string)

    # Remove any remaining parentheses
    result = result.replace('(', '').replace(')', '')

    return result

#
# This function will return a set of all of the stripped usage values
# only handles conditional statements taht are separated by a pipe
#
def get_stripped_usage(usage: str, 
                       macros: Dict[str, Macros],
                       aliases: Dict[str, str]) -> Set[str]:
    usages = set()

    tmp = []
    for usage_value in usage.split("|"):
        tmp.append(remove_casts(usage_value.strip(), aliases))
    # loop through the tmp list and add all of the orderings of the values
    # example: if the usage is "a|b|c" then add "a|b|c", "b|a|c", "c|a|b", etc.
    permutations_list = list(permutations(tmp))

    # Convert each permutation tuple back to a list of strings
    ordered_strings = ['|'.join(perm) for perm in permutations_list]

    # Add all permutations mixed with the macro values to the set
    # Add the macro values to the set, incase the macro value is used in the conditional
    # EDK2 tends to redefine the same macro value in different files
    for permutation in permutations_list:
        permutation = list(permutation)
        for index, element in enumerate(permutation):
            if element in macros.keys():
                permutation[index] = re.sub(r'\s', '', remove_casts(macros[element].value, aliases))
                ordered_strings.append('|'.join(permutation))
    # Convert the list to a set
    usages.update(set(ordered_strings))

    return usages

def contains_usage(usage: str, 
                   current_usages: Set[str],
                   macros: Dict[str, Macros], 
                   aliases: Dict[str, str]) -> bool:
    usages = get_stripped_usage(remove_casts(usage, aliases), macros, aliases)
    for use in usages:
        if use in current_usages:
            return True
    return False

def contains_void_star(s):
    s_no_spaces = s.replace(" ", "").lower()
    return "void*" in s_no_spaces

# def contains_void_star(s: str,
#                        aliases: Dict[str, str]):
#     s_no_spaces = s.replace(" ", "").lower()
#     return "void*" in s_no_spaces or "void*" in aliases.get(remove_ref_symbols(s), "").replace(" ", "").lower()

def is_fuzzable(type: str,
                aliases: Dict[str, str],
                typemap: Dict[str, TypeInfo],
                level: int) -> bool:
    if level > 2:
        return False
    elif any(param.lower() in type.lower() for param in scalable_params):
        return True  # If the type is a scalar, then it is fuzzable
    elif type in aliases.keys():
        # If the type is an alias, then check the alias
        return is_fuzzable(aliases[type], aliases, typemap, level)
    elif type in typemap.keys():
        fuzzable = False
        for field_info in typemap[type].fields:
            # If any of the fields are scalars, then the type is fuzzable
            # one level deep
            if is_fuzzable(field_info.type, aliases, typemap, level + 1):
                fuzzable = True
            else:
                fuzzable = False
                break
        return fuzzable

    return False

def print_function_block(function_block: FunctionBlock) -> None:
    print('----------------------------------------------')
    print('Function Block:')
    print(f'\tService: {function_block.service}')
    print(f'\tFunction: {function_block.function}')
    print(f'\tReturn Type: {function_block.return_type}')
    for arg_num, arg_list in function_block.arguments.items():
        print(f'\t{arg_num}: ')
        for arg in arg_list:
            print(f'\t\tArg Dir: {arg.arg_dir}')
            print(f'\t\tArg Type: {arg.arg_type}')
            print(f'\t\tAssignment: {arg.assignment}')
            print(f'\t\tData Type: {arg.data_type}')
            print(f'\t\tUsage: {arg.usage}')
            print(f'\t\tPointer Count: {arg.pointer_count}')
            print(f'\t\tPotential Values: {arg.potential_outputs}')
            print(f'\t\tVariable: {arg.variable}')
    print('----------------------------------------------')

#
# Get the intersect between all of the includes for each function of the same name
#
def get_intersect(input_data: Dict[str, List[FunctionBlock]],
                  pre_processed_data: Dict[str, FunctionBlock]) -> Dict[str, FunctionBlock]:
    for function, function_blocks in input_data.items():
        for function_block in function_blocks:
            if len(pre_processed_data[function].includes) == 0:
                pre_processed_data[function].includes = function_block.includes
            else:
                pre_processed_data[function].includes = list(
                    set(pre_processed_data[function].includes) & set(function_block.includes))
    return pre_processed_data


#
# Get the union between all of the includes between all functions
#
def get_union(pre_processed_data: Dict[str, FunctionBlock],
              processed_generators: Dict[str, FunctionBlock]) -> List[str]:
    union = []
    for function, function_block in pre_processed_data.items():
        if function_block.includes is not None:
            union = list(set(union) | set(function_block.includes))
    for function, function_block in processed_generators.items():
        if function_block.includes is not None:
            union = list(set(union) | set(function_block.includes))
    return union