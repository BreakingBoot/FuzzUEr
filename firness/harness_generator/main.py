from typing import Dict, List
import argparse
import os
import uuid
import json
from datetime import datetime
from common.types import FunctionBlock, FieldInfo, EnumDef, scalable_params
from common.utils import clean_harnesses, gen_file, compile
from data_analysis.analyze import analyze_data
import path_trace.header_template as tracer_header
import path_trace.harnesses_template as tracer_harnesses
import path_trace.main_template as tracer_main
import uefi_harness.harnesses_template as uefi_harnesses
import uefi_harness.main_template as uefi_main
import uefi_harness.inf_template as uefi_inf
import uefi_harness.dsc_template as uefi_dsc
import uefi_harness.headers_template as uefi_header

def generate_main_std(function_dict: Dict[str, FunctionBlock], harness_folder):
    code = tracer_main.gen_firness_main(function_dict)
    gen_file(f'{harness_folder}/FirnessMain_std.c', code)


def generate_code_std(function_dict: Dict[str, FunctionBlock],
                      data_template: Dict[str, FunctionBlock],
                      types_dict: Dict[str, List[FieldInfo]],
                      generators_dict: Dict[str, FunctionBlock],
                      aliases: Dict[str, str],
                      harness_folder):
    code = tracer_harnesses.harness_generator(
        data_template, function_dict, types_dict, aliases, generators_dict)
    gen_file(f'{harness_folder}/FirnessHarnesses_std.c', code)


def generate_header_std(function_dict: Dict[str, FunctionBlock],
                        all_includes: List[str],
                        types: Dict[str, List[FieldInfo]],
                        aliases: Dict[str, str],
                        harness_folder):
    code = tracer_header.harness_header(all_includes, function_dict, types, aliases)
    gen_file(f'{harness_folder}/FirnessHarnesses_std.h', code)


def generate_harness_debugger(merged_data: Dict[str, FunctionBlock],
                              template: Dict[str, FunctionBlock],
                              types: Dict[str, List[FieldInfo]],
                              all_includes: List[str],
                              generators: Dict[str, FunctionBlock],
                              aliases: Dict[str, str],
                              harness_folder: str):

    generate_main_std(merged_data, harness_folder)
    generate_code_std(merged_data, template, types, generators, aliases, harness_folder)
    generate_header_std(merged_data, all_includes, types, aliases, harness_folder)
    compile(harness_folder)

def generate_main(function_dict: Dict[str, FunctionBlock], harness_folder):
    code = uefi_main.gen_firness_main(function_dict)
    gen_file(f'{harness_folder}/FirnessMain.c', code)


def generate_code(function_dict: Dict[str, FunctionBlock],
                  data_template: Dict[str, FunctionBlock],
                  types_dict: Dict[str, List[FieldInfo]],
                  generators_dict: Dict[str, FunctionBlock],
                  aliases: Dict[str, str],
                  harness_folder,
                  enums: Dict[str, List[str]],
                  random: bool = False):
    code = uefi_harnesses.harness_generator(
        data_template, function_dict, types_dict, generators_dict, aliases, enums, random)
    gen_file(f'{harness_folder}/FirnessHarnesses.c', code)


def generate_header(function_dict: Dict[str, FunctionBlock],
                    matched_macros: Dict[str, str],
                    harness_folder):
    code = uefi_header.harness_header(function_dict, matched_macros)
    gen_file(f'{harness_folder}/FirnessHarnesses.h', code)


def generate_inf(harness_folder: str, libraries: Dict[str, str], driver_guids: set = None, protocol_guids: set = None):
    code = uefi_inf.gen_firness_inf(uuid.uuid4(), driver_guids, protocol_guids, libraries)
    gen_file(f'{harness_folder}/FirnessHarnesses.inf', code)

def generate_dsc(harness_folder: str, libraries: Dict[str, str]):
    code = uefi_dsc.gen_firness_dsc(libraries)
    gen_file(f'{harness_folder}/Firness.dsc', code)

def generate_includes(all_includes: List[str], harness_folder: str):
    code = uefi_header.harness_includes(all_includes)
    gen_file(f'{harness_folder}/includes.txt', all_includes)
    gen_file(f'{harness_folder}/FirnessIncludes.h', code)


def generate_harness(merged_data: Dict[str, FunctionBlock],
                     template: Dict[str, FunctionBlock],
                     types: Dict[str, List[FieldInfo]],
                     enums: Dict[str, List[str]],
                     all_includes: List[str],
                     libraries: Dict[str, str],
                     generators: Dict[str, FunctionBlock],
                     aliases: Dict[str, str],
                     matched_macros: Dict[str, str],
                     protocol_guids: set,
                     driver_guids: set,
                     harness_folder: str,
                     output_dir: str,
                     random: bool = False):

    generate_main(merged_data, harness_folder)
    generate_code(merged_data, template, types, generators, aliases, harness_folder, enums, random)
    generate_header(merged_data, matched_macros, harness_folder)
    generate_includes(all_includes, harness_folder)
    generate_inf(harness_folder, libraries, protocol_guids, driver_guids)
    generate_dsc(harness_folder, libraries)
    # generate_harness_debugger(merged_data, template,
                            #   types, all_includes, generators, aliases, harness_folder)
    output_dir = os.path.join(output_dir, 'Firness')
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    os.system(f'cp {harness_folder}/* {output_dir}')

def generate_harness_folder(dir: str):
    # Define the outer directory name
    outer_dir = f'{dir}/GeneratedHarnesses'

    # Get the date and time in the formate MM_DD_YYYY_HH_MM
    now = datetime.now()
    time_str = now.strftime('%m_%d_%Y_%H_%M')

    # Define the inner directory name based on the current time
    inner_dir = f'Harness_{time_str}'

    # Combine the outer and inner directory names to get the full path
    full_path = os.path.join(outer_dir, inner_dir)

    # Check if the outer directory exists, if not create it
    if not os.path.exists(outer_dir):
        os.makedirs(outer_dir)

    # Create the inner directory (this will create it regardless of whether it already exists)
    os.makedirs(full_path, exist_ok=True)

    # Copy the FirnessHelper.h to the full path
    os.system(f'cp /workspace/HarnessHelpers/* {full_path}')

    # Return the full path of the inner directory
    return full_path

def calculate_statistics(merged_data: Dict[str, FunctionBlock],
                     generators: Dict[str, FunctionBlock],
                     aliases: Dict[str, str],
                     enums: Dict[str, EnumDef],
                     harness_folder: str,
                     total_generators: int):
    total_functions = len(merged_data)

    # collect total number of scalable types that aren't pointers
    total_scalable_types = 0
    total_pointer_types = 0
    total_struct_types = 0
    total_constants = 0
    enum_list = []
    for _, function_block in merged_data.items():
        for _, argument in function_block.arguments.items():
            is_scalable = any(param.lower() in argument[-1].arg_type.lower() or param.lower() in aliases.get(argument[-1].arg_type, "").lower() for param in scalable_params)
            if '*' not in argument[-1].arg_type and (is_scalable or "__FUZZABLE__" == argument[-1].variable):
                total_scalable_types += 1
            elif (is_scalable or "__FUZZABLE__" == argument[-1].variable):
                total_pointer_types += 1
            else:
                total_struct_types += 1
            for arg in argument:
                if "CONSTANT" in arg.variable and arg.arg_dir == "IN":
                    total_constants += 1
                elif "__ENUM_ARG__" in arg.variable and arg.arg_type not in enum_list:
                    total_constants += len(enums.get(arg.arg_type, EnumDef()).values)
                    enum_list.append(arg.arg_type)
    
    print(f"Total Functions: {total_functions}")
    print(f"Total Generators: {total_generators}")
    print(f"Total Scalable Types: {total_scalable_types}")
    print(f"Total Pointer Types: {total_pointer_types}")
    print(f"Total Struct Types: {total_struct_types}")
    print(f"Total Constants: {total_constants}")

    # output total stats to csv file
    with open(f'{harness_folder}/stats.csv', 'w') as file:
        file.write(f"Total Functions,{total_functions}\n")
        file.write(f"Total Generators,{total_generators}\n")
        file.write(f"Total Scalable Types,{total_scalable_types}\n")
        file.write(f"Total Pointer Types,{total_pointer_types}\n")
        file.write(f"Total Struct Types,{total_struct_types}\n")
        file.write(f"Total Constants,{total_constants}\n")



def main():
    parser = argparse.ArgumentParser(description='Process some data.')
    parser.add_argument('--edk2', dest='edk2', default='/workspace/tmp/edk2', help='Path to the edk2 directory (default: /workspace/tmp/edk2)')
    parser.add_argument('-d', '--data-file', dest='data_file', default='/output/tmp/call-database.json',
                        help='Path to the data file (default: /output/tmp/call-database.json)')
    parser.add_argument('-g', '--generator-file', dest='generator_file', default='/output/tmp/generator-database.json',
                        help='Path to the generator file (default: /output/tmp/generator-database.json)')
    parser.add_argument('-gd', '--generators', dest='generators', default='/output/tmp/generators.json',
                        help='Path to the generator file (default: /output/tmp/generators.json)')
    parser.add_argument('-in', '--includes-file', dest='includes_file', default='/output/tmp/includes.json',
                        help='Path to the includes file (default: /output/tmp/includes.json)')
    parser.add_argument('-t', '--types-file', dest='types_file', default='/output/tmp/types.json',
                        help='Path to the types file (default: /output/tmp/types.json)')
    parser.add_argument('-a', '--alias-file', dest='alias_file', default='/output/tmp/aliases.json',
                        help='Path to the typedef aliases file (default: /output/tmp/aliases.json)')
    parser.add_argument('-m', '--macro-file', dest='macro_file', default='/output/tmp/macros.json',
                        help='Path to the macros file (default: /output/tmp/macros.json)')
    parser.add_argument('-e', '--enum-file', dest='enum_file', default='/output/tmp/enums.json',
                        help='Path to the enums file (default: /output/tmp/enums.json)')
    parser.add_argument('-i', '--input-file', dest='input_file',
                        default='/input/input.txt', help='Path to the input file (default: /input/input.txt)')
    parser.add_argument('-f', '--function-file', dest='function_file',
                        default='/output/tmp/functions.json', help='Path to the function file (default: /output/tmp/functions.json)')
    parser.add_argument('-s', '--cast-file', dest='cast_file',
                        default='/output/tmp/cast-map.json', help='Path to the cast file (default: /output/tmp/cast-map.json)')
    parser.add_argument('-o', '--output', dest='output',
                        default='/output', help='Path to the output directory (default: /output)')
    parser.add_argument('-c', '--clean', dest='clean', action='store_true',
                        help='Clean the generator database (default: False)')
    parser.add_argument('-r', '--random', dest='random', action='store_true',
                        help='Use random input instead of structured input data (default: False)')
    parser.add_argument('-b', '--best-guess', dest='best_guess', action='store_true',
                        help='Choose the function match with the highest frequency even if it might not be the right one (default: False)')

    args = parser.parse_args()

    clean_harnesses(args.clean, args.output)
    harness_folder = generate_harness_folder(args.output)
    processed_data, processed_generators, template, types, all_includes, libraries, matched_macros, aliases, protocol_guids, driver_guids, enums, total_generators = analyze_data(args.macro_file, args.enum_file, args.generator_file, args.input_file,
                                                  args.data_file, args.types_file, args.alias_file, args.cast_file, args.random, harness_folder, args.best_guess, args.function_file, args.generators, args.edk2, args.includes_file)
    
    main_dir = os.path.dirname(os.path.abspath(args.data_file))
    calculate_statistics(processed_data, processed_generators, aliases, enums, main_dir, total_generators)

    generate_harness(processed_data, template, types, enums,
                     all_includes, libraries, processed_generators, aliases, matched_macros, protocol_guids, driver_guids, harness_folder, args.output, args.random)


if __name__ == '__main__':
    main()