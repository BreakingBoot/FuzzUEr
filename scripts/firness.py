import shutil
import sys
import subprocess
import csv
import os
import json
import time
import random
import signal
import re
import argparse
from collections import defaultdict
import matplotlib.pyplot as plt
from typing import List, Dict
import networkx as nx
import pydot
from tabulate import tabulate

fuzzer_process = None
final_output_dir = ""
fuzzing_dir = ""

# These four paths are also spelled out in Harness/fuzz.simics and
# Harness/qsp-uefi-custom.target.yml; if you change one, change them all.
BUILD_TARGET = 'DEBUG_CLANGSAN'
FIRMWARE_BUILD_DIR = f'/workspace/tmp/Build/SimicsOpenBoardPkg/BoardX58Ich10/{BUILD_TARGET}'
FIRMWARE_IMAGE = f'{FIRMWARE_BUILD_DIR}/FV/BOARDX58ICH10.fd'
FIRMWARE_MAP = f'{FIRMWARE_BUILD_DIR}/SimicsX58.map'
HARNESS_IMAGE = f'/workspace/tmp/edk2/Build/Firness/{BUILD_TARGET}/X64/Firness.efi'

class AsanError:
    def __init__(self, file, line, error_type = "", message = "", asan_msg = "", count = 1, phase = "boot"):
        self.file = file
        self.line = line
        self.error_type = error_type
        self.count = count
        self.message = message
        self.asan_msg = asan_msg
        # "boot" before the harness ran, "fuzz" after -- boot reports repeat every campaign
        self.phase = phase


def generate_includes(src):
    includes = []
    with open(os.path.join(src, 'includes.txt'), 'r') as f:
        includes = [line.strip() for line in f.readlines()]
    # randomize the includes
    random.shuffle(includes)

    output = []
    output.append("#ifndef __FIRNESS_INCLUDES__")
    output.append("#define __FIRNESS_INCLUDES__")

    output.append("")
    for include in includes:
        output.append(f"#include <{include}>")

    output.append("")
    output.append("#endif // __FIRNESS_INCLUDES__")
    gen_file(os.path.join(src, 'includes.txt'), includes)
    gen_file(os.path.join(src, 'FirnessIncludes.h'), output)

def gen_file(filename: str, output: List[str]):
    with open(filename, 'w') as f:
        f.writelines([line + '\n' for line in output])

# build the firmware. when capture_db is set the whole build runs under bear so the
# compilation database firness needs lands at {src}/compile_commands.json.
# this used to need scripts/build_bios2.py -- a 41KB copy of upstream build_bios.py whose
# only change was prefixing one command with "bear --". wrapping the outer script instead
# produces an identical database (1180 entries either way, measured) and nothing to rot.
def compile(src, capture_db=False):

    # Change directory to BaseTools and run make
    dir1 = os.path.join(src, 'edk2')
    test_cmd = f'cd {dir1} && make -C BaseTools clean && make -C BaseTools && export WORKSPACE=/workspace/tmp/edk2 && export EDK_TOOLS_PATH=/workspace/tmp/edk2/BaseTools && export CONF_PATH=/workspace/tmp/edk2/Conf && source edksetup.sh'
    process = subprocess.run(test_cmd, shell=True, executable='/bin/bash', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    log = process.stdout.decode('utf-8', errors='ignore')
    log += process.stderr.decode('utf-8', errors='ignore')
    # Change directory to Intel Platform and run build_bios.py
    dir2 = os.path.join(src, 'edk2-platforms', 'Silicon', 'Intel', 'Tools')
    dir3 = os.path.join(src, 'edk2-platforms', 'Platform', 'Intel')
    bear = f'bear --output {os.path.join(src, "compile_commands.json")} -- ' if capture_db else ''
    test_cmd2 = f'cd {dir1} && export CLANGSAN_BIN=/usr/bin/ && source edksetup.sh && cd {dir3} && python build_bios.py --cleanall && make -C {dir2} clean && {bear}python build_bios.py -p BoardX58Ich10 -t CLANGSAN'
    process = subprocess.run(test_cmd2, shell=True, executable='/bin/bash', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    log += process.stdout.decode('utf-8', errors='ignore')
    log += process.stderr.decode('utf-8', errors='ignore')
    return log


# Run bear on the entire simics code base to get the compilation database
def get_compilation_database(src, dst):
    # run the stock upstream build under bear
    log = compile(dst, capture_db=True)
    # there are a couple gcc commands that need to be removed from the compilation database
    # remove them
    compilation_db = os.path.join(dst, 'compile_commands.json')
    with open(compilation_db, 'r') as f:
        compile_commands = json.load(f)

    filtered_commands = [cmd for cmd in compile_commands if 'gcc' not in cmd['arguments'][0]]

    with open(compilation_db, 'w') as f:
        json.dump(filtered_commands, f, indent=2)
    print('++++ Generated Compilation Database ++++')
    return log


def compile2(src):
    # Change directory to BaseTools and run make
    test_cmd = f'cd /workspace/edk2 && make -C BaseTools clean && make -C BaseTools && export WORKSPACE=/workspace/tmp/ && export EDK_TOOLS_PATH=/workspace/edk2/BaseTools && export CONF_PATH=/workspace/edk2/Conf && source edksetup.sh && cd {src} && bear -- build -a X64 -t CLANGDWARF -p OvmfPkg/OvmfPkgX64.dsc'
    process = subprocess.run(test_cmd, shell=True, executable='/bin/bash', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    log = process.stdout.decode('utf-8', errors='ignore')
    log += process.stderr.decode('utf-8', errors='ignore')
    return log


# Run bear on the entire simics code base to get the compilation database
def get_compilation_database2(src, dst):
    # # run it
    os.system(f'cp -r {src}/BackupBase/* {dst}/BaseTools/')
    log = compile2(dst)
    # there are a couple gcc commands that need to be removed from the compilation database
    # remove them
    compilation_db = os.path.join(dst, 'compile_commands.json')
    with open(compilation_db, 'r') as f:
        compile_commands = json.load(f)

    filtered_commands = [cmd for cmd in compile_commands if 'gcc' not in cmd['arguments'][0]]

    with open(compilation_db, 'w') as f:
        json.dump(filtered_commands, f, indent=2)
    print('++++ Generated Compilation Database ++++')
    return log

def copy(src, dir, file, dst, is_file=True, override=False):
    src_path = os.path.join(src, file)
    dst_path = os.path.join(dir, dst, file)

    if os.path.exists(dst_path) and not override:
        print(f"File '{file}' already exists in '{dst}', skipping copy.")
        return

    if is_file:
        shutil.copy2(src_path, dst_path)
    else:
        shutil.copytree(src_path, dst_path)
    

def patch_already_applied(dir):
    # Check if a file indicating the patch has been applied exists
    return os.path.exists(os.path.join(dir, 'patch_applied'))

def asan_instrumetation(src, dir):
    # copy the source files to their corrsponding directories
    copy(src, dir, 'Asan.h', 'MdeModulePkg/Include/Library')
    copy(src, dir, 'AsanInfo.h', 'MdeModulePkg/Include/Guid')

    # copy the folders to their corresponding directories
    copy(src, dir, 'AsanLib', 'MdeModulePkg/Library/', False)
    copy(src, dir, 'AsanLibNull', 'MdeModulePkg/Library/', False)
    copy(src, dir, 'AsanRuntimeLib', 'MdeModulePkg/Library/', False)
    copy(src, dir, 'AsanMemoryLib', 'MdePkg/Library/', False)
    copy(src, dir, 'AsanMemoryLibRepStr', 'MdePkg/Library/', False)

    if patch_already_applied(dir):
        print('Patch has already been applied. Skipping patching.')
        print('++++ Instrumented Firmware ++++')
        return "Patch already applied"

    # apply the patch file in src to the entire dst dir.
    # --forward/--batch are needed because eval_source/edk2 already carries this patch,
    # and plain patch blocks on an interactive "Assume -R? [n]" prompt
    patch_path = os.path.join(src, 'asan.patch')
    patch_cmd = f'patch -p1 --forward --batch --binary -d {dir} < {patch_path}'
    process = subprocess.run(patch_cmd, shell=True, executable='/bin/bash', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    log = process.stdout.decode('utf-8', errors='ignore')
    log += process.stderr.decode('utf-8', errors='ignore')

    # patch exits 1 both for "already applied" (fine) and for rejected hunks (not fine)
    already_applied = 'Reversed (or previously applied) patch detected' in log
    rejected = '.rej' in log or 'FAILED at' in log
    if process.returncode != 0 and not already_applied:
        print(f'Error: failed to apply {patch_path} (exit {process.returncode})')
        print(log)
        return log
    if rejected:
        print(f'Warning: some hunks of {patch_path} were rejected; the firmware may '
              f'be only partially instrumented. See the .rej files under {dir}.')
    elif already_applied:
        print('Patch was already present in the source tree.')

    open(os.path.join(dir, 'patch_applied'), 'w').close()

    print('++++ Instrumented Firmware ++++')
    return log

# run the static analysis tool on the compilation database
def run_firness(edk_dir, output_dir, input_file, smi=False):
    cmd = 'firness -p ' + edk_dir +' -o ' + output_dir + ' -i ' + input_file 
    if smi:
        cmd += ' -smi '
    cmd += ' dummyfile'
    process = subprocess.run(cmd, shell=True, executable='/bin/bash', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    log = process.stdout.decode('utf-8', errors='ignore')
    log += process.stderr.decode('utf-8', errors='ignore')
    print('++++ Ran Static Analysis Tool ++++')
    return log


# inside the output dir, create one subdirectory for each input file in the input dir
# and run the static analysis tool on each of them
def eval_firness(edk2_dir, output_dir, input_dir, random):
    collected_stats = dict()
    min_time = 0
    max_time = 0
    runtimes = dict()
    total_files = len(os.listdir(input_dir))
    for i, file in enumerate(os.listdir(input_dir)):
        if os.path.isfile(os.path.join(input_dir, file)):
            new_dir = os.path.join(output_dir, os.path.basename(file).split('.')[0])
            if not os.path.exists(new_dir):
                os.mkdir(new_dir)
            start_time = time.time()
            result = run_firness(edk2_dir, new_dir, os.path.join(input_dir, file))
            print(f'\t++++ INFO: Finished running static analysis tool on {file} ++++')
            # get_total_edges(output_dir, os.path.join(input_dir, file), new_dir)
            # print(f'\t++++ INFO: Finished getting total edges for {file} ++++')
            result = generate_harness(edk2_dir, new_dir, os.path.join(input_dir, file), random)
            print(f'\t++++ INFO: Finished generating harness for {file} ++++')
            result += compile_harness(new_dir)
            print(f'\t++++ INFO: Finished compiling harness for {file} ++++')
            write_log(new_dir, result.split('\n'), 'log.txt')
            collected_stats[file] = collect_stats(new_dir)
            runtimes[file] = collect_runtime_stats((time.time() - start_time), new_dir, os.path.join(input_dir, file))
            print(f'Completed {i+1}/{total_files}', end='\r')
    #print stats 
    print_stats(collected_stats)

    with open(os.path.join(output_dir, 'runtimes.csv'), 'w') as file:
        for key, value in runtimes.items():
            line = f'{key},'
            for k, v in value.items():
                line += f'{v},'
            file.write(line + '\n')

    # write the collected stats to a file
    with open(os.path.join(output_dir, 'stats.csv'), 'w') as file:
        for key, value in collected_stats.items():
            line = f'{key},'
            for k, v in value.items():
                line += f'{v},'
            file.write(line + '\n')

def collect_runtime_stats(time, dir, input_file):
    functions = collect_functions(dir, input_file)
    stats = dict()
    stats['time'] = time
    stats['functions'] = len(functions)
    stats['lines'] = get_lines(dir)
    return stats

def get_lines(dir):
    # look for a folder called Firness in the dir
    # and get the number of lines in all .c and .h files
    lines = 0
    firness_dir = os.path.join(dir, 'Firness')
    if os.path.exists(firness_dir):
        for file in os.listdir(firness_dir):
            if file.endswith('.c') or file.endswith('.h'):
                with open(os.path.join(firness_dir, file), 'r') as f:
                    lines += len(f.readlines())
    return lines
        



def print_stats(stats):
    for key, value in stats.items():
        line = f'{key}: '
        for k, v in value.items():
            line += f'{v} '
        print(line)

def collect_stats(dir):
    stats = dict()
    # read in the csv file called stats.csv
    stats_file = os.path.join(dir, 'stats.csv')
    try:
        with open(stats_file, 'r') as file:
            data = file.readlines()
        for line in data:
            key, value = line.strip().split(',')
            stats[key] = value
    except FileNotFoundError:
        print('Error: stats.csv not found')
    return stats

def collect_callgraphs(src, dst):
    compilation_db_file = os.path.join(src, 'compile_commands.json')
    bitcode_dir = os.path.join(dst, 'bitcode')
    if not os.path.exists(bitcode_dir):
        os.mkdir(bitcode_dir)
    # Load compilation commands from compilation database
    with open(compilation_db_file, 'r') as f:
        compilation_db = json.load(f)
    # create a cfg directory
    cfg_dir = os.path.join(dst, 'cfg')
    if not os.path.exists(cfg_dir):
        os.mkdir(cfg_dir)
    os.chdir(cfg_dir)
    bitcode_dir = os.path.join(dst, 'bitcode')
    bitcode_cmd = ['-Xclang', '-disable-O0-optnone', '-S', '-emit-llvm']

    # Iterate over each compilation command
    for entry in compilation_db:
        command = entry['arguments']
        # get the output file name
        output_index = command.index('-o') + 1
        output_file = command[output_index]
        # get the base file name
        base_file = os.path.basename(output_file)
        new_output_file = os.path.join(bitcode_dir, base_file)
        cfg_cmd = ['opt', '-dot-cfg', new_output_file]
        command[output_index] = new_output_file

        command.extend(bitcode_cmd)
        # Execute the compilation command
        try:
            subprocess.run(' '.join(command), shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(' '.join(cfg_cmd), shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            print(f"Compilation failed with exit code {e.returncode}")

def generate_callgraph(src, dst):
    # make a {src}/callgraphs directory if it doesn't exist
    callgraphs_dir = os.path.join(dst, 'callgraphs')
    if not os.path.exists(callgraphs_dir):
        os.mkdir(callgraphs_dir)

    # compile the firmware to generate the call graphs
    collect_callgraphs(src, callgraphs_dir)
    combine_cfgs(callgraphs_dir)
    print('++++ Generated Callgraph ++++')

def get_all_functions(functions, out_dir):
    # I need to get all of the function aliases that are stored in
    # the function-aliases.json file
    function_aliases_file = os.path.join(out_dir, 'function-aliases.json')
    with open(function_aliases_file, 'r') as file:
        data = json.load(file)
    if not data:
        return functions
    function_aliases = {item["Function"]: item["Aliases"] for item in data}

    all_functions = set()
    for function in functions:
        if function in function_aliases.keys():
            all_functions.add(function)
            for function2 in function_aliases[function]:
                all_functions.add(function2)
    return all_functions

def collect_functions(out_dir, input_file):
    with open(input_file, 'r') as file:
        data = file.readlines()
    functions = set()
    for line in data:
        if line.strip() != "":
            if not line.strip().startswith("//") and not line.strip().startswith("["):
                if ':' in line:
                    functions.add(line.split(':')[1].strip())
                else:
                    functions.add(line.strip())
    # functions = get_all_functions(functions, out_dir)
    return functions


def get_total_edges(src, input_file, output_dir):
    callgraphs_dir = os.path.join(src, 'callgraphs')
    edge_dir = os.path.join(output_dir, 'function_edges')
    if not os.path.exists(edge_dir):
        os.mkdir(edge_dir)
    functions = collect_functions(output_dir, input_file)
    counter = 1
    total_edges = 0
    for function in functions:
        subgraph_edges = search_callgraph(output_dir, function, callgraphs_dir)
        print(f'++++ Completed: {function} - {counter}/{len(functions)} ++++', end='\r')
        # save the subgraph edges to a file called .{function}_edges.txt
        with open(os.path.join(edge_dir, f'.{function}_edges.txt'), 'w') as file:
            file.write(str(subgraph_edges))
        counter += 1
        total_edges += subgraph_edges
    
    # write the total number of edges to a file
    with open(os.path.join(output_dir, 'total_edges.txt'), 'w') as file:
        file.write(str(total_edges))
    print(f'++++ Total edges in firmware callgraph: {total_edges} ++++')
    return total_edges

def search_callgraph(src, function, callgraphs_dir):
    # make a {src}/callgraphs directory if it doesn't exist
    firmware_callgraph = os.path.join(src, 'call-graph.dot')
    function_edge_file = os.path.join(callgraphs_dir, 'call-graph.dot.json')
    callgraph = nx.drawing.nx_pydot.read_dot(firmware_callgraph)
    with open(function_edge_file, 'r') as file:
        function_edge_map = json.load(file)
    
    # search for the function in the callgraph and make a new subgraph with function as root
    subgraph = nx.DiGraph()
    for node in callgraph.nodes():
        if function in node:
            subgraph.add_node(node)
            get_subgraph(callgraph, subgraph, node)
            break
    
    # write the subgraph to a .dot file
    subgraphs = os.path.join(src, 'subpgraphs')
    if not os.path.exists(subgraphs):
        os.mkdir(subgraphs)

    total_edges = sum(function_edge_map.get(node, {'edges': 0}).get('edges', 0) for node in subgraph.nodes())
    total_edges += subgraph.number_of_edges()
    nx.drawing.nx_pydot.write_dot(subgraph, os.path.join(subgraphs, f'{function}.dot'))
    return total_edges

def get_subgraph(callgraph, subgraph, node):
    neighbors = list(callgraph.neighbors(node))
    if not neighbors:
        # do a fuzzy search for the node
        for n in callgraph.nodes():
            n_neighbors = list(callgraph.neighbors(n))
            if node.lower() in n.lower() and node.lower() != n.lower() and n_neighbors and n not in subgraph.nodes():
                subgraph.add_edge(node, n)
                node = n

                break
    for neighbor in callgraph.neighbors(node):
        if neighbor not in subgraph.nodes():
            subgraph.add_node(neighbor)
            subgraph.add_edge(node, neighbor)
            get_subgraph(callgraph, subgraph, neighbor)

def convert_cfg_to_callgraph(cfg_file, function_edge_map):
    with open(cfg_file, 'r') as file:
        dot_data = file.read()

    # Parse the .dot data
    cfg_graph = pydot.graph_from_dot_data(dot_data)[0]
    function_node = os.path.basename(cfg_file).split('.')[1]
    
    num_edges = len(list(cfg_graph.get_edges()))
    function_edge_map[function_node] = {'edges': num_edges}

    return function_edge_map

def get_function_calls(node_label):
    function_calls = []
    get_call = re.findall(r'call (\S+)?(\s+)?void (%|@)([^,(]+)', node_label)
    for call in get_call:
        # if the call[-1] is an int then it is a function pointer
        if not call[-1].isdigit():
            function_calls.append(call[-1])
        else:
            pattern = r'%s = load void(.*?)%%([^,]+)' % str(call[-1])
            get_function_ptr = re.findall(pattern, node_label)
            if get_function_ptr:
                function_calls.append(get_function_ptr[0][-1])
    return function_calls

def combine_cfgs(src):
    # create a cfg directory
    cfg_callgraph = os.path.join(src, 'call-graph.dot')
    cfg_dir = os.path.join(src, 'cfg')

    cfg_files = [os.path.join(cfg_dir, file) for file in os.listdir(cfg_dir) if file.endswith('.dot')]
    function_edge_map = defaultdict(list)
    counter = 1
    for cfg_file in cfg_files:        
        function_edge_map = convert_cfg_to_callgraph(cfg_file, function_edge_map)
        print(f' +++  {counter}:{len(cfg_files)}  +++', end='\r')
        counter += 1
    
    with open(f'{cfg_callgraph}.json', 'w') as file:
        json.dump(function_edge_map, file)

# generate the harness for fuzzing with the results from the static analysis tool
def generate_harness(src, output_dir, input_file, random: bool = False, smi: bool = False,
                     backend: str = 'tsffs', max_steps: int = 0):
    dst = output_dir
    edk2_dir = os.path.join(src, 'edk2')
    # all of the paths to the static analysis results are fixed
    # so we can hard code them
    generate_cmd = f'python3 /workspace/harness_generator/main.py -d {output_dir}/call-database.json -g {output_dir}/generator-database.json -gd {output_dir}/generators.json -t {output_dir}/types.json -a {output_dir}/aliases.json -m {output_dir}/macros.json -e {output_dir}/enums.json -i {input_file} -s {output_dir}/cast-map.json -in {output_dir}/includes.json -f {output_dir}/functions.json --edk2 {edk2_dir} -o {dst}'
    if smi:
        generate_cmd += f' --smi -sm {output_dir}/smi-function-guid-map.json'
    if random:
        generate_cmd += ' -r'
    # the harness compiles against whichever fuzzer it will run under
    if backend and backend != 'tsffs':
        generate_cmd += f' --backend {backend}'
    if max_steps:
        generate_cmd += f' --max-steps {max_steps}'
    process = subprocess.run(generate_cmd, shell=True, executable='/bin/bash', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    log = process.stdout.decode('utf-8', errors='ignore')
    log += process.stderr.decode('utf-8', errors='ignore')
    print(process.stdout.decode('utf-8', errors='ignore'))
    print(process.stderr.decode('utf-8', errors='ignore'))
    # copy the generated harness to the output directory
    # take into account if the dst directory already exists
    if os.path.exists(os.path.join(edk2_dir, 'Firness')):
        shutil.rmtree(os.path.join(edk2_dir, 'Firness'))
    relocate_cmd = f'cp -r {dst}/Firness {edk2_dir}'
    process = subprocess.run(relocate_cmd, shell=True, executable='/bin/bash', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    log += process.stdout.decode('utf-8', errors='ignore')
    log += process.stderr.decode('utf-8', errors='ignore')
    print('++++ Generated Harness ++++')
    return log

# compile the harness
def compile_harness(src, count=0):
    dir1 = os.path.join(src, 'edk2')
    test_cmd = f'cd {dir1} && make -C BaseTools clean && make -C BaseTools && export WORKSPACE=/workspace/tmp/edk2 && export EDK_TOOLS_PATH=/workspace/tmp/edk2/BaseTools && export CONF_PATH=/workspace/tmp/edk2/Conf && export CLANGSAN_BIN=/usr/bin/ && source edksetup.sh && build -a X64 -b DEBUG -p Firness/Firness.dsc -t CLANGSAN'
    process = subprocess.run(test_cmd, shell=True, executable='/bin/bash', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    log = process.stdout.decode('utf-8', errors='ignore')
    log += process.stderr.decode('utf-8', errors='ignore')
    if process.returncode != 0:
        # generate_includes(os.path.join(dir1, 'Firness'))
        # if count < 5:
        #     compile_harness(src, count + 1)
        # else:
        #     exit(1)
        print('Error: Harness compilation failed')
    else:
        print('++++ Compiled Harness ++++')
    return log

# compile the firmware
def compile_firmware(src):
    log = compile(src)
    print('++++ Compiled Firmware ++++')
    return log


# Fuzzing without generating first reuses whatever Firness.efi is in the build tree. That
# harness targets whichever protocol was generated last, so a campaign can run to completion
# and report coverage for a protocol it never actually fuzzed. Compare the built harness
# against the request file that is supposed to have produced it.
def warn_if_harness_is_stale(input_file):
    harness = HARNESS_IMAGE
    if not os.path.isfile(harness) or not os.path.isfile(input_file):
        return False
    if os.path.getmtime(harness) >= os.path.getmtime(input_file):
        return False
    print(f'Warning: {harness} is older than {input_file}. It was built for a different '
          f'protocol, and -f on its own does not rebuild it -- pass -g as well, seeding '
          f'firness_output/ with that protocol\'s analysis, or the coverage below belongs '
          f'to the previously generated harness.')
    return True


# The fuzzing path reuses whatever BOARDX58ICH10.fd is already in the build tree. That is
# usually what you want -- the firmware build takes the better part of an hour -- but it
# silently fuzzes a binary older than the sanitizer sources, which is how a whole campaign
# can run without the ASan changes it was meant to exercise.
def warn_if_firmware_is_stale(src):
    firmware = FIRMWARE_IMAGE
    if not os.path.isfile(firmware):
        return False
    built = os.path.getmtime(firmware)
    newer = []
    for library in ('MdeModulePkg/Library/AsanLib',
                    'MdePkg/Library/AsanMemoryLib',
                    'MdePkg/Library/AsanMemoryLibRepStr'):
        directory = os.path.join(src, 'edk2', library)
        if not os.path.isdir(directory):
            continue
        for name in os.listdir(directory):
            path = os.path.join(directory, name)
            if os.path.isfile(path) and os.path.getmtime(path) > built:
                newer.append(f'{library}/{name}')
    if newer:
        print(f'WARNING: {firmware} predates {len(newer)} sanitizer source file(s); '
              f'the run will not exercise them.')
        for name in sorted(newer)[:5]:
            print(f'         {name}')
        print('         Rebuild the firmware first (build_bios.py -p BoardX58Ich10 '
              '-t CLANGSAN) to pick them up.')
    return bool(newer)


# block until tsffs has actually reached HARNESS_START. the magic start instruction
# kicks off the fuzzer thread, which creates corpus/ and solutions/ and makes
# save_initial_snapshot() append the first record to log.json. all three default to
# "%simics%/..." which resolves to simics_dir, so their appearance means the harness
# was reached. returns False on timeout or if simics exits early
def wait_for_fuzzing_start(simics_dir, process, deadline_s, stale_dirs):
    log_path = os.path.join(simics_dir, 'log.json')
    corpus_dir = os.path.join(simics_dir, 'corpus')
    solutions_dir = os.path.join(simics_dir, 'solutions')
    start = time.time()
    while time.time() - start < deadline_s:
        if process.poll() is not None:
            print(f'\nError: simics exited (status {process.returncode}) before the harness '
                  f'was reached. See {simics_dir}/fuzz.txt for how far the boot got.')
            return False
        try:
            log_started = os.path.getsize(log_path) > 0
        except OSError:
            log_started = False
        fresh_dir = any(os.path.isdir(d) and d not in stale_dirs
                        for d in (corpus_dir, solutions_dir))
        if log_started or fresh_dir:
            print(f'\n++++ Harness reached after {int(time.time() - start)}s of boot ++++')
            return True
        print(f'Booting to the harness: {int(time.time() - start)}s ', end='\r')
        time.sleep(2)
    print(f'\nError: the harness was never reached within {deadline_s}s, so ZERO fuzzing '
          f'iterations ran. Re-run with a larger --boot-timeout and check '
          f'{simics_dir}/fuzz.txt for how far the boot got.')
    return False


# tsffs.timeout is simulated seconds per iteration. Under emulation a timed-out iteration
# costs far more wall clock than a completed one, and some protocols time out on most of
# their inputs -- EfiShell spent 41 of 62 iterations timing out -- so this is worth tuning
# per campaign rather than leaving at the value baked into fuzz.simics.
# Every campaign started from random inputs and threw away the corpus the previous run had
# evolved -- about 144 inputs per protocol, 20,000 across the matrix. Seeding from the last
# run lets coverage compound across campaigns instead of restarting from nothing each time.
def seed_corpus(simics_dir, seed_dir):
    if not seed_dir or not os.path.isdir(seed_dir):
        return 0
    target = os.path.join(simics_dir, 'corpus')
    os.makedirs(target, exist_ok=True)
    copied = 0
    for name in sorted(os.listdir(seed_dir)):
        if name.startswith('.'):
            continue
        source = os.path.join(seed_dir, name)
        if os.path.isfile(source):
            try:
                shutil.copy2(source, os.path.join(target, name))
                copied += 1
            except OSError:
                continue
    if copied:
        print(f'Seeded the corpus with {copied} input(s) from {seed_dir}')
    return copied


def set_iteration_timeout(simics_dir, seconds):
    if not seconds:
        return
    script = os.path.join(simics_dir, 'fuzz.simics')
    if not os.path.isfile(script):
        return
    with open(script) as handle:
        text = handle.read()
    updated = re.sub(r'@tsffs\.timeout\s*=\s*[0-9.]+',
                     f'@tsffs.timeout = {seconds}', text)
    if updated != text:
        with open(script, 'w') as handle:
            handle.write(updated)
        print(f'Set the per-iteration timeout to {seconds}s of simulated time')


def run_fuzzer(simics_dir, timeout, output_dir, boot_timeout=2700, iteration_timeout=None,
               seed_dir=None):
    global fuzzer_process
    set_iteration_timeout(simics_dir, iteration_timeout)
    seed_corpus(simics_dir, seed_dir)
    log_path = os.path.join(simics_dir, 'log.json')
    corpus_dir = os.path.join(simics_dir, 'corpus')
    solutions_dir = os.path.join(simics_dir, 'solutions')
    # tsffs appends to log.json, so a stale file would look like an instant start.
    # corpus/ and solutions/ are never truncated, so remember which already existed
    open(log_path, 'w').close()
    stale_dirs = {d for d in (corpus_dir, solutions_dir) if os.path.isdir(d)}

    signal.signal(signal.SIGINT, generate_report2)
    warn_if_firmware_is_stale(os.path.join(os.getcwd(), 'tmp'))
    # spawn the fuzzer in a subprocess
    cmd = f"./simics -no-win -no-gui fuzz.simics"
    fuzzer_process  = subprocess.Popen(cmd, cwd=simics_dir, shell=True, executable='/bin/bash')

    # -t is a fuzzing budget, not a budget for the whole simics run. the instrumented
    # firmware has to boot, walk the boot menu, start the shell and pull Firness.efi
    # over the agent first; charging that to -t is why short runs reported no iterations
    print(f'Waiting up to {boot_timeout}s for the boot to reach the harness; the '
          f'{timeout if timeout is not None else 86400}s fuzzing budget starts after that.')
    started = wait_for_fuzzing_start(simics_dir, fuzzer_process, boot_timeout, stale_dirs)

    if timeout is None:
        timeout = 86400
    execution_time = 0
    exited_early = False
    while started and execution_time < timeout:
        # simics exiting means the budget cannot be spent, and sleeping out the rest only
        # holds the slot: a run that fuzzed for seconds was still occupying a worker for
        # the full budget
        if fuzzer_process.poll() is not None:
            exited_early = True
            print(f'\nFuzzer exited after {execution_time}s of its {timeout}s budget '
                  f'(rc={fuzzer_process.returncode}); see {simics_dir}/fuzz.txt')
            break
        hours, rem = divmod(execution_time, 3600)
        minutes, seconds = divmod(rem, 60)
        formatted_time = f'{int(hours)}hrs {int(minutes)}mins {int(seconds)}secs'
        print(f'Fuzzing time: {formatted_time}', end="\r")
        time.sleep(1)
        execution_time += 1

    if started and not exited_early:
        print(f'\nFuzzed for the full {timeout}s budget')

    fuzzer_process.kill()
    fuzzer_process.wait()
    os.system(f'cp {simics_dir}/log.json {output_dir}')
    # fuzz.simics writes the serial capture to fuzz.txt, not fuzz.log
    os.system(f'cp {simics_dir}/fuzz.txt {output_dir}')
    for d in ('corpus', 'solutions'):
        if os.path.isdir(os.path.join(simics_dir, d)):
            os.system(f'cp -r {simics_dir}/{d} {output_dir}')
    print('++++ Ran Fuzzer ++++' if started else '++++ Fuzzer never started ++++')
    return started


# replay one saved test case, defaulting to the first file in solutions/.
# tsffs ships no python trampolines in this build, so its fuzz.repro() interface is not
# reachable from a script; instead stage the test case in a corpus of its own and let
# reproduce.simics run a single iteration against it
def reproduce_crash(simics_dir, testcase=None):
    script = os.path.join(simics_dir, 'reproduce.simics')
    if not os.path.isfile(script):
        print(f'Error: {script} is missing. It is installed by the Dockerfile; '
              f'rebuild the image if you are on an older one.')
        return 1

    solutions = os.path.join(simics_dir, 'solutions')
    if not testcase:
        found = sorted(f for f in os.listdir(solutions) if not f.startswith('.')) \
            if os.path.isdir(solutions) else []
        if not found:
            print(f'Error: no test case given and {solutions} is empty. '
                  f'Pass --testcase <path>.')
            return 1
        testcase = os.path.join(solutions, found[0])
    if not os.path.isabs(testcase):
        testcase = os.path.join(simics_dir, testcase)
    if not os.path.isfile(testcase):
        print(f'Error: test case {testcase} does not exist')
        return 1

    # a corpus holding only this input, so the single iteration runs exactly it
    repro_dir = os.path.join(simics_dir, 'repro_corpus')
    if os.path.isdir(repro_dir):
        shutil.rmtree(repro_dir)
    os.mkdir(repro_dir)
    shutil.copy2(testcase, os.path.join(repro_dir, os.path.basename(testcase)))

    print(f'++++ Reproducing {testcase} ++++')
    cmd = './simics -no-win -no-gui -e \'$testcase_dir="repro_corpus"\' reproduce.simics'
    process = subprocess.run(cmd, cwd=simics_dir, executable='/bin/bash', shell=True)
    capture = os.path.join(simics_dir, 'reproduce.txt')
    if os.path.isfile(capture):
        collect_unique_crashes(capture, simics_dir)
    return process.returncode


def save_crashes_to_file(crashes, output_dir=None):
    crash_list = [['Phase', 'File', 'Line', 'Asan Msg', 'ErrorType', 'Message', 'Count']]
    # fuzzing findings first, boot reports are a fixed baseline
    ordered = sorted(crashes.values(), key=lambda c: (c.phase != 'fuzz', c.file, c.line))
    for crash in ordered:
        crash_list.append([crash.phase, crash.file, f'{crash.line}', crash.asan_msg,
                           crash.error_type, crash.message, f'{crash.count}'])
    path = os.path.join(output_dir, 'crashes.csv') if output_dir else 'crashes.csv'
    # csv.writer, not ",".join: a sanitizer message contains commas of its own, and joining
    # raw shifted every later column. One site then read back as several different rows,
    # so AtaBus.c:1380 counted seven times instead of once.
    with open(path, 'w', newline='') as out:
        writer = csv.writer(out)
        for row in crash_list:
            writer.writerow([str(c) for c in row])

    return crash_list

# parse the log file and collect statisitics on the run:
# file name, line number, and the number of times it crashed
# along with ErrorType and the asan error message.
# the firmware emits hundreds of reports before the harness ever runs, so split them
# on the line where DXE dispatches the harness image: everything before that is a boot
# baseline that repeats on every campaign, everything after is attributable to an input.
# uefi_asan produces two report shapes:
#   <path>, line:0x0D28, column:0x0027
#   ASAN MEMORY ACCESS check fail! __ubsan_handle_pointer_overflow is called:
# and
#   [ASan] ERROR: Invalid memory access: address 0x..., size 0x60, is_write 0x1, ip 0x...
#   bug_descr=unknown-crash in file: <path> at line: 0x3B
def collect_unique_crashes(log_file, output_dir=None):
    crashes = dict()
    phase = 'boot'

    def record(path, line_text, asan_msg, error_type='', message=''):
        path = path.strip()
        if not path:
            return
        try:
            line_no = int(line_text, 16)
        except (ValueError, TypeError):
            try:
                line_no = int(line_text)
            except (ValueError, TypeError):
                line_no = 0
        key = f'{phase}:{path}:{line_no}'
        existing = crashes.get(key)
        if existing is None:
            crashes[key] = AsanError(path, line_no, error_type, message, asan_msg, 1, phase)
        else:
            existing.count += 1

    with open(log_file, 'r', encoding='utf-8', errors='ignore') as handle:
        prev_line = ''
        for line in handle:
            # anything after DXE dispatches Firness.efi is attributable to an input
            if phase == 'boot' and 'EntryPoint=' in line and 'Firness.efi' in line:
                phase = 'fuzz'

            if 'ASAN MEMORY ACCESS check fail' in line and 'line:' in prev_line:
                parts = prev_line.split(',')
                path = parts[0]
                line_no = ''
                if len(parts) > 1 and ':' in parts[1]:
                    line_no = parts[1].split(':', 1)[1].strip()
                error_type = message = ''
                if len(parts) > 2 and 'ErrorType' in parts[2] and '=' in parts[2]:
                    body = parts[2].split('=', 1)[1]
                    bits = body.split(':', 1)
                    error_type = bits[0].strip()
                    message = bits[1].strip() if len(bits) > 1 else ''
                asan_msg = ''
                if '!' in line:
                    tail = line.split('!', 1)[1].strip().split(' ')
                    asan_msg = tail[0] if tail else ''
                record(path, line_no, asan_msg, error_type, message)

            elif line.startswith('bug_descr=') and ' in file: ' in line and ' at line: ' in line:
                descr = line.split('=', 1)[1].split(' in file: ', 1)[0].strip()
                rest = line.split(' in file: ', 1)[1]
                path, _, line_no = rest.partition(' at line: ')
                detail = ''
                if 'ERROR: Invalid memory access' in prev_line:
                    detail = prev_line.split('Invalid memory access:', 1)[1].strip()
                record(path, line_no.strip(), descr, 'asan', detail)

            prev_line = line

    crash_list = save_crashes_to_file(crashes, output_dir)
    boot = sum(c.count for c in crashes.values() if c.phase == 'boot')
    fuzz = sum(c.count for c in crashes.values() if c.phase == 'fuzz')
    n_fuzz = sum(1 for c in crashes.values() if c.phase == 'fuzz')
    print('++++ Collected Unique Crashes ++++')
    print(f'  boot baseline: {boot} report(s) at '
          f'{sum(1 for c in crashes.values() if c.phase == "boot")} site(s) -- not fuzzing findings')
    print(f'  fuzzing:       {fuzz} report(s) at {n_fuzz} site(s)')
    if len(crash_list) > 1:
        print(tabulate(crash_list, headers='firstrow', tablefmt='grid'))
    else:
        print('  (no sanitizer reports in the capture)')


def parse_time_to_seconds(time_str):
    parts = time_str.split('-')
    hours = int(parts[0].replace('h', ''))
    minutes = int(parts[1].replace('m', ''))
    seconds = int(parts[2].replace('s', ''))
    total_seconds = hours * 3600 + minutes * 60 + seconds
    return total_seconds

def parse_coverage_into(filename):
    coverage_per_time = defaultdict(list)
    map = set()
    with open(filename, 'r') as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except ValueError:
                # a run killed mid-write leaves a partial final line
                continue
            if 'Interesting' in data.keys():
                map |= set(data['Interesting']['message'].get('indices') or [])
            elif 'Message' in data.keys():
                text = data['Message'].get('message', '')
                if 'run time:' not in text:
                    continue
                timestamp = text.split(',')[0].split(' ')[-1]
                try:
                    coverage_per_time[parse_time_to_seconds(timestamp)] = len(map)
                except (ValueError, IndexError):
                    continue
    return coverage_per_time


def plot_coverage(coverage_per_time, filename):
    plt.plot(coverage_per_time.keys(), coverage_per_time.values())
    plt.title('Coverage over time')
    plt.xlabel('Time (s)')
    plt.ylabel('Number of edges covered')
    plt.savefig(filename)  

# save to a csv file
def save_coverage_to_file(coverage_per_time, filename):
    with open(filename, 'w') as file:
        for timestamp, num_edges in coverage_per_time.items():
            file.write(f"{timestamp},{num_edges}\n")

# generate the results report
def generate_report2(sig, frame):
    global fuzzer_process
    global final_output_dir
    global fuzzing_dir

    if fuzzer_process:
        fuzzer_process.terminate()
        fuzzer_process.wait()  # Wait for the process to terminate

    os.system(f'cp {fuzzing_dir}/log.json {final_output_dir}')
    os.system(f'cp {fuzzing_dir}/fuzz.txt {final_output_dir}')
    # analyze the results from the coverage log 
    # and from the cmd line output that contains the crash results
    log_file = os.path.join(fuzzing_dir, 'log.json')
    output_csv = os.path.join(final_output_dir, 'coverage.csv')
    output_plot = os.path.join(final_output_dir, 'coverage.png')
    coverage_per_time = parse_coverage_into(log_file)
    save_coverage_to_file(coverage_per_time, output_csv)
    plot_coverage(coverage_per_time, output_plot)
    collect_unique_crashes(os.path.join(fuzzing_dir, 'fuzz.txt'), final_output_dir)
    print('++++ Generated Report ++++')
    exit(0)

def generate_report(simics_dir, output_dir):
    # analyze the results from the coverage log 
    # and from the cmd line output that contains the crash results
    fuzz_log = os.path.join(simics_dir, 'fuzz.txt')
    os.system(f'cp {fuzz_log} {output_dir}')
    log_file = os.path.join(simics_dir, 'log.json')
    output_csv = os.path.join(output_dir, 'coverage.csv')
    output_plot = os.path.join(output_dir, 'coverage.png')
    coverage_per_time = parse_coverage_into(log_file)
    save_coverage_to_file(coverage_per_time, output_csv)
    plot_coverage(coverage_per_time, output_plot)
    # the timeout path needs the same crash triage the Ctrl+C path does
    collect_unique_crashes(fuzz_log, output_dir)

    print('++++ Generated Report ++++')

# make sure all of the source files are there
def sanity_check(dir):
    # make sure there is at least an input.txt file
    # and the edk2 directory
    if not os.path.exists(os.path.join(dir, 'edk2')):
        print('Error: edk2 directory not found')
        return False
    # check to see if there is the FSP, edk2-platforms, and edk2-non-osi dirs
    if not os.path.exists(os.path.join(dir, 'FSP')):
        print('Error: FSP directory not found')
    if not os.path.exists(os.path.join(dir, 'edk2-platforms')):
        print('Error: edk2-platforms directory not found')
    if not os.path.exists(os.path.join(dir, 'edk2-non-osi')):
        print('Error: edk2-non-osi directory not found')
    return True

def cleanup(src, tmp_dir, output):
    # move output to src
    os.system(f'cp -r {output} {src}')
    # os.system('reset')

def write_log(output, logs, filename='log.txt'):
    with open(os.path.join(output, filename), 'w') as f:
        for log in logs:
            f.write(log + '\n')

def run_eval(edk2_dir, input_dir, random):
    # create fresh output directory or clear existing one
    output_dir = os.path.join('/input', 'firness_eval')
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.mkdir(output_dir)
    # create fresh source directory or clear existing one
    src_dir = os.path.join(os.getcwd(), 'tmp')
    if os.path.exists(src_dir):
        shutil.rmtree(src_dir)
    os.mkdir(src_dir)
    # copy the source files to the tmp directory
    os.system(f'cp -r {edk2_dir}/* {src_dir}')

    # get compilation database
    get_compilation_database('/workspace/scripts', src_dir)
    # generate_callgraph(src_dir, output_dir)
    eval_firness(src_dir, output_dir, input_dir, random)

    print('++++ Finished Evaluation ++++')


def run_eval2(src):
    # iterate over all directories in the src directory
    # for dir in os.listdir(src):
    #     if os.path.isdir(os.path.join(src, dir)):
    # main = os.path.join(src, 'edk2')
    # get the only dir inside the path
    for edk in os.listdir(src):
        if os.path.isdir(os.path.join(src, edk)):
            edk2_dir = os.path.join(src, edk)
    # create fresh output directory or clear existing one
    print(f'++++ Starting Evaluation {edk2_dir} ++++')
    output_dir = os.path.join(src, 'firness_eval2')
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.mkdir(output_dir)
    
    # create fresh source directory or clear existing one
    src_dir = os.path.join(os.getcwd(), 'tmp')
    if os.path.exists(src_dir):
        shutil.rmtree(src_dir)
    os.mkdir(src_dir)
    # copy the source files to the tmp directory
    os.system(f'cp -r {edk2_dir}/* {src_dir}')
    # get compilation database
    get_compilation_database2('/workspace/', src_dir)
    # generate_callgraph(src_dir, output_dir)
    eval_firness(src_dir, output_dir, src, False)

    print(f'++++ Finished Evaluation {dir} ++++')


def main():
    global final_output_dir
    global fuzzing_dir
    parser = argparse.ArgumentParser(description='Firness')
    parser.add_argument('-i', '--input', type=str, help='Path to the input directory with the source files or input file for single run')
    parser.add_argument('-s', '--src', type=str, help='Path to the source directory with edk2 and input.txt')
    parser.add_argument('-a', '--analyze', action='store_true', help='Run the static analysis tool')
    parser.add_argument('-f', '--fuzz', action='store_true', help='Run the fuzzer')
    parser.add_argument('-r', '--random', action='store_true', help='randomize the input for the static analysis tool')
    # parser.add_argument('-r', '--reproduce', action='store_true', help='Reproduce a crash')
    parser.add_argument('-g', '--generate', action='store_true', help='Generate the harness')
    parser.add_argument('-t', '--timeout', type=int,
                        help='Fuzzing budget in seconds, counted from the moment the harness '
                             'is reached (not from simics startup)')
    parser.add_argument('--max-steps', type=int, default=0,
                        help='Calls chained per fuzzing iteration; lower it for protocols '
                             'whose calls are slow enough to starve the fuzzer')
    parser.add_argument('--seed-corpus', type=str, default='',
                        help='Directory of inputs to start the corpus from, usually the '
                             'corpus a previous campaign for this protocol produced')
    parser.add_argument('--iteration-timeout', type=float, default=None,
                        help='Simulated seconds allowed per fuzzing iteration before it '
                             'counts as a timeout (default: whatever fuzz.simics sets)')
    parser.add_argument('--boot-timeout', type=int, default=2700,
                        help='Seconds to wait for the instrumented firmware to boot and reach '
                             'HARNESS_START before giving up (default: 2700)')
    parser.add_argument('-e', '--eval', action='store_true', help='Evaluate the results of the static analysis tool')
    parser.add_argument('--smi', action='store_true', help='Run the SMI fuzzer')
    parser.add_argument('--backend', type=str, default='tsffs',
                        choices=['tsffs', 'qemu', 'nyx', 'none'],
                        help='Fuzzer the generated harness targets (default: tsffs)')
    parser.add_argument('--reproduce', action='store_true',
                        help='Replay a saved test case under reproduce.simics instead of fuzzing')
    parser.add_argument('--testcase', type=str,
                        help='Test case to replay with --reproduce (default: first file in solutions/)')
    args = parser.parse_args()
    complete_analysis = not args.analyze and not args.fuzz and not args.generate

    if args.eval:
        run_eval(args.src, args.input, args.random)
        return 0

    # replaying a saved test case needs neither the target list nor the source tree
    if args.reproduce:
        simics_dir = os.path.join(os.getcwd(), 'projects', 'example')
        fuzzing_dir = simics_dir
        return reproduce_crash(simics_dir, args.testcase)

    if not args.src:
        print('Error: -s/--src is required. Pass the directory that CONTAINS edk2, '
              'edk2-platforms, edk2-non-osi and FSP (e.g. -s /input), not edk2 itself.')
        return 2
    if not args.input:
        print('Error: -i/--input is required (the [Protocols] target file, e.g. /input/input.txt).')
        return 2
    input_file = os.path.normpath(args.input)
    if not os.path.isfile(input_file):
        print(f'Error: input file {input_file} does not exist')
        return 2

    # create a tmp directory to copy the source files to and work out of
    tmp_dir = os.path.join(os.getcwd(), 'tmp')
    if not os.path.exists(tmp_dir):
        os.mkdir(tmp_dir)
        os.system(f'cp -r {args.src}/* {tmp_dir}')
    output = os.path.join(os.getcwd(), 'firness_output')
    final_output_dir = output
    if not os.path.exists(output):
        os.mkdir(output)
    asan_dir = os.path.join(os.getcwd(), 'uefi_asan')
    simics_dir = os.path.join(os.getcwd(), 'projects', 'example')

    # copy the source files to the tmp directory
    if not sanity_check(tmp_dir):
        return 2

    log = ''
    fuzz_started = True

    # run the static analysis tool
    if args.analyze or complete_analysis:
        # make sure the tree carries the sanitizer before anything is compiled;
        # this is a no-op when the tree is already instrumented
        log += asan_instrumetation(asan_dir, os.path.join(tmp_dir, 'edk2'))
        # compile the firmware to get the compilation database; this also produces
        # the instrumented BOARDX58ICH10.fd that fuzz.simics boots
        log += get_compilation_database('/workspace/scripts', tmp_dir)
        log += run_firness(tmp_dir, output, input_file, args.smi)

    # generate the harness
    if args.generate or complete_analysis:
        if not os.path.isfile(os.path.join(output, 'call-database.json')):
            print(f'Error: {output}/call-database.json is missing -- run the analysis '
                  f'stage first (-a, or no stage flags at all).')
            return 1
        log += generate_harness(tmp_dir, output, input_file, False, args.smi, args.backend,
                                args.max_steps)
        log += compile_harness(tmp_dir)
        # compile_harness only prints when the build fails, and the fuzz stage would then
        # happily run the Firness.efi left over from whatever protocol was built last and
        # report its coverage under this one. Stop instead.
        harness_source = os.path.join(tmp_dir, 'edk2', 'Firness', 'FirnessHarnesses.c')
        if not os.path.isfile(HARNESS_IMAGE) or (
                os.path.isfile(harness_source)
                and os.path.getmtime(HARNESS_IMAGE) < os.path.getmtime(harness_source)):
            print(f'Error: the harness did not compile -- {HARNESS_IMAGE} is missing or older '
                  f'than the harness just generated. Not fuzzing, because that would run the '
                  f'previously built harness and report its coverage under this protocol.')
            return 1

    if args.fuzz or complete_analysis:
        # --backend only selects which magic instructions the harness compiles against.
        # run_fuzzer always launches fuzz.simics, so fuzzing a non-tsffs harness would boot
        # it under tsffs, whose harness instructions it no longer contains: the run would
        # sit through the whole boot and never start fuzzing, with nothing saying why.
        if args.backend != 'tsffs':
            print(f'Error: --backend {args.backend} builds the harness for that fuzzer, but '
                  f'only the tsffs/simics runner is implemented here. Generate with '
                  f'--backend {args.backend} (-g) and run the harness under that fuzzer '
                  f'yourself, or drop --backend to fuzz with tsffs.')
            return 1
        if not os.path.isfile(FIRMWARE_IMAGE):
            print(f'Error: {FIRMWARE_IMAGE} is missing -- run the analysis stage '
                  f'first so the instrumented firmware is built.')
            return 1
        if not os.path.isfile(HARNESS_IMAGE):
            print(f'Error: {HARNESS_IMAGE} is missing -- run the generate stage first.')
            return 1
        if not (args.generate or complete_analysis):
            warn_if_harness_is_stale(input_file)

        # run the fuzzer
        fuzzing_dir = simics_dir
        fuzz_started = run_fuzzer(simics_dir, args.timeout, output, args.boot_timeout,
                                  args.iteration_timeout, args.seed_corpus)
        generate_report(simics_dir, output)
        if not fuzz_started:
            print('Warning: ZERO fuzzing iterations ran, so coverage.csv is empty and every '
                  'row of the crash table is boot-time sanitizer noise, not a finding.')

    write_log(output, log.split('\n'))
    cleanup(args.src, tmp_dir, output)
    # a stage that produced nothing must not look like success
    return 0 if fuzz_started else 1


if __name__ == "__main__":
    sys.exit(main())