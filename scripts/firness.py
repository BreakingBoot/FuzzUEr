import shutil
import sys
import subprocess
import csv
import hashlib
import os
import json
import time
import random
import signal
import glob
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
    def __init__(self, file, line, error_type = "", message = "", asan_msg = "", count = 1, phase = "boot", module = ""):
        self.file = file
        self.line = line
        self.error_type = error_type
        self.count = count
        self.message = message
        self.asan_msg = asan_msg
        # "boot" before the harness ran, "fuzz" after -- boot reports repeat every campaign
        self.phase = phase
        # the loaded image the faulting address falls in; distinguishes a report raised
        # inside the harness from one raised in the firmware under test
        self.module = module


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


# Fuzz the built harness under LibAFL-QEMU instead of Simics.
#
# The two backends share everything downstream of this function: LibAFL's heartbeat line
# has the same "run time: .., corpus: .., objectives: .., executions: .., exec/sec: .."
# shape that tsffs writes, so coverage_matrix.py parses either without knowing which ran.
# What it cannot get from that line is the absolute edge count -- LibAFL prints the
# percentage in the GLOBAL line and the count only in the CLIENT one -- so the count is
# lifted out here and written as the Heartbeat record the reporting already understands.
QEMU_FUZZER = os.environ.get(
    'FIRNESS_QEMU_FUZZER',
    '/workspace/qemu_fuzzer/target/release/firness_qemu')
QEMU_ESP_TOOL = os.environ.get('FIRNESS_MAKE_ESP', '/workspace/scripts/make_esp.sh')
# The instrumented firmware, not the distribution one. Left unset, the fuzzer defaults to
# /usr/share/OVMF/OVMF_CODE.fd, which has no sanitizer in it at all -- the campaign then
# reports crashes and timeouts only, finds nothing, and looks exactly like a clean target.
QEMU_OVMF_CODE = os.environ.get('FIRNESS_OVMF_CODE',
                                '/workspace/qemu_fw/OVMF_CODE.fd')
QEMU_OVMF_VARS = os.environ.get('FIRNESS_OVMF_VARS',
                                '/workspace/qemu_fw/OVMF_VARS.fd')


def qemu_bios_dir():
    """Where the emulator's roms live.

    The emulator is linked into the fuzzer, so it has no data directory and resolves the
    rom path relative to the working directory -- which is not where cargo put it. Without
    this the run dies with "no QEMU rom directory holds kvmvapic.bin", which reads as a
    broken target.
    """
    configured = os.environ.get('FIRNESS_QEMU_BIOS_DIR', '')
    if configured:
        return configured
    for candidate in (os.path.join(os.path.dirname(QEMU_FUZZER),
                                   'qemu-libafl-bridge', 'pc-bios'),
                      '/work/qemu-libafl-bridge/pc-bios',
                      os.path.join(os.path.dirname(QEMU_FUZZER), 'pc-bios')):
        if os.path.isfile(os.path.join(candidate, 'kvmvapic.bin')):
            return candidate
    return ''


def run_qemu_fuzzer(harness, output, timeout, seed_corpus=''):
    if not os.path.isfile(QEMU_FUZZER) or not os.access(QEMU_FUZZER, os.X_OK):
        print(f'Error: no LibAFL-QEMU fuzzer at {QEMU_FUZZER}. Build it with '
              f'"cargo build --release" in Harness/qemu_fuzzer, or point '
              f'FIRNESS_QEMU_FUZZER at it.')
        return False
    if not os.path.isfile(QEMU_ESP_TOOL):
        print(f'Error: no {QEMU_ESP_TOOL} to build the ESP with.')
        return False

    work = os.path.join(output, 'qemu')
    corpus = seed_corpus or os.path.join(work, 'corpus')
    os.makedirs(corpus, exist_ok=True)
    os.makedirs(os.path.join(work, 'crashes'), exist_ok=True)
    esp = os.path.join(work, 'esp.qcow2')
    build = subprocess.run(['bash', QEMU_ESP_TOOL, harness, esp, '64'],
                           capture_output=True, text=True)
    if build.returncode != 0:
        print(f'Error: could not build the ESP: {build.stdout}{build.stderr}')
        return False
    # an empty corpus makes LibAFL exit with "No entries in corpus", which reads as a
    # broken target rather than a missing seed
    if not os.listdir(corpus):
        # Zeroes, not random bytes. A fuzzer needs one input that survives before it has
        # a corpus to mutate, and random bytes do not survive: every fuzzable handle is a
        # raw value, so a random EFI_HII_HANDLE is a wild pointer and IsHiiHandleValid
        # dereferences it -- #GP on the very first execution, nothing imported, and the
        # client stops with "No entries in corpus". All zeroes takes the NULL path, which
        # the firmware does check.
        with open(os.path.join(corpus, 'seed'), 'wb') as handle:
            handle.write(bytes(64))

    environment = dict(os.environ)
    environment.update({
        'FIRNESS_ESP': esp,
        'FIRNESS_CORPUS': corpus,
        'FIRNESS_CRASHES': os.path.join(work, 'crashes'),
        'FIRNESS_SERIAL': os.path.join(output, 'fuzz.txt'),
        # OVMF writes DEBUG to the ISA debug port, not to serial, so without this there
        # is no record of how far the boot got when an iteration does not complete
        'FIRNESS_DEBUGCON': os.path.join(work, 'debugcon.log'),
        'FIRNESS_OVMF_CODE': QEMU_OVMF_CODE,
        'FIRNESS_OVMF_VARS': QEMU_OVMF_VARS,
        # 10s is the fuzzer's default and an instrumented boot exceeds it, so every
        # input becomes a timeout objective and the corpus never grows
        'FIRNESS_TIMEOUT': os.environ.get('FIRNESS_TIMEOUT', '60'),
        # Snapshot restore is the per-iteration cost and it scales with guest RAM, which
        # is most of why this backend looked slow. Measured on EfiGraphicsOutput, 600s:
        #   2048MB  159 executions, 408 edges
        #    512MB  899 executions, 368 edges
        #    256MB 6112 executions, 105 edges
        # 256 is fastest and much shallower -- the guest does less before it runs out of
        # memory, and coverage collapses with it. 512 keeps nearly all the edges at five
        # times the throughput, so it is the default.
        'FIRNESS_MEMORY': os.environ.get('FIRNESS_MEMORY', '512'),
    })
    bios = qemu_bios_dir()
    if bios:
        environment['FIRNESS_QEMU_BIOS_DIR'] = bios
    for label, path in (('OVMF_CODE', QEMU_OVMF_CODE), ('OVMF_VARS', QEMU_OVMF_VARS)):
        if not os.path.isfile(path):
            print(f'Error: no {label} at {path}. The QEMU backend needs the instrumented '
                  f'firmware; point FIRNESS_{label} at it.')
            return False
    log_path = os.path.join(output, 'log.json')
    # the fuzzer gets a file of its own rather than log.json. LibAFL forks a broker and
    # clients that inherit the descriptor, and they keep writing at their own offsets
    # while they are being killed, so anything composed into a shared log.json is
    # overwritten by their parting messages
    raw_path = os.path.join(work, 'run.txt')
    print(f'++++ Fuzzing under LibAFL-QEMU for {timeout}s ++++')
    with open(raw_path, 'w') as log:
        process = subprocess.Popen([QEMU_FUZZER], stdout=log, stderr=subprocess.STDOUT,
                                   env=environment, cwd=work)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    # LibAFL forks a broker and clients; killing the parent leaves them holding the
    # snapshot, and the next run then fails to bind the broker port
    # -x, not -f: -f matches whole command lines, and any wrapper script that mentions
    # the fuzzer's path -- including the one that launched this -- is then a match
    subprocess.run(['pkill', '-x', os.path.basename(QEMU_FUZZER)],
                   capture_output=True, text=True)
    # and they still hold the log's file descriptor at their own offset, so anything
    # written here before they die is overwritten by their parting message rather than
    # appended after it
    time.sleep(2)

    iterations, solutions, edges = 0, 0, 0
    with open(raw_path, 'r', errors='ignore') as handle:
        lines = handle.readlines()
    # the CLIENT line, not the GLOBAL one: the absolute edge count is only in the
    # per-client tally, the global line carries the percentage
    for line in lines:
        if 'CLIENT' not in line:
            continue
        for pattern, name in ((r'executions:\s*(\d+)', 'iterations'),
                              (r'objectives:\s*(\d+)', 'solutions'),
                              (r'edges:\s*(\d+)/', 'edges')):
            match = re.search(pattern, line)
            if not match:
                continue
            if name == 'iterations':
                iterations = max(iterations, int(match.group(1)))
            elif name == 'solutions':
                solutions = max(solutions, int(match.group(1)))
            else:
                edges = max(edges, int(match.group(1)))
    # coverage_matrix.py reads the Heartbeat record for the edge count, which LibAFL
    # prints only as a percentage in the line its regex matches
    heartbeat = json.dumps({'Heartbeat': {'iterations': iterations,
                                          'solutions': solutions,
                                          'edges': edges}})
    with open(log_path, 'w') as handle:
        handle.writelines(lines)
        handle.write(heartbeat + '\n')
    print(f'Fuzzed {iterations} iteration(s), {edges} edge(s), {solutions} solution(s)')
    return iterations > 0


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
def wait_for_fuzzing_start(simics_dir, process, deadline_s, stale_dirs,
                           baseline_log_size=0):
    log_path = os.path.join(simics_dir, 'log.json')
    corpus_dir = os.path.join(simics_dir, 'corpus')
    solutions_dir = os.path.join(simics_dir, 'solutions')
    start = time.time()
    while time.time() - start < deadline_s:
        # read the exit status first, then the evidence: a segment can reach the harness
        # and die again inside one poll interval -- restoring a checkpoint puts the
        # harness within 8s, and a run that stops on an unmapped address can be over in
        # under a second. Checking poll() first reported those as never having started
        # and threw the segment away.
        exited = process.poll() is not None
        try:
            # on a restart log.json already holds the previous segment's records, so
            # "not empty" would report the harness reached before the boot even began
            log_started = os.path.getsize(log_path) > baseline_log_size
        except OSError:
            log_started = False
        fresh_dir = any(os.path.isdir(d) and d not in stale_dirs
                        for d in (corpus_dir, solutions_dir))
        if log_started or fresh_dir:
            print(f'\n++++ Harness reached after {int(time.time() - start)}s of boot ++++')
            return True
        if exited:
            print(f'\nError: simics exited (status {process.returncode}) before the harness '
                  f'was reached. See {simics_dir}/fuzz.txt for how far the boot got.')
            return False
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
# Booting is the same ~500s for every campaign: firmware up, Shell running, FS0: selected.
# snapshot.simics saves the machine at exactly that point, before the harness is downloaded,
# so one checkpoint serves every protocol. When it is present the fuzzing session restores
# it instead of booting.
# A checkpoint captures one firmware image. Rebuild the firmware and the checkpoint is of
# the old one -- it will still restore and still fuzz, silently exercising a binary that no
# longer matches the sources. That is the same stale-artifact trap as fuzzing a harness that
# was built for another protocol, so the checkpoint records what it was booted from.
def firmware_fingerprint():
    if not os.path.isfile(FIRMWARE_IMAGE):
        return ''
    digest = hashlib.md5()
    with open(FIRMWARE_IMAGE, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def checkpoint_matches_firmware(simics_dir):
    stamp = os.path.join(simics_dir, 'booted.ckpt.firmware')
    if not os.path.isfile(stamp):
        return None
    with open(stamp) as handle:
        return handle.read().strip()


def fuzzing_script(simics_dir, use_snapshot):
    checkpoint = os.path.join(simics_dir, 'booted.ckpt')
    script = os.path.join(simics_dir, 'fuzz_snapshot.simics')
    if use_snapshot and os.path.isdir(checkpoint) and os.path.isfile(script):
        recorded = checkpoint_matches_firmware(simics_dir)
        current = firmware_fingerprint()
        if recorded and current and recorded != current:
            print(f'Warning: {checkpoint} was booted from a different firmware '
                  f'({recorded[:8]} vs {current[:8]}); booting instead so the run matches '
                  f'the current build. Recreate it with --make-snapshot.')
            return 'fuzz.simics'
        print(f'Restoring {checkpoint} instead of booting')
        return 'fuzz_snapshot.simics'
    if use_snapshot:
        print(f'No usable checkpoint at {checkpoint}; booting instead. Create one with '
              f'./simics -no-win -no-gui snapshot.simics')
    return 'fuzz.simics'


def make_snapshot(simics_dir):
    """Boot once and save the machine at the shell, for later campaigns to restore."""
    script = os.path.join(simics_dir, 'snapshot.simics')
    if not os.path.isfile(script):
        print(f'Error: {script} is missing; rebuild the image.')
        return 1
    checkpoint = os.path.join(simics_dir, 'booted.ckpt')
    # write-configuration refuses to write over an existing checkpoint, and the image
    # ships one from whatever firmware it was built with. Without clearing it the boot
    # runs to the shell and only then fails, which reads like a boot problem rather than
    # a stale file
    stamp = os.path.join(simics_dir, 'booted.ckpt.firmware')
    if os.path.isdir(checkpoint):
        print(f'Replacing the existing checkpoint at {checkpoint}')
        shutil.rmtree(checkpoint, ignore_errors=True)
    if os.path.isfile(stamp):
        os.remove(stamp)
    print('++++ Booting once to write the checkpoint ++++')
    process = subprocess.run('./simics -no-win -no-gui snapshot.simics', cwd=simics_dir,
                             shell=True, executable='/bin/bash')
    if process.returncode == 0 and os.path.isdir(checkpoint):
        fingerprint = firmware_fingerprint()
        if fingerprint:
            with open(os.path.join(simics_dir, 'booted.ckpt.firmware'), 'w') as handle:
                handle.write(fingerprint)
        # Restoring the checkpoint skips the boot, so a campaign started from it captures
        # no boot phase at all -- and collect_unique_crashes subtracts boot repeats by
        # comparing a run's fuzz reports against its OWN boot reports. Under --snapshot that
        # set is empty, so firmware doing what it always does gets counted as a finding:
        # matrix v11 reported 135 HiiDatabaseDxe/Database.c pointer-overflows that matrix v8
        # correctly discounted. The boot that writes the checkpoint is the one boot this
        # firmware will ever do here, so record its report sites alongside it.
        capture = os.path.join(simics_dir, 'snapshot.txt')
        # The same boot carries every "Loading driver at" line, which is what attributes a
        # report to the image it came from. A restored run sees only the images loaded
        # after the checkpoint, so every firmware finding was landing on SimicsAgent.efi.
        loads = []
        if os.path.isfile(capture):
            with open(capture, 'r', encoding='utf-8', errors='ignore') as handle:
                for line in handle:
                    found = LOAD_LINE.search(line)
                    if found:
                        loads.append(f'{found.group(1)} {found.group(2)}')
        if loads:
            with open(os.path.join(simics_dir, 'booted.ckpt.modules'), 'w') as handle:
                handle.write('\n'.join(sorted(set(loads))))
            print(f'  recorded {len(set(loads))} image load(s) for module attribution')
        sites = boot_report_sites(capture)
        if sites:
            with open(os.path.join(simics_dir, 'booted.ckpt.baseline'), 'w') as handle:
                handle.write('\n'.join(f'{f}:{l}' for f, l in sorted(sites)))
            print(f'  recorded {len(sites)} boot report site(s) as the baseline')
        else:
            print('  warning: no boot reports found in the capture, so snapshot-restored '
                  'campaigns will have no boot baseline to subtract')
        print(f'++++ Checkpoint written to {checkpoint} (firmware {fingerprint[:8]}) ++++')
        return 0
    print('Error: the checkpoint was not written; see snapshot.txt')
    return 1


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


# Simics halts the whole run on conditions TSFFS cannot score. The common one is a wild
# pointer read of an address that is not mapped in the physical memory space:
#
#   [qsp.mb.cpu0.mem[0][0] error] Access (read of 8 bytes) at 0x7910000000 where nothing
#   is mapped.
#   [tsffs info] Simulation stopped without reason, not resuming.
#
# TSFFS scores CPU exceptions 6/12/13/14; an unmapped *physical* access is a simulator
# error, not an exception, so the simulation stops and the script is interrupted -- with
# status 0, which is why this looked like a clean finish. The budget is then forfeit, and
# it is forfeit precisely on the campaigns that are finding things: across matrix v7 the
# protocols that produced solutions averaged 540 iterations while those that produced none
# averaged 3373. Relaunching spends the rest of the budget; corpus/ persists, so the
# restarted segment resumes from the coverage the previous one had evolved rather than
# from random inputs.
MIN_SEGMENT_TO_RESTART = 30


# one campaign can span several simics runs; keep each run's log.json and serial capture
# under a .segN suffix so nothing is overwritten by the next launch
def rotate_segment(simics_dir, index):
    for name in ('log.json', 'fuzz.txt'):
        path = os.path.join(simics_dir, name)
        if os.path.isfile(path):
            os.replace(path, f'{path}.seg{index}')
    open(os.path.join(simics_dir, 'log.json'), 'w').close()


# log.json is JSONL and fuzz.txt is plain text, so both concatenate in segment order
def join_segments(simics_dir):
    for name in ('log.json', 'fuzz.txt'):
        path = os.path.join(simics_dir, name)
        parts = sorted(glob.glob(f'{path}.seg*'),
                       key=lambda p: int(p.rsplit('seg', 1)[1]))
        if not parts:
            continue
        tail = b''
        if os.path.isfile(path):
            with open(path, 'rb') as handle:
                tail = handle.read()
        with open(path, 'wb') as out:
            for part in parts:
                with open(part, 'rb') as handle:
                    out.write(handle.read())
                os.remove(part)
            out.write(tail)


def run_fuzzer(simics_dir, timeout, output_dir, boot_timeout=2700, iteration_timeout=None,
               seed_dir=None, use_snapshot=False, max_restarts=None):
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

    if timeout is None:
        timeout = 86400

    # -t is a fuzzing budget, not a budget for the whole simics run. the instrumented
    # firmware has to boot, walk the boot menu, start the shell and pull Firness.efi
    # over the agent first; charging that to -t is why short runs reported no iterations
    print(f'Waiting up to {boot_timeout}s for the boot to reach the harness; the '
          f'{timeout}s fuzzing budget starts after that.')

    fuzzed = 0
    attempt = 0
    started_ever = False
    while True:
        baseline_log_size = os.path.getsize(log_path) if os.path.isfile(log_path) else 0
        # corpus/ and solutions/ survive a restart, so only a growing log.json can mark
        # the second and later segments as having reached the harness
        stale = stale_dirs if attempt == 0 else {corpus_dir, solutions_dir}

        script = fuzzing_script(simics_dir, use_snapshot)
        # restoring the checkpoint takes ~12s where booting takes ~490s, which is what
        # decides whether relaunching after a short segment is worth it at all
        cheap_restart = script == 'fuzz_snapshot.simics'
        if max_restarts is None:
            max_restarts = 20 if cheap_restart else 3
        cmd = f'./simics -no-win -no-gui {script}'
        fuzzer_process = subprocess.Popen(cmd, cwd=simics_dir, shell=True,
                                          executable='/bin/bash')
        started = wait_for_fuzzing_start(simics_dir, fuzzer_process, boot_timeout, stale,
                                         baseline_log_size)
        if not started:
            break
        started_ever = True

        segment = 0
        exited_early = False
        while fuzzed < timeout:
            if fuzzer_process.poll() is not None:
                exited_early = True
                print(f'\nFuzzer exited after {fuzzed}s of its {timeout}s budget '
                      f'(rc={fuzzer_process.returncode}); see {simics_dir}/fuzz.txt')
                break
            hours, rem = divmod(fuzzed, 3600)
            minutes, seconds = divmod(rem, 60)
            formatted_time = f'{int(hours)}hrs {int(minutes)}mins {int(seconds)}secs'
            print(f'Fuzzing time: {formatted_time}', end="\r")
            time.sleep(1)
            fuzzed += 1
            segment += 1

        if not exited_early:
            print(f'\nFuzzed for the full {timeout}s budget')
            break

        fuzzer_process.kill()
        fuzzer_process.wait()

        remaining = timeout - fuzzed
        if attempt >= max_restarts:
            print(f'   not restarting: already restarted {attempt} time(s); '
                  f'{remaining}s of budget unspent')
            break
        if remaining < MIN_SEGMENT_TO_RESTART:
            print(f'   not restarting: only {remaining}s of budget left')
            break
        if segment < MIN_SEGMENT_TO_RESTART and not cheap_restart:
            # a segment that died almost immediately will most likely die again the same
            # way, and without a checkpoint each restart costs a ~490s boot -- do not
            # spend that on a segment that lasted seconds. With --snapshot the restart is
            # ~12s, so it is worth taking even then: EfiHiiString dies after 12-24s every
            # time and would otherwise forfeit its whole budget while producing more
            # solutions per iteration than almost any other protocol.
            print(f'   not restarting: the segment only lasted {segment}s and a restart '
                  f'would cost a full boot; use --snapshot to make restarts cheap')
            break
        # fuzz.simics starts the serial capture with -overwrite and tsffs reopens
        # log.json, so a relaunch would drop everything the previous segment recorded --
        # including its asan reports, which is what the crash triage reads. Rotate both
        # aside and stitch them back together once the budget is spent.
        rotate_segment(simics_dir, attempt)
        attempt += 1
        print(f'   restarting to spend the remaining {remaining}s '
              f'(restart {attempt} of {max_restarts}); the corpus so far is kept')

    if attempt:
        join_segments(simics_dir)
    started = started_ever
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
    crash_list = [['Phase', 'AtBoot', 'Module', 'File', 'Line', 'Asan Msg', 'ErrorType',
                   'Message', 'Count']]
    # a site that also reported during boot is firmware doing what it does anyway; the
    # harness starting does not make it a finding
    at_boot = {(c.file, c.line) for c in crashes.values() if c.phase == 'boot'}
    # fuzzing findings first, boot reports are a fixed baseline
    ordered = sorted(crashes.values(), key=lambda c: (c.phase != 'fuzz', c.file, c.line))
    for crash in ordered:
        repeat = 'yes' if (crash.phase == 'fuzz'
                           and (crash.file, crash.line) in at_boot) else ''
        crash_list.append([crash.phase, repeat, getattr(crash, 'module', ''), crash.file,
                           f'{crash.line}', crash.asan_msg,
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
# DXE announces every image it loads, so an address in a report can be attributed to the
# module whose image contains it. That distinction matters more than it looks: the harness
# links MdeModulePkg libraries of its own, and reports raised inside those name edk2 source
# paths exactly like firmware ones do. PiDxeS3BootScriptLib was the whole of it -- 6 sites
# reported by 84 of 142 protocols in matrix v7, dominating every solution count -- and the
# faulting addresses all land inside Firness.efi, which links the library through its
# generated dsc and never calls it. Nothing about the protocol under test.
LOAD_LINE = re.compile(
    r'Loading (?:driver|PEIM) at (0x[0-9A-Fa-f]+) EntryPoint=0x[0-9A-Fa-f]+\s+(\S+\.efi)')
REPORT_IP = re.compile(r'(?:Return IP address is|\bip) (0x[0-9A-Fa-f]+)')
# the module name DXE reports for the harness image. Distinct from
# HARNESS_IMAGE above, which is the path the build writes it to.
HARNESS_MODULE = 'Firness.efi'


def module_for(modules, ip):
    """The loaded image containing ip, or '' when the capture never showed a load."""
    if not modules or ip is None:
        return ''
    found = ''
    for base, name in modules:
        if base <= ip:
            found = name
        else:
            break
    return found


def boot_report_sites(capture):
    """The (file, line) pairs a boot of this firmware reports on its own.

    Same two report shapes collect_unique_crashes parses, but phase-blind: everything in a
    boot capture is by definition boot behaviour.
    """
    sites = set()
    if not os.path.isfile(capture):
        return sites
    with open(capture, 'r', encoding='utf-8', errors='ignore') as handle:
        prev = ''
        for line in handle:
            if 'ASAN MEMORY ACCESS check fail' in line and 'line:' in prev:
                parts = prev.split(',')
                if len(parts) > 1 and ':' in parts[1]:
                    try:
                        sites.add((parts[0].strip(), int(parts[1].split(':', 1)[1].strip(), 16)))
                    except ValueError:
                        pass
            elif line.startswith('bug_descr=') and ' in file: ' in line and ' at line: ' in line:
                path, _, num = line.split(' in file: ', 1)[1].partition(' at line: ')
                try:
                    sites.add((path.strip(), int(num.strip(), 16)))
                except ValueError:
                    pass
            prev = line
    return sites


def collect_unique_crashes(log_file, output_dir=None):
    crashes = dict()
    phase = 'boot'

    def record(path, line_text, asan_msg, error_type='', message='', module=''):
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
            existing = AsanError(path, line_no, error_type, message, asan_msg, 1, phase)
            crashes[key] = existing
        else:
            existing.count += 1
        # uefi_asan prints the faulting address *after* the file and line, so the module
        # cannot be resolved yet -- hold the entry until that line arrives. Reading the
        # most recent address instead attributed every report to the previous one's module
        pending.append(existing)

    modules = []
    pending = []
    # a checkpoint-restored run has no boot, so seed the map with what the boot that wrote
    # the checkpoint saw; loads from this run are appended as they appear
    recorded_modules = os.path.join(os.path.dirname(os.path.abspath(log_file)),
                                    'booted.ckpt.modules')
    if os.path.isfile(recorded_modules):
        for entry in open(recorded_modules):
            base, _, name = entry.strip().partition(' ')
            if name:
                try:
                    modules.append((int(base, 16), name))
                except ValueError:
                    pass
        modules.sort()
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as handle:
        prev_line = ''
        for line in handle:
            # anything after DXE dispatches Firness.efi is attributable to an input
            if phase == 'boot' and 'EntryPoint=' in line and 'Firness.efi' in line:
                phase = 'fuzz'

            loaded = LOAD_LINE.search(line)
            if loaded:
                modules.append((int(loaded.group(1), 16), loaded.group(2)))
                modules.sort()
            seen_ip = REPORT_IP.search(line)
            if seen_ip and pending:
                owner = module_for(modules, int(seen_ip.group(1), 16))
                for entry in pending:
                    if owner and not entry.module:
                        entry.module = owner
                pending = []

            if 'ASAN MEMORY ACCESS check fail' in line and 'line:' in prev_line:
                # split(',', 2) so a detail containing a comma survives: the message
                # is free text from the firmware and only the first two fields are
                # positional.
                parts = prev_line.split(',', 2)
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
    # a report raised inside the harness image is about the harness, whatever edk2 source
    # path it names, so keep it out of the firmware total rather than leaving it to be
    # counted as a finding
    harness = [c for c in crashes.values()
               if c.phase == 'fuzz' and getattr(c, 'module', '') == HARNESS_MODULE]
    if harness:
        print(f'    of which {sum(c.count for c in harness)} report(s) at '
              f'{len(harness)} site(s) were raised inside {HARNESS_MODULE} itself '
              f'-- harness, not firmware')
    at_boot = {(c.file, c.line) for c in crashes.values() if c.phase == 'boot'}
    # a snapshot-restored run skips the boot, so it has no boot phase of its own to compare
    # against; fall back to the baseline recorded when the checkpoint was written
    if not at_boot:
        recorded = os.path.join(os.path.dirname(os.path.abspath(log_file)),
                                'booted.ckpt.baseline')
        if os.path.isfile(recorded):
            for entry in open(recorded):
                path, _, num = entry.strip().rpartition(':')
                if path and num.isdigit():
                    at_boot.add((path, int(num)))
            if at_boot:
                print(f'  (no boot in this run; using the {len(at_boot)} site baseline '
                      f'recorded with the checkpoint)')
    repeats = [c for c in crashes.values()
               if c.phase == 'fuzz' and (c.file, c.line) in at_boot]
    if repeats:
        print(f'    of which {sum(c.count for c in repeats)} report(s) at {len(repeats)} '
              f'site(s) also reported during boot -- firmware doing what it does anyway')
    real = [c for c in crashes.values()
            if c.phase == 'fuzz' and (c.file, c.line) not in at_boot
            and getattr(c, 'module', '') != HARNESS_MODULE]
    print(f'    leaving {len(real)} site(s) attributable to an input')
    unattributed = sum(1 for c in crashes.values()
                       if c.phase == 'fuzz' and not getattr(c, 'module', ''))
    if unattributed and not modules:
        print(f'    ({unattributed} site(s) unattributed: the capture has no image loads, '
              f'which is normal when restoring a checkpoint)')
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
    # the QEMU runner writes the serial capture straight into output_dir, so the copy
    # would be a file onto itself
    if os.path.abspath(simics_dir) != os.path.abspath(output_dir):
        os.system(f'cp {fuzz_log} {output_dir}')
    log_file = os.path.join(simics_dir, 'log.json')
    output_csv = os.path.join(output_dir, 'coverage.csv')
    output_plot = os.path.join(output_dir, 'coverage.png')
    coverage_per_time = parse_coverage_into(log_file)
    save_coverage_to_file(coverage_per_time, output_csv)
    plot_coverage(coverage_per_time, output_plot)
    # A run that never booted leaves no serial capture. Reporting that plainly beats a
    # traceback, which buries the reason the campaign failed under a stack trace from the
    # reporting code.
    if os.path.isfile(fuzz_log):
        collect_unique_crashes(fuzz_log, output_dir)
    else:
        print(f'Warning: no serial capture at {fuzz_log} -- the run produced no output, '
              f'so there is no crash table. The fuzzer log says why.')

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
    parser.add_argument('--snapshot', action='store_true',
                        help='Restore projects/example/booted.ckpt instead of booting')
    parser.add_argument('--make-snapshot', action='store_true',
                        help='Boot once and write booted.ckpt, then stop')
    parser.add_argument('--max-steps', type=int, default=0,
                        help='Calls chained per fuzzing iteration; lower it for protocols '
                             'whose calls are slow enough to starve the fuzzer')
    parser.add_argument('--seed-corpus', type=str, default='',
                        help='Directory of inputs to start the corpus from, usually the '
                             'corpus a previous campaign for this protocol produced')
    parser.add_argument('--iteration-timeout', type=float, default=None,
                        help='Simulated seconds allowed per fuzzing iteration before it '
                             'counts as a timeout (default: whatever fuzz.simics sets)')
    parser.add_argument('--max-restarts', type=int, default=None,
                        help='How many times to relaunch simics when it stops before the '
                             'fuzzing budget is spent -- an unmapped-address access halts '
                             'the simulation with status 0 and forfeits the rest of the '
                             'budget. The corpus is kept across restarts. 0 disables '
                             '(default: 20 when restoring a checkpoint, else 3)')
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
    if args.make_snapshot:
        return make_snapshot(os.path.join(os.getcwd(), 'projects', 'example'))

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
        if args.backend == 'qemu':
            if not os.path.isfile(HARNESS_IMAGE):
                print(f'Error: {HARNESS_IMAGE} is missing -- run the generate stage first.')
                return 1
            fuzz_started = run_qemu_fuzzer(HARNESS_IMAGE, output, args.timeout,
                                           args.seed_corpus)
            # the same report the tsffs path produces, from the same serial capture, so a
            # QEMU campaign is directly comparable to a Simics one rather than reporting
            # only the fuzzer's own objective count
            generate_report(output, output)
            write_log(output, log.split('\n'))
            cleanup(args.src, tmp_dir, output)
            return 0 if fuzz_started else 1
        if args.backend != 'tsffs':
            print(f'Error: --backend {args.backend} builds the harness for that fuzzer, but '
                  f'only tsffs and qemu have a runner here.')
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
                                  args.iteration_timeout, args.seed_corpus,
                                  args.snapshot, args.max_restarts)
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