import shutil
import subprocess
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

fuzzer_process = None
final_output_dir = ""
fuzzing_dir = ""


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

def compile(src, compile_script='build_bios.py'):

    # Change directory to BaseTools and run make
    dir1 = os.path.join(src, 'edk2')
    test_cmd = f'cd {dir1} && make -C BaseTools clean && make -C BaseTools && export WORKSPACE=/workspace/tmp/edk2 && export EDK_TOOLS_PATH=/workspace/tmp/edk2/BaseTools && export CONF_PATH=/workspace/tmp/edk2/Conf && source edksetup.sh'
    process = subprocess.run(test_cmd, shell=True, executable='/bin/bash', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    log = process.stdout.decode('utf-8', errors='ignore')
    log += process.stderr.decode('utf-8', errors='ignore')
    # Change directory to Intel Platform and run build_bios.py
    dir2 = os.path.join(src, 'edk2-platforms', 'Silicon', 'Intel', 'Tools')
    dir3 = os.path.join(src, 'edk2-platforms', 'Platform', 'Intel')
    test_cmd2 = f'cd {dir1} && export CLANGSAN_BIN=/usr/bin/ && source edksetup.sh && cd {dir3} && python {compile_script} --cleanall && make -C {dir2} clean && python {compile_script} -p BoardX58Ich10 -t CLANGSAN'
    process = subprocess.run(test_cmd2, shell=True, executable='/bin/bash', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    log += process.stdout.decode('utf-8', errors='ignore')
    log += process.stderr.decode('utf-8', errors='ignore')
    return log


# Run bear on the entire simics code base to get the compilation database
def get_compilation_database(src, dst):
    # copy the modified build script to the platforms directory
    src_file = os.path.join(src, 'build_bios2.py')
    platforms_dir = os.path.join(dst, 'edk2-platforms/Platform/Intel', 'build_bios2.py')
    shutil.copyfile(src_file, platforms_dir)
    # # run it
    log = compile(dst, 'build_bios2.py')
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

    # apply the patch file in src to the entire dst dir
    patch_path = os.path.join(src, 'asan.patch')
    patch_cmd = 'patch -p1 -d ' + dir + ' < ' + patch_path + ' --binary'
    process = subprocess.run(patch_cmd, shell=True, executable='/bin/bash', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    log = process.stdout.decode('utf-8', errors='ignore')
    log += process.stderr.decode('utf-8', errors='ignore')

    open(os.path.join(dir, 'patch_applied'), 'w').close()

    print('++++ Instrumented Firmware ++++')
    return log

# run the static analysis tool on the compilation database
def run_firness(edk_dir, output_dir, input_file):
    cmd = 'firness -p ' + edk_dir +' -o ' + output_dir + ' -i ' + input_file + ' dummyfile'
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
def generate_harness(src, output_dir, input_file, random: bool = False):
    dst = output_dir
    edk2_dir = os.path.join(src, 'edk2')
    # all of the paths to the static analysis results are fixed
    # so we can hard code them
    generate_cmd = f'python3 /workspace/harness_generator/main.py -d {output_dir}/call-database.json -g {output_dir}/generator-database.json -gd {output_dir}/generators.json -t {output_dir}/types.json -a {output_dir}/aliases.json -m {output_dir}/macros.json -e {output_dir}/enums.json -i {input_file} -s {output_dir}/cast-map.json -in {output_dir}/includes.json -f {output_dir}/functions.json --edk2 {edk2_dir} -o {dst}'
    if random:
        generate_cmd += ' -r'
    process = subprocess.run(generate_cmd, shell=True, executable='/bin/bash', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    log = process.stdout.decode('utf-8', errors='ignore')
    log += process.stderr.decode('utf-8', errors='ignore')
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
        generate_includes(os.path.join(dir1, 'Firness'))
        if count < 5:
            compile_harness(src, count + 1)
        else:
            exit(1)
        print('Error: Harness compilation failed')
    else:
        print('++++ Compiled Harness ++++')
    return log

# compile the firmware
def compile_firmware(src):
    log = compile(src)
    print('++++ Compiled Firmware ++++')
    return log

def run_fuzzer(simics_dir, timeout, output_dir):
    global fuzzer_process
    # reset the coverage log
    open(os.path.join(simics_dir, 'log.json'), 'w').close()
    signal.signal(signal.SIGINT, generate_report2)
    # spawn the fuzzer in a subprocess
    cmd = f"./simics -no-win -no-gui fuzz.simics"
    fuzzer_process  = subprocess.Popen(cmd, cwd=simics_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, executable='/bin/bash')
    if timeout is None:
        timeout = 86400
    execution_time = 0
    while execution_time < timeout:
        hours, rem = divmod(execution_time, 3600)
        minutes, seconds = divmod(rem, 60)
        formatted_time = f'{int(hours)}hrs {int(minutes)}mins {int(seconds)}secs'
        print(f'Execution time: {formatted_time}', end="\r")
        time.sleep(1)
        execution_time += 1

    fuzzer_process.kill()
    os.system(f'cp {simics_dir}/log.json {output_dir}')
    os.system(f'cp {simics_dir}/fuzz.log {output_dir}')
    print('++++ Ran Fuzzer ++++')


def reproduce_crash(simics_dir):
    # spawn the fuzzer in a subprocess and kill it after a certain time
    cmd = "./simics -no-win -no-gui reproduce.simics"
    subprocess.run(cmd, cwd=simics_dir, executable='/bin/bash', shell=True)


def collect_unique_crashes():
    pass


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
            data = json.loads(line)
            if 'Interesting' in data.keys():
                map |= set(data['Interesting']['indices'])
            elif 'Message' in data.keys():
                # Extract timestamp from the key (assuming it's the timestamp)
                timestamp = data['Message'].split(',')[0].split(' ')[-1]
                # Store coverage information for this timestamp
                coverage_per_time[parse_time_to_seconds(timestamp)] = len(map)
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
    os.system(f'cp {fuzzing_dir}/log.json {final_output_dir}')
    # analyze the results from the coverage log 
    # and from the cmd line output that contains the crash results
    log_file = os.path.join(fuzzing_dir, 'log.json')
    output_csv = os.path.join(final_output_dir, 'coverage.csv')
    output_plot = os.path.join(final_output_dir, 'coverage.png')
    coverage_per_time = parse_coverage_into(log_file)
    save_coverage_to_file(coverage_per_time, output_csv)
    plot_coverage(coverage_per_time, output_plot)
    print('++++ Generated Report ++++')
    exit(0)

def generate_report(simics_dir, output_dir):
    # analyze the results from the coverage log 
    # and from the cmd line output that contains the crash results
    log_file = os.path.join(simics_dir, 'log.json')
    output_csv = os.path.join(output_dir, 'coverage.csv')
    output_plot = os.path.join(output_dir, 'coverage.png')
    coverage_per_time = parse_coverage_into(log_file)
    save_coverage_to_file(coverage_per_time, output_csv)
    plot_coverage(coverage_per_time, output_plot)
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
    parser.add_argument('-t', '--timeout', type=int, help='Timeout for the fuzzer')
    parser.add_argument('-e', '--eval', action='store_true', help='Evaluate the results of the static analysis tool')
    args = parser.parse_args()
    complete_analysis = not args.analyze and not args.fuzz and not args.generate

    # if args.eval and args.generate:
    #     print(generate_harness(args.src, args.src, args.input))
    #     return 

    if args.eval:
        # run_eval2(args.src)
        run_eval(args.src, args.input, args.random)
        return 
    # input_file = args.input
    if args.input:
        input_file = os.path.normpath(args.input)
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

    # copy the source files to the tmp directory
    if not sanity_check(tmp_dir):
        return
    
    log = ''
    # if args.reproduce:
    #     reproduce_crash(os.path.join(os.getcwd(), 'projects', 'example'))
    #     return
    # run the static analysis tool
    if args.analyze or complete_analysis or args.generate:
        # compile the firmware to get compilation database
        log += get_compilation_database('/workspace/scripts', tmp_dir)
        log += run_firness(tmp_dir, output, input_file)

    # generate the harness
    if args.generate or complete_analysis:
        log += generate_harness(tmp_dir, output, input_file)
        log += compile_harness(tmp_dir)

    if args.fuzz or complete_analysis:
        # log += asan_instrumetation(asan_dir, os.path.join(tmp_dir, 'edk2'))
        # compile the firmware
        # log += compile_firmware(tmp_dir)
        # log += compile_harness(tmp_dir)

        # run the fuzzer
        simics_dir = os.path.join(os.getcwd(), 'projects', 'example')
        fuzzing_dir = simics_dir
        run_fuzzer(simics_dir, args.timeout, output)
        generate_report(simics_dir, output)
    
    write_log(output, log.split('\n'))
    cleanup(args.src, tmp_dir, output)


if __name__ == "__main__":
    main()