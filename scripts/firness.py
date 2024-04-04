import shutil
import subprocess
import os
import json
import argparse
from collections import defaultdict
import matplotlib.pyplot as plt


def compile(src, compile_script='build_bios.py'):

    # Change directory to BaseTools and run make
    dir1 = os.path.join(src, 'edk2')
    test_cmd = f'cd {dir1} && make -C BaseTools clean && make -C BaseTools && export WORKSPACE=/workspace/tmp/edk2 && export EDK_TOOLS_PATH=/workspace/tmp/edk2/BaseTools && export CONF_PATH=/workspace/tmp/edk2/Conf && source edksetup.sh'
    process = subprocess.run(test_cmd, shell=True, executable='/bin/bash', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    log = process.stdout.decode('utf-8', errors='ignore')
    # Change directory to Intel Platform and run build_bios.py
    dir2 = os.path.join(src, 'edk2-platforms', 'Silicon', 'Intel', 'Tools')
    dir3 = os.path.join(src, 'edk2-platforms', 'Platform', 'Intel')
    test_cmd2 = f'cd {dir1} && export CLANGSAN_BIN=/usr/bin/ && source edksetup.sh && cd {dir3} && python {compile_script} --cleanall && make -C {dir2} clean && python {compile_script} -p BoardX58Ich10 -t CLANGSAN'
    process = subprocess.run(test_cmd2, shell=True, executable='/bin/bash', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    log += process.stdout.decode('utf-8', errors='ignore')
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

    open(os.path.join(dir, 'patch_applied'), 'w').close()

    print('++++ Instrumented Firmware ++++')
    return log

# run the static analysis tool on the compilation database
def run_firness(edk_dir, output_dir, input_file):
    cmd = 'firness -p ' + edk_dir +' -o ' + output_dir + ' -i ' + input_file + ' dummyfile'
    process = subprocess.run(cmd, shell=True, executable='/bin/bash', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    log = process.stdout.decode('utf-8', errors='ignore')
    print('++++ Ran Static Analysis Tool ++++')
    return log

# generate the harness for fuzzing with the results from the static analysis tool
def generate_harness(src, output_dir, input_file):
    dst = os.path.join(src, 'edk2')
    # all of the paths to the static analysis results are fixed
    # so we can hard code them
    generate_cmd = f'python3 /workspace/harness_generator/main.py -d {output_dir}/call-database.json -g {output_dir}/generator-database.json -t {output_dir}/types.json -a {output_dir}/aliases.json -m {output_dir}/macros.json -e {output_dir}/enums.json -i {input_file} -f {output_dir}/functions.json -o {dst}'
    process = subprocess.run(generate_cmd, shell=True, executable='/bin/bash', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    log = process.stdout.decode('utf-8', errors='ignore')
    relocate_cmd = f'cp -r {dst}/Firness {output_dir}'
    process = subprocess.run(relocate_cmd, shell=True, executable='/bin/bash', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    log += process.stdout.decode('utf-8', errors='ignore')
    print('++++ Generated Harness ++++')
    return log

# compile the harness
def compile_harness(src):
    dir1 = os.path.join(src, 'edk2')
    test_cmd = f'cd {dir1} && make -C BaseTools clean && make -C BaseTools && export WORKSPACE=/workspace/tmp/edk2 && export EDK_TOOLS_PATH=/workspace/tmp/edk2/BaseTools && export CONF_PATH=/workspace/tmp/edk2/Conf && source edksetup.sh && build -a X64 -b DEBUG -p Firness/FirnessHarnesses.inf -t CLANGSAN'
    process = subprocess.run(test_cmd, shell=True, executable='/bin/bash', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    log = process.stdout.decode('utf-8', errors='ignore')
    print('++++ Compiled Harness ++++')
    return log

# compile the firmware
def compile_firmware(src):
    log = compile(src)
    print('++++ Compiled Firmware ++++')
    return log

# run the fuzzer
def run_fuzzer(simics_dir, timeout):
    # reset the coverage log
    open(os.path.join(simics_dir, 'log.json'), 'w').close()
    # spawn the fuzzer in a subprocess and kill it after a certain time
    cmd = "./simics -no-win -no-gui fuzz.simics"
    try:
        subprocess.run(cmd, cwd=simics_dir, timeout=timeout, executable='/bin/bash', shell=True)
        print('++++ Ran Fuzzer ++++')
    except subprocess.TimeoutExpired as e:
        print("Fuzzer timed out. Killing process.")


def run_stacktrace():
    # this will need to utilize the stack trace info generated by simics
    # via the debug-context and stack-trace commands
    pass

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
    if not os.path.exists(os.path.join(dir, 'input.txt')):
        print('Error: input.txt not found')
        return False
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
    # remove the tmp directory
    os.system('rm -rf ' + tmp_dir)
    os.system('rm -rf ' + output)
    os.system('reset')

def write_log(output, logs):
    with open(os.path.join(output, 'log.txt'), 'w') as f:
        for log in logs:
            f.write(log + '\n')

def main():
    parser = argparse.ArgumentParser(description='Firness')
    parser.add_argument('-s', '--src', type=str, help='Path to the source directory with edk2 and input.txt')
    parser.add_argument('-a', '--analyze', action='store_true', help='Run the static analysis tool')
    parser.add_argument('-f', '--fuzz', action='store_true', help='Run the fuzzer')
    parser.add_argument('-g', '--generate', action='store_true', help='Generate the harness')
    parser.add_argument('-t', '--timeout', type=int, help='Timeout for the fuzzer')
    args = parser.parse_args()
    complete_analysis = not args.analyze and not args.fuzz and not args.generate

    # create a tmp directory to copy the source files to and work out of
    tmp_dir = os.path.join(os.getcwd(), 'tmp')
    os.mkdir(tmp_dir)
    os.system(f'cp -r {args.src}/* {tmp_dir}')
    output = os.path.join(os.getcwd(), 'firness_output')
    os.mkdir(output)
    input_file = os.path.join(tmp_dir, 'input.txt')
    asan_dir = os.path.join(os.getcwd(), 'uefi_asan')

    # copy the source files to the tmp directory
    if not sanity_check(tmp_dir):
        return

    # run the static analysis tool
    if args.analyze or complete_analysis or args.generate:
        # compile the firmware to get compilation database
        log = get_compilation_database('/workspace/scripts', tmp_dir)
        log += run_firness(tmp_dir, output, input_file)

    # generate the harness
    if args.generate or complete_analysis:
        log += generate_harness(tmp_dir, output, input_file)
        log += compile_harness(tmp_dir)

    if args.fuzz or complete_analysis:
        # log += asan_instrumetation(asan_dir, os.path.join(tmp_dir, 'edk2'))
        # compile the firmware
        log += compile_firmware(tmp_dir)

        # run the fuzzer
        simics_dir = os.path.join(os.getcwd(), 'projects', 'example')
        run_fuzzer(simics_dir, args.timeout)
        generate_report(simics_dir, output)
    
    write_log(output, log.split('\n'))
    cleanup(args.src, tmp_dir, output)


if __name__ == "__main__":
    main()