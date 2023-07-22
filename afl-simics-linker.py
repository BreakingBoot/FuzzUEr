from simics import *
import os
import sys
import time
import signal
import pickle
import json
import ctypes
from ctypes import c_uint8



#SIM_continue() # Continue Simulation
#SIM_run_command_file(filename) # Run a command rile
#SIM_simics_is_running() # Check if simics is running
#cli.quiet_run_command(input) # Run a CLI command, same as directly inputting into the terminal
def fuzz(input):
    # Create  Input
    input = input[:-7]
    fuzz_input = "BBClient.efi " + input + "\n"
    
    # Save to log file
    with open("log.txt", "a") as f:
        f.write("INPUT: " + fuzz_input)

    # Start simics
    # Set up serial output
    cli.quiet_run_command('board.serconsole.con.capture-start "log.txt"')

    # Set up code coverage
    try:
        cli.quiet_run_command('board.software.tracker.detect-parameters -load')
        cli.quiet_run_command('board.software.enable-tracker')
    except:
        with open("log.txt", "a") as f:
            f.write("ERROR: Couldn't set up simics tracker\n")
        
    # Set up code coverage
    start_coverage()
          
    # Normally add a path map, but I don't need one since I am in the same system
    # Run
    cli.quiet_run_command('board.console.con.input \"'+fuzz_input+'\"')

    # wait until simics is finally running after start
    if (not SIM_simics_is_running()):
        cli.quiet_run_command("run-seconds seconds = 1")

    
    # Stop code coverage capture and create a report
    save_coverage()
    
    # Update the snapshot
    update_checkpoint()

    # Stop serial output
    cli.quiet_run_command('board.serconsole.con.capture-stop')
    bp = cli.quiet_run_command("bp.list")
    with open("log.txt", "a") as f:
        f.write(str(bp)+"\n")
    
    # If the breakpoint is triggered then save the input into a crash log
    # and then exit with SIGABRT so AFL can detect a crash
    for i in bp[0]:
        bp_info = cli.quiet_run_command("bp.show id = " + str(i))
        if int(bp_info[1].split(":")[-1]) > 0:
            with open("crashes.txt", "a") as f:
                f.write(fuzz_input + " " + str(bp)+"\n")
            sys.exit(signal.SIGABRT)
        
def unpickle_data():
    # unpickling the object
    pickle_in = open("coverage", "rb")
    unpickled_data = pickle.load(pickle_in)
    pickle_in.close()

    modify_shared_memory(unpickled_data)

def modify_shared_memory(unpickled_coverage):
    # Get shared memory ID from environment variable
    shm_id_str = os.environ.get("__AFL_SHM_ID")
    if shm_id_str is None:
        print("Not running under AFL.")
        exit(1)

    shm_id = int(shm_id_str)

    # Attach to the shared memory segment
    libc = ctypes.CDLL('libc.so.6')
    data_pointer = libc.shmat(shm_id, None, 0)
    if data_pointer == -1:
        print("shmat call failed")
        exit(1)

    # Now we have a pointer to the shared memory segment, but we need to
    # tell Python how to use it. We create an array of c_uint8. The size of the 
    # array (65536) is the size of AFL's shared memory segment.
    afl_area_ptr = (c_uint8 * 65536).from_address(data_pointer)

    # Now you can modify the shared memory. For example, to set the first byte:
    for map in unpickled_coverage["mappings"]:
        try:
            for cur_location, info in map["branches"].items():
                afl_area_ptr[(cur_location ^ prev_location)%len(afl_area_ptr)] += info["taken"]

                # Shift cur_location right by 1 bit and store the result in prev_location for the next iteration
                prev_location = cur_location >> 1
        except:
            NotImplemented
    # After you're done with the shared memory
    result = libc.shmdt(ctypes.c_void_p(data_pointer))
    if result == -1:
        print("shmdt call failed")
        exit(1)


def update_checkpoint():
    # save the new checkpoint
    os.system('rm -rf checkpoint.conf')
    cli.quiet_run_command("write-configuration checkpoint.conf")

def start_coverage():
    cli.quiet_run_command("collect-coverage -access-count -branch-coverage -linear context-query = \"'UEFI Firmware'\" name = cc")
    try:
        cli.quiet_run_command("coverage_cc_0.add-report -ignore-addresses input = coverage")
    except:
        NotImplemented

def save_coverage():
    cli.quiet_run_command("coverage_cc_0.stop")
    cli.quiet_run_command("coverage_cc_0.remove-unknown-addresses")
    cli.quiet_run_command("coverage_cc_0.combine-mappings")
    cli.quiet_run_command("coverage_cc_0.save coverage -overwrite")

def main():
    input = sys.argv[-1]
    fuzz(input)

if __name__ == "__main__":
    main() 
