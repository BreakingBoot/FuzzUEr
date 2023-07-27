from simics import *
import os
import sys
import time
import signal
import pickle
import json
import ctypes
from ctypes import c_uint8
from datetime import datetime


def fuzz(input, logfile):
    # Create  Input
    fuzz_input = "BBClient.efi " + input + "\n"
    
    # Save to log file
    log(logfile, "LOG_INFO", f'Fuzzer input: {fuzz_input}')

    # Start simics
    # Set up serial output
    cli.quiet_run_command('board.serconsole.con.capture-start "'+ logfile +'"')

    # Set up code coverage
    try:
        cli.quiet_run_command('board.software.tracker.detect-parameters -load')
        cli.quiet_run_command('board.software.enable-tracker')
    except:
        log(logfile, "LOG_WARNING", "Couldn't set up the simics tracker (may be the first run)")
        
    # Set up code coverage
    start_coverage(logfile)
          
    # Normally add a path map, but I don't need one since I am in the same system
    # Run
    cli.quiet_run_command('board.console.con.input \"'+fuzz_input+'\"')

    # wait until simics is finally running after start
    if (not SIM_simics_is_running()):
        cli.quiet_run_command("run-seconds seconds = 1")

    
    # Stop code coverage capture and create a report
    save_coverage()
    
    # Update the snapshot
    # update_checkpoint()

    # Stop serial output
    cli.quiet_run_command('board.serconsole.con.capture-stop')
    bp = cli.quiet_run_command("bp.list")
    
    # If the breakpoint is triggered then save the input into a crash log
    # and then exit with SIGABRT so AFL can detect a crash
    for i in bp[0]:
        bp_info = cli.quiet_run_command("bp.show id = " + str(i))
        if int(bp_info[1].split(":")[-1]) > 0:
            sys.exit(signal.SIGABRT)


def update_checkpoint():
    # save the new checkpoint
    os.system('rm -rf checkpoint.conf')
    cli.quiet_run_command("write-configuration checkpoint.conf")

def start_coverage(logfile):
    cli.quiet_run_command("collect-coverage -access-count -branch-coverage -linear context-query = \"'UEFI Firmware'\" name = cc")
    try:
        cli.quiet_run_command("coverage_cc_0.add-report -ignore-addresses input = coverage")
    except:
        log(logfile, "LOG_WARNING", "Couldn't import previous coverage file")

def log(logfile, level, msg):
    with open(logfile, "a") as file:
        # Get current time
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Write the log message
        file.write(f'[{current_time}] [{level}] {msg}\n')

def save_coverage():
    cli.quiet_run_command("coverage_cc_0.stop")
    cli.quiet_run_command("coverage_cc_0.remove-unknown-addresses")
    cli.quiet_run_command("coverage_cc_0.combine-mappings")
    cli.quiet_run_command("coverage_cc_0.save coverage -overwrite")
    pickle_in = open("coverage", "rb")
    unpickled_data = pickle.load(pickle_in)
    pickle_in.close()
    
    with open("unpickled_coverage.json", "w") as f:
        json.dump(unpickled_data, f, indent=4)

def main():
    input = simenv.fuzz_arg
    logfile = simenv.logfile
    fuzz(input, logfile)

if __name__ == "__main__":
    main() 
