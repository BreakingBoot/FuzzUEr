from simics import *
import os
import sys
import time
import signal

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
    cli.quiet_run_command('$cc = (collect-coverage context-query="\'UEFI Firmware\'")')
    try:
        cli.quiet_run_command('$cc.add-report \"coverage\"')
    except:
        with open("log.txt", "a") as f:
            f.write("ERROR: Couldn't load existing code coverage report\n")
          
    # Normally add a path map, but I don't need one since I am in the same system
    # Run
    cli.quiet_run_command('board.console.con.input \"'+fuzz_input+'\"')

    # wait until simics is finally running after start
    if (not SIM_simics_is_running()):
        cli.quiet_run_command("run-seconds seconds = 1")

    
    # Stop code coverage capture and create a report
    cli.quiet_run_command('$cc.stop')
    cli.quiet_run_command('$cc.save coverage -overwrite')
    os.system("rm -rf coverage-lcov")
    os.system("rm merged_tracefile.info")
    cli.quiet_run_command('$cc.lcov-output coverage-lcov')
    os.system("lcov_tracefile=$(ls coverage-lcov | sed -e \"s/^/-a coverage-lcov\//\") && lcov $lcov_tracefile -o merged_tracefile.info")

    # Stop serial output
    cli.quiet_run_command('board.serconsole.con.capture-stop')
    bp = cli.quiet_run_command('bp.show id = 1')
    with open("log.txt", "a") as f:
        f.write(str(bp)+"\n")
    
    # If the breakpoint is triggered then save the input into a crash log
    # and then exit with SIGABRT so AFL can detect a crash
    if int(bp[1].split(":")[-1]) > 0:
        with open("crashes.txt", "a") as f:
            f.write(fuzz_input + " " + str(bp)+"\n")
        sys.exit(signal.SIGABRT)

def main():
    input = sys.argv[-1]
    fuzz(input)

if __name__ == "__main__":
    main() 
