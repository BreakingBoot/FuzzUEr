from simics import *
import os
import sys
import time

#SIM_continue() # Continue Simulation
#SIM_run_command_file(filename) # Run a command rile
#SIM_simics_is_running() # Check if simics is running
#cli.quiet_run_command(input) # Run a CLI command, same as directly inputting into the terminal
def fuzz(input):
    # Create  Input
    fuzz_input = "BBClient.efi " + input + "\n"

    # Start simics
    # Set up serial output
    cli.quiet_run_command('board.serconsole.con.capture-start -overwrite "console-output.txt"')
    # Set up code coverage
    try:
        cli.quiet_run_command('board.software.tracker.detect-parameters -load')
        cli.quiet_run_command('board.software.enable-tracker')
    except:
        print("Ran into som error with Tracker")
        
    cli.quiet_run_command('$cc = (collect-coverage context-query="\'UEFI Firmware\'")')
    try:
        cli.quiet_run_command('$cc.add-report \"coverage\"')
    except:
        print("No coverage report to load")
    #print("started code coverage")
    # Normally add a path map, but I don't need one since I am in the same system

    cli.quiet_run_command('board.console.con.input \"'+fuzz_input+'\"')
    #SIM_stop()
    # wait until simics is finally running after start
    if (not SIM_simics_is_running()):
        # Continue the simulation
    #    SIM_continue(0)
        cli.run_command("run-seconds seconds = 10")
        #sleep

    
    # Stop code coverage capture and create a report
    cli.quiet_run_command('$cc.stop')
    cli.quiet_run_command('$cc.save coverage -overwrite')
    os.system("rm -rf coverage-lcov")
    os.system("rm merged_tracefile.info")
    cli.quiet_run_command('$cc.lcov-output coverage-lcov')
    os.system("lcov_tracefile=$(ls coverage-lcov | sed -e \"s/^/-a coverage-lcov\//\") && lcov $lcov_tracefile -o merged_tracefile.info")
    #print("generated report")

    # Stop serial output
    cli.quiet_run_command('board.serconsole.con.capture-stop')
    #cli.quiet_run_command('restart-simics shell-restore.conf')


def main():
    input = sys.argv[len(sys.argv)-1]
    #print(input)
    fuzz(input)

if __name__ == "__main__":
    main() 
