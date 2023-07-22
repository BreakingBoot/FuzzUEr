#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

int fuzz(char* input, int execs)
{
    // Command specifications
    char* cmd = "./simics -no-win -c \"checkpoint.conf\" -batch-mode -p breakpoints.py -e \"@cli.simenv.fuzz_arg = ";
    if((execs%10) == 0)
    {
        cmd = "./simics -no-win -c \"shell-restore.conf\" -batch-mode -p breakpoints.py -e \"@cli.simenv.fuzz_arg = ";
    }
    int len = strlen(input);
    char* last = "\" -p afl-simics-linker.py";
    char* final_command = malloc(strlen(cmd) + len + strlen(last));

    // Create the command
    memcpy(final_command, cmd, strlen(cmd));
    memcpy(final_command + strlen(cmd), input, len);
    memcpy(final_command + strlen(cmd) + len, last, strlen(last));

    // Save to the command to an output file for logging
    FILE *out = fopen("command-output.txt", "a");
    fwrite(final_command, strlen(final_command), 1, out);
    fwrite("\n", 1, 1, out);
    fclose(out);

    // Run the Simics command
    int status = system(final_command);
    int exit = WEXITSTATUS(status);
    if(exit == 6)
    {
        raise(SIGABRT);
    }
    return 0;
}

int main(int argc, char* argv[])
{
    if(argc > 0)
    {
        char* filename = argv[2];
        int execs = atoi(argv[3]);
        FILE *fp = fopen(filename, "r");
        fseek(fp, 0, SEEK_END);
        int size = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        char buffer[size+1];
        memcpy(buffer, argv[1], sizeof(char));
        fread(buffer+1, size, 1, fp);
        return fuzz(buffer, execs);
    }
    return 0;
}
