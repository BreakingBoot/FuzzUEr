#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

int fuzz(char* input)
{
    char* cmd = "./simics -no-win -c \"shell-restore.conf\" -batch-mode -p afl-simics-linker.py ";
    int len = strlen(input);
    char* final_command = malloc(strlen(cmd) + len);
    memcpy(final_command, cmd, strlen(cmd));
    memcpy(final_command + strlen(cmd), input, len);
    FILE *out = fopen("command-output.txt", "a");
    fwrite(final_command, strlen(final_command), 1, out);
    fwrite("\n", 1, 1, out);
    fclose(out);
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
        FILE *fp = fopen(filename, "r");
        fseek(fp, 0, SEEK_END);
        int size = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        char buffer[size+1];
        memcpy(buffer, argv[1], sizeof(char));
        fread(buffer+1, size, 1, fp);
        return fuzz(buffer);
    }
    return 0;
}
