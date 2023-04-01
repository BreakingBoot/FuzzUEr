#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void fuzz(char* input)
{
    char* cmd = "./simics -no-win -c \"shell-restore.conf\" -batch-mode -e \"bp.console_string.break object = board.serconsole.con string = Error\"-p afl-simics-linker.py ";
    int len = strlen(input);
    char* final_command = malloc(strlen(cmd) + len);
    memcpy(final_command, cmd, strlen(cmd));
    memcpy(final_command + strlen(cmd), input, len);
    FILE *out = fopen("command-output.txt", "a");
    fwrite(final_command, strlen(final_command), 1, out);
    fwrite("\n", 1, 1, out);
    fclose(out);
    system(final_command);
}

int main(int argc, char* argv[])
{
    if(argc > 0)
    {
        char* filename = argv[1];
        FILE *fp = fopen(filename, "r");
        fseek(fp, 0, SEEK_END);
        int size = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        char buffer[size];
        fread(buffer, size, 1, fp);
        fuzz(buffer);
    }
    return 0;
}