#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

char* base64(const unsigned char* input, int length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, input, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    char* buff = (char*)malloc((bufferPtr->length + 1)*sizeof(char));
    memcpy(buff, bufferPtr->data, bufferPtr->length-1);
    buff[bufferPtr->length-1] = '\0';

    return buff;
}
int fuzz(char* input, int execs)
{
    // Command specifications
    char* cmd = "./simics -no-win -c \"checkpoint.conf\" -batch-mode -p breakpoints.py -e \"@cli.simenv.fuzz_arg = \'";
    if((execs%10) == 0)
    {
        cmd = "./simics -no-win -c \"shell-restore.conf\" -batch-mode -p breakpoints.py -e \"@cli.simenv.fuzz_arg = \'";
    }
    char* fuzz_input = base64(input, strlen(input));
    int len = strlen(fuzz_input);
    char* last = "\'\" -p afl-simics-linker.py";
    char* final_command = malloc(strlen(cmd) + len + strlen(last));

    // Create the command
    memcpy(final_command, cmd, strlen(cmd));
    memcpy(final_command + strlen(cmd), fuzz_input, len);
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
