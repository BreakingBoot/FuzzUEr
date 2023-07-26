#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <openssl/bio.h>
#include <jansson.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <stdint.h>
#include <sys/shm.h>

#define SHM_ENV_VAR "__AFL_SHM_ID"
#define MAP_SIZE 65536

#define AFL_BITMAP_SET(_bitmap, _index) do { \
  uint8_t* _p = &(_bitmap)[_index]; \
  if (*_p < 2) (*_p)++; \
  else if (*_p < 4) (*_p) += 2; \
  else if (*_p < 8) (*_p) += 4; \
  else if (*_p < 16) (*_p) += 8; \
  else if (*_p < 32) (*_p) += 16; \
  else if (*_p < 64) (*_p) += 32; \
  else if (*_p < 128) (*_p) += 64; \
  else if (*_p < 255) (*_p)++; \
} while (0)


void update_bitmap(void) { 
  char *id_str = getenv(SHM_ENV_VAR); 

  if (id_str) { 
    uint32_t shm_id = atoi(id_str); 
    uint8_t *__afl_area_ptr = shmat(shm_id, NULL, 0); 

    if (__afl_area_ptr == (void *)-1) exit(1); 

    json_error_t error;
    json_t *root, *mappings, *map, *branches, *branch;
    size_t index_map;
    const char *cur_location;
    unsigned int prev_location = 0;

    
    root = json_load_file("unpickled_coverage.json", 0, &error);

    if(!root) exit(1);

    if(!json_is_object(root)) exit(1);

    mappings = json_object_get(root, "mappings");
    if (!json_is_array(mappings)) exit(1);

    int cur_location_int = 0;
    json_array_foreach(mappings, index_map, map) {
        branches = json_object_get(map, "branches");
        if (json_is_object(branches)) {

            json_object_foreach(branches, cur_location, branch) {
                json_t *taken_json = json_object_get(branch, "taken");
                if (json_is_integer(taken_json)) {
                    int taken = json_integer_value(taken_json);

                    AFL_BITMAP_SET(__afl_area_ptr, (cur_location_int ^ prev_location) % MAP_SIZE);
                    cur_location_int++;
                    prev_location = cur_location_int >> 1;
                }
            }
        }
    }
    json_decref(root);
  } 
} 

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
int fuzz(char* input)//, int execs)
{
    // Command specifications
    // char* cmd = "./simics -no-win -c \"checkpoint.conf\" -batch-mode -p breakpoints.py -e \"@cli.simenv.fuzz_arg = \'";
    // if((execs%10) == 0)
    // {
    //     cmd = "./simics -no-win -c \"shell-restore.conf\" -batch-mode -p breakpoints.py -e \"@cli.simenv.fuzz_arg = \'";
    // }
    char *cmd = "./simics -no-win -c \"shell-restore.conf\" -batch-mode -p breakpoints.py -e \"@cli.simenv.fuzz_arg = \'";
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
    update_bitmap();
    return 0;
}

int main(int argc, char* argv[])
{
    if(argc > 0)
    {
        char* filename = argv[2];
        //int execs = atoi(argv[3]);
        FILE *fp = fopen(filename, "r");
        fseek(fp, 0, SEEK_END);
        int size = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        char buffer[size+1];
        memcpy(buffer, argv[1], sizeof(char));
        fread(buffer+1, size, 1, fp);
        fclose(fp);
        return fuzz(buffer);//, execs);
    }
    return 0;
}
