#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char name[50];
    int type;
} name_type_map;

name_type_map map[] = {
                    {"ProcessFirmwareVolume", 0},
                    {"Event", 1},
                    {"LoadImage", 2},
                    {"SmmHarden", 3},
                    {"Example", 4},
                    {"Memory", 5},
                    {"Unknown", 6},
                    {"Protocol", 7},
                    {"Demo1", 8}
                    };

char* get_log_filename(int type) {
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);

    char* name = NULL;
    for(int i = 0; i < sizeof(map) / sizeof(map[0]); i++)
    {
        if(map[i].type == type)
        {
            name = map[i].name;
            break;
        }
    }

    // Allocate memory for the filename string on the heap instead of stack.
    char* filename = malloc(100 * sizeof(char));
    sprintf(filename, "%s_%d%02d%02d_%02d%02d%02d", name, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    return filename;
}