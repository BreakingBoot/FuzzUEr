#include "logs.h"

char cwd[1024];
name_type_map mapping[] = {
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

char* name;
// Function to log a message
void log_msg(char* logfile, LogLevel level, char* msg) {
    FILE* file = fopen(logfile, "a");
    if (file == NULL) {
        // Unable to open the logfile
        return;
    }

    // Get current time
    time_t t = time(NULL);
    struct tm* time_info = localtime(&t);
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", time_info);

    // Write the log message
    fprintf(file, "[%s] [%s] %s\n", time_str, get_log_level_str(level), msg);

    // Close the file
    fclose(file);
}

// Gets the name of the input type from the map
char* get_name(int type)
{
    char* name = malloc(50 * sizeof(char));
    for(int i = 0; i < sizeof(mapping) / sizeof(mapping[0]); i++)
    {
        if(mapping[i].type == type)
        {
            sprintf(name,"%s", mapping[i].name);
            return name;
        }
    }
}

// Generate a logfile name based off of the functions being fuzzed and the current time
char* get_log_filename(int type) {
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);

    name = get_name(type);
    if (!getcwd(cwd, sizeof(cwd))) exit(1);

    if(cwd[strlen(cwd)-1] != '/') {
        strncat(cwd, "/", sizeof(cwd) - strlen(cwd) - 1);
    }
    // Allocate memory for the filename string on the heap instead of stack.
    char* filename = malloc(2000 * sizeof(char));
    sprintf(filename, "%s%s%s/%s_%d%02d%02d_%02d%02d%02d", cwd, LOG_DIR, name, name, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    return filename;
}

// Copies logfile from it's normal location to the crash folder
void report_crash(char* logfile)
{
    char *dest = malloc(strlen(cwd) + strlen(CRASHES_DIR) + strlen(name) + 1);
    strcpy(dest, cwd);
    strcat(dest, CRASHES_DIR);
    strcat(dest, name);

    char* cmd = malloc(strlen(dest) + strlen(logfile) + strlen("cp  ") + 1);

    sprintf(cmd, "cp %s %s", logfile, dest);

    int status = system(cmd);
    free(dest);
    free(cmd);
    if (status == -1 || WEXITSTATUS(status) != 0) {
        exit(1);
    }
}

// Helper function to get string representation of the log levels
const char* get_log_level_str(LogLevel level) {
    switch (level) {
        case LOG_DEBUG: return "DEBUG";
        case LOG_INFO: return "INFO";
        case LOG_WARN: return "WARN";
        case LOG_ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

