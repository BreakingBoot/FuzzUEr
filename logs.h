#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
} LogLevel;

#define LOG_DIR "FuzzUEr_logs/logs/"
#define CRASHES_DIR "FuzzUEr_logs/crashes/"

typedef struct {
    char name[50];
    int type;
} name_type_map;

extern name_type_map mapping[];

char* get_log_filename(int type);

void log_msg(char* logfile, LogLevel level, char* msg);

char* get_name(int type);

void report_crash(char* logfile);

const char* get_log_level_str(LogLevel level);