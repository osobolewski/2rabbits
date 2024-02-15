#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "colors.h"
#include "string.h"


void logger(int level, const char* message, const char* module) {
    char* tag;
    char* color;
    time_t now;
    time(&now);

    if (level < VERBOSITY) {
        return;
    }

    if (level < LOG_DBG || level > LOG_ERR || !strcmp(message, "")) {
        return;
    } 

    switch (level)
    {
    case LOG_DBG:
        tag = "DBG";
        color = WHT;
        break;
    case LOG_INFO:
        tag = "INF";
        color = BLU;
        break;
    case LOG_WARN:
        tag = "WRN";
        color = YEL;
        break;
    case LOG_ERR:
        tag = "ERR";
        color = RED;
        break;    
    }

    const char* time_str = ctime(&now); 
    // hopefully days and moths are always 3 char long...
    printf("%.*s", strlen(time_str) - 11 - 4 - 1, time_str + 11);
    printf("[%s", color);
    printf("%s", tag);
    printf("%s", COLOR_RESET);

    if (module != NULL) {
        printf("](%s): %s\n", module, message);
    } else {
        printf("]: %s\n", message);
    }
}