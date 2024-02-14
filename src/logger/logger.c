#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "colors.h"

void logger(int level, const char* message, const char* module) {
    char* tag;
    char* color;
    time_t now;
    time(&now);

    if (level < LOG_DBG || level > LOG_ERR || message == "" || message == NULL) {
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

    printf("%s [", ctime(&now));
    printf(color);
    printf("%s", ctime(&now));
    printf(COLOR_RESET);
    if (module != NULL) {
        printf("](%s): %s\n", tag, module, message);
    } else {
        printf("]: %s\n", tag, message);
    }
}