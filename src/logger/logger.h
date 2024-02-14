#ifndef LOGGER_H
#define LOGGER_H

#define LOG_DBG     0
#define LOG_INFO    1
#define LOG_WARN    2
#define LOG_ERR     3

void logger(int level, const char* message, const char* module);

#endif /* LOG_H */