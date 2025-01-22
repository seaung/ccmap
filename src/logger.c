#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include "../include/logger.h"

static FILE *log_fp = NULL;

void log_init(const char *log_file) {
    if (log_file) {
        log_fp = fopen(log_file, "a");
        if (!log_fp) {
            fprintf(stderr, "无法打开日志文件: %s\n", log_file);
            return;
        }
    }
}

void log_close(void) {
    if (log_fp) {
        fclose(log_fp);
        log_fp = NULL;
    }
}

const char *log_level_str(log_level_t level) {
    switch (level) {
        case LOG_INFO:
            return "INFO";
        case LOG_WARNING:
            return "WARNING";
        case LOG_ERROR:
            return "ERROR";
        default:
            return "UNKNOWN";
    }
}

void log_write(log_level_t level, const char *format, ...) {
    va_list args;
    time_t now;
    char time_buf[64];
    
    time(&now);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    // 输出到控制台
    va_start(args, format);
    printf("[%s] [%s] ", time_buf, log_level_str(level));
    vprintf(format, args);
    printf("\n");
    va_end(args);
    
    // 输出到文件
    if (log_fp) {
        va_start(args, format);
        fprintf(log_fp, "[%s] [%s] ", time_buf, log_level_str(level));
        vfprintf(log_fp, format, args);
        fprintf(log_fp, "\n");
        fflush(log_fp);
        va_end(args);
    }
}