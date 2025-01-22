#ifndef __LOGGER_H_
#define __LOGGER_H_

#include <stdio.h>
#include <time.h>

// 日志级别
typedef enum {
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR
} log_level_t;

// 初始化日志系统
void log_init(const char *log_file);

// 关闭日志系统
void log_close(void);

// 写入日志
void log_write(log_level_t level, const char *format, ...);

// 获取日志级别的字符串表示
const char *log_level_str(log_level_t level);

#endif