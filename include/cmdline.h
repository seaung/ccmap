#ifndef __CMDLINE_H_
#define __CMDLINE_H_

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VERSION "1.0.0"

// 扫描类型
typedef enum {
    SCAN_SYN,
    SCAN_TCP,
    SCAN_UDP,
    SCAN_PING
} scan_type_t;

// 命令行参数结构
typedef struct {
    char *target;           // 目标IP
    char *target_end;       // IP范围结束地址
    unsigned char cidr;     // CIDR前缀长度
    unsigned int port_start; // 起始端口
    unsigned int port_end;   // 结束端口
    scan_type_t scan_type;  // 扫描类型
    int is_range;           // 是否是IP范围扫描
    int is_cidr;           // 是否是CIDR格式
} cmdline_args_t;

// 解析命令行参数
int parse_args(int argc, char *argv[], cmdline_args_t *args);

// 显示帮助信息
void show_help(void);

// 显示版本信息
void show_version(void);

#endif