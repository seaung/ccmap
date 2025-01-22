#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../include/cmdline.h"
#include "../include/scan.h"
#include "../include/logger.h"

#define MAX_THREADS 100
#define MAX_OPEN_PORTS 1000

// 扫描结果结构体
// 扫描结果结构体
typedef struct {
    char ip[INET_ADDRSTRLEN];            // IP地址字符串
    unsigned int open_ports[MAX_OPEN_PORTS]; // 开放的端口列表
    int port_count;                       // 开放端口数量
    pthread_mutex_t mutex;                // 互斥锁，用于线程同步
} scan_result_t;

// 线程参数结构体
// 线程参数结构体
typedef struct {
    char ip[INET_ADDRSTRLEN];      // 要扫描的IP地址
    unsigned int port_start;        // 起始端口
    unsigned int port_end;          // 结束端口
    scan_type_t scan_type;          // 扫描类型
    scan_result_t *result;          // 扫描结果指针
} thread_args_t;

// 全局变量
volatile sig_atomic_t running = 1;
scan_result_t *scan_results = NULL;
int total_ips = 0;
int current_ip = 0;
pthread_mutex_t progress_mutex = PTHREAD_MUTEX_INITIALIZER;

// 显示程序banner
void show_banner(void) {
    printf("\n");
    printf("  ██████╗ ██████╗███╗   ███╗ █████╗ ██████╗ \n");
    printf(" ██╔════╝██╔════╝████╗ ████║██╔══██╗██╔══██╗\n");
    printf(" ██║     ██║     ██╔████╔██║███████║██████╔╝\n");
    printf(" ██║     ██║     ██║╚██╔╝██║██╔══██║██╔═══╝ \n");
    printf(" ╚██████╗╚██████╗██║ ╚═╝ ██║██║  ██║██║     \n");
    printf("  ╚═════╝ ╚═════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     \n");
    printf("\n");
    printf("欢迎使用CCMAP端口扫描工具 v%s\n", VERSION);
    printf("作者: SeAung\n\n");
}

// 全局变量用于信号处理
// running变量已在上面定义

// 信号处理函数
void signal_handler(int signo) {
    if (signo == SIGINT || signo == SIGTERM) {
        printf("\n正在停止扫描...\n");
        running = 0;
        
        // 清理资源
        if (scan_results != NULL) {
            for (int i = 0; i < total_ips; i++) {
                pthread_mutex_destroy(&scan_results[i].mutex);
            }
            free(scan_results);
        }
        
        // 关闭日志系统
        log_close();
        
        // 强制退出程序
        exit(EXIT_SUCCESS);
    }
}

// 显示扫描进度
void show_progress(void) {
    pthread_mutex_lock(&progress_mutex);
    float progress = (float)current_ip / total_ips * 100;
    printf("\r扫描进度: [%3.1f%%] %d/%d IPs", progress, current_ip, total_ips);
    fflush(stdout);
    pthread_mutex_unlock(&progress_mutex);
}

// 线程扫描函数
void *scan_thread(void *arg) {
    thread_args_t *args = (thread_args_t *)arg;
    int result;
    unsigned int port;
    
    for (port = args->port_start; port <= args->port_end && running; port++) {
        switch (args->scan_type) {
            case SCAN_SYN:
                result = syn_scan(args->ip, port);
                break;
            case SCAN_TCP:
                result = tcp_connect_scan(args->ip, port);
                break;
            case SCAN_UDP:
                result = udp_scan(args->ip, port);
                break;
            case SCAN_PING:
                result = ping_scan(args->ip, port);
                break;
            default:
                continue;
        }
        
        if (result == 0) {
            pthread_mutex_lock(&args->result->mutex);
            if (args->result->port_count < MAX_OPEN_PORTS) {
                args->result->open_ports[args->result->port_count++] = port;
            }
            pthread_mutex_unlock(&args->result->mutex);
            log_write(LOG_INFO, "IP: %s 端口 %u 开放", args->ip, port);
        }
        
        usleep(100);
    }
    
    return NULL;
}

// 显示扫描结果
void show_results(void) {
    printf("\n\n扫描结果汇总:\n");
    printf("----------------------------------------\n");
    
    for (int i = 0; i < total_ips; i++) {
        if (scan_results[i].port_count > 0) {
            printf("\nIP: %s\n", scan_results[i].ip);
            printf("开放端口: ");
            for (int j = 0; j < scan_results[i].port_count; j++) {
                printf("%u ", scan_results[i].open_ports[j]);
            }
            printf("\n");
        }
    }
    printf("\n----------------------------------------\n");
}

// 执行端口扫描
// 执行端口扫描
// 该函数负责初始化扫描环境，创建线程池，并管理扫描过程
void perform_scan(cmdline_args_t *args) {
    struct in_addr ip_addr, network_addr, broadcast_addr;
    uint32_t start_ip, end_ip, current_ip;
    char current_ip_str[INET_ADDRSTRLEN];
    pthread_t threads[MAX_THREADS];
    thread_args_t thread_args[MAX_THREADS];
    int thread_count = 0;
    
    // 计算IP范围
    if (args->is_cidr) {
        inet_pton(AF_INET, args->target, &ip_addr);
        uint32_t mask = 0xffffffff << (32 - args->cidr);
        network_addr.s_addr = ntohl(ip_addr.s_addr & htonl(mask));
        broadcast_addr.s_addr = ntohl(ip_addr.s_addr | htonl(~mask));
        start_ip = ntohl(network_addr.s_addr);
        end_ip = ntohl(broadcast_addr.s_addr);
    } else if (args->is_range) {
        inet_pton(AF_INET, args->target, &ip_addr);
        start_ip = ntohl(ip_addr.s_addr);
        inet_pton(AF_INET, args->target_end, &ip_addr);
        end_ip = ntohl(ip_addr.s_addr);
    } else {
        inet_pton(AF_INET, args->target, &ip_addr);
        start_ip = end_ip = ntohl(ip_addr.s_addr);
    }
    
    // 初始化全局变量
    total_ips = end_ip - start_ip + 1;
    current_ip = 0;
    scan_results = calloc(total_ips, sizeof(scan_result_t));
    
    for (int i = 0; i < total_ips; i++) {
        pthread_mutex_init(&scan_results[i].mutex, NULL);
    }
    
    log_write(LOG_INFO, "开始扫描IP范围: %s", args->target);
    if (args->is_range || args->is_cidr) {
        ip_addr.s_addr = htonl(end_ip);
        inet_ntop(AF_INET, &ip_addr, current_ip_str, INET_ADDRSTRLEN);
        log_write(LOG_INFO, "结束IP: %s", current_ip_str);
    }
    log_write(LOG_INFO, "端口范围: %u-%u", args->port_start, args->port_end);
    
    // 为每个IP创建扫描线程
    for (current_ip = start_ip; current_ip <= end_ip && running; current_ip++) {
        ip_addr.s_addr = htonl(current_ip);
        inet_ntop(AF_INET, &ip_addr, current_ip_str, INET_ADDRSTRLEN);
        
        thread_args_t *args_ptr = &thread_args[thread_count];
        strncpy(args_ptr->ip, current_ip_str, INET_ADDRSTRLEN);
        args_ptr->port_start = args->port_start;
        args_ptr->port_end = args->port_end;
        args_ptr->scan_type = args->scan_type;
        args_ptr->result = &scan_results[thread_count];
        strncpy(scan_results[thread_count].ip, current_ip_str, INET_ADDRSTRLEN);
        
        pthread_create(&threads[thread_count], NULL, scan_thread, args_ptr);
        
        thread_count++;
        show_progress();
        
        // 等待线程完成，如果达到最大线程数
        if (thread_count >= MAX_THREADS || current_ip == end_ip) {
            for (int i = 0; i < thread_count; i++) {
                pthread_join(threads[i], NULL);
            }
            thread_count = 0;
        }
    }
    
    // 显示最终结果
    show_results();
    
    // 清理资源
    for (int i = 0; i < total_ips; i++) {
        pthread_mutex_destroy(&scan_results[i].mutex);
    }
    free(scan_results);
    
    log_write(LOG_INFO, "扫描完成");
}

int main(int argc, char *argv[]) {
    cmdline_args_t args;
    
    // 显示banner
    show_banner();
    
    // 初始化日志系统
    log_init("ccmap.log");
    
    // 设置信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // 解析命令行参数
    if (parse_args(argc, argv, &args) != 0) {
        return EXIT_FAILURE;
    }
    
    // 执行扫描
    perform_scan(&args);
    
    // 关闭日志系统
    log_close();
    return EXIT_SUCCESS;
}