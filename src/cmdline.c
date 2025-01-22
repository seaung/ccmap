#include "../include/cmdline.h"

static struct option long_options[] = {
    {"help", no_argument, 0, 'h'},
    {"version", no_argument, 0, 'v'},
    {"target", required_argument, 0, 't'},
    {"port", required_argument, 0, 'p'},
    {"scan", required_argument, 0, 's'},
    {0, 0, 0, 0}
};

void show_help(void) {
    printf("Usage: ccmap [options]\n");
    printf("Options:\n");
    printf("  -h, --help\t\t显示帮助信息\n");
    printf("  -v, --version\t\t显示版本信息\n");
    printf("  -t, --target <ip>\t指定目标IP地址 (支持范围192.168.1.1-192.168.1.254或CIDR 192.168.1.0/24)\n");
    printf("  -p, --port <range>\t指定端口范围 (例如: 80 或 1-1000)\n");
    printf("  -s, --scan <type>\t指定扫描类型 (syn/tcp/udp/ping)\n");
}

void show_version(void) {
    printf("ccmap version %s\n", VERSION);
}

int parse_args(int argc, char *argv[], cmdline_args_t *args) {
    int opt;
    int option_index = 0;
    char *port_range;
    char *scan_type;
    char *target_str;
    char *cidr_pos;
    char *range_pos;

    // 设置默认值
    args->target = NULL;
    args->target_end = NULL;
    args->cidr = 0;
    args->port_start = 0;
    args->port_end = 0;
    args->scan_type = SCAN_TCP;
    args->is_range = 0;
    args->is_cidr = 0;

    while ((opt = getopt_long(argc, argv, "hvt:p:s:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                show_help();
                return -1;
            case 'v':
                show_version();
                return -1;
            case 't':
                target_str = strdup(optarg);
                if ((cidr_pos = strchr(target_str, '/')) != NULL) {
                    // CIDR格式
                    *cidr_pos = '\0';
                    args->target = target_str;
                    args->cidr = atoi(cidr_pos + 1);
                    args->is_cidr = 1;
                    if (args->cidr < 0 || args->cidr > 32) {
                        fprintf(stderr, "错误: 无效的CIDR前缀长度\n");
                        free(target_str);
                        return -1;
                    }
                } else if ((range_pos = strchr(target_str, '-')) != NULL) {
                    // IP范围格式
                    *range_pos = '\0';
                    args->target = target_str;
                    args->target_end = strdup(range_pos + 1);
                    args->is_range = 1;
                } else {
                    // 单个IP
                    args->target = target_str;
                }
                break;
            case 'p':
                port_range = optarg;
                if (strchr(port_range, '-')) {
                    sscanf(port_range, "%u-%u", &args->port_start, &args->port_end);
                } else {
                    args->port_start = args->port_end = atoi(port_range);
                }
                break;
            case 's':
                scan_type = optarg;
                if (strcmp(scan_type, "syn") == 0) {
                    args->scan_type = SCAN_SYN;
                } else if (strcmp(scan_type, "tcp") == 0) {
                    args->scan_type = SCAN_TCP;
                } else if (strcmp(scan_type, "udp") == 0) {
                    args->scan_type = SCAN_UDP;
                } else if (strcmp(scan_type, "ping") == 0) {
                    args->scan_type = SCAN_PING;
                } else {
                    fprintf(stderr, "错误: 无效的扫描类型 '%s'\n", scan_type);
                    return -1;
                }
                break;
            default:
                show_help();
                return -1;
        }
    }

    // 验证必需参数
    if (args->target == NULL) {
        fprintf(stderr, "错误: 必须指定目标IP地址\n");
        return -1;
    }

    if (args->port_start == 0 && args->port_end == 0) {
        fprintf(stderr, "错误: 必须指定端口范围\n");
        return -1;
    }

    if (args->port_start > args->port_end) {
        fprintf(stderr, "错误: 无效的端口范围\n");
        return -1;
    }

    return 0;
}