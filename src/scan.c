#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include "../include/protocol.h"
#include "../include/utils.h"

/**
 * SYN扫描函数 - 发送TCP SYN包进行端口扫描
 * @param target: 目标IP地址
 * @param port: 目标端口
 * @return: 成功返回0，失败返回-1
 */
int syn_scan(char *target, unsigned int port) {
    int sockfd;
    struct sockaddr_in dest;
    char packet[4096];
    struct ipheader *ip = (struct ipheader *)packet;
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ipheader));
    
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("Socket Error");
        return -1;
    }
    
    // 构造IP头
    // 0x45: IPv4(4) + 首部长度5个32位字(5)
    ip->version_len = 0x45;
    ip->tos = 0;
    ip->length = sizeof(struct ipheader) + sizeof(struct tcpheader);
    ip->flag_offset = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->source_addr = inet_addr("192.168.1.2"); // 源IP
    ip->dest_addr = inet_addr(target);
    ip->chcksum = 0;
    ip->chcksum = csum((unsigned short *)ip, sizeof(struct ipheader)/2);
    
    // 构造TCP头
    // 使用随机序列号，设置SYN标志位
    tcp->tcph_srcport = htons(12345);
    tcp->tcph_destport = htons(port);
    tcp->tcph_seqnum = htonl(rand());
    tcp->tcph_acknum = 0;
    tcp->tcph_offset = 5;
    tcp->tcph_flags = 0x02; // SYN
    tcp->tcph_win = htons(5840);
    tcp->tcph_chksum = 0;
    tcp->tcph_urgptr = 0;
    tcp->tcph_chksum = csum((unsigned short *)tcp, sizeof(struct tcpheader)/2);
    
    // 设置目标地址
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = inet_addr(target);
    
    // 发送数据包
    if (sendto(sockfd, packet, ip->length, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("Sendto Error");
        close(sockfd);
        return -1;
    }
    
    close(sockfd);
    return 0;
}

/**
 * PING扫描函数 - 发送ICMP ECHO请求检测主机存活状态
 * @param target: 目标IP地址
 * @param port: 目标端口(ICMP不使用)
 * @return: 成功返回0，失败返回-1
 */
int ping_scan(char *target, unsigned int port) {
    int sockfd;
    struct sockaddr_in dest;
    char packet[4096];
    struct ipheader *ip = (struct ipheader *)packet;
    struct icmpheader *icmp = (struct icmpheader *)(packet + sizeof(struct ipheader));
    
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("Socket Error");
        return -1;
    }
    
    // 构造IP头
    // 0x45: IPv4(4) + 首部长度5个32位字(5)
    ip->version_len = 0x45;
    ip->tos = 0;
    ip->length = sizeof(struct ipheader) + sizeof(struct icmpheader);
    ip->flag_offset = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_ICMP;
    ip->source_addr = inet_addr("192.168.1.2");
    ip->dest_addr = inet_addr(target);
    ip->chcksum = 0;
    ip->chcksum = csum((unsigned short *)ip, sizeof(struct ipheader)/2);
    
    // 设置ICMP头
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->id = htons(getpid());
    icmp->sequeue = htons(1);
    icmp->chcksum = 0;
    icmp->chcksum = csum((unsigned short *)icmp, sizeof(struct icmpheader)/2);
    
    // 设置目标地址
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(target);
    
    // 发送数据包
    if (sendto(sockfd, packet, ip->length, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("Sendto Error");
        close(sockfd);
        return -1;
    }
    
    close(sockfd);
    return 0;
}

/**
 * TCP连接扫描函数 - 尝试建立完整的TCP连接
 * @param target: 目标IP地址
 * @param port: 目标端口
 * @return: 端口开放返回0，关闭返回-1
 */
int tcp_connect_scan(char *target, unsigned int port) {
    int sockfd;
    struct sockaddr_in dest;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket Error");
        return -1;
    }
    
    // 设置目标地址
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = inet_addr(target);
    
    // 尝试连接
    if (connect(sockfd, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        close(sockfd);
        return -1; // 端口关闭
    }
    
    close(sockfd);
    return 0; // 端口开放
}

/**
 * UDP扫描函数 - 发送UDP数据包检测端口状态
 * @param target: 目标IP地址
 * @param port: 目标端口
 * @return: 成功返回0，失败返回-1
 */
int udp_scan(char *target, unsigned int port) {
    int sockfd;
    struct sockaddr_in dest;
    char packet[4096];
    struct ipheader *ip = (struct ipheader *)packet;
    struct udpheader *udp = (struct udpheader *)(packet + sizeof(struct ipheader));
    
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("Socket Error");
        return -1;
    }
    
    // 构造IP头
    // 0x45: IPv4(4) + 首部长度5个32位字(5)
    ip->version_len = 0x45;
    ip->tos = 0;
    ip->length = sizeof(struct ipheader) + sizeof(struct udpheader);
    ip->flag_offset = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->source_addr = inet_addr("192.168.1.2");
    ip->dest_addr = inet_addr(target);
    ip->chcksum = 0;
    ip->chcksum = csum((unsigned short *)ip, sizeof(struct ipheader)/2);
    
    // 设置UDP头
    udp->udph_srcport = htons(12345);
    udp->udph_destport = htons(port);
    udp->udph_len = htons(sizeof(struct udpheader));
    udp->udph_chksum = 0;
    udp->udph_chksum = csum((unsigned short *)udp, sizeof(struct udpheader)/2);
    
    // 设置目标地址
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = inet_addr(target);
    
    // 发送数据包
    if (sendto(sockfd, packet, ip->length, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("Sendto Error");
        close(sockfd);
        return -1;
    }
    
    close(sockfd);
    return 0;
}