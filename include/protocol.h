#ifndef __PROTOCOL_H_
#define __PROTOCOL_H_

#define TIMEOUT 1000

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

// IP协议头结构体
typedef struct ipheader {
	unsigned char version_len;    // IP版本号(4位)和首部长度(4位)
	unsigned char tos;            // 服务类型
	unsigned short length;        // 总长度
	unsigned short flag_offset;   // 标志(3位)和片偏移(13位)
	unsigned char ttl;            // 生存时间
	unsigned char protocol;       // 协议类型(TCP/UDP/ICMP等)
	unsigned short chcksum;       // 首部校验和
	unsigned int source_addr;     // 源IP地址
	unsigned int dest_addr;       // 目标IP地址
}ipheader;

// ICMP协议头结构体
typedef struct icmpheader {
	u_int8_t type;               // ICMP报文类型
	u_int8_t code;               // 代码
	unsigned short chcksum;       // 校验和
	unsigned short id;            // 标识符
	unsigned short sequeue;       // 序列号
}icmpheader;

// UDP协议头结构体
typedef struct udpheader {
	unsigned short int udph_srcport;  // 源端口
	unsigned short int udph_destport; // 目标端口
	unsigned short int udph_len;      // UDP数据报长度
	unsigned short int udph_chksum;   // 校验和
}udpheader;

// TCP协议头结构体
typedef struct tcpheader {
	unsigned short int tcph_srcport;  // 源端口
	unsigned short int tcph_destport; // 目标端口
	unsigned int tcph_seqnum;         // 序列号
	unsigned int tcph_acknum;         // 确认号
	unsigned char tcph_reserved:4,     // 保留位(4位)
	            tcph_offset:4;        // 数据偏移(4位)
	unsigned char tcph_flags;         // 标志位(URG,ACK,PSH,RST,SYN,FIN)
	unsigned short int tcph_win;      // 窗口大小
	unsigned short int tcph_chksum;   // 校验和
	unsigned short int tcph_urgptr;   // 紧急指针
}tcpheader;

#endif
