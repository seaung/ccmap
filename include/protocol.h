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

typedef struct ipheader {
	unsigned char version_len;
	unsigned char tos;
	unsigned short length;
	unsigned short flag_offset;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short chcksum;
	unsigned int source_addr;
	unsigned int dest_addr;
}ipheader;

typedef struct icmpheader {
	u_int8_t type;
	u_int8_t code;
	unsigned short chcksum;
	unsigned short id;
	unsigned short sequeue;
}icmpheader;

#endif
