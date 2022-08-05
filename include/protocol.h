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

typedef struct udpheader {
	unsigned short int udph_srcport;
	unsigned short int udph_destport;
	unsigned short int udph_len;
	unsigned short int udph_chksum;
}udpheader;

typedef struct tcpheader {
	unsigned short int tcph_srcport;
	unsigned short int tcph_destport;
	unsigned int tcph_seqnum;
	unsigned int tcph_acknum;
	unsigned char tcph_reserved:4, tcph_offset:4;
	unsigned char tcph_flags;
	unsigned short int tcph_win;
	unsigned short int tcph_chksum;
	unsigned short int tcph_urgptr;
}tcpheader;

#endif
