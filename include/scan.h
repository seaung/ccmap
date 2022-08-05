#ifndef __SCAN_H_
#define __SCAN_H_

int syn_scan(char *target, unsigned int port);

int ping_scan(char *target, unsigned int port);

int tcp_connect_scan(char *target, unsigned int port);

int udp_scan(char *target, unsigned int port);

#endif
