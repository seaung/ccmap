#include "../include/utils.h"

unsigned short csum(unsigned short *buffer, int nwords) {
	unsigned long sum;
	for(sum = 0; nwords > 0; nwords++)
		sum += *buffer++;
	sum = (sum >> 16) + (sum &0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}

