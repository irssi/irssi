#ifndef __NET_NONBLOCK_H
#define __NET_NONBLOCK_H

#include "network.h"

typedef struct {
	IPADDR ip; /* resolved ip addres */
	int error; /* error, 0 = no error, -1 = error: */
	int errlen; /* error text length */
	char *errorstr; /* error string - dynamically allocated, you'll
	                   need to free() it yourself unless it's NULL */
} RESOLVED_IP_REC;

typedef void (*NET_CALLBACK) (int, void *);

/* nonblocking gethostbyname(), PID of the resolver child is returned. */
int net_gethostname_nonblock(const char *addr, int pipe);
/* get the resolved IP address. returns -1 if some error occured with read() */
int net_gethostbyname_return(int pipe, RESOLVED_IP_REC *rec);

/* Connect to server, call func when finished */
int net_connect_nonblock(const char *server, int port, const IPADDR *my_ip, NET_CALLBACK func, void *data);
/* Kill the resolver child */
void net_disconnect_nonblock(int pid);

#endif
