#ifndef __NET_NONBLOCK_H
#define __NET_NONBLOCK_H

#include "network.h"

typedef struct {
	IPADDR ip4, ip6; /* resolved ip addresses */
	int error; /* error, 0 = no error, -1 = error: */
	int errlen; /* error text length */
	char *errorstr; /* error string - dynamically allocated, you'll
	                   need to free() it yourself unless it's NULL */
	char *host4, *host6; /* dito */
} RESOLVED_IP_REC;

typedef struct {
        int namelen;
	char *name;

	int error;
	int errlen;
	char *errorstr;
} RESOLVED_NAME_REC;

typedef void (*NET_CALLBACK) (GIOChannel *, void *);
typedef void (*NET_HOST_CALLBACK) (RESOLVED_NAME_REC *, void *);

/* nonblocking gethostbyname(), PID of the resolver child is returned. */
int net_gethostbyname_nonblock(const char *addr, GIOChannel *pipe,
			       int reverse_lookup);
/* Get host's name, call func when finished */
int net_gethostbyaddr_nonblock(IPADDR *ip, NET_HOST_CALLBACK func, void *data);
/* get the resolved IP address. returns -1 if some error occured with read() */
int net_gethostbyname_return(GIOChannel *pipe, RESOLVED_IP_REC *rec);

/* Connect to server, call func when finished */
int net_connect_nonblock(const char *server, int port, const IPADDR *my_ip,
			 NET_CALLBACK func, void *data);
/* Kill the resolver child */
void net_disconnect_nonblock(int pid);

#endif
