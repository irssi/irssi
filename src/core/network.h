#ifndef __NETWORK_H
#define __NETWORK_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

struct _ipaddr {
	unsigned short family;
	union {
#ifdef HAVE_IPV6
		struct in6_addr ip6;
#else
		struct in_addr ip;
#endif
	} addr;
};

typedef struct _ipaddr IPADDR;

/* maxmimum string length of IP address */
#ifdef HAVE_IPV6
#  define MAX_IP_LEN INET6_ADDRSTRLEN
#else
#  define MAX_IP_LEN 20
#endif

#define is_ipv6_addr(ip) ((ip)->family != AF_INET)

/* returns 1 if IPADDRs are the same */
int net_ip_compare(IPADDR *ip1, IPADDR *ip2);

/* Connect to socket */
int net_connect(const char *addr, int port, IPADDR *my_ip);
/* Connect to socket with ip address */
int net_connect_ip(IPADDR *ip, int port, IPADDR *my_ip);
/* Disconnect socket */
void net_disconnect(int handle);
/* Try to let the other side close the connection, if it still isn't
   disconnected after certain amount of time, close it ourself */
void net_disconnect_later(int handle);

/* Listen for connections on a socket */
int net_listen(IPADDR *my_ip, int *port);
/* Accept a connection on a socket */
int net_accept(int handle, IPADDR *addr, int *port);

/* Read data from socket, return number of bytes read, -1 = error */
int net_receive(int handle, char *buf, int len);
/* Transmit data, return number of bytes sent, -1 = error */
int net_transmit(int handle, const char *data, int len);

/* Get IP address for host, returns 0 = ok,
   others = error code for net_gethosterror() */
int net_gethostbyname(const char *addr, IPADDR *ip);
/* Get name for host, *name should be g_free()'d unless it's NULL.
   Return values are the same as with net_gethostbyname() */
int net_gethostbyaddr(IPADDR *ip, char **name);
/* get error of net_gethostname() */
const char *net_gethosterror(int error);
/* return TRUE if host lookup failed because it didn't exist (ie. not
   some error with name server) */
int net_hosterror_notfound(int error);

/* Get socket address/port */
int net_getsockname(int handle, IPADDR *addr, int *port);

int net_ip2host(IPADDR *ip, char *host);
int net_host2ip(const char *host, IPADDR *ip);

/* Get socket error */
int net_geterror(int handle);

int is_ipv4_address(const char *host);
int is_ipv6_address(const char *host);

#endif
