#ifndef __NETWORK_H
#define __NETWORK_H

#ifdef HAVE_SOCKS_H
#include <socks.h>
#endif

#include <sys/types.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <netdb.h>
#  include <arpa/inet.h>

#ifndef AF_INET6
#  ifdef PF_INET6
#    define AF_INET6 PF_INET6
#  else
#    define AF_INET6 10
#  endif
#endif

struct _IPADDR {
	unsigned short family;
	struct in6_addr ip;
};

/* maxmimum string length of IP address */
#define MAX_IP_LEN INET6_ADDRSTRLEN

#define IPADDR_IS_V6(ip) ((ip)->family != AF_INET)

extern IPADDR ip4_any;

GIOChannel *g_io_channel_new(int handle);

/* Returns 1 if IPADDRs are the same. */
/* Deprecated since it is unused. It will be deleted in a later release. */
int net_ip_compare(IPADDR *ip1, IPADDR *ip2) G_GNUC_DEPRECATED;
int g_io_channel_write_block(GIOChannel *channel, void *data, int len);
int g_io_channel_read_block(GIOChannel *channel, void *data, int len);

int net_connect_ip_handle(const IPADDR *ip, int port, const IPADDR *my_ip);

/* Connect to socket with ip address and SSL*/
GIOChannel *net_connect_ip_ssl(IPADDR *ip, int port, IPADDR *my_ip, SERVER_REC *server);
/* Start TLS */
GIOChannel *net_start_ssl(SERVER_REC *server);

int irssi_ssl_handshake(GIOChannel *handle);
/* Connect to socket with ip address */
GIOChannel *net_connect_ip(IPADDR *ip, int port, IPADDR *my_ip);
/* Connect to named UNIX socket */
GIOChannel *net_connect_unix(const char *path);
/* Disconnect socket */
void net_disconnect(GIOChannel *handle);

/* Listen for connections on a socket */
GIOChannel *net_listen(IPADDR *my_ip, int *port);
/* Accept a connection on a socket */
GIOChannel *net_accept(GIOChannel *handle, IPADDR *addr, int *port);

/* Read data from socket, return number of bytes read, -1 = error */
int net_receive(GIOChannel *handle, char *buf, int len);
/* Transmit data, return number of bytes sent, -1 = error */
int net_transmit(GIOChannel *handle, const char *data, int len);

/* Get IP addresses for host, both IPv4 and IPv6 if possible.
   If ip->family is 0, the address wasn't found.
   Returns 0 = ok, others = error code for net_gethosterror() */
int net_gethostbyname(const char *addr, IPADDR *ip4, IPADDR *ip6);
/* Get name for host, *name should be g_free()'d unless it's NULL.
   Return values are the same as with net_gethostbyname() */
int net_gethostbyaddr(IPADDR *ip, char **name);
/* get error of net_gethostname() */
const char *net_gethosterror(int error);
/* return TRUE if host lookup failed because it didn't exist (ie. not
   some error with name server) */
int net_hosterror_notfound(int error);

/* Get socket address/port */
int net_getsockname(GIOChannel *handle, IPADDR *addr, int *port);

/* IPADDR -> char* translation. `host' must be at least MAX_IP_LEN bytes */
int net_ip2host(IPADDR *ip, char *host);
/* char* -> IPADDR translation. */
int net_host2ip(const char *host, IPADDR *ip);

/* Get socket error */
int net_geterror(GIOChannel *handle);

/* Get name of TCP service */
char *net_getservbyport(int port);

int is_ipv4_address(const char *host);
int is_ipv6_address(const char *host);

#endif
