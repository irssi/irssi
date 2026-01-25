#ifndef IRSSI_CORE_NETWORK_H
#define IRSSI_CORE_NETWORK_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <irssi/src/common.h>

#ifndef AF_INET6
#  ifdef PF_INET6
#    define AF_INET6 PF_INET6
#  else
#    define AF_INET6 10
#  endif
#endif

#if GLIB_CHECK_VERSION(2, 59, 0)
/* nothing */
#else
/* compatibility code for old GLib */

typedef enum {
	G_RESOLVER_NAME_LOOKUP_FLAGS_DEFAULT = 0,
	G_RESOLVER_NAME_LOOKUP_FLAGS_IPV4_ONLY = 1 << 0,
	G_RESOLVER_NAME_LOOKUP_FLAGS_IPV6_ONLY = 1 << 1,
} GResolverNameLookupFlags;

#endif

struct _IPADDR {
	unsigned short family;
	struct in6_addr ip;
};

typedef struct {
	int refcount;
	/* GList<GInetAddress> */
	GList *ailist; /* needs to be freed */
	GError *error; /* needs to be freed */
} RESOLVED_IP_REC;

/* maxmimum string length of IP address */
#define MAX_IP_LEN INET6_ADDRSTRLEN

#define IPADDR_IS_V6(ip) ((ip)->family != AF_INET)

extern IPADDR ip4_any;

GIOChannel *i_io_channel_new(int handle);

/* OTR */
int i_io_channel_write_block(GIOChannel *channel, void *data, int len);
int i_io_channel_read_block(GIOChannel *channel, void *data, int len);

int net_connect_ip_handle(const IPADDR *ip, int port, const IPADDR *my_ip);

/* Connect to socket with ip address and SSL*/
GIOChannel *net_connect_ip_ssl_channel(IPADDR *ip, int port, IPADDR *my_ip, SERVER_REC *server);
/* Start TLS */
GIOChannel *net_start_ssl_channel(SERVER_REC *server);

int irssi_ssl_handshake_channel(GIOChannel *channel);
/* Connect to socket with ip address */
GIOChannel *net_connect_ip_channel(IPADDR *ip, int port, IPADDR *my_ip);
/* Connect to named UNIX socket */
GIOChannel *net_connect_unix_channel(const char *path);
/* Disconnect socket */
void net_disconnect_channel(GIOChannel *channel);
/* Disconnect socket */
void net_disconnect_stream(GIOStream *stream);

/* Listen for connections on a socket */
GIOChannel *net_listen_channel(IPADDR *my_ip, int *port);
/* Accept a connection on a socket */
GIOChannel *net_accept_channel(GIOChannel *channel, IPADDR *addr, int *port);

/* Read data from socket, return number of bytes read, -1 = error */
int net_receive_channel(GIOChannel *channel, char *buf, int len);
/* Read data from stream, return number of bytes read, -1 = error */
int net_receive_stream(GIOStream *stream, char *buf, int len);
/* Transmit data, return number of bytes sent, -1 = error */
int net_transmit_channel(GIOChannel *channel, const char *data, int len);
/* Transmit data, return number of bytes sent, -1 = error */
int net_transmit_stream(GIOStream *stream, const char *data, int len);

/* Get the first IP address for host, both IPv4 and IPv6 if possible. */
int net_gethostbyname_first_ips(const char *addr, GResolverNameLookupFlags flags, IPADDR *ip4,
                                IPADDR *ip6);

/* Get socket address/port */
int net_getsockname_channel(GIOChannel *channel, IPADDR *addr, int *port);

/* IPADDR -> char* translation. `host' must be at least MAX_IP_LEN bytes */
int net_ip2host(IPADDR *ip, char *host);
/* char* -> IPADDR translation. */
int net_host2ip(const char *host, IPADDR *ip);

/* Get socket error */
int net_geterror_channel(GIOChannel *channel);

/* Get name of TCP service */
char *net_getservbyport(int port);

int is_ipv4_address(const char *host);
int is_ipv6_address(const char *host);

void resolved_ip_ref(RESOLVED_IP_REC *iprec);
int resolved_ip_unref(RESOLVED_IP_REC *iprec);

#endif
