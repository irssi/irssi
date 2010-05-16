/*
 network.c : Network stuff

    Copyright (C) 1999-2000 Timo Sirainen

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include "network.h"

#include <sys/un.h>

#ifndef INADDR_NONE
#  define INADDR_NONE INADDR_BROADCAST
#endif

union sockaddr_union {
	struct sockaddr sa;
	struct sockaddr_in sin;
#ifdef HAVE_IPV6
	struct sockaddr_in6 sin6;
#endif
};

#ifdef HAVE_IPV6
#  define SIZEOF_SOCKADDR(so) ((so).sa.sa_family == AF_INET6 ? \
	sizeof(so.sin6) : sizeof(so.sin))
#else
#  define SIZEOF_SOCKADDR(so) (sizeof(so.sin))
#endif

GIOChannel *g_io_channel_new(int handle)
{
	GIOChannel *chan;
#ifdef WIN32
	chan = g_io_channel_win32_new_socket(handle);
#else
	chan = g_io_channel_unix_new(handle);
#endif
	g_io_channel_set_encoding(chan, NULL, NULL);
	g_io_channel_set_buffered(chan, FALSE);
	return chan;
}

/* Cygwin need this, don't know others.. */
/*#define BLOCKING_SOCKETS 1*/

IPADDR ip4_any = {
	AF_INET,
	{ INADDR_ANY }
};

int net_ip_compare(IPADDR *ip1, IPADDR *ip2)
{
	if (ip1->family != ip2->family)
		return 0;

#ifdef HAVE_IPV6
	if (ip1->family == AF_INET6)
		return memcmp(&ip1->ip, &ip2->ip, sizeof(ip1->ip)) == 0;
#endif

	return memcmp(&ip1->ip, &ip2->ip, 4) == 0;
}


static void sin_set_ip(union sockaddr_union *so, const IPADDR *ip)
{
	if (ip == NULL) {
#ifdef HAVE_IPV6
		so->sin6.sin6_family = AF_INET6;
		so->sin6.sin6_addr = in6addr_any;
#else
		so->sin.sin_family = AF_INET;
		so->sin.sin_addr.s_addr = INADDR_ANY;
#endif
		return;
	}

	so->sin.sin_family = ip->family;
#ifdef HAVE_IPV6
	if (ip->family == AF_INET6)
		memcpy(&so->sin6.sin6_addr, &ip->ip, sizeof(ip->ip));
	else
#endif
		memcpy(&so->sin.sin_addr, &ip->ip, 4);
}

void sin_get_ip(const union sockaddr_union *so, IPADDR *ip)
{
	ip->family = so->sin.sin_family;

#ifdef HAVE_IPV6
	if (ip->family == AF_INET6)
		memcpy(&ip->ip, &so->sin6.sin6_addr, sizeof(ip->ip));
	else
#endif
		memcpy(&ip->ip, &so->sin.sin_addr, 4);
}

static void sin_set_port(union sockaddr_union *so, int port)
{
#ifdef HAVE_IPV6
	if (so->sin.sin_family == AF_INET6)
                so->sin6.sin6_port = htons((unsigned short)port);
	else
#endif
		so->sin.sin_port = htons((unsigned short)port);
}

static int sin_get_port(union sockaddr_union *so)
{
#ifdef HAVE_IPV6
	if (so->sin.sin_family == AF_INET6)
		return ntohs(so->sin6.sin6_port);
#endif
	return ntohs(so->sin.sin_port);
}

/* Connect to socket */
GIOChannel *net_connect(const char *addr, int port, IPADDR *my_ip)
{
	IPADDR ip4, ip6, *ip;

	g_return_val_if_fail(addr != NULL, NULL);

	if (net_gethostbyname(addr, &ip4, &ip6) == -1)
		return NULL;

	if (my_ip == NULL) {
                /* prefer IPv4 addresses */
		ip = ip4.family != 0 ? &ip4 : &ip6;
	} else if (IPADDR_IS_V6(my_ip)) {
                /* my_ip is IPv6 address, use it if possible */
		if (ip6.family != 0)
			ip = &ip6;
		else {
			my_ip = NULL;
                        ip = &ip4;
		}
	} else {
                /* my_ip is IPv4 address, use it if possible */
		if (ip4.family != 0)
			ip = &ip4;
		else {
			my_ip = NULL;
                        ip = &ip6;
		}
	}

	return net_connect_ip(ip, port, my_ip);
}

/* Connect to socket with ip address */
GIOChannel *net_connect_ip(IPADDR *ip, int port, IPADDR *my_ip)
{
	union sockaddr_union so;
	int handle, ret, opt = 1;

	if (my_ip != NULL && ip->family != my_ip->family) {
		g_warning("net_connect_ip(): ip->family != my_ip->family");
                my_ip = NULL;
	}

	/* create the socket */
	memset(&so, 0, sizeof(so));
        so.sin.sin_family = ip->family;
	handle = socket(ip->family, SOCK_STREAM, 0);

	if (handle == -1)
		return NULL;

	/* set socket options */
#ifndef WIN32
	fcntl(handle, F_SETFL, O_NONBLOCK);
#endif
	setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	setsockopt(handle, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));

	/* set our own address */
	if (my_ip != NULL) {
		sin_set_ip(&so, my_ip);
		if (bind(handle, &so.sa, SIZEOF_SOCKADDR(so)) < 0) {
			int old_errno = errno;

			close(handle);
			errno = old_errno;
			return NULL;
		}
	}

	/* connect */
	sin_set_ip(&so, ip);
	sin_set_port(&so, port);
	ret = connect(handle, &so.sa, SIZEOF_SOCKADDR(so));

#ifndef WIN32
	if (ret < 0 && errno != EINPROGRESS)
#else
	if (ret < 0 && WSAGetLastError() != WSAEWOULDBLOCK)
#endif
	{
		int old_errno = errno;
		close(handle);
		errno = old_errno;
		return NULL;
	}

	return g_io_channel_new(handle);
}

/* Connect to named UNIX socket */
GIOChannel *net_connect_unix(const char *path)
{
	struct sockaddr_un sa;
	int handle, ret;

	/* create the socket */
	handle = socket(PF_UNIX, SOCK_STREAM, 0);
	if (handle == -1)
		return NULL;

	/* set socket options */
#ifndef WIN32
	fcntl(handle, F_SETFL, O_NONBLOCK);
#endif

	/* connect */
	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, path, sizeof(sa.sun_path)-1);
	sa.sun_path[sizeof(sa.sun_path)-1] = '\0';

	ret = connect(handle, (struct sockaddr *) &sa, sizeof(sa));
	if (ret < 0 && errno != EINPROGRESS) {
		int old_errno = errno;
		close(handle);
		errno = old_errno;
		return NULL;
	}

	return g_io_channel_new(handle);
}

/* Disconnect socket */
void net_disconnect(GIOChannel *handle)
{
	g_return_if_fail(handle != NULL);

	g_io_channel_close(handle);
	g_io_channel_unref(handle);
}

/* Listen for connections on a socket. if `my_ip' is NULL, listen in any
   address. */
GIOChannel *net_listen(IPADDR *my_ip, int *port)
{
	union sockaddr_union so;
	int ret, handle, opt = 1;
	socklen_t len;

	g_return_val_if_fail(port != NULL, NULL);

	memset(&so, 0, sizeof(so));
	sin_set_ip(&so, my_ip);
	sin_set_port(&so, *port);

	/* create the socket */
	handle = socket(so.sin.sin_family, SOCK_STREAM, 0);
#ifdef HAVE_IPV6
	if (handle == -1 && (errno == EINVAL || errno == EAFNOSUPPORT)) {
		/* IPv6 is not supported by OS */
		so.sin.sin_family = AF_INET;
		so.sin.sin_addr.s_addr = INADDR_ANY;

		handle = socket(AF_INET, SOCK_STREAM, 0);
	}
#endif
	if (handle == -1)
		return NULL;

	/* set socket options */
#ifndef WIN32
	fcntl(handle, F_SETFL, O_NONBLOCK);
#endif
	setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	setsockopt(handle, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));

	/* specify the address/port we want to listen in */
	ret = bind(handle, &so.sa, SIZEOF_SOCKADDR(so));
	if (ret >= 0) {
		/* get the actual port we started listen */
		len = SIZEOF_SOCKADDR(so);
		ret = getsockname(handle, &so.sa, &len);
		if (ret >= 0) {
			*port = sin_get_port(&so);

			/* start listening */
			if (listen(handle, 1) >= 0)
                                return g_io_channel_new(handle);
		}

	}

        /* error */
	close(handle);
	return NULL;
}

/* Accept a connection on a socket */
GIOChannel *net_accept(GIOChannel *handle, IPADDR *addr, int *port)
{
	union sockaddr_union so;
	int ret;
	socklen_t addrlen;

	g_return_val_if_fail(handle != NULL, NULL);

	addrlen = sizeof(so);
	ret = accept(g_io_channel_unix_get_fd(handle), &so.sa, &addrlen);

	if (ret < 0)
		return NULL;

	if (addr != NULL) sin_get_ip(&so, addr);
	if (port != NULL) *port = sin_get_port(&so);

#ifndef WIN32
	fcntl(ret, F_SETFL, O_NONBLOCK);
#endif
	return g_io_channel_new(ret);
}

/* Read data from socket, return number of bytes read, -1 = error */
int net_receive(GIOChannel *handle, char *buf, int len)
{
        gsize ret;
	GIOStatus status;
	GError *err = NULL;

	g_return_val_if_fail(handle != NULL, -1);
	g_return_val_if_fail(buf != NULL, -1);

	status = g_io_channel_read_chars(handle, buf, len, &ret, &err);
	if (err != NULL) {
	        g_warning(err->message);
	        g_error_free(err);
	}
	if (status == G_IO_STATUS_ERROR || status == G_IO_STATUS_EOF)
		return -1; /* disconnected */

	return ret;
}

/* Transmit data, return number of bytes sent, -1 = error */
int net_transmit(GIOChannel *handle, const char *data, int len)
{
        gsize ret;
	GIOStatus status;
	GError *err = NULL;

	g_return_val_if_fail(handle != NULL, -1);
	g_return_val_if_fail(data != NULL, -1);

	status = g_io_channel_write_chars(handle, (char *) data, len, &ret, &err);
	if (err != NULL) {
	        g_warning(err->message);
	        g_error_free(err);
	}
	if (status == G_IO_STATUS_ERROR)
		return -1;

	return ret;
}

/* Get socket address/port */
int net_getsockname(GIOChannel *handle, IPADDR *addr, int *port)
{
	union sockaddr_union so;
	socklen_t addrlen;

	g_return_val_if_fail(handle != NULL, -1);
	g_return_val_if_fail(addr != NULL, -1);

	addrlen = sizeof(so);
	if (getsockname(g_io_channel_unix_get_fd(handle),
			(struct sockaddr *) &so, &addrlen) == -1)
		return -1;

        sin_get_ip(&so, addr);
	if (port) *port = sin_get_port(&so);

	return 0;
}

/* Get IP addresses for host, both IPv4 and IPv6 if possible.
   If ip->family is 0, the address wasn't found.
   Returns 0 = ok, others = error code for net_gethosterror() */
int net_gethostbyname(const char *addr, IPADDR *ip4, IPADDR *ip6)
{
#ifdef HAVE_IPV6
	union sockaddr_union *so;
	struct addrinfo hints, *ai, *ailist;
	int ret, count_v4, count_v6, use_v4, use_v6;
#else
	struct hostent *hp;
	int count;
#endif

	g_return_val_if_fail(addr != NULL, -1);

	memset(ip4, 0, sizeof(IPADDR));
	memset(ip6, 0, sizeof(IPADDR));

#ifdef HAVE_IPV6
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_socktype = SOCK_STREAM;

	/* save error to host_error for later use */
	ret = getaddrinfo(addr, NULL, &hints, &ailist);
	if (ret != 0)
		return ret;

	/* count IPs */
        count_v4 = count_v6 = 0;
	for (ai = ailist; ai != NULL; ai = ai->ai_next) {
		if (ai->ai_family == AF_INET)
			count_v4++;
		else if (ai->ai_family == AF_INET6)
			count_v6++;
	}

	if (count_v4 == 0 && count_v6 == 0)
		return HOST_NOT_FOUND; /* shouldn't happen? */

	/* if there are multiple addresses, return random one */
	use_v4 = count_v4 <= 1 ? 0 : rand() % count_v4;
	use_v6 = count_v6 <= 1 ? 0 : rand() % count_v6;

	count_v4 = count_v6 = 0;
	for (ai = ailist; ai != NULL; ai = ai->ai_next) {
		so = (union sockaddr_union *) ai->ai_addr;

		if (ai->ai_family == AF_INET) {
			if (use_v4 == count_v4)
				sin_get_ip(so, ip4);
                        count_v4++;
		} else if (ai->ai_family == AF_INET6) {
			if (use_v6 == count_v6)
				sin_get_ip(so, ip6);
			count_v6++;
		}
	}
	freeaddrinfo(ailist);
	return 0;
#else
	hp = gethostbyname(addr);
	if (hp == NULL)
		return h_errno;

	/* count IPs */
	count = 0;
	while (hp->h_addr_list[count] != NULL)
		count++;

	if (count == 0)
		return HOST_NOT_FOUND; /* shouldn't happen? */

	/* if there are multiple addresses, return random one */
	ip4->family = AF_INET;
	memcpy(&ip4->ip, hp->h_addr_list[rand() % count], 4);

	return 0;
#endif
}

/* Get name for host, *name should be g_free()'d unless it's NULL.
   Return values are the same as with net_gethostbyname() */
int net_gethostbyaddr(IPADDR *ip, char **name)
{
#ifdef HAVE_IPV6
	union sockaddr_union so;
	int host_error;
	char hostname[NI_MAXHOST];
#else
	struct hostent *hp;
#endif

	g_return_val_if_fail(ip != NULL, -1);
	g_return_val_if_fail(name != NULL, -1);

	*name = NULL;
#ifdef HAVE_IPV6
	memset(&so, 0, sizeof(so));
	sin_set_ip(&so, ip);

	/* save error to host_error for later use */
        host_error = getnameinfo((struct sockaddr *) &so, sizeof(so),
                                 hostname, sizeof(hostname), NULL, 0, 0);
        if (host_error != 0)
                return host_error;

	*name = g_strdup(hostname);
#else
	if (ip->family != AF_INET) return -1;
	hp = gethostbyaddr((const char *) &ip->ip, 4, AF_INET);
	if (hp == NULL) return -1;

	*name = g_strdup(hp->h_name);
#endif

	return 0;
}

int net_ip2host(IPADDR *ip, char *host)
{
#ifdef HAVE_IPV6
	if (!inet_ntop(ip->family, &ip->ip, host, MAX_IP_LEN))
		return -1;
#else
	unsigned long ip4;

	if (ip->family != AF_INET) {
		strcpy(host, "0.0.0.0");
	} else {
		ip4 = ntohl(ip->ip.s_addr);
		g_snprintf(host, MAX_IP_LEN, "%lu.%lu.%lu.%lu",
			   (ip4 & 0xff000000UL) >> 24,
			   (ip4 & 0x00ff0000) >> 16,
			   (ip4 & 0x0000ff00) >> 8,
			   (ip4 & 0x000000ff));
	}
#endif
	return 0;
}

int net_host2ip(const char *host, IPADDR *ip)
{
	unsigned long addr;

	if (strchr(host, ':') != NULL) {
		/* IPv6 */
		ip->family = AF_INET6;
#ifdef HAVE_IPV6
		if (inet_pton(AF_INET6, host, &ip->ip) == 0)
			return -1;
#else
		ip->ip.s_addr = 0;
#endif
	} else {
		/* IPv4 */
		ip->family = AF_INET;
#ifdef HAVE_INET_ATON
		if (inet_aton(host, &ip->ip.s_addr) == 0)
			return -1;
#else
		addr = inet_addr(host);
		if (addr == INADDR_NONE)
			return -1;

		memcpy(&ip->ip, &addr, 4);
#endif
	}

	return 0;
}

/* Get socket error */
int net_geterror(GIOChannel *handle)
{
	int data;
	socklen_t len = sizeof(data);

	if (getsockopt(g_io_channel_unix_get_fd(handle),
		       SOL_SOCKET, SO_ERROR, (void *) &data, &len) == -1)
		return -1;

	return data;
}

/* get error of net_gethostname() */
const char *net_gethosterror(int error)
{
#ifdef HAVE_IPV6
	g_return_val_if_fail(error != 0, NULL);

	return gai_strerror(error);
#else
	switch (error) {
	case HOST_NOT_FOUND:
		return "Host not found";
	case NO_ADDRESS:
		return "No IP address found for name";
	case NO_RECOVERY:
		return "A non-recovable name server error occurred";
	case TRY_AGAIN:
		return "A temporary error on an authoritative name server";
	}

	/* unknown error */
	return NULL;
#endif
}

/* return TRUE if host lookup failed because it didn't exist (ie. not
   some error with name server) */
int net_hosterror_notfound(int error)
{
#ifdef HAVE_IPV6
#ifdef EAI_NODATA /* NODATA is depricated */
	return error != 1 && (error == EAI_NONAME || error == EAI_NODATA);
#else
	return error != 1 && (error == EAI_NONAME);
#endif
#else
	return error == HOST_NOT_FOUND || error == NO_ADDRESS;
#endif
}

/* Get name of TCP service */
char *net_getservbyport(int port)
{
	struct servent *entry;

	entry = getservbyport(htons((unsigned short) port), "tcp");
	return entry == NULL ? NULL : entry->s_name;
}

int is_ipv4_address(const char *host)
{
	while (*host != '\0') {
		if (*host != '.' && !i_isdigit(*host))
			return 0;
                host++;
	}

	return 1;
}

int is_ipv6_address(const char *host)
{
	while (*host != '\0') {
		if (*host != ':' && !i_isxdigit(*host))
			return 0;
                host++;
	}

	return 1;
}
