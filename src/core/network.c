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
#include <irssi/src/core/network.h>
#ifdef HAVE_CAPSICUM
#include <irssi/src/core/capsicum.h>
#endif

#include <sys/un.h>

#ifndef INADDR_NONE
#  define INADDR_NONE INADDR_BROADCAST
#endif

union sockaddr_union {
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
};

#define SIZEOF_SOCKADDR(so) ((so).sa.sa_family == AF_INET6 ? \
	sizeof(so.sin6) : sizeof(so.sin))

GIOChannel *i_io_channel_new(int handle)
{
	GIOChannel *chan;
	chan = g_io_channel_unix_new(handle);
	g_io_channel_set_encoding(chan, NULL, NULL);
	g_io_channel_set_buffered(chan, FALSE);
	return chan;
}

int i_io_channel_write_block(GIOChannel *channel, void *data, int len)
{
	gsize ret;
	int sent;
	GIOStatus status;

	sent = 0;
	do {
		status = g_io_channel_write_chars(channel, (char *) data + sent, len - sent, &ret, NULL);
		sent += ret;
	} while (sent < len && status != G_IO_STATUS_ERROR);

	return sent < len ? -1 : 0;
}

int i_io_channel_read_block(GIOChannel *channel, void *data, int len)
{
	time_t maxwait;
	gsize ret;
	int received;
	GIOStatus status;

	maxwait = time(NULL)+2;
	received = 0;
	do {
		status = g_io_channel_read_chars(channel, (char *) data + received, len - received, &ret, NULL);
		received += ret;
	} while (received < len && time(NULL) < maxwait &&
		status != G_IO_STATUS_ERROR && status != G_IO_STATUS_EOF);

	return received < len ? -1 : 0;
}

IPADDR ip4_any = {
	AF_INET,
#if defined(IN6ADDR_ANY_INIT)
	IN6ADDR_ANY_INIT
#else
	{ INADDR_ANY }
#endif
};

int net_ip_compare(IPADDR *ip1, IPADDR *ip2)
{
	if (ip1->family != ip2->family)
		return 0;

	if (ip1->family == AF_INET6)
		return memcmp(&ip1->ip, &ip2->ip, sizeof(ip1->ip)) == 0;

	return memcmp(&ip1->ip, &ip2->ip, 4) == 0;
}


static void sin_set_ip(union sockaddr_union *so, const IPADDR *ip)
{
	if (ip == NULL) {
		so->sin6.sin6_family = AF_INET6;
		so->sin6.sin6_addr = in6addr_any;
		return;
	}

	so->sin.sin_family = ip->family;

	if (ip->family == AF_INET6)
		memcpy(&so->sin6.sin6_addr, &ip->ip, sizeof(ip->ip));
	else
		memcpy(&so->sin.sin_addr, &ip->ip, 4);
}

void sin_get_ip(const union sockaddr_union *so, IPADDR *ip)
{
	ip->family = so->sin.sin_family;

	if (ip->family == AF_INET6)
		memcpy(&ip->ip, &so->sin6.sin6_addr, sizeof(ip->ip));
	else
		memcpy(&ip->ip, &so->sin.sin_addr, 4);
}

static void sin_set_port(union sockaddr_union *so, int port)
{
	if (so->sin.sin_family == AF_INET6)
                so->sin6.sin6_port = htons((unsigned short)port);
	else
		so->sin.sin_port = htons((unsigned short)port);
}

static int sin_get_port(union sockaddr_union *so)
{
	return ntohs((so->sin.sin_family == AF_INET6) ?
		     so->sin6.sin6_port :
		     so->sin.sin_port);
}

int net_connect_ip_handle(const IPADDR *ip, int port, const IPADDR *my_ip)
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
		return -1;

	/* set socket options */
	fcntl(handle, F_SETFL, O_NONBLOCK);
	setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	setsockopt(handle, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));

	/* set our own address */
	if (my_ip != NULL) {
		sin_set_ip(&so, my_ip);
		if (bind(handle, &so.sa, SIZEOF_SOCKADDR(so)) < 0) {
			int old_errno = errno;

			close(handle);
			errno = old_errno;
			return -1;
		}
	}

	/* connect */
	sin_set_ip(&so, ip);
	sin_set_port(&so, port);
	ret = connect(handle, &so.sa, SIZEOF_SOCKADDR(so));

	if (ret < 0 && errno != EINPROGRESS)
	{
		int old_errno = errno;
		close(handle);
		errno = old_errno;
		return -1;
	}

	return handle;
}

/* Connect to socket with ip address */
GIOChannel *net_connect_ip(IPADDR *ip, int port, IPADDR *my_ip)
{
	int handle = -1;

#ifdef HAVE_CAPSICUM
	if (capsicum_enabled())
		handle = capsicum_net_connect_ip(ip, port, my_ip);
	else
		handle = net_connect_ip_handle(ip, port, my_ip);
#else
	handle = net_connect_ip_handle(ip, port, my_ip);
#endif

	if (handle == -1)
		return (NULL);

	return i_io_channel_new(handle);
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
	fcntl(handle, F_SETFL, O_NONBLOCK);

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

	return i_io_channel_new(handle);
}

/* Disconnect socket */
void net_disconnect(GIOChannel *handle)
{
	g_return_if_fail(handle != NULL);

	g_io_channel_shutdown(handle, TRUE, NULL);
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

	if (handle == -1 && (errno == EINVAL || errno == EAFNOSUPPORT)) {
		/* IPv6 is not supported by OS */
		so.sin.sin_family = AF_INET;
		so.sin.sin_addr.s_addr = INADDR_ANY;

		handle = socket(AF_INET, SOCK_STREAM, 0);
	}

	if (handle == -1)
		return NULL;

	/* set socket options */
	fcntl(handle, F_SETFL, O_NONBLOCK);
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
				return i_io_channel_new(handle);
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

	fcntl(ret, F_SETFL, O_NONBLOCK);
	return i_io_channel_new(ret);
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
	        g_warning("%s", err->message);
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
	        g_warning("%s", err->message);
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
	union sockaddr_union *so;
	struct addrinfo hints, *ai, *ailist;
	int ret, count_v4, count_v6, use_v4, use_v6;

#ifdef HAVE_CAPSICUM
	if (capsicum_enabled())
		return (capsicum_net_gethostbyname(addr, ip4, ip6));
#endif

	g_return_val_if_fail(addr != NULL, -1);

	memset(ip4, 0, sizeof(IPADDR));
	memset(ip6, 0, sizeof(IPADDR));

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG;

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
		return EAI_NONAME; /* shouldn't happen? */

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
}

/* Get name for host, *name should be g_free()'d unless it's NULL.
   Return values are the same as with net_gethostbyname() */
int net_gethostbyaddr(IPADDR *ip, char **name)
{
	union sockaddr_union so;
	int host_error;
	char hostname[NI_MAXHOST];

	g_return_val_if_fail(ip != NULL, -1);
	g_return_val_if_fail(name != NULL, -1);

	*name = NULL;

	memset(&so, 0, sizeof(so));
	sin_set_ip(&so, ip);

	/* save error to host_error for later use */
        host_error = getnameinfo((struct sockaddr *)&so, sizeof(so),
				 hostname, sizeof(hostname),
				 NULL, 0,
				 NI_NAMEREQD);
        if (host_error != 0)
                return host_error;

	*name = g_strdup(hostname);

	return 0;
}

int net_ip2host(IPADDR *ip, char *host)
{
	host[0] = '\0';
	return inet_ntop(ip->family, &ip->ip, host, MAX_IP_LEN) ? 0 : -1;
}

int net_host2ip(const char *host, IPADDR *ip)
{
	if (strchr(host, ':') != NULL) {
		/* IPv6 */
		ip->family = AF_INET6;
		if (inet_pton(AF_INET6, host, &ip->ip) == 0)
			return -1;
	} else {
		/* IPv4 */
		ip->family = AF_INET;
		if (inet_pton(AF_INET, host, &ip->ip) == 0)
			return -1;
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
	g_return_val_if_fail(error != 0, NULL);

	if (error == EAI_SYSTEM) {
		return strerror(errno);
	} else {
		return gai_strerror(error);
	}
}

/* return TRUE if host lookup failed because it didn't exist (ie. not
   some error with name server) */
int net_hosterror_notfound(int error)
{
#ifdef EAI_NODATA /* NODATA is deprecated */
	return error != 1 && (error == EAI_NONAME || error == EAI_NODATA);
#else
	return error != 1 && (error == EAI_NONAME);
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
