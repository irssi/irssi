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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "network.h"
#include "net-internal.h"

#ifndef INADDR_NONE
#define INADDR_NONE INADDR_BROADCAST
#endif

union sockaddr_union {
	struct sockaddr sa;
	struct sockaddr_in sin;
#ifdef HAVE_IPV6
	struct sockaddr_in6 sin6;
#endif
};

/* Cygwin need this, don't know others.. */
/*#define BLOCKING_SOCKETS 1*/

int net_ip_compare(IPADDR *ip1, IPADDR *ip2)
{
	if (ip1->family != ip2->family)
		return 0;

#ifdef HAVE_IPV6
	if (ip1->family == AF_INET6)
		return memcmp(&ip1->addr, &ip2->addr, sizeof(ip1->addr)) == 0;
#endif

	return memcmp(&ip1->addr, &ip2->addr, 4) == 0;
}


/* copy IP to sockaddr */
inline void sin_set_ip(union sockaddr_union *so, const IPADDR *ip)
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
		memcpy(&so->sin6.sin6_addr, &ip->addr, sizeof(ip->addr.ip6));
	else
#endif
		memcpy(&so->sin.sin_addr, &ip->addr, 4);
}

inline void sin_get_ip(const union sockaddr_union *so, IPADDR *ip)
{
	ip->family = so->sin.sin_family;

#ifdef HAVE_IPV6
	if (ip->family == AF_INET6)
		memcpy(&ip->addr, &so->sin6.sin6_addr, sizeof(ip->addr.ip6));
	else
#endif
		memcpy(&ip->addr, &so->sin.sin_addr, 4);
}

G_INLINE_FUNC void sin_set_port(union sockaddr_union *so, int port)
{
#ifdef HAVE_IPV6
	if (so->sin.sin_family == AF_INET6)
                so->sin6.sin6_port = htons(port);
	else
#endif
		so->sin.sin_port = htons(port);
}

G_INLINE_FUNC int sin_get_port(union sockaddr_union *so)
{
#ifdef HAVE_IPV6
	if (so->sin.sin_family == AF_INET6)
		return ntohs(so->sin6.sin6_port);
#endif
	return ntohs(so->sin.sin_port);
}

/* Connect to socket */
int net_connect(const char *addr, int port, IPADDR *my_ip)
{
	IPADDR ip;

	g_return_val_if_fail(addr != NULL, -1);

	if (net_gethostbyname(addr, &ip) == -1)
		return -1;

	return net_connect_ip(&ip, port, my_ip);
}

/* Connect to socket with ip address */
int net_connect_ip(IPADDR *ip, int port, IPADDR *my_ip)
{
	union sockaddr_union so;
	int handle, ret, opt = 1;

	/* create the socket */
	memset(&so, 0, sizeof(so));
        so.sin.sin_family = ip->family;
	handle = socket(ip->family, SOCK_STREAM, 0);

	if (handle == -1)
		return -1;

	/* set socket options */
	fcntl(handle, F_SETFL, O_NONBLOCK);
	setsockopt(handle, SOL_SOCKET, SO_REUSEADDR,
		   (char *) &opt, sizeof(opt));
	setsockopt(handle, SOL_SOCKET, SO_KEEPALIVE,
		   (char *) &opt, sizeof(opt));

	/* set our own address, ignore if bind() fails */
	if (my_ip != NULL) {
		sin_set_ip(&so, my_ip);
		bind(handle, &so.sa, sizeof(so));
	}

	/* connect */
	sin_set_ip(&so, ip);
	sin_set_port(&so, port);
	ret = connect(handle, &so.sa, sizeof(so));

	if (ret < 0 && errno != EINPROGRESS) {
		close(handle);
		return -1;
	}

	return handle;
}

/* Disconnect socket */
void net_disconnect(int handle)
{
	g_return_if_fail(handle != -1);

	close(handle);
}

/* Listen for connections on a socket. if `my_ip' is NULL, listen in any
   address. */
int net_listen(IPADDR *my_ip, int *port)
{
	union sockaddr_union so;
	int ret, handle, opt = 1;
	socklen_t len = sizeof(so);

	g_return_val_if_fail(port != NULL, -1);

	memset(&so, 0, sizeof(so));
	sin_set_port(&so, *port);
	sin_set_ip(&so, my_ip);

	/* create the socket */
	handle = socket(so.sin.sin_family, SOCK_STREAM, 0);
	if (handle == -1)
		return -1;

	/* set socket options */
	fcntl(handle, F_SETFL, O_NONBLOCK);
	setsockopt(handle, SOL_SOCKET, SO_REUSEADDR,
		   (char *) &opt, sizeof(opt));
	setsockopt(handle, SOL_SOCKET, SO_KEEPALIVE,
		   (char *) &opt, sizeof(opt));

	/* specify the address/port we want to listen in */
	ret = bind(handle, &so.sa, sizeof(so));
	if (ret < 0) {
		close(handle);
		return -1;
	}

	/* get the actual port we started listen */
	ret = getsockname(handle, &so.sa, &len);
	if (ret < 0) {
		close(handle);
		return -1;
	}

	*port = sin_get_port(&so);

	/* start listening */
	if (listen(handle, 1) < 0) {
		close(handle);
		return -1;
	}

	return handle;
}

/* Accept a connection on a socket */
int net_accept(int handle, IPADDR *addr, int *port)
{
	union sockaddr_union so;
	int ret;
	socklen_t addrlen;

	g_return_val_if_fail(handle != -1, -1);

	addrlen = sizeof(so);
	ret = accept(handle, &so.sa, &addrlen);

	if (ret < 0)
		return -1;

	if (addr != NULL) sin_get_ip(&so, addr);
	if (port != NULL) *port = sin_get_port(&so);

	fcntl(ret, F_SETFL, O_NONBLOCK);
	return ret;
}

/* Read data from socket, return number of bytes read, -1 = error */
int net_receive(int handle, char *buf, int len)
{
#ifdef BLOCKING_SOCKETS
	fd_set set;
	struct timeval tv;
#endif
	int ret;

	g_return_val_if_fail(handle != -1, -1);
	g_return_val_if_fail(buf != NULL, -1);

#ifdef BLOCKING_SOCKETS
	FD_ZERO(&set);
	FD_SET(handle, &set);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	if (select(handle+1, &set, NULL, NULL, &tv) <= 0 ||
	    !FD_ISSET(handle, &set)) return 0;
#endif

	ret = recv(handle, buf, len, 0);
	if (ret == 0)
		return -1; /* disconnected */

	if (ret == -1 && (errno == EWOULDBLOCK || errno == EAGAIN ||
			  errno == EINTR))
		return 0; /* no bytes received */

	return ret;
}

/* Transmit data, return number of bytes sent, -1 = error */
int net_transmit(int handle, const char *data, int len)
{
	int n;

	g_return_val_if_fail(handle != -1, -1);
	g_return_val_if_fail(data != NULL, -1);

	n = send(handle, data, len, 0);
	if (n == -1 && (errno == EWOULDBLOCK || errno == EAGAIN ||
			errno == EINTR || errno == EPIPE))
		return 0;

	return n > 0 ? n : -1;
}

/* Get socket address/port */
int net_getsockname(int handle, IPADDR *addr, int *port)
{
	union sockaddr_union so;
#ifdef HAVE_IPV6
	socklen_t len = sizeof(so.sin6);
#else
	socklen_t len = sizeof(so.sin);
#endif

	g_return_val_if_fail(handle != -1, -1);
	g_return_val_if_fail(addr != NULL, -1);

#ifdef HAVE_IPV6
	if (getsockname(handle, &so.sin6, &len) == -1)
#else
	if (getsockname(handle, &so.sin, &len) == -1)
#endif
		return -1;

        sin_get_ip(&so, addr);
	if (port) *port = sin_get_port(&so);

	return 0;
}

/* Get IP address for host, returns 0 = ok,
   others = error code for net_gethosterror() */
int net_gethostbyname(const char *addr, IPADDR *ip)
{
#ifdef HAVE_IPV6
	union sockaddr_union *so;
	struct addrinfo req, *ai;
	char hbuf[NI_MAXHOST];
	int host_error;
#else
	struct hostent *hp;
#endif

	g_return_val_if_fail(addr != NULL, -1);

#ifdef HAVE_IPV6
	memset(ip, 0, sizeof(IPADDR));
	memset(&req, 0, sizeof(struct addrinfo));
	req.ai_socktype = SOCK_STREAM;

	/* save error to host_error for later use */
	host_error = getaddrinfo(addr, NULL, &req, &ai);
	if (host_error != 0)
		return host_error;

	if (getnameinfo(ai->ai_addr, ai->ai_addrlen, hbuf,
			sizeof(hbuf), NULL, 0, NI_NUMERICHOST))
		return 1;

	so = (union sockaddr_union *) ai->ai_addr;
        sin_get_ip(so, ip);
	freeaddrinfo(ai);
#else
	hp = gethostbyname(addr);
	if (hp == NULL) return h_errno;

	ip->family = AF_INET;
	memcpy(&ip->addr, hp->h_addr, 4);
#endif

	return 0;
}

/* Get name for host, *name should be g_free()'d unless it's NULL.
   Return values are the same as with net_gethostbyname() */
int net_gethostbyaddr(IPADDR *ip, char **name)
{
#ifdef HAVE_IPV6
	struct addrinfo req, *ai;
	int host_error;
#else
	struct hostent *hp;
#endif
	char ipname[MAX_IP_LEN];

	g_return_val_if_fail(ip != NULL, -1);
	g_return_val_if_fail(name != NULL, -1);

	net_ip2host(ip, ipname);

	*name = NULL;
#ifdef HAVE_IPV6
	memset(&req, 0, sizeof(struct addrinfo));
	req.ai_socktype = SOCK_STREAM;
	req.ai_flags = AI_CANONNAME;

	/* save error to host_error for later use */
	host_error = getaddrinfo(ipname, NULL, &req, &ai);
	if (host_error != 0)
		return host_error;
	*name = g_strdup(ai->ai_canonname);

	freeaddrinfo(ai);
#else
	hp = gethostbyaddr(ipname, strlen(ipname), AF_INET);
	if (hp == NULL) return -1;

	*name = g_strdup(hp->h_name);
#endif

	return 0;
}

int net_ip2host(IPADDR *ip, char *host)
{
#ifdef HAVE_IPV6
	if (!inet_ntop(ip->family, &ip->addr, host, MAX_IP_LEN))
		return -1;
#else
	unsigned long ip4;

	ip4 = ntohl(ip->addr.ip.s_addr);
	sprintf(host, "%lu.%lu.%lu.%lu",
		(ip4 & 0xff000000UL) >> 24,
		(ip4 & 0x00ff0000) >> 16,
		(ip4 & 0x0000ff00) >> 8,
		(ip4 & 0x000000ff));
#endif
	return 0;
}

int net_host2ip(const char *host, IPADDR *ip)
{
	unsigned long addr;

#ifdef HAVE_IPV6
	if (strchr(host, ':') != NULL) {
		/* IPv6 */
		ip->family = AF_INET6;
		if (inet_pton(AF_INET6, host, &ip->addr) == 0)
			return -1;
	} else
#endif
	{
		/* IPv4 */
		ip->family = AF_INET;
#ifdef HAVE_INET_ATON
		if (inet_aton(host, &ip->addr.ip.s_addr) == 0)
			return -1;
#else
		addr = inet_addr(host);
		if (addr == INADDR_NONE)
			return -1;

		memcpy(&ip->addr, &addr, 4);
#endif
	}

	return 0;
}

/* Get socket error */
int net_geterror(int handle)
{
	int data;
	socklen_t len = sizeof(data);

	if (getsockopt(handle, SOL_SOCKET, SO_ERROR, &data, &len) == -1)
		return -1;

	return data;
}

/* get error of net_gethostname() */
const char *net_gethosterror(int error)
{
#ifdef HAVE_IPV6
	g_return_val_if_fail(error != 0, NULL);

	if (error == 1) {
		/* getnameinfo() failed ..
		   FIXME: does strerror return the right error message? */
		return g_strerror(errno);
	}

	return gai_strerror(error);
#else
	switch (error) {
	case HOST_NOT_FOUND:
		return _("Host not found");
	case NO_ADDRESS:
		return _("No IP address found for name");
	case NO_RECOVERY:
		return _("A non-recovable name server error occurred");
	case TRY_AGAIN:
		return _("A temporary error on an authoritative name server");
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
	return error != 1 && (error == EAI_NONAME || error == EAI_NODATA);
#else
	return error == HOST_NOT_FOUND || error == NO_ADDRESS;
#endif
}

int is_ipv4_address(const char *host)
{
	while (*host != '\0') {
		if (*host != '.' && !isdigit(*host))
			return 0;
                host++;
	}

	return 1;
}

int is_ipv6_address(const char *host)
{
	while (*host != '\0') {
		if (*host != ':' && !isxdigit(*host))
			return 0;
                host++;
	}

	return 1;
}
