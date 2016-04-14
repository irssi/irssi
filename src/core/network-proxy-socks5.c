/*	--*- c -*--
 * Copyright (C) 2008 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 and/or 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "module.h"
#include "network-proxy-socks5.h"

#include <stdlib.h>
#include <stdint.h>

#include "network.h"
#include "network-proxy-priv.h"

/* RFC 1928 */
struct client_greeting
{
	uint8_t		ver;
	uint8_t		nmethods;
	uint8_t		methods[];
} __attribute__((__packed__));

struct server_greeting
{
	uint8_t		ver;
	uint8_t		method;
} __attribute__((__packed__));

struct server_response_plain
{
	uint8_t		ver;
	uint8_t		status;
} __attribute__((__packed__));

struct client_request
{
	uint8_t		ver;
	uint8_t		cmd;
	uint8_t		rsv;
	uint8_t		atyp;
	uint8_t		dst[];
} __attribute__((__packed__));

struct server_response
{
	uint8_t		ver;
	uint8_t		rep;
	uint8_t		res;
	uint8_t		atyp;
	uint8_t		bnd[];
} __attribute__((__packed__));

static void
network_proxy_socks5_destroy(struct network_proxy *proxy)
{
	struct _network_proxy_socks5	*self = container_of(proxy, struct _network_proxy_socks5, proxy);

	g_free((void *)self->password);
	g_free((void *)self->username);
	_network_proxy_destroy(proxy);
	g_free(self);
}

static struct network_proxy *
network_proxy_socks5_clone(struct network_proxy const *proxy)
{
	struct _network_proxy_socks5	*self = container_of(proxy, struct _network_proxy_socks5, proxy);
	struct _network_proxy_socks5	*res;

	res = g_malloc0(sizeof *res);

	_network_proxy_clone(&res->proxy, &self->proxy);
	res->username = g_strdup(self->username);
	res->password = g_strdup(self->password);
	return &res->proxy;
}

static bool
socks5_connect_unauthorized(GIOChannel *ch)
{
	/* nothing to do here */
	(void)ch;
	return true;
}

/* TODO: test this method! */
static bool
socks5_connect_plain(struct _network_proxy_socks5 const *proxy, GIOChannel *ch)
{
	uint8_t				ver  = 0x01;
	uint8_t				ulen = strlen(proxy->username);
	uint8_t				plen = proxy->password ? strlen(proxy->password) : 0;
	struct server_response_plain	resp;

	if (ulen==0 ||
	    !_network_proxy_send_all(ch, &ver, sizeof ver) ||
	    !_network_proxy_send_all(ch, &ulen, sizeof ulen) ||
	    !_network_proxy_send_all(ch, proxy->username, ulen) ||
	    !_network_proxy_send_all(ch, &plen, sizeof plen) ||
	    (plen>0 && !_network_proxy_send_all(ch, proxy->password, plen)) ||
	    !_network_proxy_flush(ch) ||
	    !_network_proxy_recv_all(ch, &resp, sizeof resp))
		return false;

	if (resp.ver!=0x01) {
		g_warning("unexpected plaintext response version %#04x", resp.ver);
		return false;
	}

	if (resp.status!=0x00) {
		g_warning("socks5 authentication error (%#04x)", resp.status);
		return false;
	}

	return true;
}

static bool
socks5_connect(struct _network_proxy_socks5 const *proxy, GIOChannel *ch,
	       char const *address, uint16_t port)
{
	bool				rc;

	struct server_greeting		s_greeting;
	struct server_response		s_response;


	/* Phase 1: exchange greeting */
	{
		struct client_greeting		c_greeting = {
			.ver      = 0x05,
			.nmethods = proxy->username && proxy->username[0] ? 2 : 1
		};
		/* HACK: order is important because it depends upon
		 * c_greeting.nmethods  */
		char const			methods[] = {
			0x00,			/* no authentication */
			0x02			/* username/password */
		};
		if (!_network_proxy_send_all(ch, &c_greeting, sizeof c_greeting) ||
		    !_network_proxy_send_all(ch, methods,     c_greeting.nmethods) ||
		    !_network_proxy_flush(ch) ||
		    !_network_proxy_recv_all(ch, &s_greeting, sizeof s_greeting))
			goto err;

		if (s_greeting.ver!=5) {
			g_warning("version mismatch during initial socks5 greeting; got version %#04x",
				  s_greeting.ver);
			goto err;
		}
	}

	/* Phase 2: authentication */
	{
		switch (s_greeting.method) {
		case 0x00: rc = socks5_connect_unauthorized(ch); break;
		case 0x02: rc = socks5_connect_plain(proxy, ch); break;
		default:
			g_warning("unsupported authentication method %#04x", s_greeting.method);
			rc = false;
		}

		if (!rc)
			goto err;
	}

	/* Phase 3: connection request */
	{
		struct client_request		c_request = {
			.ver	  = 0x05,
			.cmd	  = 0x01,	/* CONNECT */
			.atyp     = 0x03,	/* domain name */
		};
		uint8_t				address_len = strlen(address);
		uint16_t			dst_port = htons(port);
		uint16_t			bnd_port;
		char				bnd_address[257];

		if (!_network_proxy_send_all(ch, &c_request,   sizeof c_request) ||
		    !_network_proxy_send_all(ch, &address_len, sizeof address_len) ||
		    !_network_proxy_send_all(ch, address,      address_len) ||
		    !_network_proxy_send_all(ch, &dst_port,    sizeof dst_port) ||
		    !_network_proxy_flush(ch) ||
		    !_network_proxy_recv_all(ch, &s_response,  sizeof s_response))
			goto err;

		if (s_response.ver != 0x05) {
			g_warning("version mismatch in socks5 response; got version %#04x",
				  s_response.ver);
			goto err;
		}

		rc = false;
		switch (s_response.rep) {
		case 0x00: rc = true; break;	/* succeeded */
		case 0x01: g_warning("SOCKS5: general SOCKS server failure"); break;
		case 0x02: g_warning("SOCKS5: connection not allowed by ruleset"); break;
		case 0x03: g_warning("SOCKS5: Network unreachable"); break;
		case 0x04: g_warning("SOCKS5: Host unreachable"); break;
		case 0x05: g_warning("SOCKS5: Connection refused"); break;
		case 0x06: g_warning("SOCKS5: TTL expired"); break;
		case 0x07: g_warning("SOCKS5: Command not supported"); break;
		case 0x08: g_warning("SOCKS5: Address type not supported"); break;
		default:   g_warning("SOCKS5: unknown error %#04x", s_response.rep); break;
		}

		if (!rc)
			goto err;

		switch(s_response.atyp) {
		case 0x01: {
			struct in_addr	ip;
			if (!_network_proxy_recv_all(ch, &ip,     sizeof ip) ||
			    !inet_ntop(AF_INET, &ip, bnd_address, sizeof bnd_address))
				rc = false;
			break;
		}

		case 0x04: {
			struct in6_addr	ip;
			if (!_network_proxy_recv_all(ch, &ip,      sizeof ip) ||
			    !inet_ntop(AF_INET6, &ip, bnd_address, sizeof bnd_address))
				rc = false;
			break;
		}

		case 0x03: {
			uint8_t		tmp;
			if (!_network_proxy_recv_all(ch, &tmp, sizeof tmp) ||
			    tmp==0 ||
			    !_network_proxy_recv_all(ch, &bnd_address, tmp))
				rc = false;
			else
				bnd_address[tmp] = '\0';
		}

		default:
			g_warning("SOCKS5: unsupported address family in response: %#04x",
				  s_response.atyp);
			rc = false;
		}

		if (!rc ||
		    !_network_proxy_recv_all(ch, &bnd_port, sizeof bnd_port))
			goto err;

		bnd_port = ntohs(bnd_port);
		g_debug("SOCKS5: bound to %s:%u", bnd_address, bnd_port);
	}

	return true;

err:
	g_warning("connecting through socks5 proxy failed");
	return  false;
}


static GIOChannel *
network_proxy_socks5_connect(struct network_proxy const *proxy, IPADDR const *hint_ip,
			     char const *address, int port)
{
	struct _network_proxy_socks5	*self = container_of(proxy, struct _network_proxy_socks5, proxy);
	GIOChannel			*ch;

	GIOFlags			old_flags;
	gchar const			*old_enc;
	gboolean			old_buf;
	GError				*err = NULL;

	if (hint_ip)
		ch = net_connect_ip(hint_ip, self->proxy.port, NULL);
	else
		ch = net_connect(self->proxy.host, self->proxy.port, NULL);

	if (!ch)
		return NULL;

	old_enc   = g_io_channel_get_encoding(ch);
	old_flags = g_io_channel_get_flags(ch);
	old_buf   = g_io_channel_get_buffered(ch);

	if (g_io_channel_set_encoding(ch, NULL, &err)!=G_IO_STATUS_NORMAL ||
	    g_io_channel_set_flags(ch, old_flags & ~G_IO_FLAG_NONBLOCK, &err)!=G_IO_STATUS_NORMAL)
		goto err;

	g_io_channel_set_buffered(ch, false);

	if (!socks5_connect(self, ch, address, port))
		goto err;

	g_io_channel_set_buffered(ch, old_buf);

	if (g_io_channel_set_flags(ch, old_flags, &err) !=G_IO_STATUS_NORMAL ||
	    g_io_channel_set_encoding(ch, old_enc, &err)!=G_IO_STATUS_NORMAL)
		goto err;

	return ch;

err:
	if (err) {
		g_warning("something went wrong while preparing SOCKS5 proxy request: %s",
			  err->message);
		g_error_free(err);
	}

	net_disconnect(ch);
	return NULL;
}

struct network_proxy *
_network_proxy_socks5_create(void)
{
	struct _network_proxy_socks5	*res;

	res = g_malloc0(sizeof *res);

	_network_proxy_create(&res->proxy);
	res->username    = g_strdup(settings_get_str("proxy_username"));
	res->password    = g_strdup(settings_get_str("proxy_password"));

	res->proxy.destroy = network_proxy_socks5_destroy;
	res->proxy.connect = network_proxy_socks5_connect;
	res->proxy.clone   = network_proxy_socks5_clone;

	return &res->proxy;
}
