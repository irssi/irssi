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
#include "network-proxy-http.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "network.h"
#include "network-proxy-priv.h"

static void
network_proxy_http_destroy(struct network_proxy *proxy)
{
	struct _network_proxy_http	*self = container_of(proxy, struct _network_proxy_http, proxy);

	g_free((void *)self->password);
	_network_proxy_destroy(proxy);

	g_free(self);
}

static struct network_proxy *
network_proxy_http_clone(struct network_proxy const *proxy)
{
	struct _network_proxy_http	*self = container_of(proxy, struct _network_proxy_http, proxy);
	struct _network_proxy_http	*res;

	res = g_malloc0(sizeof *res);

	_network_proxy_clone(&res->proxy, &self->proxy);
	res->password = g_strdup(self->password);
	return &res->proxy;
}

static bool
send_connect(struct _network_proxy_http *proxy, GIOChannel *ch, char const *address, uint16_t port)
{
	char				port_str[6];

	(void)proxy;
	sprintf(port_str, "%u", port);

	if (!_network_proxy_send_all(ch, "CONNECT ", -1) ||
	    !_network_proxy_send_all(ch, address,    -1) ||
	    !_network_proxy_send_all(ch, ":",        -1) ||
	    !_network_proxy_send_all(ch, port_str,   -1) ||
	    !_network_proxy_send_all(ch, " HTTP/1.0\r\n\r\n", -1) ||
	    !_network_proxy_flush(ch))
		return false;

	return true;
}

static int
read_response(struct _network_proxy_http *proxy, GIOChannel *ch)
{
	GIOStatus			status;
	GString				line = { .str = NULL };
	gsize				term_pos;
	GError				*err = NULL;
	int				state = 0;
	int				rc = 0;
	gchar				*resp = NULL;

	(void)proxy;
	for (;;) {
		/* TODO: a malicious proxy can DOS us by sending much data
		 * without a line break */
		while ((status=g_io_channel_read_line_string(ch, &line, &term_pos,
							     &err))==G_IO_STATUS_AGAIN)
		{
			/* noop */
		}

		if (status!=G_IO_STATUS_NORMAL) {
			g_warning("failed to read HTTP response: %s", err->message);
			goto err;
		}

		if (state==0) {
			if (g_str_has_prefix(line.str, "HTTP/1.0 ")) {
				resp = g_strndup(line.str+9, line.len-9-2);
				rc   = g_ascii_strtoull(resp, NULL, 10);
			} else {
				g_warning("unexpected HTTP response: '%s'", line.str);
				goto err;
			}

			/* state=1 ... read additional response headers
			 *             (ignored for now) */
			state=1;
		}

		if (line.len==2)	/* only the \r\n terminators */
			break;
	}

	if (rc!=200)
		g_warning("unexpected HTTP response code: %s", resp);

	g_free(resp);
	g_free(line.str);
	return rc;

err:
	g_free(resp);
	g_free(line.str);
	return -1;
}

static GIOChannel *
network_proxy_http_connect(struct network_proxy const *proxy, IPADDR const *hint_ip,
			   char const *address, int port)
{
	struct _network_proxy_http	*self = container_of(proxy, struct _network_proxy_http, proxy);
	GIOChannel			*ch;
	GIOFlags			old_flags;
	GError				*err = NULL;
	gchar const			*line_term;
	gint				line_term_sz;

	if (hint_ip)
		ch = net_connect_ip(hint_ip, self->proxy.port, NULL);
	else
		ch = net_connect(self->proxy.host, self->proxy.port, NULL);

	if (!ch)
		return NULL;

	/* set \r\n line delims */
	line_term = g_io_channel_get_line_term(ch, &line_term_sz);
	g_io_channel_set_line_term(ch, "\r\n", 2);

	/* set to non-blocking */
	old_flags = g_io_channel_get_flags(ch);
	if (g_io_channel_set_flags(ch, old_flags & ~G_IO_FLAG_NONBLOCK, &err)!=G_IO_STATUS_NORMAL)
		goto err;

	if (!send_connect(self, ch, address, port) ||
	    read_response(self, ch)!=200)
		goto err;

	if (g_io_channel_set_flags(ch, old_flags, &err)!=G_IO_STATUS_NORMAL)
		goto err;

	g_io_channel_set_line_term(ch, line_term, line_term_sz);
	return ch;
err:
	if (err) {
		g_warning("something went wrong while preparing HTTP proxy request: %s",
			  err->message);
		g_error_free(err);
	}

	net_disconnect(ch);
	return NULL;

}


struct network_proxy *
_network_proxy_http_create(void)
{
	struct _network_proxy_http	*res;

	res = g_malloc0(sizeof *res);

	_network_proxy_create(&res->proxy);
	res->password    = g_strdup(settings_get_str("proxy_password"));

	res->proxy.destroy = network_proxy_http_destroy;
	res->proxy.connect = network_proxy_http_connect;
	res->proxy.clone   = network_proxy_http_clone;

	return &res->proxy;
}
