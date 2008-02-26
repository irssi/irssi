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
#include "network-proxy-simple.h"

#include "network-proxy-priv.h"
#include "network.h"

static void
network_proxy_simple_destroy(struct network_proxy *proxy)
{
	struct _network_proxy_simple	*self = container_of(proxy, struct _network_proxy_simple, proxy);

	g_free((void *)self->password);
	g_free((void *)self->string_after);
	g_free((void *)self->string);

	_network_proxy_destroy(proxy);

	g_free(self);
}

static struct network_proxy *
network_proxy_simple_clone(struct network_proxy const *proxy)
{
	struct _network_proxy_simple	*self = container_of(proxy, struct _network_proxy_simple, proxy);
	struct _network_proxy_simple	*res;

	res = g_malloc0(sizeof *res);

	_network_proxy_clone(&res->proxy, &self->proxy);

	res->string       = g_strdup(self->string);
	res->string_after = g_strdup(self->string_after);
	res->password     = g_strdup(self->password);
	return &res->proxy;
}

static GIOChannel *
network_proxy_simple_connect(struct network_proxy const *proxy, IPADDR const *hint_ip,
			     char const *address, int port)
{
	struct _network_proxy_simple	*self = container_of(proxy, struct _network_proxy_simple, proxy);

	(void)address;
	(void)port;
	if (hint_ip)
		return net_connect_ip(hint_ip, self->proxy.port, NULL);
	else
		return net_connect(self->proxy.host, self->proxy.port, NULL);
}

static void
network_proxy_simple_send_string(struct network_proxy const *proxy,
				 struct network_proxy_send_string_info const *info)
{
	struct _network_proxy_simple	*self = container_of(proxy, struct _network_proxy_simple, proxy);
	char				*cmd;

	if (self->password && self->password[0]) {
		cmd = g_strdup_printf("PASS %s", self->password);
		info->func(info->obj, cmd);
		g_free(cmd);
	}

	if (self->string && self->string[0]) {
		cmd = g_strdup_printf(self->string, info->host, info->port);
		info->func(info->obj, cmd);
		g_free(cmd);
	}
}

static void
network_proxy_simple_send_string_after(struct network_proxy const *proxy,
				 struct network_proxy_send_string_info const *info)
{
	struct _network_proxy_simple	*self = container_of(proxy, struct _network_proxy_simple, proxy);
	char				*cmd;

	if (self->string_after && self->string_after[0]) {
		cmd = g_strdup_printf(self->string_after, info->host, info->port);
		info->func(info->obj, cmd);
		g_free(cmd);
	}
}

struct network_proxy *
_network_proxy_simple_create(void)
{
	struct _network_proxy_simple	*res;

	res = g_malloc0(sizeof *res);

	_network_proxy_create(&res->proxy);
	res->string        = g_strdup(settings_get_str("proxy_string"));
	res->string_after  = g_strdup(settings_get_str("proxy_string_after"));
	res->password      = g_strdup(settings_get_str("proxy_password"));

	res->proxy.destroy = network_proxy_simple_destroy;
	res->proxy.connect = network_proxy_simple_connect;
	res->proxy.clone   = network_proxy_simple_clone;

	res->proxy.send_string       = network_proxy_simple_send_string;
	res->proxy.send_string_after = network_proxy_simple_send_string_after;

	return &res->proxy;
}
