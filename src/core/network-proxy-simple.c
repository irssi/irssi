/*
 network-proxy-simple.c : irssi

    Copyright (C) 2008 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; version 2 and/or 3 of the License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "module.h"
#include "network-proxy-simple.h"

#include "network-proxy-priv.h"
#include "network.h"

static void network_proxy_simple_destroy(struct network_proxy *proxy)
{
	struct network_proxy_simple *self = (struct network_proxy_simple *)proxy->privdata;

	g_free(self->password);
	g_free(self->string_after);
	g_free(self->string);

	g_free(self);

	_network_proxy_destroy(proxy);

	// We are responsible for the whole proxy struct
	g_free(proxy);
}

static struct network_proxy *network_proxy_simple_clone(const struct network_proxy *proxy)
{
	struct network_proxy_simple *self = (struct network_proxy_simple *)proxy->privdata;
	struct network_proxy *res;
	struct network_proxy_simple *newself;

	// First make and set the parent struct
	res = g_malloc0(sizeof(struct network_proxy));
	_network_proxy_clone(res, proxy);

	// Then allocate and set the private data
	newself = g_malloc0(sizeof(struct network_proxy_simple));
	res->privdata = (void *)newself;

	newself->string = g_strdup(self->string);
	newself->string_after = g_strdup(self->string_after);
	newself->password = g_strdup(self->password);

	return res;
}

static GIOChannel *network_proxy_simple_connect(const struct network_proxy *proxy,
						const IPADDR *hint_ip, char const *address, int port)
{
	if (hint_ip)
		return net_connect_ip(hint_ip, proxy->port, NULL);
	else
		return net_connect(proxy->host, proxy->port, NULL);
}

static void network_proxy_simple_send_string(const struct network_proxy *proxy,
					     const struct network_proxy_send_string_info *info)
{
	struct network_proxy_simple *self = (struct network_proxy_simple *)proxy->privdata;
	char *cmd;

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

static void network_proxy_simple_send_string_after(const struct network_proxy *proxy,
						   const struct network_proxy_send_string_info *info)
{
	struct network_proxy_simple *self = (struct network_proxy_simple *)proxy->privdata;
	char *cmd;

	if (self->string_after && self->string_after[0]) {
		cmd = g_strdup_printf(self->string_after, info->host, info->port);
		info->func(info->obj, cmd);
		g_free(cmd);
	}
}

struct network_proxy *network_proxy_simple_create(void)
{
	struct network_proxy *proxy;
	struct network_proxy_simple *self;

	proxy = g_malloc0(sizeof(struct network_proxy));

	// assume it could reset every variable to a known state
	_network_proxy_create(proxy);

	self = g_malloc0(sizeof(struct network_proxy_simple));
	proxy->privdata = (void *)self;

	self->string = g_strdup(settings_get_str("proxy_string"));
	self->string_after = g_strdup(settings_get_str("proxy_string_after"));
	self->password = g_strdup(settings_get_str("proxy_password"));

	proxy->destroy = network_proxy_simple_destroy;
	proxy->connect = network_proxy_simple_connect;
	proxy->clone = network_proxy_simple_clone;

	proxy->send_string = network_proxy_simple_send_string;
	proxy->send_string_after = network_proxy_simple_send_string_after;

	return proxy;
}
