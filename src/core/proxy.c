/*
 * Copyright (c) 2015 Alexander Færøy <ahf@irssi.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include "module.h"
#include "signals.h"
#include "lib-config/iconfig.h"
#include "settings.h"

#include "proxy.h"

GSList *proxies;

static void proxy_config_save(PROXY_REC *proxy)
{
	CONFIG_NODE *node;

	node = iconfig_node_traverse("proxies", TRUE);
	node = iconfig_node_section(node, proxy->name, NODE_TYPE_BLOCK);
	iconfig_node_clear(node);

	iconfig_node_set_str(node, "address", proxy->address);
	iconfig_node_set_int(node, "port", proxy->port);

	signal_emit("proxy saved", 2, proxy, node);
}

static void proxy_config_remove(PROXY_REC *proxy)
{
	CONFIG_NODE *node;

	node = iconfig_node_traverse("proxies", FALSE);

	if (node != NULL)
		iconfig_node_set_str(node, proxy->name, NULL);
}

static void read_proxy(CONFIG_NODE *node)
{
	PROXY_REC *rec;

	if (node == NULL || node->key == NULL)
		return;

	rec = g_new(PROXY_REC, 1);
	rec->name = g_strdup(node->key);
	rec->address = g_strdup(config_node_get_str(node, "address", NULL));
	rec->port = config_node_get_int(node, "port", 0);

	proxies = g_slist_append(proxies, rec);
	signal_emit("proxy read", 2, rec, node);
}

static void read_proxies(void)
{
	CONFIG_NODE *node;
	GSList *tmp;

	while (proxies != NULL)
		proxy_destroy(proxies->data);

	node = iconfig_node_traverse("proxies", FALSE);

	if (node != NULL) {
		for (tmp = config_node_first(node->value); tmp != NULL; tmp = config_node_next(tmp))
			read_proxy(tmp->data);
	}
}

void proxy_create(PROXY_REC *proxy)
{
	g_return_if_fail(proxy != NULL);

	proxy->type = module_get_uniq_id("PROXY", 0);

	if (g_slist_find(proxies, proxy) == NULL)
		proxies = g_slist_append(proxies, proxy);

	proxy_config_save(proxy);
	signal_emit("proxy created", 1, proxy);
}

void proxy_remove(PROXY_REC *proxy)
{
	g_return_if_fail(proxy != NULL);

	signal_emit("proxy removed", 1, proxy);

	proxy_config_remove(proxy);
	proxy_destroy(proxy);
}

void proxy_destroy(PROXY_REC *proxy)
{
	g_return_if_fail(IS_PROXY(proxy));

	proxies = g_slist_remove(proxies, proxy);
	signal_emit("proxy destroyed", 1, proxy);

	g_free(proxy->name);
	g_free(proxy->address);
	g_free(proxy);
}

PROXY_REC *proxy_find(const char *name)
{
	GSList *tmp;

	g_return_val_if_fail(name != NULL, NULL);

	for (tmp = proxies; tmp != NULL; tmp = tmp->next) {
		PROXY_REC *rec = tmp->data;

		if (g_ascii_strcasecmp(rec->name, name) == 0)
			return rec;
	}

	return NULL;
}

void proxy_init(void)
{
	proxies = NULL;

	settings_add_str("proxy", "default_proxy", NULL);

	signal_add("setup reread", (SIGNAL_FUNC)read_proxies);
	signal_add("irssi init read settings", (SIGNAL_FUNC)read_proxies);
}

void proxy_deinit(void)
{
	module_uniq_destroy("PROXY");

	signal_remove("setup reread", (SIGNAL_FUNC)read_proxies);
	signal_remove("irssi init read settings", (SIGNAL_FUNC)read_proxies);
}
