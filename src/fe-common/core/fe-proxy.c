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
#include "commands.h"
#include "network.h"
#include "levels.h"
#include "settings.h"
#include "proxy.h"

#include "module-formats.h"
#include "printtext.h"

/* SYNTAX: PROXY ADD <name> <type> <address> <port> */
static void cmd_proxy_add(const char *data)
{
	char *name, *type, *address, *port;
	GHashTable *optlist;
	PROXY_REC *rec;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 4 | PARAM_FLAG_OPTIONS,
				"proxy add", &optlist, &name, &type, &address, &port))
		return;

	if (*name == '\0' || *type == '\0' || *address == '\0' || *port == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	rec = proxy_find(name);

	if (rec == NULL) {
		rec = g_new0(PROXY_REC, 1);
		rec->name = g_strdup(name);
	} else {
		g_free_and_null(rec->address);
	}

	rec->address = g_strdup(address);
	rec->port = atoi(port);

	proxy_create(rec);
	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_PROXY_ADDED, name);

	cmd_params_free(free_arg);
}

/* SYNTAX: PROXY REMOVE <name> */
static void cmd_proxy_remove(const char *data)
{
	PROXY_REC *rec;

	if (*data == '\0')
		cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

	rec = proxy_find(data);

	if (rec == NULL)
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_PROXY_NOT_FOUND, data);
	else {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_PROXY_REMOVED, data);
		proxy_remove(rec);
	}
}

/* SYNTAX: PROXY LIST */
static void cmd_proxy_list(void)
{
	GString *str;
	GSList *tmp;

	str = g_string_new(NULL);
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_PROXY_HEADER);

	for (tmp = proxies; tmp != NULL; tmp = tmp->next) {
		PROXY_REC *rec = tmp->data;

		printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_PROXY_LINE, rec->name, rec->address, rec->port, str->str);
	}

	g_string_free(str, TRUE);
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_PROXY_FOOTER);
}

static void cmd_proxy(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	if (*data == '\0')
		cmd_proxy_list();
	else
		command_runsub("proxy", data, server, item);
}

void fe_proxy_init(void)
{
	command_bind("proxy", NULL, (SIGNAL_FUNC)cmd_proxy);
	command_bind("proxy list", NULL, (SIGNAL_FUNC)cmd_proxy_list);
	command_bind("proxy add", NULL, (SIGNAL_FUNC)cmd_proxy_add);
	command_bind("proxy remove", NULL, (SIGNAL_FUNC)cmd_proxy_remove);

	command_set_options("proxy add", "");
}

void fe_proxy_deinit(void)
{
	command_unbind("proxy", (SIGNAL_FUNC)cmd_proxy);
	command_unbind("proxy list", (SIGNAL_FUNC)cmd_proxy_list);
	command_unbind("proxy add", (SIGNAL_FUNC)cmd_proxy_add);
	command_unbind("proxy remove", (SIGNAL_FUNC)cmd_proxy_remove);
}
