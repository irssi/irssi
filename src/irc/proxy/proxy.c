/*
 proxy.c : irc proxy

    Copyright (C) 1999-2001 Timo Sirainen

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
#include "signals.h"
#include "settings.h"
#include "levels.h"

#include "fe-common/core/printtext.h"

/* SYNTAX: IRSSIPROXY STATUS */
static void cmd_irssiproxy_status(const char *data, IRC_SERVER_REC *server)
{
	GSList *tmp;

	if (!settings_get_bool("irssiproxy")) {
		printtext(server, NULL, MSGLEVEL_CLIENTNOTICE,
			  "Proxy is currently disabled");
		return;
	}


	printtext(server, NULL, MSGLEVEL_CLIENTNOTICE,
		  "Proxy: Currently connected clients: %d",
		  g_slist_length(proxy_clients));

	for (tmp = proxy_clients; tmp != NULL; tmp = tmp->next) {
		CLIENT_REC *rec = tmp->data;

		printtext(server, NULL, MSGLEVEL_CLIENTNOTICE,
			  "  %s connect%s to %s (%s)",
			  rec->addr,
			  rec->connected ? "ed" : "ing",
			  rec->listen->port_or_path, rec->listen->ircnet);
	}
}

/* SYNTAX: IRSSIPROXY */
static void cmd_irssiproxy(const char *data, IRC_SERVER_REC *server, void *item)
{
	if (*data == '\0') {
		cmd_irssiproxy_status(data, server);
		return;
	}

	command_runsub("irssiproxy", data, server, item);
}

static void irc_proxy_setup_changed(void)
{
	if (settings_get_bool("irssiproxy")) {
		proxy_listen_init();
	} else {
		proxy_listen_deinit();
	}
}

void irc_proxy_init(void)
{
	settings_add_str("irssiproxy", "irssiproxy_ports", "");
	settings_add_str("irssiproxy", "irssiproxy_password", "");
	settings_add_str("irssiproxy", "irssiproxy_bind", "");
	settings_add_bool("irssiproxy", "irssiproxy", TRUE);

	if (*settings_get_str("irssiproxy_password") == '\0') {
		/* no password - bad idea! */
		signal_emit("gui dialog", 2, "warning",
			    "Warning!! Password not specified, everyone can "
			    "use this proxy! Use /set irssiproxy_password "
			    "<password> to set it");
	}
	if (*settings_get_str("irssiproxy_ports") == '\0') {
		signal_emit("gui dialog", 2, "warning",
			    "No proxy ports specified. Use /SET "
			    "irssiproxy_ports <ircnet>=<port> <ircnet2>=<port2> "
			    "... to set them.");
	}

	command_bind("irssiproxy", NULL, (SIGNAL_FUNC) cmd_irssiproxy);
	command_bind("irssiproxy status", NULL, (SIGNAL_FUNC) cmd_irssiproxy_status);

	signal_add_first("setup changed", (SIGNAL_FUNC) irc_proxy_setup_changed);

	if (settings_get_bool("irssiproxy")) {
		proxy_listen_init();
	}
	settings_check();
        module_register("proxy", "irc");
}

void irc_proxy_deinit(void)
{
	proxy_listen_deinit();
}

void irc_proxy_abicheck(int *version)
{
	*version = IRSSI_ABI_VERSION;
}
