/*
 irc-session.c : irssi

    Copyright (C) 2001 Timo Sirainen

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
#include "signals.h"
#include "lib-config/iconfig.h"

#include "irc-servers.h"
#include "irc-channels.h"

static void sig_session_save_server(IRC_SERVER_REC *server, CONFIG_REC *config,
				    CONFIG_NODE *node)
{
	char *chans;

	if (!IS_IRC_SERVER(server))
		return;

	config_node_set_str(config, node, "real_address", server->real_address);
	config_node_set_str(config, node, "userhost", server->userhost);

        chans = irc_server_get_channels(server);
	config_node_set_str(config, node, "channels", chans);
        g_free(chans);
}

static void sig_session_restore_server(IRC_SERVER_REC *server,
				       CONFIG_NODE *node)
{
	if (!IS_IRC_SERVER(server))
		return;

        if (server->real_address == NULL)
		server->real_address = g_strdup(config_node_get_str(node, "real_address", NULL));
	server->userhost = g_strdup(config_node_get_str(node, "userhost", NULL));

	g_free_not_null(server->connrec->channels);
	server->connrec->channels = g_strdup(config_node_get_str(node, "channels", NULL));
}

static void sig_connected(IRC_SERVER_REC *server)
{
	GSList *tmp;
        char *str;

	if (!IS_IRC_SERVER(server) || !server->session_reconnect)
		return;

	str = g_strdup_printf("%s :Restoring connection to %s",
			      server->nick, server->connrec->address);
	signal_emit("event 001", 3, server, str, server->real_address);
        g_free(str);

        /* send join events for each channel and ask names list for them */
	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *rec = tmp->data;

		signal_emit("event join", 4, server, rec->name,
			    server->nick, server->userhost);
                irc_send_cmdv(server, "TOPIC %s", rec->name);
                irc_send_cmdv(server, "NAMES %s", rec->name);
	}
}

void irc_session_init(void)
{
	signal_add("session save server", (SIGNAL_FUNC) sig_session_save_server);
	signal_add("session restore server", (SIGNAL_FUNC) sig_session_restore_server);

	signal_add("server connected", (SIGNAL_FUNC) sig_connected);
}

void irc_session_deinit(void)
{
	signal_remove("session save server", (SIGNAL_FUNC) sig_session_save_server);
	signal_remove("session restore server", (SIGNAL_FUNC) sig_session_restore_server);

	signal_remove("server connected", (SIGNAL_FUNC) sig_connected);
}
