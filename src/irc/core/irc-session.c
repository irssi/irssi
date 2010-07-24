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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include "signals.h"
#include "net-sendbuffer.h"
#include "lib-config/iconfig.h"
#include "misc.h"

#include "irc-servers.h"
#include "irc-channels.h"
#include "irc-nicklist.h"

struct _isupport_data { CONFIG_REC *config; CONFIG_NODE *node; };

static void session_isupport_foreach(char *key, char *value, struct _isupport_data *data)
{
        config_node_set_str(data->config, data->node, key, value);
}

static void sig_session_save_server(IRC_SERVER_REC *server, CONFIG_REC *config,
				    CONFIG_NODE *node)
{
        GSList *tmp;
	CONFIG_NODE *isupport;
	struct _isupport_data isupport_data;

	if (!IS_IRC_SERVER(server))
		return;

        /* send all non-redirected commands to server immediately */
	for (tmp = server->cmdqueue; tmp != NULL; tmp = tmp->next->next) {
		const char *cmd = tmp->data;
                void *redirect = tmp->next->data;

		if (redirect == NULL) {
			if (net_sendbuffer_send(server->handle, cmd,
						strlen(cmd)) == -1)
				break;
		}
	}
        net_sendbuffer_flush(server->handle);

	config_node_set_str(config, node, "real_address", server->real_address);
	config_node_set_str(config, node, "userhost", server->userhost);
	config_node_set_str(config, node, "usermode", server->usermode);
	config_node_set_bool(config, node, "usermode_away", server->usermode_away);
	config_node_set_str(config, node, "away_reason", server->away_reason);
	config_node_set_bool(config, node, "emode_known", server->emode_known);

	config_node_set_bool(config, node, "isupport_sent", server->isupport_sent);
        isupport = config_node_section(node, "isupport", NODE_TYPE_BLOCK);
        isupport_data.config = config;
        isupport_data.node = isupport;
		        
        g_hash_table_foreach(server->isupport, (GHFunc) session_isupport_foreach, &isupport_data);
}

static void sig_session_restore_server(IRC_SERVER_REC *server,
				       CONFIG_NODE *node)
{
	GSList *tmp;

	if (!IS_IRC_SERVER(server))
		return;

        if (server->real_address == NULL)
		server->real_address = g_strdup(config_node_get_str(node, "real_address", NULL));
	server->userhost = g_strdup(config_node_get_str(node, "userhost", NULL));
	server->usermode = g_strdup(config_node_get_str(node, "usermode", NULL));
	server->usermode_away = config_node_get_bool(node, "usermode_away", FALSE);
	server->away_reason = g_strdup(config_node_get_str(node, "away_reason", NULL));
	server->emode_known = config_node_get_bool(node, "emode_known", FALSE);
	server->isupport_sent = config_node_get_bool(node, "isupport_sent", FALSE);

	if (server->isupport == NULL) {
		server->isupport = g_hash_table_new((GHashFunc) g_istr_hash,
						    (GCompareFunc) g_istr_equal);
	}

	node = config_node_section(node, "isupport", -1);
	tmp = node == NULL ? NULL : config_node_first(node->value);

	for (; tmp != NULL; tmp = config_node_next(tmp)) {
		node = tmp->data;
		if (node == NULL)
			break;

		g_hash_table_insert(server->isupport, g_strdup(node->key),
				    g_strdup(node->value));
	}
	irc_server_init_isupport(server);

}

static void sig_session_restore_nick(IRC_CHANNEL_REC *channel,
				     CONFIG_NODE *node)
{
	const char *nick, *prefixes;
        int op, halfop, voice;
        NICK_REC *nickrec;
	char newprefixes[MAX_USER_PREFIXES + 1];
	int i;

	if (!IS_IRC_CHANNEL(channel))
		return;

	nick = config_node_get_str(node, "nick", NULL);
	if (nick == NULL)
                return;

	op = config_node_get_bool(node, "op", FALSE);
        voice = config_node_get_bool(node, "voice", FALSE);
        halfop = config_node_get_bool(node, "halfop", FALSE);
	prefixes = config_node_get_str(node, "prefixes", NULL);
	if (prefixes == NULL || *prefixes == '\0') {
		/* upgrading from old irssi or from an in-between
		 * version that did not imply non-present prefixes from
		 * op/voice/halfop, restore prefixes
		 */
		i = 0;
		if (op)
			newprefixes[i++] = '@';
		if (halfop)
			newprefixes[i++] = '%';
		if (voice)
			newprefixes[i++] = '+';
		newprefixes[i] = '\0';
		prefixes = newprefixes;
	}
	nickrec = irc_nicklist_insert(channel, nick, op, halfop, voice, FALSE, prefixes);
}

static void session_restore_channel(IRC_CHANNEL_REC *channel)
{
	char *data;

	signal_emit("event join", 4, channel->server, channel->name,
		    channel->server->nick, channel->server->userhost);

	data = g_strconcat(channel->server->nick, " ", channel->name, NULL);
	signal_emit("event 366", 2, channel->server, data);
	g_free(data);
}

static void sig_connected(IRC_SERVER_REC *server)
{
	GSList *tmp;
        char *str, *addr;

	if (!IS_IRC_SERVER(server) || !server->session_reconnect)
		return;

	str = g_strdup_printf("%s :Restoring connection to %s",
			      server->nick, server->connrec->address);
	/* addr needs to be strdup'd because the event_connected() handler
	   free()'s the server->real_address and then tries to strdup() the
	   given origin again */
	addr = g_strdup(server->real_address);
	signal_emit("event 001", 3, server, str, addr);
        g_free(addr);
        g_free(str);

	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		IRC_CHANNEL_REC *rec = tmp->data;

		if (rec->session_rejoin)
                        session_restore_channel(rec);
	}
}

void irc_session_init(void)
{
	signal_add("session save server", (SIGNAL_FUNC) sig_session_save_server);
	signal_add("session restore server", (SIGNAL_FUNC) sig_session_restore_server);
	signal_add("session restore nick", (SIGNAL_FUNC) sig_session_restore_nick);

	signal_add("server connected", (SIGNAL_FUNC) sig_connected);
}

void irc_session_deinit(void)
{
	signal_remove("session save server", (SIGNAL_FUNC) sig_session_save_server);
	signal_remove("session restore server", (SIGNAL_FUNC) sig_session_restore_server);
	signal_remove("session restore nick", (SIGNAL_FUNC) sig_session_restore_nick);

	signal_remove("server connected", (SIGNAL_FUNC) sig_connected);
}
