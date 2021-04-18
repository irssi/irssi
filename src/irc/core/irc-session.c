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
#include <irssi/src/core/signals.h>
#include <irssi/src/core/net-sendbuffer.h>
#include <irssi/src/lib-config/iconfig.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/network.h>

#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/irc/core/irc-servers-setup.h>
#include <irssi/src/irc/core/irc-channels.h>
#include <irssi/src/irc/core/irc-nicklist.h>

#include <irssi/src/irc/core/sasl.h>

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
	int tls_disconnect;

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
	/* we cannot upgrade TLS (yet?) */
	tls_disconnect = server->connrec->use_tls || server->connrec->starttls;
	if (tls_disconnect) {
		config_node_set_str(config, node, "rejoin_channels",
		                    irc_server_get_channels(server, REJOIN_CHANNELS_MODE_ON));
		irc_send_cmd_now(server, "QUIT :[TLS] Client upgrade");
	}

	net_sendbuffer_flush(server->handle);

	config_node_set_str(config, node, "real_address", server->real_address);
	config_node_set_str(config, node, "userhost", server->userhost);
	config_node_set_str(config, node, "usermode", server->usermode);
	config_node_set_bool(config, node, "usermode_away", server->usermode_away);
	config_node_set_str(config, node, "away_reason", server->away_reason);
	config_node_set_bool(config, node, "emode_known", server->emode_known);

	config_node_set_int(config, node, "sasl_mechanism", server->connrec->sasl_mechanism);
	config_node_set_str(config, node, "sasl_username", server->connrec->sasl_username);
	config_node_set_str(config, node, "sasl_password", server->connrec->sasl_password);

	config_node_set_int(config, node, "starttls",
	                    server->connrec->disallow_starttls ? STARTTLS_DISALLOW :
	                    server->connrec->starttls          ? STARTTLS_ENABLED :
                                                                 STARTTLS_NOTSET);

	config_node_set_bool(config, node, "no_cap", server->connrec->no_cap);
	config_node_set_bool(config, node, "isupport_sent", server->isupport_sent);
	isupport = config_node_section(config, node, "isupport", NODE_TYPE_BLOCK);
        isupport_data.config = config;
        isupport_data.node = isupport;

        g_hash_table_foreach(server->isupport, (GHFunc) session_isupport_foreach, &isupport_data);

	/* we have to defer the disconnect to irc_server_connect */
}

static void sig_session_restore_server(IRC_SERVER_REC *server,
				       CONFIG_NODE *node)
{
	GSList *tmp;
	int starttls_mode;

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

	server->connrec->no_cap = config_node_get_bool(node, "no_cap", FALSE);
	server->connrec->sasl_mechanism = config_node_get_int(node, "sasl_mechanism", SASL_MECHANISM_NONE);
	/* The fields below might have been filled when loading the chatnet
	 * description from the config and we favor the content that's been saved
	 * in the session file over that. */
	g_free(server->connrec->sasl_username);
	server->connrec->sasl_username = g_strdup(config_node_get_str(node, "sasl_username", NULL));
	g_free(server->connrec->sasl_password);
	server->connrec->sasl_password = g_strdup(config_node_get_str(node, "sasl_password", NULL));

	server->connrec->channels = g_strdup(config_node_get_str(node, "rejoin_channels", NULL));

	starttls_mode = config_node_get_int(node, "starttls", STARTTLS_NOTSET);
	if (starttls_mode == STARTTLS_DISALLOW)
		server->connrec->disallow_starttls = 1;
	if (starttls_mode == STARTTLS_ENABLED) {
		server->connrec->starttls = 1;
		server->connrec->use_tls = 0;
	}

	if (server->isupport == NULL) {
		server->isupport =
		    g_hash_table_new((GHashFunc) i_istr_hash, (GCompareFunc) i_istr_equal);
	}

	node = config_node_section(NULL, node, "isupport", -1);
	tmp = node == NULL ? NULL : config_node_first(node->value);

	for (; tmp != NULL; tmp = config_node_next(tmp)) {
		node = tmp->data;
		if (node == NULL)
			break;

		g_hash_table_insert(server->isupport, g_strdup(node->key),
				    g_strdup(node->value));
	}
	irc_server_init_isupport(server);

	/* we will reconnect in irc_server_connect if the connection was TLS */
}

static void sig_session_restore_nick(IRC_CHANNEL_REC *channel,
				     CONFIG_NODE *node)
{
	const char *nick, *prefixes;
        int op, halfop, voice;
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
	irc_nicklist_insert(channel, nick, op, halfop, voice, FALSE, prefixes);
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
