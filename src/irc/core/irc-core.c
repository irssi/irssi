/*
 irc-core.c : irssi

    Copyright (C) 1999-2000 Timo Sirainen

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
#include <irssi/src/core/chat-protocols.h>
#include <irssi/src/core/settings.h>

#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/irc/core/irc-chatnets.h>
#include <irssi/src/irc/core/irc-channels.h>
#include <irssi/src/irc/core/irc-queries.h>
#include <irssi/src/irc/core/irc-cap.h>
#include <irssi/src/irc/core/sasl.h>

#include <irssi/src/irc/core/irc-servers-setup.h>
#include <irssi/src/core/channels-setup.h>

#include <irssi/src/irc/core/ctcp.h>
#include <irssi/src/irc/core/irc-commands.h>
#include <irssi/src/irc/core/netsplit.h>

void irc_expandos_init(void);
void irc_expandos_deinit(void);

void irc_session_init(void);
void irc_session_deinit(void);

void lag_init(void);
void lag_deinit(void);

static CHATNET_REC *create_chatnet(void)
{
        return g_malloc0(sizeof(IRC_CHATNET_REC));
}

static SERVER_SETUP_REC *create_server_setup(void)
{
        return g_malloc0(sizeof(IRC_SERVER_SETUP_REC));
}

static CHANNEL_SETUP_REC *create_channel_setup(void)
{
        return g_malloc0(sizeof(CHANNEL_SETUP_REC));
}

static SERVER_CONNECT_REC *create_server_connect(void)
{
        return g_malloc0(sizeof(IRC_SERVER_CONNECT_REC));
}

static void destroy_server_connect(SERVER_CONNECT_REC *conn)
{
	IRC_SERVER_CONNECT_REC *ircconn;

        ircconn = IRC_SERVER_CONNECT(conn);
	if (ircconn == NULL)
		return;

	g_free_not_null(ircconn->usermode);
	g_free_not_null(ircconn->alternate_nick);
	g_free_not_null(ircconn->sasl_username);
	g_free_not_null(ircconn->sasl_password);

	if (ircconn->scram_session != NULL) {
		scram_session_free(ircconn->scram_session);
	}
}

void irc_core_init(void)
{
	CHAT_PROTOCOL_REC *rec;

	rec = g_new0(CHAT_PROTOCOL_REC, 1);
	rec->name = "IRC";
	rec->fullname = "Internet Relay Chat";
	rec->chatnet = "ircnet";

        rec->case_insensitive = TRUE;

	rec->create_chatnet = create_chatnet;
        rec->create_server_setup = create_server_setup;
        rec->create_channel_setup = create_channel_setup;
	rec->create_server_connect = create_server_connect;
	rec->destroy_server_connect = destroy_server_connect;

	rec->server_init_connect = irc_server_init_connect;
	rec->server_connect = irc_server_connect;
	rec->channel_create =
		(CHANNEL_REC *(*) (SERVER_REC *, const char *,
				   const char *, int))
                irc_channel_create;
	rec->query_create =
		(QUERY_REC *(*) (const char *, const char *, int))
                irc_query_create;

        irc_session_init();
	irc_chatnets_init();
	irc_servers_init();
	irc_channels_init();
	irc_queries_init();

	ctcp_init();
	irc_commands_init();
	irc_irc_init();
	lag_init();
	netsplit_init();
	irc_expandos_init();
	irc_cap_init();
	sasl_init();

	settings_check();

	chat_protocol_register(rec);
	g_free(rec);

	module_register("irc", "core");
}

void irc_core_deinit(void)
{
	signal_emit("chat protocol deinit", 1, chat_protocol_find("IRC"));

	sasl_deinit();
	irc_cap_deinit();
	irc_expandos_deinit();
	netsplit_deinit();
	lag_deinit();
	irc_commands_deinit();
	ctcp_deinit();

	irc_queries_deinit();
	irc_channels_deinit();
	irc_irc_deinit();
	irc_servers_deinit();
	irc_chatnets_deinit();
	irc_session_deinit();

	chat_protocol_unregister("IRC");
}

MODULE_ABICHECK(irc_core)
