/*
 servers-reconnect.c : irssi

    Copyright (C) 1999-2000 Timo Sirainen

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
#include "commands.h"
#include "network.h"
#include "signals.h"

#include "irc.h"
#include "modes.h"
#include "irc-servers.h"

#include "settings.h"

static void sig_server_connect_copy(SERVER_CONNECT_REC **dest,
				    IRC_SERVER_CONNECT_REC *src)
{
	IRC_SERVER_CONNECT_REC *rec;

	g_return_if_fail(dest != NULL);
	if (!IS_IRC_SERVER_CONNECT(src))
		return;

	rec = g_new0(IRC_SERVER_CONNECT_REC, 1);
	rec->chat_type = IRC_PROTOCOL;
	rec->cmd_queue_speed = src->cmd_queue_speed;
	rec->max_kicks = src->max_kicks;
	rec->max_modes = src->max_modes;
	rec->max_msgs = src->max_msgs;
	rec->usermode = g_strdup(src->usermode);
	*dest = (SERVER_CONNECT_REC *) rec;
}

static void sig_server_reconnect_save_status(IRC_SERVER_CONNECT_REC *conn,
					     IRC_SERVER_REC *server)
{
	if (!IS_IRC_SERVER_CONNECT(conn))
		return;
	g_return_if_fail(IS_IRC_SERVER(server));

	g_free_not_null(conn->channels);
	conn->channels = irc_server_get_channels(server);

	g_free_not_null(conn->usermode);
	conn->usermode = g_strdup(server->usermode);
}

static int sig_set_user_mode(IRC_SERVER_REC *server)
{
	const char *mode;
	char *newmode;

	if (g_slist_find(servers, server) == NULL)
		return 0; /* got disconnected */

	mode = server->connrec->usermode;
	if (mode == NULL) return 0;

	newmode = server->usermode == NULL ? NULL :
		modes_join(server->usermode, mode);

	if (server->usermode == NULL) {
		/* server didn't set user mode, just set the new one */
		irc_send_cmdv(server, "MODE %s %s", server->nick, mode);
	} else {
		if (strcmp(newmode, server->usermode) != 0)
			irc_send_cmdv(server, "MODE %s -%s+%s", server->nick, server->usermode, mode);
	}

	g_free_not_null(newmode);
	return 0;
}

static void sig_connected(IRC_SERVER_REC *server)
{
	if (!server->connrec->reconnection)
		return;

	if (server->connrec->channels != NULL)
		irc_channels_join(server, server->connrec->channels, TRUE);
	if (server->connrec->away_reason != NULL)
		signal_emit("command away", 2, server->connrec->away_reason, server, NULL);
	if (server->connrec->usermode != NULL) {
		/* wait a second and then send the user mode */
		g_timeout_add(1000, (GSourceFunc) sig_set_user_mode, server);
	}
}

void irc_servers_reconnect_init(void)
{
	signal_add("server connect copy", (SIGNAL_FUNC) sig_server_connect_copy);
	signal_add("server reconnect save status", (SIGNAL_FUNC) sig_server_reconnect_save_status);
	signal_add("event connected", (SIGNAL_FUNC) sig_connected);
}

void irc_servers_reconnect_deinit(void)
{
	signal_remove("server connect copy", (SIGNAL_FUNC) sig_server_connect_copy);
	signal_remove("server reconnect save status", (SIGNAL_FUNC) sig_server_reconnect_save_status);
	signal_remove("event connected", (SIGNAL_FUNC) sig_connected);
}
