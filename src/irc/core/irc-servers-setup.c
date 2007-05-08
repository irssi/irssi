/*
 irc-servers-setup.c : irssi

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
#include "signals.h"
#include "network.h"
#include "servers-setup.h"
#include "lib-config/iconfig.h"
#include "settings.h"

#include "irc-chatnets.h"
#include "irc-servers-setup.h"
#include "irc-servers.h"

/* Fill information to connection from server setup record */
static void sig_server_setup_fill_reconn(IRC_SERVER_CONNECT_REC *conn,
					 IRC_SERVER_SETUP_REC *sserver)
{
        if (!IS_IRC_SERVER_CONNECT(conn) ||
	    !IS_IRC_SERVER_SETUP(sserver))
		return;

	if (sserver->cmd_queue_speed > 0)
		conn->cmd_queue_speed = sserver->cmd_queue_speed;
	if (sserver->max_cmds_at_once > 0)
		conn->max_cmds_at_once = sserver->max_cmds_at_once;
	if (sserver->max_query_chans > 0)
		conn->max_query_chans = sserver->max_query_chans;
}

static void sig_server_setup_fill_connect(IRC_SERVER_CONNECT_REC *conn)
{
	if (!IS_IRC_SERVER_CONNECT(conn))
		return;

	conn->alternate_nick = *settings_get_str("alternate_nick") != '\0' ?
		g_strdup(settings_get_str("alternate_nick")) : NULL;
        conn->usermode = g_strdup(settings_get_str("usermode"));
}

static void sig_server_setup_fill_chatnet(IRC_SERVER_CONNECT_REC *conn,
					  IRC_CHATNET_REC *ircnet)
{
	if (!IS_IRC_SERVER_CONNECT(conn))
		return;
	g_return_if_fail(IS_IRCNET(ircnet));

	if (ircnet->nick != NULL) g_free_and_null(conn->alternate_nick);
	if (ircnet->usermode != NULL) {
		g_free_and_null(conn->usermode);
		conn->usermode = g_strdup(ircnet->usermode);
	}

	if (ircnet->max_kicks > 0) conn->max_kicks = ircnet->max_kicks;
	if (ircnet->max_msgs > 0) conn->max_msgs = ircnet->max_msgs;
	if (ircnet->max_modes > 0) conn->max_modes = ircnet->max_modes;
	if (ircnet->max_whois > 0) conn->max_whois = ircnet->max_whois;

	if (ircnet->max_cmds_at_once > 0)
		conn->max_cmds_at_once = ircnet->max_cmds_at_once;
	if (ircnet->cmd_queue_speed > 0)
		conn->cmd_queue_speed = ircnet->cmd_queue_speed;
	if (ircnet->max_query_chans > 0)
		conn->max_query_chans = ircnet->max_query_chans;
}

static void init_userinfo(void)
{
	const char *set, *nick, *user_name, *str;

	/* check if nick/username/realname wasn't read from setup.. */
        set = settings_get_str("real_name");
	if (set == NULL || *set == '\0') {
		str = g_getenv("IRCNAME");
		settings_set_str("real_name",
				 str != NULL ? str : g_get_real_name());
	}

	/* username */
        user_name = settings_get_str("user_name");
	if (user_name == NULL || *user_name == '\0') {
		str = g_getenv("IRCUSER");
		settings_set_str("user_name",
				 str != NULL ? str : g_get_user_name());

		user_name = settings_get_str("user_name");
	}

	/* nick */
        nick = settings_get_str("nick");
	if (nick == NULL || *nick == '\0') {
		str = g_getenv("IRCNICK");
		settings_set_str("nick", str != NULL ? str : user_name);

		nick = settings_get_str("nick");
	}

	/* host name */
        set = settings_get_str("hostname");
	if (set == NULL || *set == '\0') {
		str = g_getenv("IRCHOST");
		if (str != NULL)
			settings_set_str("hostname", str);
	}
}

static void sig_server_setup_read(IRC_SERVER_SETUP_REC *rec, CONFIG_NODE *node)
{
	g_return_if_fail(rec != NULL);
	g_return_if_fail(node != NULL);

	if (!IS_IRC_SERVER_SETUP(rec))
		return;

	rec->max_cmds_at_once = config_node_get_int(node, "cmds_max_at_once", 0);
	rec->cmd_queue_speed = config_node_get_int(node, "cmd_queue_speed", 0);
	rec->max_query_chans = config_node_get_int(node, "max_query_chans", 0);
}

static void sig_server_setup_saved(IRC_SERVER_SETUP_REC *rec,
				   CONFIG_NODE *node)
{
	if (!IS_IRC_SERVER_SETUP(rec))
		return;

	if (rec->max_cmds_at_once > 0)
		iconfig_node_set_int(node, "cmds_max_at_once", rec->max_cmds_at_once);
	if (rec->cmd_queue_speed > 0)
		iconfig_node_set_int(node, "cmd_queue_speed", rec->cmd_queue_speed);
	if (rec->max_query_chans > 0)
		iconfig_node_set_int(node, "max_query_chans", rec->max_query_chans);
}

void irc_servers_setup_init(void)
{
	settings_add_bool("server", "skip_motd", FALSE);
	settings_add_str("server", "alternate_nick", "");

	init_userinfo();
	signal_add("server setup fill reconn", (SIGNAL_FUNC) sig_server_setup_fill_reconn);
	signal_add("server setup fill connect", (SIGNAL_FUNC) sig_server_setup_fill_connect);
	signal_add("server setup fill chatnet", (SIGNAL_FUNC) sig_server_setup_fill_chatnet);
	signal_add("server setup read", (SIGNAL_FUNC) sig_server_setup_read);
	signal_add("server setup saved", (SIGNAL_FUNC) sig_server_setup_saved);
}

void irc_servers_setup_deinit(void)
{
	signal_remove("server setup fill reconn", (SIGNAL_FUNC) sig_server_setup_fill_reconn);
	signal_remove("server setup fill connect", (SIGNAL_FUNC) sig_server_setup_fill_connect);
	signal_remove("server setup fill chatnet", (SIGNAL_FUNC) sig_server_setup_fill_chatnet);
	signal_remove("server setup read", (SIGNAL_FUNC) sig_server_setup_read);
	signal_remove("server setup saved", (SIGNAL_FUNC) sig_server_setup_saved);
}
