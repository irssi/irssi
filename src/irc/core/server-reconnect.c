/*
 server-reconnect.c : irssi

    Copyright (C) 1999 Timo Sirainen

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
#include "modules.h"
#include "commands.h"
#include "network.h"
#include "signals.h"

#include "irc.h"
#include "modes.h"
#include "irc-server.h"
#include "server-setup.h"
#include "server-reconnect.h"

#include "settings.h"
#include "common-setup.h"

GSList *reconnects;
static int last_reconnect_tag;
static int reconnect_timeout_tag;
static int reconnect_time;

static void server_reconnect_add(IRC_SERVER_CONNECT_REC *conn, time_t next_connect)
{
	RECONNECT_REC *rec;

	rec = g_new(RECONNECT_REC, 1);
	rec->tag = ++last_reconnect_tag;
	rec->conn = conn;
	rec->next_connect = next_connect;

	reconnects = g_slist_append(reconnects, rec);
}

static void server_reconnect_destroy(RECONNECT_REC *rec, int free_conn)
{
	reconnects = g_slist_remove(reconnects, rec);

	signal_emit("server reconnect remove", 1, rec);
	if (free_conn) irc_server_connect_free(rec->conn);
	g_free(rec);

	if (reconnects == NULL)
	    last_reconnect_tag = 0;
}

static int server_reconnect_timeout(void)
{
	IRC_SERVER_CONNECT_REC *conn;
	GSList *tmp, *next;
	time_t now;

	now = time(NULL);
	for (tmp = reconnects; tmp != NULL; tmp = next) {
		RECONNECT_REC *rec = tmp->data;

		next = tmp->next;
		if (rec->next_connect <= now) {
			conn = rec->conn;
			server_reconnect_destroy(rec, FALSE);
			irc_server_connect(conn);
		}
	}

	return 1;
}

static void sserver_connect(SETUP_SERVER_REC *rec, IRC_SERVER_CONNECT_REC *conn)
{
	conn->address = g_strdup(rec->server);
	conn->port = rec->port;
	conn->password = rec->password == NULL ? NULL :
		g_strdup(rec->password);
	if (rec->cmd_queue_speed > 0)
                conn->cmd_queue_speed = rec->cmd_queue_speed;

	if (rec->last_connect > time(NULL)-reconnect_time) {
		/* can't reconnect this fast, wait.. */
		server_reconnect_add(conn, rec->last_connect+reconnect_time);
	} else {
		/* connect to server.. */
		irc_server_connect(conn);
	}
}

static void server_connect_copy_skeleton(IRC_SERVER_CONNECT_REC *dest, IRC_SERVER_CONNECT_REC *src)
{
	dest->proxy = src->proxy == NULL ? NULL :
		g_strdup(src->proxy);
        dest->proxy_port = src->proxy_port;
	dest->proxy_string = src->proxy_string == NULL ? NULL :
		g_strdup(src->proxy_string);

	dest->ircnet = src->ircnet == NULL ? NULL :
		g_strdup(src->ircnet);
	dest->nick = src->nick == NULL ? NULL :
		g_strdup(src->nick);
	dest->username = src->username == NULL ? NULL :
		g_strdup(src->username);
	dest->realname = src->realname == NULL ? NULL :
		g_strdup(src->realname);

	if (src->own_ip != NULL) {
		dest->own_ip = g_new(IPADDR, 1);
		memcpy(dest->own_ip, src->own_ip, sizeof(IPADDR));
	}

	dest->cmd_queue_speed = src->cmd_queue_speed;
	dest->max_kicks = src->max_kicks;
	dest->max_modes = src->max_modes;
	dest->max_msgs = src->max_msgs;
}

static void sig_reconnect(IRC_SERVER_REC *server)
{
	IRC_SERVER_CONNECT_REC *conn;
	SETUP_SERVER_REC *sserver;
	GSList *tmp;
	int found, through;
	time_t now;

	g_return_if_fail(server != NULL);

	if (reconnect_time == -1 || !server->connection_lost || !irc_server_check(server))
		return;

	conn = g_new0(IRC_SERVER_CONNECT_REC, 1);
	conn->reconnection = TRUE;
	server_connect_copy_skeleton(conn, server->connrec);

	/* save the server status */
	if (!server->connected) {
		conn->channels = g_strdup(server->connrec->channels);
		conn->away_reason = g_strdup(server->connrec->away_reason);
		conn->usermode = g_strdup(server->connrec->usermode);
	} else {
		conn->channels = irc_server_get_channels(server);
		conn->away_reason = !server->usermode_away ? NULL :
			g_strdup(server->away_reason);
		conn->usermode = g_strdup(server->usermode);
	}

	sserver = server_setup_find(server->connrec->address, server->connrec->port);
	if (sserver == NULL) {
		/* port specific record not found, try without port.. */
		sserver = server_setup_find(server->connrec->address, -1);
	}

	if (sserver != NULL) {
		/* save the last connection time/status */
		sserver->last_connect = server->connect_time == 0 ?
			time(NULL) : server->connect_time;
		sserver->last_failed = !server->connected;
	}

	if (sserver == NULL || conn->ircnet == NULL) {
		/* not in any ircnet, just reconnect back to same server */
		conn->address = g_strdup(server->connrec->address);
		conn->port = server->connrec->port;
		conn->password = server->connrec->password == NULL ? NULL :
			g_strdup(server->connrec->password);

		if (server->connect_time != 0 &&
		    time(NULL)-server->connect_time > reconnect_time) {
			/* there's been enough time since last connection,
			   reconnect back immediately */
			irc_server_connect(conn);
		} else {
			/* reconnect later.. */
			server_reconnect_add(conn, (server->connect_time == 0 ? time(NULL) :
						    server->connect_time) + reconnect_time);
		}
		return;
	}

	/* always try to first connect to the first on the list where we
	   haven't got unsuccessful connection attempts for the last half
	   an hour. */

	now = time(NULL);
	for (tmp = setupservers; tmp != NULL; tmp = tmp->next) {
		SETUP_SERVER_REC *rec = tmp->data;

		if (rec->ircnet == NULL || g_strcasecmp(conn->ircnet, rec->ircnet) != 0)
			continue;

		if (!rec->last_connect || !rec->last_failed || rec->last_connect < now-FAILED_RECONNECT_WAIT) {
			sserver_connect(rec, conn);
			return;
		}
	}

	/* just try the next server in list */
	found = through = FALSE;
	for (tmp = setupservers; tmp != NULL; ) {
		SETUP_SERVER_REC *rec = tmp->data;

		if (!found && g_strcasecmp(rec->server, server->connrec->address) == 0 &&
		    server->connrec->port == rec->port)
			found = TRUE;
		else if (found && rec->ircnet != NULL && g_strcasecmp(conn->ircnet, rec->ircnet) == 0) {
			sserver_connect(rec, conn);
			break;
		}

		if (tmp->next != NULL) {
			tmp = tmp->next;
			continue;
		}

		if (through) {
			/* shouldn't happen unless there's no servers in
			   this ircnet in setup.. */
			break;
		}

		tmp = setupservers;
		found = through = TRUE;
	}
}

static void sig_server_looking(IRC_SERVER_REC *server)
{
	IRC_SERVER_CONNECT_REC *conn;
	GSList *tmp, *next;

	g_return_if_fail(server != NULL);
	if (!irc_server_check(server))
		return;

	/* trying to connect somewhere, check if there's anything in reconnect
	   queue waiting to connect to same ircnet or same server+port.. */
        conn = server->connrec;
	for (tmp = reconnects; tmp != NULL; tmp = next) {
		RECONNECT_REC *rec = tmp->data;

		next = tmp->next;
		if (g_strcasecmp(conn->address, rec->conn->address) == 0 &&
		    conn->port == rec->conn->port) {
			server_reconnect_destroy(rec, TRUE);
		}
		else if (conn->ircnet != NULL && rec->conn->ircnet != NULL &&
			 g_strcasecmp(conn->ircnet, rec->conn->ircnet) == 0) {
			server_reconnect_destroy(rec, TRUE);
		}
	}
}

/* Remove all servers from reconnect list */
static void cmd_rmreconns(void)
{
	while (reconnects != NULL)
		server_reconnect_destroy(reconnects->data, TRUE);
}

static RECONNECT_REC *reconnect_find_tag(int tag)
{
	GSList *tmp;

	for (tmp = reconnects; tmp != NULL; tmp = tmp->next) {
		RECONNECT_REC *rec = tmp->data;

		if (rec->tag == tag)
			return rec;
	}

	return NULL;
}

/* Try to reconnect immediately */
static void cmd_reconnect(const char *data)
{
	IRC_SERVER_CONNECT_REC *conn;
	RECONNECT_REC *rec;
	int tag;

	if (g_strncasecmp(data, "RECON-", 6) == 0)
		data += 6;

	rec = sscanf(data, "%d", &tag) == 1 && tag > 0 ?
		reconnect_find_tag(tag) : NULL;

	if (rec == NULL)
		signal_emit("server reconnect not found", 1, data);
	else {
		conn = rec->conn;
		server_reconnect_destroy(rec, FALSE);
		irc_server_connect(rec->conn);
	}
}

static void cmd_disconnect(const char *data, SERVER_REC *server)
{
	RECONNECT_REC *rec;
	int tag;

	if (g_strncasecmp(data, "RECON-", 6) != 0)
		return; /* handle only reconnection removing */

	rec = sscanf(data+6, "%d", &tag) == 1 && tag > 0 ?
		reconnect_find_tag(tag) : NULL;

	if (rec == NULL)
		signal_emit("server reconnect not found", 1, data);
	else
		server_reconnect_destroy(rec, TRUE);
}

static int sig_set_user_mode(IRC_SERVER_REC *server)
{
	const char *mode;
	char *newmode;

	if (g_slist_find(servers, server) == NULL)
		return 0; /* got disconnected */

	mode = server->connrec->usermode;
	if (mode == NULL) return 0;

	newmode = modes_join(server->usermode, mode);
	if (strcmp(newmode, server->usermode) != 0)
		irc_send_cmdv(server, "MODE %s -%s+%s", server->nick, server->usermode, mode);
	g_free(newmode);
	return 0;
}

static void sig_connected(IRC_SERVER_REC *server)
{
	if (!server->connrec->reconnection)
		return;

	if (server->connrec->channels != NULL)
		channels_join(server, server->connrec->channels, TRUE);
	if (server->connrec->away_reason != NULL)
		signal_emit("command away", 2, server->connrec->away_reason, server, NULL);
	if (server->connrec->usermode != NULL) {
		/* wait a second and then send the user mode */
		g_timeout_add(1000, (GSourceFunc) sig_set_user_mode, server);
	}
}

static void read_settings(void)
{
	reconnect_time = settings_get_int("server_reconnect_time");
}

void servers_reconnect_init(void)
{
	reconnects = NULL;
	last_reconnect_tag = 0;

	reconnect_timeout_tag = g_timeout_add(1000, (GSourceFunc) server_reconnect_timeout, NULL);
	read_settings();

	signal_add("server looking", (SIGNAL_FUNC) sig_server_looking);
	signal_add("server connect failed", (SIGNAL_FUNC) sig_reconnect);
	signal_add("server disconnected", (SIGNAL_FUNC) sig_reconnect);
	signal_add("event connected", (SIGNAL_FUNC) sig_connected);
	command_bind("rmreconns", NULL, (SIGNAL_FUNC) cmd_rmreconns);
	command_bind("reconnect", NULL, (SIGNAL_FUNC) cmd_reconnect);
	command_bind("disconnect", NULL, (SIGNAL_FUNC) cmd_disconnect);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
}

void servers_reconnect_deinit(void)
{
	g_source_remove(reconnect_timeout_tag);

	while (reconnects != NULL)
		server_reconnect_destroy(reconnects->data, TRUE);

	signal_remove("server looking", (SIGNAL_FUNC) sig_server_looking);
	signal_remove("server connect failed", (SIGNAL_FUNC) sig_reconnect);
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_reconnect);
	signal_remove("event connected", (SIGNAL_FUNC) sig_connected);
	command_unbind("rmreconns", (SIGNAL_FUNC) cmd_rmreconns);
	command_unbind("reconnect", (SIGNAL_FUNC) cmd_reconnect);
	command_unbind("disconnect", (SIGNAL_FUNC) cmd_disconnect);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
}
