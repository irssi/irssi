/*
 irc-server.c : irssi

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

#include "net-nonblock.h"
#include "line-split.h"
#include "signals.h"
#include "modules.h"
#include "rawlog.h"
#include "misc.h"

#include "irc-server.h"
#include "server-idle.h"
#include "server-reconnect.h"
#include "server-setup.h"
#include "ircnet-setup.h"
#include "channels.h"
#include "modes.h"
#include "irc.h"
#include "query.h"

#include "settings.h"

#define DEFAULT_MAX_KICKS 1
#define DEFAULT_MAX_MODES 3
#define DEFAULT_MAX_WHOIS 4
#define DEFAULT_MAX_MSGS 1

#define DEFAULT_USER_MODE "+i"
#define DEFAULT_CMD_QUEUE_SPEED 2200
#define DEFAULT_CMDS_MAX_AT_ONCE 5

static int cmd_tag;

void irc_server_connect_free(IRC_SERVER_CONNECT_REC *rec)
{
	g_return_if_fail(rec != NULL);

        g_free_not_null(rec->proxy);
        g_free_not_null(rec->proxy_string);
        g_free_not_null(rec->ircnet);
        g_free_not_null(rec->password);
        g_free_not_null(rec->nick);
        g_free_not_null(rec->alternate_nick);
        g_free_not_null(rec->username);
	g_free_not_null(rec->realname);
	g_free_not_null(rec->own_ip);
        g_free_not_null(rec->channels);
        g_free_not_null(rec->away_reason);
        g_free_not_null(rec->usermode);
	g_free_not_null(rec->address);
        g_free(rec);
}

static void server_init(IRC_SERVER_REC *server)
{
	IRC_SERVER_CONNECT_REC *conn;
	char hostname[100];

	g_return_if_fail(server != NULL);

	conn = server->connrec;

	if (conn->proxy_string != NULL)
		irc_send_cmdv(server, conn->proxy_string, conn->address, conn->port);

	if (conn->password != NULL && *conn->password != '\0') {
                /* send password */
		server->cmdcount = 0;
		irc_send_cmdv(server, "PASS %s", conn->password);
	}

        /* send nick */
	server->cmdcount = 0;
	irc_send_cmdv(server, "NICK %s", conn->nick);

	/* send user/realname */
	server->cmdcount = 0;

	if (gethostname(hostname, sizeof(hostname)) != 0 || *hostname == '\0')
		strcpy(hostname, "xx");

	irc_send_cmdv(server, "USER %s %s %s :%s", conn->username, hostname,
		      server->connrec->address, conn->realname);

	server->cmdcount = 0;
}

IRC_SERVER_REC *irc_server_connect(IRC_SERVER_CONNECT_REC *conn)
{
	IRC_SERVER_REC *server;

	g_return_val_if_fail(conn != NULL, NULL);
	if (conn->address == NULL || *conn->address == '\0') return NULL;
	if (conn->nick == NULL || *conn->nick == '\0') return NULL;

	server = g_new0(IRC_SERVER_REC, 1);
	server->type = module_get_uniq_id("IRC SERVER", SERVER_TYPE_IRC);

	server->connrec = conn;
	if (conn->port <= 0) conn->port = 6667;
	if (conn->username == NULL || *conn->username == '\0') {
		g_free_not_null(conn->username);

		conn->username = g_get_user_name();
		if (*conn->username == '\0') conn->username = "-";
		conn->username = g_strdup(conn->username);
	}
	if (conn->realname == NULL || *conn->realname == '\0') {
		g_free_not_null(conn->realname);

		conn->realname = g_get_real_name();
		if (*conn->realname == '\0') conn->realname = "-";
		conn->realname = g_strdup(conn->realname);
	}

	server->nick = g_strdup(conn->nick);

	server->cmd_queue_speed = conn->cmd_queue_speed > 0 ?
		conn->cmd_queue_speed : settings_get_int("cmd_queue_speed");
	server->max_cmds_at_once = conn->max_cmds_at_once > 0 ?
		conn->max_cmds_at_once : settings_get_int("cmds_max_at_once");

	server->max_kicks_in_cmd = conn->max_kicks > 0 ?
		conn->max_kicks : DEFAULT_MAX_KICKS;
	server->max_modes_in_cmd = conn->max_modes > 0 ?
		conn->max_modes : DEFAULT_MAX_MODES;
	server->max_whois_in_cmd = conn->max_whois > 0 ?
		conn->max_whois : DEFAULT_MAX_WHOIS;
	server->max_msgs_in_cmd = conn->max_msgs > 0 ?
		conn->max_msgs : DEFAULT_MAX_MSGS;

	if (!server_connect((SERVER_REC *) server)) {
                irc_server_connect_free(conn);
		g_free(server->nick);
		g_free(server);
		return NULL;
	}
	return server;
}

static void sig_connected(IRC_SERVER_REC *server)
{
	server->eventtable = g_hash_table_new((GHashFunc) g_istr_hash, (GCompareFunc) g_istr_equal);
	server->eventgrouptable = g_hash_table_new((GHashFunc) g_direct_hash, (GCompareFunc) g_direct_equal);
	server->cmdtable = g_hash_table_new((GHashFunc) g_istr_hash, (GCompareFunc) g_istr_equal);
	server->splits = g_hash_table_new((GHashFunc) g_istr_hash, (GCompareFunc) g_istr_equal);

	server_init(server);
}

static int server_remove_channels(IRC_SERVER_REC *server)
{
	GSList *tmp;
	int found;

	g_return_val_if_fail(server != NULL, FALSE);

	found = FALSE;
	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *channel = tmp->data;

		channel->server = NULL;
		channel_destroy(channel);
		found = TRUE;
	}

	for (tmp = server->queries; tmp != NULL; tmp = tmp->next)
		query_change_server(tmp->data, NULL);

	g_slist_free(server->channels);
	g_slist_free(server->queries);

	return found;
}

static void sig_disconnected(IRC_SERVER_REC *server)
{
	int chans;

	/* close all channels */
	chans = server_remove_channels(server);

	g_slist_foreach(server->cmdqueue, (GFunc) g_free, NULL);
	g_slist_free(server->cmdqueue);

	if (server->handle != -1) {
		if (!chans || server->connection_lost)
			net_disconnect(server->handle);
		else {
			/* we were on some channels, try to let the server
			   disconnect so that our quit message is guaranteed
			   to get displayed */
			net_disconnect_later(server->handle);
		}
		server->handle = -1;
	}

	irc_server_connect_free(server->connrec);
	g_free_not_null(server->real_address);
	g_free_not_null(server->version);
	g_free_not_null(server->usermode);
	g_free_not_null(server->userhost);
	g_free_not_null(server->last_invite);
	g_free_not_null(server->away_reason);
}

static void sig_connect_failed(IRC_SERVER_REC *server)
{
	server_remove_channels(server);
        irc_server_connect_free(server->connrec);
}

static void server_cmd_timeout(IRC_SERVER_REC *server, GTimeVal *now)
{
	long usecs;
	char *cmd;
	int len, ret, add_rawlog;

	if (server->cmdcount == 0 && server->cmdqueue == NULL)
		return;

	if (!server->cmd_last_split) {
		usecs = get_timeval_diff(now, &server->last_cmd);
		if (usecs < server->cmd_queue_speed)
			return;
	}

	server->cmdcount--;
	if (server->cmdqueue == NULL) return;

	/* send command */
	cmd = server->cmdqueue->data;
	len = strlen(cmd);

	add_rawlog = !server->cmd_last_split;

        ret = net_transmit(server->handle, cmd, len);
	if (ret != len) {
		/* we didn't transmit all data, try again a bit later.. */
		if (ret > 0) {
			cmd = g_strdup((char *) (server->cmdqueue->data) + ret);
			g_free(server->cmdqueue->data);
			server->cmdqueue->data = cmd;
		}
		server->cmd_last_split = TRUE;
		server->cmdcount++;
	} else {
		memcpy(&server->last_cmd, now, sizeof(GTimeVal));
		if (server->cmd_last_split)
			server->cmd_last_split = FALSE;
	}

	if (add_rawlog) {
		/* add to rawlog without CR+LF */
		int slen;

		slen = strlen(cmd);
		cmd[slen-2] = '\0';
		rawlog_output(server->rawlog, cmd);
		cmd[slen-2] = '\r';
	}

	if (ret == len) {
		/* remove from queue */
		g_free(cmd);
		server->cmdqueue = g_slist_remove(server->cmdqueue, cmd);
	}
}

/* check every now and then if there's data to be sent in command buffer */
static int servers_cmd_timeout(void)
{
	GTimeVal now;

	g_get_current_time(&now);
	g_slist_foreach(servers, (GFunc) server_cmd_timeout, &now);
	return 1;
}

/* Return a string of all channels (and keys, if any have them) in server,
   like "#a,#b,#c,#d x,b_chan_key,x,x" or just "#e,#f,#g" */
char *irc_server_get_channels(IRC_SERVER_REC *server)
{
	GSList *tmp;
	GString *chans, *keys;
	char *ret;
	int use_keys;

	g_return_val_if_fail(server != NULL, FALSE);

	chans = g_string_new(NULL);
	keys = g_string_new(NULL);

	use_keys = FALSE;
	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *channel = tmp->data;

		g_string_sprintfa(chans, "%s,", channel->name);
		g_string_sprintfa(keys, "%s,", channel->key == NULL ? "x" : channel->key);
		if (channel->key != NULL)
			use_keys = TRUE;
	}

	if (chans->len > 0) {
		g_string_truncate(chans, chans->len-1);
		g_string_truncate(keys, keys->len-1);
		if (use_keys) g_string_sprintfa(chans, " %s", keys->str);
	}

	ret = chans->str;
	g_string_free(chans, FALSE);
	g_string_free(keys, TRUE);

	return ret;
}

static int sig_set_user_mode(IRC_SERVER_REC *server)
{
	const char *mode;
	char *newmode;

	if (g_slist_find(servers, server) == NULL)
		return 0; /* got disconnected */

	mode = settings_get_str("usermode");
	newmode = server->usermode == NULL ? NULL :
		modes_join(server->usermode, mode);
	if (server->usermode == NULL || strcmp(newmode, server->usermode) != 0)
		irc_send_cmdv(server, "MODE %s %s", server->nick, mode);
	g_free_not_null(newmode);
	return 0;
}

static void event_connected(const char *data, IRC_SERVER_REC *server, const char *from)
{
	char *params, *nick;
	const char *mode;

	g_return_if_fail(server != NULL);

	params = event_get_params(data, 1, &nick);

	if (strcmp(server->nick, nick) != 0) {
		/* nick changed unexpectedly .. connected via proxy, etc. */
		g_free(server->nick);
		server->nick = g_strdup(nick);
	}

	if (server->real_address == NULL) {
		/* set the server address */
		server->real_address = g_strdup(from);
	}

	/* last welcome message found - commands can be sent to server now. */
	server->connected = 1;
	server->real_connect_time = time(NULL);

	if (!server->connrec->reconnection) {
		/* wait a second and then send the user mode */
		mode = settings_get_str("usermode");
		if (*mode != '\0')
			g_timeout_add(1000, (GSourceFunc) sig_set_user_mode, server);
	}

	signal_emit("event connected", 1, server);
	g_free(params);
}

static void event_server_info(const char *data, IRC_SERVER_REC *server)
{
	char *params, *ircd_version, *usermodes, *chanmodes;

	g_return_if_fail(server != NULL);

	params = event_get_params(data, 5, NULL, NULL, &ircd_version, &usermodes, &chanmodes);

	/* check if server understands I and e channel modes */
	if (strchr(chanmodes, 'I') && strchr(chanmodes, 'e'))
		server->emode_known = TRUE;

	/* save server version */
	g_free_not_null(server->version);
	server->version = g_strdup(ircd_version);

	g_free(params);
}

static void event_server_banned(const char *data, IRC_SERVER_REC *server)
{
	g_return_if_fail(server != NULL);

        server->banned = TRUE;
}

static void event_error(const char *data, IRC_SERVER_REC *server)
{
	g_return_if_fail(server != NULL);

	if (!server->connected && (stristr(data, "Unauthorized") != NULL ||
				   stristr(data, "K-lined") != NULL))
		server->banned = TRUE;
}

static void event_ping(const char *data, IRC_SERVER_REC *server)
{
	char *str;

	g_return_if_fail(data != NULL);

	str = g_strdup_printf("PONG %s", data);
	irc_send_cmd_now(server, str);
	g_free(str);
}

static void event_empty(void)
{
}

void irc_servers_init(void)
{
	settings_add_str("misc", "usermode", DEFAULT_USER_MODE);
	settings_add_int("flood", "cmd_queue_speed", DEFAULT_CMD_QUEUE_SPEED);
	settings_add_int("flood", "cmds_max_at_once", DEFAULT_CMDS_MAX_AT_ONCE);

	cmd_tag = g_timeout_add(500, (GSourceFunc) servers_cmd_timeout, NULL);

	signal_add_first("server connected", (SIGNAL_FUNC) sig_connected);
	signal_add_last("server disconnected", (SIGNAL_FUNC) sig_disconnected);
	signal_add_last("server connect failed", (SIGNAL_FUNC) sig_connect_failed);
	signal_add("event 001", (SIGNAL_FUNC) event_connected);
	signal_add("event 004", (SIGNAL_FUNC) event_server_info);
	signal_add("event 465", (SIGNAL_FUNC) event_server_banned);
	signal_add("event error", (SIGNAL_FUNC) event_error);
	signal_add("event ping", (SIGNAL_FUNC) event_ping);
	signal_add("event empty", (SIGNAL_FUNC) event_empty);

	servers_setup_init();
	ircnets_setup_init();
	servers_idle_init();
	servers_reconnect_init();
}

void irc_servers_deinit(void)
{
	while (servers != NULL)
		server_disconnect(servers->data);
	while (lookup_servers != NULL)
		server_disconnect(lookup_servers->data);

	g_source_remove(cmd_tag);

	signal_remove("server connected", (SIGNAL_FUNC) sig_connected);
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_disconnected);
	signal_remove("server connect failed", (SIGNAL_FUNC) sig_connect_failed);
	signal_remove("event 001", (SIGNAL_FUNC) event_connected);
	signal_remove("event 004", (SIGNAL_FUNC) event_server_info);
	signal_remove("event 465", (SIGNAL_FUNC) event_server_banned);
	signal_remove("event error", (SIGNAL_FUNC) event_error);
	signal_remove("event ping", (SIGNAL_FUNC) event_ping);
	signal_remove("event empty", (SIGNAL_FUNC) event_empty);

	servers_setup_deinit();
	ircnets_setup_deinit();
	servers_idle_deinit();
	servers_reconnect_deinit();
}
