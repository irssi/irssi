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
#include "net-sendbuffer.h"
#include "line-split.h"
#include "signals.h"
#include "rawlog.h"
#include "misc.h"

#include "channels.h"
#include "queries.h"

#include "irc.h"
#include "irc-servers-setup.h"
#include "irc-servers.h"
#include "channel-rejoin.h"
#include "server-idle.h"
#include "servers-reconnect.h"
#include "modes.h"

#include "settings.h"

#define DEFAULT_MAX_KICKS 1
#define DEFAULT_MAX_MODES 3
#define DEFAULT_MAX_WHOIS 4
#define DEFAULT_MAX_MSGS 1

#define DEFAULT_USER_MODE "+i"
#define DEFAULT_CMD_QUEUE_SPEED 2200
#define DEFAULT_CMDS_MAX_AT_ONCE 5
#define DEFAULT_MAX_QUERY_CHANS 10

void irc_servers_reconnect_init(void);
void irc_servers_reconnect_deinit(void);

static int cmd_tag;

static void sig_server_connect_free(IRC_SERVER_CONNECT_REC *conn)
{
	if (!IS_IRC_SERVER_CONNECT(conn))
		return;

	g_free_not_null(conn->alternate_nick);
}

static int isnickflag_func(char flag)
{
	return isnickflag(flag);
}

static int ischannel_func(char flag)
{
	return ischannel(flag);
}

static void send_message(IRC_SERVER_REC *server, const char *target,
			 const char *msg)
{
	char *str;

	g_return_if_fail(server != NULL);
	g_return_if_fail(target != NULL);
	g_return_if_fail(msg != NULL);

	str = g_strdup_printf("PRIVMSG %s :%s", target, msg);
	irc_send_cmd_split(server, str, 2, server->max_msgs_in_cmd);
	g_free(str);
}

static void sig_server_looking(IRC_SERVER_REC *server)
{
	if (!IS_IRC_SERVER(server))
		return;

	server->isnickflag = isnickflag_func;
	server->ischannel = ischannel_func;
	server->send_message =
		(void (*)(void *, const char *, const char *)) send_message;
}

static void server_init(IRC_SERVER_REC *server)
{
	IRC_SERVER_CONNECT_REC *conn;
	char hostname[100], *address, *ptr;

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

	address = server->connrec->address;
        ptr = strrchr(address, ':');
	if (ptr != NULL) {
		/* IPv6 address .. doesn't work here, use the string after
		   the last : char */
                address = ptr+1;
	}
	irc_send_cmdv(server, "USER %s %s %s :%s", conn->username, hostname,
		      address, conn->realname);

	server->cmdcount = 0;
}

IRC_SERVER_REC *irc_server_connect(IRC_SERVER_CONNECT_REC *conn)
{
	IRC_SERVER_REC *server;

	g_return_val_if_fail(IS_IRC_SERVER_CONNECT(conn), NULL);
	if (conn->address == NULL || *conn->address == '\0') return NULL;
	if (conn->nick == NULL || *conn->nick == '\0') return NULL;

	server = g_new0(IRC_SERVER_REC, 1);
	server->chat_type = IRC_PROTOCOL;
	server->connrec = conn;
	if (server->connrec->port <= 0) server->connrec->port = 6667;

	server->cmd_queue_speed = conn->cmd_queue_speed > 0 ?
		conn->cmd_queue_speed : settings_get_int("cmd_queue_speed");
	server->max_cmds_at_once = conn->max_cmds_at_once > 0 ?
		conn->max_cmds_at_once : settings_get_int("cmds_max_at_once");
	server->max_query_chans = conn->max_query_chans > 0 ?
		conn->max_query_chans : DEFAULT_MAX_QUERY_CHANS;

	server->max_kicks_in_cmd = conn->max_kicks > 0 ?
		conn->max_kicks : DEFAULT_MAX_KICKS;
	server->max_modes_in_cmd = conn->max_modes > 0 ?
		conn->max_modes : DEFAULT_MAX_MODES;
	server->max_whois_in_cmd = conn->max_whois > 0 ?
		conn->max_whois : DEFAULT_MAX_WHOIS;
	server->max_msgs_in_cmd = conn->max_msgs > 0 ?
		conn->max_msgs : DEFAULT_MAX_MSGS;

	if (!server_start_connect((SERVER_REC *) server)) {
                server_connect_free(SERVER_CONNECT(conn));
		g_free(server);
		return NULL;
	}
	return server;
}

static void sig_server_connect(IRC_SERVER_REC **server,
			       IRC_SERVER_CONNECT_REC *conn)
{
	g_return_if_fail(server != NULL);
	if (!IS_IRC_SERVER_CONNECT(conn))
		return;

	*server = irc_server_connect(conn);
        signal_stop();
}

static void sig_connected(IRC_SERVER_REC *server)
{
	if (!IS_IRC_SERVER(server))
		return;

	server->splits = g_hash_table_new((GHashFunc) g_istr_hash, (GCompareFunc) g_istr_equal);
	server_init(server);
}

static void sig_disconnected(IRC_SERVER_REC *server)
{
	if (!IS_IRC_SERVER(server))
		return;

	g_slist_foreach(server->cmdqueue, (GFunc) g_free, NULL);
	g_slist_free(server->cmdqueue);

	g_free_not_null(server->real_address);
	g_free_not_null(server->usermode);
	g_free_not_null(server->userhost);
	g_free_not_null(server->last_invite);
}

static void sig_server_quit(IRC_SERVER_REC *server, const char *msg)
{
	char *str;

	if (!IS_IRC_SERVER(server) || server->handle == NULL ||
	    server->buffer == NULL)
		return;

	str = g_strdup_printf("QUIT :%s", msg);
	irc_send_cmd_now(server, str);
	g_free(str);
}

static void server_cmd_timeout(IRC_SERVER_REC *server, GTimeVal *now)
{
	long usecs;
	char *cmd;
	int len, add_rawlog;

	if (!IS_IRC_SERVER(server))
		return;

	if (server->cmdcount == 0 && server->cmdqueue == NULL)
		return;

	if (!server->cmd_last_split) {
		if (g_timeval_cmp(now, &server->wait_cmd) == -1)
			return;

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

	if (net_sendbuffer_send(server->handle, cmd, len) == -1) {
		/* something bad happened */
		g_warning("net_sendbuffer_send() failed: %s", g_strerror(errno));
		return;
	}

	server->wait_cmd.tv_sec = 0;
	memcpy(&server->last_cmd, now, sizeof(GTimeVal));
	if (server->cmd_last_split)
		server->cmd_last_split = FALSE;

	if (add_rawlog) {
		/* add to rawlog without CR+LF */
		int slen;

		slen = strlen(cmd);
		cmd[slen-2] = '\0';
		rawlog_output(server->rawlog, cmd);
		cmd[slen-2] = '\r';
	}

	/* remove from queue */
	g_free(cmd);
	server->cmdqueue = g_slist_remove(server->cmdqueue, cmd);
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

	/* get currently joined channels */
	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *channel = tmp->data;

		g_string_sprintfa(chans, "%s,", channel->name);
		g_string_sprintfa(keys, "%s,", channel->key == NULL ? "x" :
				  channel->key);
		if (channel->key != NULL)
			use_keys = TRUE;
	}

	/* get also the channels that are in rejoin list */
	for (tmp = server->rejoin_channels; tmp != NULL; tmp = tmp->next) {
		REJOIN_REC *rec = tmp->data;

		g_string_sprintfa(chans, "%s,", rec->channel);
		g_string_sprintfa(keys, "%s,", rec->key == NULL ? "x" :
				  rec->key);
		if (rec->key != NULL) use_keys = TRUE;
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
		modes_join(server->usermode, mode, FALSE);
	if (server->usermode == NULL || strcmp(newmode, server->usermode) != 0)
		irc_send_cmdv(server, "MODE %s %s", server->nick, mode);
	g_free_not_null(newmode);
	return 0;
}

static void event_connected(IRC_SERVER_REC *server, const char *data, const char *from)
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
		server->real_address = from == NULL ?
			g_strdup(server->connrec->address) : /* shouldn't happen.. */
			g_strdup(from);
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

static void event_server_info(IRC_SERVER_REC *server, const char *data)
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

static void event_server_banned(IRC_SERVER_REC *server, const char *data)
{
	g_return_if_fail(server != NULL);

        server->banned = TRUE;
}

static void event_error(IRC_SERVER_REC *server, const char *data)
{
	g_return_if_fail(server != NULL);

	if (!server->connected && (stristr(data, "Unauthorized") != NULL ||
				   stristr(data, "K-lined") != NULL))
		server->banned = TRUE;
}

static void event_ping(IRC_SERVER_REC *server, const char *data)
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

	signal_add("server connect free", (SIGNAL_FUNC) sig_server_connect_free);
	signal_add("server connect", (SIGNAL_FUNC) sig_server_connect);
	signal_add_first("server looking", (SIGNAL_FUNC) sig_server_looking);
	signal_add_first("server connected", (SIGNAL_FUNC) sig_connected);
	signal_add_last("server disconnected", (SIGNAL_FUNC) sig_disconnected);
	signal_add_last("server quit", (SIGNAL_FUNC) sig_server_quit);
	signal_add("event 001", (SIGNAL_FUNC) event_connected);
	signal_add("event 004", (SIGNAL_FUNC) event_server_info);
	signal_add("event 465", (SIGNAL_FUNC) event_server_banned);
	signal_add("event error", (SIGNAL_FUNC) event_error);
	signal_add("event ping", (SIGNAL_FUNC) event_ping);
	signal_add("event empty", (SIGNAL_FUNC) event_empty);

	irc_servers_setup_init();
	irc_servers_reconnect_init();
	servers_idle_init();
}

void irc_servers_deinit(void)
{
	while (servers != NULL)
		server_disconnect(servers->data);
	while (lookup_servers != NULL)
		server_disconnect(lookup_servers->data);

	g_source_remove(cmd_tag);

	signal_remove("server connect free", (SIGNAL_FUNC) sig_server_connect_free);
	signal_remove("server connect", (SIGNAL_FUNC) sig_server_connect);
	signal_remove("server looking", (SIGNAL_FUNC) sig_server_looking);
	signal_remove("server connected", (SIGNAL_FUNC) sig_connected);
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_disconnected);
        signal_remove("server quit", (SIGNAL_FUNC) sig_server_quit);
	signal_remove("event 001", (SIGNAL_FUNC) event_connected);
	signal_remove("event 004", (SIGNAL_FUNC) event_server_info);
	signal_remove("event 465", (SIGNAL_FUNC) event_server_banned);
	signal_remove("event error", (SIGNAL_FUNC) event_error);
	signal_remove("event ping", (SIGNAL_FUNC) event_ping);
	signal_remove("event empty", (SIGNAL_FUNC) event_empty);

	irc_servers_setup_deinit();
	irc_servers_reconnect_deinit();
	servers_idle_deinit();
}
