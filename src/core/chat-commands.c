/*
 chat-commands.c : irssi

    Copyright (C) 2000 Timo Sirainen

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
#include "network.h"
#include "signals.h"
#include "commands.h"
#include "special-vars.h"
#include "settings.h"

#include "chat-protocols.h"
#include "servers.h"
#include "servers-setup.h"
#include "servers-reconnect.h"
#include "channels.h"
#include "queries.h"
#include "window-item-def.h"

static SERVER_CONNECT_REC *get_server_connect(const char *data, int *plus_addr)
{
        CHAT_PROTOCOL_REC *proto;
	SERVER_CONNECT_REC *conn;
	GHashTable *optlist;
	char *addr, *portstr, *password, *nick, *chatnet, *host;
	void *free_arg;

	g_return_val_if_fail(data != NULL, NULL);

	if (!cmd_get_params(data, &free_arg, 4 | PARAM_FLAG_OPTIONS,
			    "connect", &optlist, &addr, &portstr,
			    &password, &nick))
		return NULL;
	if (plus_addr != NULL) *plus_addr = *addr == '+';
	if (*addr == '+') addr++;
	if (*addr == '\0') {
		signal_emit("error command", 1,
			    GINT_TO_POINTER(CMDERR_NOT_ENOUGH_PARAMS));
		cmd_params_free(free_arg);
		return NULL;
	}

	if (strcmp(password, "-") == 0)
		*password = '\0';

        /* check if -<chatnet> option is used to specify chat protocol */
	proto = chat_protocol_find_net(optlist);

	/* connect to server */
	chatnet = proto == NULL ? NULL :
		g_hash_table_lookup(optlist, proto->chatnet);
	conn = server_create_conn(proto != NULL ? proto->id : -1, addr,
				  atoi(portstr), chatnet, password, nick);
        if (proto == NULL)
		proto = chat_protocol_find_id(conn->chat_type);

	if (proto->not_initialized) {
		/* trying to use protocol that isn't yet initialized */
		signal_emit("chat protocol unknown", 1, proto->name);
		server_connect_free(conn);
                cmd_params_free(free_arg);
		return NULL;
	}

	if (g_hash_table_lookup(optlist, "6") != NULL)
		conn->family = AF_INET6;
	else if (g_hash_table_lookup(optlist, "4") != NULL)
		conn->family = AF_INET;

        host = g_hash_table_lookup(optlist, "host");
	if (host != NULL && *host != '\0') {
		IPADDR ip4, ip6;

		if (net_gethostbyname(host, &ip4, &ip6) == 0)
                        server_connect_own_ip_save(conn, &ip4, &ip6);
	}

	cmd_params_free(free_arg);
        return conn;
}

/* SYNTAX: CONNECT [-4 | -6] [-ircnet <ircnet>] [-host <hostname>]
                   <address>|<chatnet> [<port> [<password> [<nick>]]] */
static void cmd_connect(const char *data)
{
	SERVER_CONNECT_REC *conn;

	conn = get_server_connect(data, NULL);
        if (conn != NULL)
		CHAT_PROTOCOL(conn)->server_connect(conn);
}

static RECONNECT_REC *find_reconnect_server(int chat_type,
					    const char *addr, int port)
{
	RECONNECT_REC *match, *last_proto_match;
	GSList *tmp;
        int count;

	g_return_val_if_fail(addr != NULL, NULL);

	/* check if there's a reconnection to the same host and maybe even
	   the same port */
        match = last_proto_match = NULL; count = 0;
	for (tmp = reconnects; tmp != NULL; tmp = tmp->next) {
		RECONNECT_REC *rec = tmp->data;

		if (rec->conn->chat_type == chat_type) {
			count++; last_proto_match = rec;
			if (g_strcasecmp(rec->conn->address, addr) == 0) {
				if (rec->conn->port == port)
					return rec;
				match = rec;
			}
		}
	}

	if (count == 1) {
		/* only one reconnection with wanted protocol,
		   we probably want to use it */
                return last_proto_match;
	}

	return match;
}

static void update_reconnection(SERVER_CONNECT_REC *conn, SERVER_REC *server)
{
	SERVER_CONNECT_REC *oldconn;
	RECONNECT_REC *recon;

	if (server != NULL) {
		oldconn = server->connrec;
                reconnect_save_status(conn, server);
	} else {
		/* maybe we can reconnect some server from
		   reconnection queue */
		recon = find_reconnect_server(conn->chat_type,
					      conn->address, conn->port);
		if (recon == NULL) return;

		oldconn = recon->conn;
		server_reconnect_destroy(recon, FALSE);

		conn->away_reason = g_strdup(oldconn->away_reason);
		conn->channels = g_strdup(oldconn->channels);
	}

	conn->reconnection = TRUE;

	if (conn->chatnet == NULL && oldconn->chatnet != NULL)
		conn->chatnet = g_strdup(oldconn->chatnet);

	if (server != NULL) {
		signal_emit("command disconnect", 2,
			    "* Changing server", server);
	} else {
		server_connect_free(oldconn);
	}
}

/* SYNTAX: SERVER [-4 | -6] [-ircnet <ircnet>] [-host <hostname>]
                  [+]<address>|<chatnet> [<port> [<password> [<nick>]]] */
static void cmd_server(const char *data, SERVER_REC *server)
{
	SERVER_CONNECT_REC *conn;
	int plus_addr;

	g_return_if_fail(data != NULL);

        /* create connection record */
	conn = get_server_connect(data, &plus_addr);
	if (conn != NULL) {
		if (!plus_addr)
			update_reconnection(conn, server);
		CHAT_PROTOCOL(conn)->server_connect(conn);
	}
}

/* SYNTAX: DISCONNECT *|<tag> [<message>] */
static void cmd_disconnect(const char *data, SERVER_REC *server)
{
	char *tag, *msg;
	void *free_arg;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST, &tag, &msg))
		return;

	if (*tag != '\0' && strcmp(tag, "*") != 0)
		server = server_find_tag(tag);
	if (server == NULL) cmd_param_error(CMDERR_NOT_CONNECTED);

	if (*msg == '\0') msg = (char *) settings_get_str("quit_message");
	signal_emit("server quit", 2, server, msg);

	cmd_params_free(free_arg);
	server_disconnect(server);
}

/* SYNTAX: QUIT [<message>] */
static void cmd_quit(const char *data)
{
	GSList *tmp, *next;
	const char *quitmsg;
	char *str;

	g_return_if_fail(data != NULL);

	quitmsg = *data != '\0' ? data :
		settings_get_str("quit_message");

	/* disconnect from every server */
	for (tmp = servers; tmp != NULL; tmp = next) {
		next = tmp->next;

		str = g_strdup_printf("* %s", quitmsg);
		cmd_disconnect(str, tmp->data);
		g_free(str);
	}

	signal_emit("gui exit", 0);
}

/* SYNTAX: JOIN [-invite] [-<server tag>] <channels> [<keys>] */
static void cmd_join(const char *data, SERVER_REC *server)
{
	GHashTable *optlist;
	char *channels;
	void *free_arg;

	g_return_if_fail(data != NULL);
	if (!IS_SERVER(server) || !server->connected)
		cmd_return_error(CMDERR_NOT_CONNECTED);

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS |
			    PARAM_FLAG_UNKNOWN_OPTIONS | PARAM_FLAG_GETREST,
			    "join", &optlist, &channels))
		return;

	if (g_hash_table_lookup(optlist, "invite"))
		channels = server->last_invite;
	else {
		if (*channels == '\0')
			cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

		/* -<server tag> */
		server = cmd_options_get_server("join", optlist, server);
	}

	if (server != NULL && channels != NULL)
		server->channels_join(server, channels, FALSE);
	cmd_params_free(free_arg);
}

/* SYNTAX: MSG [-<server tag>] <targets> <message> */
static void cmd_msg(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	GHashTable *optlist;
	char *target, *origtarget, *msg;
	void *free_arg;
	int free_ret;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_OPTIONS |
			    PARAM_FLAG_UNKNOWN_OPTIONS | PARAM_FLAG_GETREST,
			    "msg", &optlist, &target, &msg))
		return;
	if (*target == '\0' || *msg == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	server = cmd_options_get_server("msg", optlist, SERVER(server));
	if (server == NULL || !server->connected)
		cmd_param_error(CMDERR_NOT_CONNECTED);

        origtarget = target;
	free_ret = FALSE;
	if (strcmp(target, ",") == 0 || strcmp(target, ".") == 0) {
		target = parse_special(&target, server, item,
				       NULL, &free_ret, NULL, 0);
		if (target != NULL && *target == '\0')
			target = NULL;
	} else if (strcmp(target, "*") == 0 && item != NULL)
		target = item->name;

	if (target != NULL)
		server->send_message(server, target, msg);

	signal_emit(target != NULL && server->ischannel(target) ?
		    "message own_public" : "message own_private", 4,
		    server, msg, target, origtarget);

	if (free_ret && target != NULL) g_free(target);
	cmd_params_free(free_arg);
}

static void cmd_foreach(const char *data, SERVER_REC *server,
			WI_ITEM_REC *item)
{
	command_runsub("foreach", data, server, item);
}

/* SYNTAX: FOREACH SERVER <command> */
static void cmd_foreach_server(const char *data, SERVER_REC *server)
{
	GSList *tmp;

	for (tmp = servers; tmp != NULL; tmp = tmp->next)
		signal_emit("send command", 3, data, tmp->data, NULL);
}

/* SYNTAX: FOREACH CHANNEL <command> */
static void cmd_foreach_channel(const char *data)
{
	GSList *tmp;

	for (tmp = channels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *rec = tmp->data;

		signal_emit("send command", 3, data, rec->server, rec);
	}
}

/* SYNTAX: FOREACH QUERY <command> */
static void cmd_foreach_query(const char *data)
{
	GSList *tmp;

	for (tmp = queries; tmp != NULL; tmp = tmp->next) {
		QUERY_REC *rec = tmp->data;

		signal_emit("send command", 3, data, rec->server, rec);
	}
}

void chat_commands_init(void)
{
	settings_add_str("misc", "quit_message", "leaving");

	command_bind("server", NULL, (SIGNAL_FUNC) cmd_server);
	command_bind("connect", NULL, (SIGNAL_FUNC) cmd_connect);
	command_bind("disconnect", NULL, (SIGNAL_FUNC) cmd_disconnect);
	command_bind("quit", NULL, (SIGNAL_FUNC) cmd_quit);
	command_bind("join", NULL, (SIGNAL_FUNC) cmd_join);
	command_bind("msg", NULL, (SIGNAL_FUNC) cmd_msg);
	command_bind("foreach", NULL, (SIGNAL_FUNC) cmd_foreach);
	command_bind("foreach server", NULL, (SIGNAL_FUNC) cmd_foreach_server);
	command_bind("foreach channel", NULL, (SIGNAL_FUNC) cmd_foreach_channel);
	command_bind("foreach query", NULL, (SIGNAL_FUNC) cmd_foreach_query);

	command_set_options("connect", "4 6 +host");
	command_set_options("join", "invite");
}

void chat_commands_deinit(void)
{
	command_unbind("server", (SIGNAL_FUNC) cmd_server);
	command_unbind("connect", (SIGNAL_FUNC) cmd_connect);
	command_unbind("disconnect", (SIGNAL_FUNC) cmd_disconnect);
	command_unbind("quit", (SIGNAL_FUNC) cmd_quit);
	command_unbind("join", (SIGNAL_FUNC) cmd_join);
	command_unbind("msg", (SIGNAL_FUNC) cmd_msg);
	command_unbind("foreach", (SIGNAL_FUNC) cmd_foreach);
	command_unbind("foreach server", (SIGNAL_FUNC) cmd_foreach_server);
	command_unbind("foreach channel", (SIGNAL_FUNC) cmd_foreach_channel);
	command_unbind("foreach query", (SIGNAL_FUNC) cmd_foreach_query);
}
