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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
#include "rawlog.h"

static SERVER_CONNECT_REC *get_server_connect(const char *data, int *plus_addr,
					      char **rawlog_file)
{
        CHAT_PROTOCOL_REC *proto;
	SERVER_CONNECT_REC *conn;
	GHashTable *optlist;
	char *addr, *portstr, *password, *nick, *chatnet, *host, *tmp;
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

	if (g_strcmp0(password, "-") == 0)
		*password = '\0';

        /* check if -<chatnet> option is used to specify chat protocol */
	proto = chat_protocol_find_net(optlist);

	/* connect to server */
	chatnet = proto == NULL ? NULL :
		g_hash_table_lookup(optlist, proto->chatnet);

	if (chatnet == NULL)
		chatnet = g_hash_table_lookup(optlist, "network");

	conn = server_create_conn(proto != NULL ? proto->id : -1, addr,
				  atoi(portstr), chatnet, password, nick);
	if (proto == NULL)
		proto = chat_protocol_find_id(conn->chat_type);

	if (proto->not_initialized) {
		/* trying to use protocol that isn't yet initialized */
		signal_emit("chat protocol unknown", 1, proto->name);
		server_connect_unref(conn);
                cmd_params_free(free_arg);
		return NULL;
	}

	if (strchr(addr, '/') != NULL)
		conn->unix_socket = TRUE;

	if (g_hash_table_lookup(optlist, "6") != NULL)
		conn->family = AF_INET6;
	else if (g_hash_table_lookup(optlist, "4") != NULL)
		conn->family = AF_INET;

	if (g_hash_table_lookup(optlist, "ssl") != NULL)
		conn->use_ssl = TRUE;
	if ((tmp = g_hash_table_lookup(optlist, "ssl_cert")) != NULL)
		conn->ssl_cert = g_strdup(tmp);
	if ((tmp = g_hash_table_lookup(optlist, "ssl_pkey")) != NULL)
		conn->ssl_pkey = g_strdup(tmp);
	if ((tmp = g_hash_table_lookup(optlist, "ssl_pass")) != NULL)
		conn->ssl_pass = g_strdup(tmp);
	if (g_hash_table_lookup(optlist, "ssl_verify") != NULL)
		conn->ssl_verify = TRUE;
	if ((tmp = g_hash_table_lookup(optlist, "ssl_cafile")) != NULL)
		conn->ssl_cafile = g_strdup(tmp);
	if ((tmp = g_hash_table_lookup(optlist, "ssl_capath")) != NULL)
		conn->ssl_capath = g_strdup(tmp);
	if ((tmp = g_hash_table_lookup(optlist, "ssl_ciphers")) != NULL)
		conn->ssl_ciphers = g_strdup(tmp);
	if ((conn->ssl_capath != NULL && conn->ssl_capath[0] != '\0')
	||  (conn->ssl_cafile != NULL && conn->ssl_cafile[0] != '\0'))
		conn->ssl_verify = TRUE;
	if ((conn->ssl_cert != NULL && conn->ssl_cert[0] != '\0') || conn->ssl_verify)
		conn->use_ssl = TRUE;

	if (g_hash_table_lookup(optlist, "!") != NULL)
		conn->no_autojoin_channels = TRUE;

    if (g_hash_table_lookup(optlist, "noautosendcmd") != NULL)
        conn->no_autosendcmd = TRUE;

	if (g_hash_table_lookup(optlist, "noproxy") != NULL)
                g_free_and_null(conn->proxy);


	*rawlog_file = g_strdup(g_hash_table_lookup(optlist, "rawlog"));

        host = g_hash_table_lookup(optlist, "host");
	if (host != NULL && *host != '\0') {
		IPADDR ip;

		if (net_gethostbyname(host, &ip, conn->family) == 0)
                        server_connect_own_ip_save(conn, &ip);
	}

	cmd_params_free(free_arg);
        return conn;
}

/* SYNTAX: CONNECT [-4 | -6] [-ssl] [-ssl_cert <cert>] [-ssl_pkey <pkey>] [-ssl_pass <password>]
                   [-ssl_verify] [-ssl_cafile <cafile>] [-ssl_capath <capath>]
                   [-ssl_ciphers <list>]
                   [-!] [-noautosendcmd]
		   [-noproxy] [-network <network>] [-host <hostname>]
		   [-rawlog <file>]
		   <address>|<chatnet> [<port> [<password> [<nick>]]] */
/* NOTE: -network replaces the old -ircnet flag. */
static void cmd_connect(const char *data)
{
	SERVER_CONNECT_REC *conn;
	SERVER_REC *server;
        char *rawlog_file;

	conn = get_server_connect(data, NULL, &rawlog_file);
	if (conn != NULL) {
		server = server_connect(conn);
                server_connect_unref(conn);

		if (server != NULL && rawlog_file != NULL)
			rawlog_open(server->rawlog, rawlog_file);

		g_free(rawlog_file);
	}
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
			if (g_ascii_strcasecmp(rec->conn->address, addr) == 0) {
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
                server_connect_ref(oldconn);
                reconnect_save_status(conn, server);
	} else {
		/* maybe we can reconnect some server from
		   reconnection queue */
		recon = find_reconnect_server(conn->chat_type,
					      conn->address, conn->port);
		if (recon == NULL) return;

		oldconn = recon->conn;
                server_connect_ref(oldconn);
		server_reconnect_destroy(recon);

		conn->away_reason = g_strdup(oldconn->away_reason);
		conn->channels = g_strdup(oldconn->channels);
	}

	conn->reconnection = TRUE;

	if (conn->chatnet == NULL && oldconn->chatnet != NULL)
		conn->chatnet = g_strdup(oldconn->chatnet);

	server_connect_unref(oldconn);
	if (server != NULL) {
		signal_emit("command disconnect", 2,
			    "* Changing server", server);
	}
}

static void cmd_server(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	command_runsub("server", data, server, item);
}

static void sig_default_command_server(const char *data, SERVER_REC *server,
				       WI_ITEM_REC *item)
{
        signal_emit("command server connect", 3, data, server, item);
}

/* SYNTAX: SERVER [-4 | -6] [-ssl] [-ssl_cert <cert>] [-ssl_pkey <pkey>] [-ssl_pass <password>]
                  [-ssl_verify] [-ssl_cafile <cafile>] [-ssl_capath <capath>]
                  [-ssl_ciphers <list>]
                  [-!] [-noautosendcmd]
		  [-noproxy] [-network <network>] [-host <hostname>]
		  [-rawlog <file>]
                  [+]<address>|<chatnet> [<port> [<password> [<nick>]]] */
/* NOTE: -network replaces the old -ircnet flag. */
static void cmd_server_connect(const char *data, SERVER_REC *server)
{
	SERVER_CONNECT_REC *conn;
        char *rawlog_file;
	int plus_addr;

	g_return_if_fail(data != NULL);

        /* create connection record */
	conn = get_server_connect(data, &plus_addr, &rawlog_file);
	if (conn != NULL) {
		if (!plus_addr)
			update_reconnection(conn, server);
		server = server_connect(conn);
		server_connect_unref(conn);

		if (server != NULL && rawlog_file != NULL)
			rawlog_open(server->rawlog, rawlog_file);

		g_free(rawlog_file);
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

	if (*tag != '\0' && g_strcmp0(tag, "*") != 0) {
		server = server_find_tag(tag);
		if (server == NULL)
			server = server_find_lookup_tag(tag);
	}
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

/* SYNTAX: MSG [-<server tag>] [-channel | -nick] *|<targets> <message> */
static void cmd_msg(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	GHashTable *optlist;
	char *target, *origtarget, *msg;
	void *free_arg;
	int free_ret, target_type = SEND_TARGET_NICK;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_OPTIONS |
			    PARAM_FLAG_UNKNOWN_OPTIONS | PARAM_FLAG_GETREST,
			    "msg", &optlist, &target, &msg))
		return;
	if (*target == '\0' || *msg == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	server = cmd_options_get_server("msg", optlist, server);
	if (server == NULL || !server->connected)
		cmd_param_error(CMDERR_NOT_CONNECTED);

        origtarget = target;
	free_ret = FALSE;
	if (g_strcmp0(target, ",") == 0 || g_strcmp0(target, ".") == 0) {
		target = parse_special(&target, server, item,
				       NULL, &free_ret, NULL, 0);
		if (target != NULL && *target == '\0') {
			if (free_ret)
				g_free(target);
			target = NULL;
			free_ret = FALSE;
		}
	}

	if (target != NULL) {
		if (g_strcmp0(target, "*") == 0) {
                        /* send to active channel/query */
			if (item == NULL)
				cmd_param_error(CMDERR_NOT_JOINED);

			target_type = IS_CHANNEL(item) ?
				SEND_TARGET_CHANNEL : SEND_TARGET_NICK;
			target = (char *) window_item_get_target(item);
		} else if (g_hash_table_lookup(optlist, "channel") != NULL)
                        target_type = SEND_TARGET_CHANNEL;
		else if (g_hash_table_lookup(optlist, "nick") != NULL)
			target_type = SEND_TARGET_NICK;
		else {
			/* Need to rely on server_ischannel(). If the protocol
			   doesn't really know if it's channel or nick based on
			   the name, it should just assume it's nick, because
			   when typing text to channels it's always sent with
			   /MSG -channel. */
			target_type = server_ischannel(server, target) ?
				SEND_TARGET_CHANNEL : SEND_TARGET_NICK;
		}
	}
	if (target != NULL) {
		char **splitmsgs;
		char **tmp = NULL;
		char *singlemsg[] = { msg, NULL };
		char *m;
		int n = 0;

		/*
		 * If split_message is NULL, the server doesn't need to split
		 * long messages.
		 */
		if (server->split_message != NULL)
			splitmsgs = tmp = server->split_message(server, target,
								msg);
		else
			splitmsgs = singlemsg;

		while ((m = splitmsgs[n++])) {
			signal_emit("server sendmsg", 4, server, target, m,
				    GINT_TO_POINTER(target_type));
			signal_emit(target_type == SEND_TARGET_CHANNEL ?
				    "message own_public" :
				    "message own_private", 4, server, m,
				    target, origtarget);
		}
		g_strfreev(tmp);
	} else {
		signal_emit("message own_private", 4, server, msg, target,
			    origtarget);
	}

	if (free_ret && target != NULL) g_free(target);
	cmd_params_free(free_arg);
}

static void sig_server_sendmsg(SERVER_REC *server, const char *target,
			       const char *msg, void *target_type_p)
{
	server->send_message(server, target, msg,
			     GPOINTER_TO_INT(target_type_p));
}

static void cmd_foreach(const char *data, SERVER_REC *server,
			WI_ITEM_REC *item)
{
	command_runsub("foreach", data, server, item);
}

/* SYNTAX: FOREACH SERVER <command> */
static void cmd_foreach_server(const char *data, SERVER_REC *server)
{
        GSList *list;

	list = g_slist_copy(servers);
	while (list != NULL) {
		signal_emit("send command", 3, data, list->data, NULL);
                list = g_slist_remove(list, list->data);
	}
}

/* SYNTAX: FOREACH CHANNEL <command> */
static void cmd_foreach_channel(const char *data)
{
        GSList *list;

	list = g_slist_copy(channels);
	while (list != NULL) {
		CHANNEL_REC *rec = list->data;

		signal_emit("send command", 3, data, rec->server, rec);
                list = g_slist_remove(list, list->data);
	}
}

/* SYNTAX: FOREACH QUERY <command> */
static void cmd_foreach_query(const char *data)
{
        GSList *list;

	list = g_slist_copy(queries);
	while (list != NULL) {
		QUERY_REC *rec = list->data;

		signal_emit("send command", 3, data, rec->server, rec);
                list = g_slist_remove(list, list->data);
	}
}

void chat_commands_init(void)
{
	settings_add_str("misc", "quit_message", "leaving");

	command_bind("server", NULL, (SIGNAL_FUNC) cmd_server);
	command_bind("server connect", NULL, (SIGNAL_FUNC) cmd_server_connect);
	command_bind("connect", NULL, (SIGNAL_FUNC) cmd_connect);
	command_bind("disconnect", NULL, (SIGNAL_FUNC) cmd_disconnect);
	command_bind("quit", NULL, (SIGNAL_FUNC) cmd_quit);
	command_bind("msg", NULL, (SIGNAL_FUNC) cmd_msg);
	command_bind("foreach", NULL, (SIGNAL_FUNC) cmd_foreach);
	command_bind("foreach server", NULL, (SIGNAL_FUNC) cmd_foreach_server);
	command_bind("foreach channel", NULL, (SIGNAL_FUNC) cmd_foreach_channel);
	command_bind("foreach query", NULL, (SIGNAL_FUNC) cmd_foreach_query);

	signal_add("default command server", (SIGNAL_FUNC) sig_default_command_server);
	signal_add("server sendmsg", (SIGNAL_FUNC) sig_server_sendmsg);

	command_set_options("connect", "4 6 !! -network ssl +ssl_cert +ssl_pkey +ssl_pass ssl_verify +ssl_cafile +ssl_capath +ssl_ciphers +host noproxy -rawlog noautosendcmd");
	command_set_options("msg", "channel nick");
}

void chat_commands_deinit(void)
{
	command_unbind("server", (SIGNAL_FUNC) cmd_server);
	command_unbind("server connect", (SIGNAL_FUNC) cmd_server_connect);
	command_unbind("connect", (SIGNAL_FUNC) cmd_connect);
	command_unbind("disconnect", (SIGNAL_FUNC) cmd_disconnect);
	command_unbind("quit", (SIGNAL_FUNC) cmd_quit);
	command_unbind("msg", (SIGNAL_FUNC) cmd_msg);
	command_unbind("foreach", (SIGNAL_FUNC) cmd_foreach);
	command_unbind("foreach server", (SIGNAL_FUNC) cmd_foreach_server);
	command_unbind("foreach channel", (SIGNAL_FUNC) cmd_foreach_channel);
	command_unbind("foreach query", (SIGNAL_FUNC) cmd_foreach_query);

        signal_remove("default command server", (SIGNAL_FUNC) sig_default_command_server);
	signal_remove("server sendmsg", (SIGNAL_FUNC) sig_server_sendmsg);
}
