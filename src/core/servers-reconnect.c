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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include <irssi/src/core/commands.h>
#include <irssi/src/core/network.h>
#include <irssi/src/core/signals.h>

#include <irssi/src/core/chat-protocols.h>
#include <irssi/src/core/servers.h>
#include <irssi/src/core/servers-setup.h>
#include <irssi/src/core/servers-reconnect.h>

#include <irssi/src/core/settings.h>

GSList *reconnects;
static int last_reconnect_tag;
static int reconnect_timeout_tag;
static int reconnect_time;
static int connect_timeout;

void reconnect_save_status(SERVER_CONNECT_REC *conn, SERVER_REC *server)
{
        g_free_not_null(conn->tag);
	conn->tag = g_strdup(server->tag);

	g_free_not_null(conn->away_reason);
	conn->away_reason = !server->usermode_away ? NULL :
		g_strdup(server->away_reason);

	if (!server->connected) {
		/* default to channels/usermode from connect record
		   since server isn't fully connected yet */
		/* XXX when is reconnect_save_status() called with
		 * server->connected==FALSE? */
		g_free_not_null(conn->channels);
		conn->channels = server->connrec->no_autojoin_channels ? NULL :
			g_strdup(server->connrec->channels);
	}

	signal_emit("server reconnect save status", 2, conn, server);
}

static void server_reconnect_add(SERVER_CONNECT_REC *conn,
				 time_t next_connect)
{
	RECONNECT_REC *rec;

	g_return_if_fail(IS_SERVER_CONNECT(conn));

	rec = g_new(RECONNECT_REC, 1);
	rec->tag = ++last_reconnect_tag;
	rec->next_connect = next_connect;

	rec->conn = conn;
	conn->reconnecting = TRUE;
	server_connect_ref(conn);

	reconnects = g_slist_append(reconnects, rec);
}

void server_reconnect_destroy(RECONNECT_REC *rec)
{
	g_return_if_fail(rec != NULL);

	reconnects = g_slist_remove(reconnects, rec);

	signal_emit("server reconnect remove", 1, rec);
	server_connect_unref(rec->conn);
	g_free(rec);

	if (reconnects == NULL)
	    last_reconnect_tag = 0;
}

static int server_reconnect_timeout(void)
{
	SERVER_CONNECT_REC *conn;
	GSList *list, *tmp, *next;
	time_t now;

	now = time(NULL);

	/* timeout any connections that haven't gotten to connected-stage */
	for (tmp = servers; tmp != NULL; tmp = next) {
		SERVER_REC *server = tmp->data;

		next = tmp->next;
		if (!server->connected &&
		    server->connect_time + connect_timeout < now &&
		    connect_timeout > 0) {
			server->connection_lost = TRUE;
			server_disconnect(server);
		}
	}

	for (tmp = lookup_servers; tmp != NULL; tmp = next) {
		SERVER_REC *server = tmp->data;

		next = tmp->next;
		if (server->connect_time + connect_timeout < now &&
		    connect_timeout > 0) {
			if (server->connect_tag != -1) {
				g_source_remove(server->connect_tag);
				server->connect_tag = -1;
			}
			server->connection_lost = TRUE;
			server_connect_failed(server, "Timeout");
		}
	}

	/* If server_connect() removes the next reconnection in queue,
	   we're screwed. I don't think this should happen anymore, but just
	   to be sure we don't crash, do this safely. */
	list = g_slist_copy(reconnects);
	for (tmp = list; tmp != NULL; tmp = tmp->next) {
		RECONNECT_REC *rec = tmp->data;

		if (g_slist_find(reconnects, rec) == NULL)
			continue;

		if (rec->next_connect <= now) {
			conn = rec->conn;
			server_connect_ref(conn);
			server_reconnect_destroy(rec);
			server_connect(conn);
			server_connect_unref(conn);
		}
	}

	g_slist_free(list);
	return 1;
}

static void sserver_connect(SERVER_SETUP_REC *rec, SERVER_CONNECT_REC *conn)
{
	server_setup_fill_reconn(conn, rec);
	server_reconnect_add(conn, rec->last_connect+reconnect_time);
	server_connect_unref(conn);
}

static SERVER_CONNECT_REC *
server_connect_copy_skeleton(SERVER_CONNECT_REC *src, int connect_info)
{
	SERVER_CONNECT_REC *dest;

        dest = NULL;
	signal_emit("server connect copy", 2, &dest, src);
	g_return_val_if_fail(dest != NULL, NULL);

        server_connect_ref(dest);
	dest->type = module_get_uniq_id("SERVER CONNECT", 0);
	dest->reconnection = src->reconnection;
	dest->last_failed_family = src->last_failed_family;
	dest->proxy = g_strdup(src->proxy);
        dest->proxy_port = src->proxy_port;
	dest->proxy_string = g_strdup(src->proxy_string);
	dest->proxy_string_after = g_strdup(src->proxy_string_after);
	dest->proxy_password = g_strdup(src->proxy_password);

	dest->tag = g_strdup(src->tag);

	if (connect_info) {
		dest->family = src->family;
		dest->address = g_strdup(src->address);
		dest->port = src->port;
		dest->password = g_strdup(src->password);

		dest->use_tls = src->use_tls;
		dest->tls_cert = g_strdup(src->tls_cert);
		dest->tls_pkey = g_strdup(src->tls_pkey);
		dest->tls_verify = src->tls_verify;
		dest->tls_cafile = g_strdup(src->tls_cafile);
		dest->tls_capath = g_strdup(src->tls_capath);
		dest->tls_ciphers = g_strdup(src->tls_ciphers);
		dest->tls_pinned_cert = g_strdup(src->tls_pinned_cert);
		dest->tls_pinned_pubkey = g_strdup(src->tls_pinned_pubkey);
	}

	dest->chatnet = g_strdup(src->chatnet);
	dest->nick = g_strdup(src->nick);
	dest->username = g_strdup(src->username);
	dest->realname = g_strdup(src->realname);

	if (src->own_ip4 != NULL) {
		dest->own_ip4 = g_new(IPADDR, 1);
		memcpy(dest->own_ip4, src->own_ip4, sizeof(IPADDR));
	}
	if (src->own_ip6 != NULL) {
		dest->own_ip6 = g_new(IPADDR, 1);
		memcpy(dest->own_ip6, src->own_ip6, sizeof(IPADDR));
	}

	dest->channels = g_strdup(src->channels);
	dest->away_reason = g_strdup(src->away_reason);
	dest->no_autojoin_channels = src->no_autojoin_channels;
	dest->no_autosendcmd = src->no_autosendcmd;
	dest->unix_socket = src->unix_socket;

	return dest;
}

#define server_should_reconnect(server) \
	((server)->connection_lost && !(server)->no_reconnect && \
	((server)->connrec->chatnet != NULL || \
		!(server)->banned))

#define sserver_connect_ok(rec, net) \
	(!(rec)->banned && (rec)->chatnet != NULL && \
	g_ascii_strcasecmp((rec)->chatnet, (net)) == 0)

static void sig_reconnect(SERVER_REC *server)
{
	SERVER_CONNECT_REC *conn;
	SERVER_SETUP_REC *sserver;
	GSList *tmp;
	int use_next, through;
	time_t now;

	g_return_if_fail(IS_SERVER(server));

	if (reconnect_time == -1 || !server_should_reconnect(server))
		return;

	sserver = server_setup_find(server->connrec->address, server->connrec->port,
	                            server->connrec->chatnet);

	conn = server_connect_copy_skeleton(server->connrec, sserver == NULL);
	g_return_if_fail(conn != NULL);

	/* save the server status */
	if (server->connected) {
		conn->reconnection = TRUE;

                reconnect_save_status(conn, server);
	}

	if (sserver != NULL) {
		/* save the last connection time/status */
		sserver->last_connect = server->connect_time == 0 ?
			time(NULL) : server->connect_time;
		sserver->last_failed = !server->connected;
		sserver->banned = server->banned;
                sserver->dns_error = server->dns_error;
	}

	if (sserver == NULL || conn->chatnet == NULL) {
		/* not in any chatnet, just reconnect back to same server */
                conn->family = server->connrec->family;
		conn->address = g_strdup(server->connrec->address);
		conn->port = server->connrec->port;
		conn->password = g_strdup(server->connrec->password);

		if (strchr(conn->address, '/') != NULL)
			conn->unix_socket = TRUE;

		server_reconnect_add(conn, (server->connect_time == 0 ? time(NULL) :
					    server->connect_time) + reconnect_time);
		server_connect_unref(conn);
		return;
	}

	/* always try to first connect to the first on the list where we
	   haven't got unsuccessful connection attempts for the past half
	   an hour. */

	now = time(NULL);
	for (tmp = setupservers; tmp != NULL; tmp = tmp->next) {
		SERVER_SETUP_REC *rec = tmp->data;

		if (sserver_connect_ok(rec, conn->chatnet) &&
		    (!rec->last_connect || !rec->last_failed ||
		     rec->last_connect < now-FAILED_RECONNECT_WAIT)) {
			if (rec == sserver)
				conn->port = server->connrec->port;
			sserver_connect(rec, conn);
			return;
		}
	}

	/* just try the next server in list */
	use_next = through = FALSE;
	for (tmp = setupservers; tmp != NULL; ) {
		SERVER_SETUP_REC *rec = tmp->data;

		if (!use_next && server->connrec->port == rec->port &&
		    g_ascii_strcasecmp(rec->address, server->connrec->address) == 0)
			use_next = TRUE;
		else if (use_next && sserver_connect_ok(rec, conn->chatnet)) {
			if (rec == sserver)
                                conn->port = server->connrec->port;
			sserver_connect(rec, conn);
			break;
		}

		if (tmp->next != NULL) {
			tmp = tmp->next;
			continue;
		}

		if (through) {
			/* shouldn't happen unless there's no servers in
			   this chatnet in setup.. */
			server_connect_unref(conn);
			break;
		}

		tmp = setupservers;
		use_next = through = TRUE;
	}
}

static void sig_connected(SERVER_REC *server)
{
	g_return_if_fail(IS_SERVER(server));
	if (!server->connrec->reconnection)
		return;

	if (server->connrec->channels != NULL)
		server->channels_join(server, server->connrec->channels, TRUE);
}

/* Remove all servers from reconnect list */
/* SYNTAX: RMRECONNS */
static void cmd_rmreconns(void)
{
	while (reconnects != NULL)
		server_reconnect_destroy(reconnects->data);
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

static void reconnect_all(void)
{
	GSList *list;
	SERVER_CONNECT_REC *conn;
	RECONNECT_REC *rec;

	/* first move reconnects to another list so if server_connect()
	   fails and goes to reconnection list again, we won't get stuck
	   here forever */
	list = NULL;
	while (reconnects != NULL) {
		rec = reconnects->data;

		list = g_slist_append(list, rec->conn);
                server_connect_ref(rec->conn);
		server_reconnect_destroy(rec);
	}


	while (list != NULL) {
		conn = list->data;

		server_connect(conn);
                server_connect_unref(conn);
                list = g_slist_remove(list, conn);
	}
}

/* SYNTAX: RECONNECT <tag> [<quit message>] */
static void cmd_reconnect(const char *data, SERVER_REC *server)
{
	SERVER_CONNECT_REC *conn;
	RECONNECT_REC *rec;
	char *tag, *msg;
	void *free_arg;
	int tagnum;

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST, &tag, &msg))
		return;

	if (*tag != '\0' && g_strcmp0(tag, "*") != 0)
		server = server_find_tag(tag);

	if (server != NULL) {
		/* reconnect connected server */
		conn = server_connect_copy_skeleton(server->connrec, TRUE);

		if (server->connected)
			reconnect_save_status(conn, server);

		msg = g_strconcat("* ", *msg == '\0' ?
				  "Reconnecting" : msg, NULL);
		signal_emit("command disconnect", 2, msg, server);
		g_free(msg);

		conn->reconnection = TRUE;
		server_connect(conn);
		server_connect_unref(conn);
		cmd_params_free(free_arg);
                return;
	}

	if (g_ascii_strcasecmp(tag, "all") == 0) {
		/* reconnect all servers in reconnect queue */
                reconnect_all();
		cmd_params_free(free_arg);
                return;
	}

	if (*data == '\0') {
		/* reconnect to first server in reconnection list */
		if (reconnects == NULL)
			cmd_param_error(CMDERR_NOT_CONNECTED);
                rec = reconnects->data;
	} else {
		if (g_ascii_strncasecmp(tag, "RECON-", 6) == 0)
			tag += 6;

		tagnum = atoi(tag);
		rec = tagnum <= 0 ? NULL : reconnect_find_tag(tagnum);
	}

	if (rec == NULL) {
		signal_emit("server reconnect not found", 1, data);
	} else {
		conn = rec->conn;
		server_connect_ref(conn);
		server_reconnect_destroy(rec);
		server_connect(conn);
		server_connect_unref(conn);
	}

	cmd_params_free(free_arg);
}

static void cmd_disconnect(const char *data, SERVER_REC *server)
{
	RECONNECT_REC *rec;

	if (g_ascii_strncasecmp(data, "RECON-", 6) != 0)
		return; /* handle only reconnection removing */

	rec = reconnect_find_tag(atoi(data+6));

	if (rec == NULL)
		signal_emit("server reconnect not found", 1, data);
	else
		server_reconnect_destroy(rec);
	signal_stop();
}

static void sig_chat_protocol_deinit(CHAT_PROTOCOL_REC *proto)
{
	GSList *tmp, *next;

	for (tmp = reconnects; tmp != NULL; tmp = next) {
		RECONNECT_REC *rec = tmp->data;

                next = tmp->next;
                if (rec->conn->chat_type == proto->id)
			server_reconnect_destroy(rec);
	}
}

static void read_settings(void)
{
	reconnect_time = settings_get_time("server_reconnect_time")/1000;
        connect_timeout = settings_get_time("server_connect_timeout")/1000;
}

void servers_reconnect_init(void)
{
	settings_add_time("server", "server_reconnect_time", "5min");
	settings_add_time("server", "server_connect_timeout", "5min");

	reconnects = NULL;
	last_reconnect_tag = 0;

	reconnect_timeout_tag = g_timeout_add(1000, (GSourceFunc) server_reconnect_timeout, NULL);
	read_settings();

	signal_add("server connect failed", (SIGNAL_FUNC) sig_reconnect);
	signal_add("server disconnected", (SIGNAL_FUNC) sig_reconnect);
	signal_add("event connected", (SIGNAL_FUNC) sig_connected);
	signal_add("chat protocol deinit", (SIGNAL_FUNC) sig_chat_protocol_deinit);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);

	command_bind("rmreconns", NULL, (SIGNAL_FUNC) cmd_rmreconns);
	command_bind("reconnect", NULL, (SIGNAL_FUNC) cmd_reconnect);
	command_bind_first("disconnect", NULL, (SIGNAL_FUNC) cmd_disconnect);
}

void servers_reconnect_deinit(void)
{
	g_source_remove(reconnect_timeout_tag);

	signal_remove("server connect failed", (SIGNAL_FUNC) sig_reconnect);
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_reconnect);
	signal_remove("event connected", (SIGNAL_FUNC) sig_connected);
	signal_remove("chat protocol deinit", (SIGNAL_FUNC) sig_chat_protocol_deinit);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);

	command_unbind("rmreconns", (SIGNAL_FUNC) cmd_rmreconns);
	command_unbind("reconnect", (SIGNAL_FUNC) cmd_reconnect);
	command_unbind("disconnect", (SIGNAL_FUNC) cmd_disconnect);
}
