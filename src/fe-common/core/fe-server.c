/*
 fe-server.c : irssi

    Copyright (C) 1999-2001 Timo Sirainen

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
#include <irssi/src/core/commands.h>
#include <irssi/src/core/network.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/core/settings.h>

#include <irssi/src/core/chat-protocols.h>
#include <irssi/src/core/chatnets.h>
#include <irssi/src/core/servers.h>
#include <irssi/src/core/servers-setup.h>
#include <irssi/src/core/servers-reconnect.h>

#include <irssi/src/fe-common/core/module-formats.h>
#include <irssi/src/fe-common/core/printtext.h>

static void print_servers(void)
{
	GSList *tmp;

	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		SERVER_REC *rec = tmp->data;

		printformat(NULL, NULL, MSGLEVEL_CRAP, TXT_SERVER_LIST,
			    rec->tag, rec->connrec->address, rec->connrec->port,
			    rec->connrec->chatnet == NULL ? "" : rec->connrec->chatnet, rec->connrec->nick);
	}
}

static void print_lookup_servers(void)
{
	GSList *tmp;
	for (tmp = lookup_servers; tmp != NULL; tmp = tmp->next) {
		SERVER_REC *rec = tmp->data;

		printformat(NULL, NULL, MSGLEVEL_CRAP, TXT_SERVER_LOOKUP_LIST,
			    rec->tag, rec->connrec->address, rec->connrec->port,
			    rec->connrec->chatnet == NULL ? "" : rec->connrec->chatnet, rec->connrec->nick);
	}
}

static void print_reconnects(void)
{
	GSList *tmp;
	char *tag, *next_connect;
	int left;

	for (tmp = reconnects; tmp != NULL; tmp = tmp->next) {
		RECONNECT_REC *rec = tmp->data;
		SERVER_CONNECT_REC *conn = rec->conn;

		tag = g_strdup_printf("RECON-%d", rec->tag);
		left = rec->next_connect-time(NULL);
		next_connect = g_strdup_printf("%02d:%02d", left/60, left%60);
		printformat(NULL, NULL, MSGLEVEL_CRAP, TXT_SERVER_RECONNECT_LIST,
			    tag, conn->address, conn->port,
			    conn->chatnet == NULL ? "" : conn->chatnet,
			    conn->nick, next_connect);
		g_free(next_connect);
		g_free(tag);
	}
}

static SERVER_SETUP_REC *create_server_setup(GHashTable *optlist)
{
	CHAT_PROTOCOL_REC *rec;
        SERVER_SETUP_REC *server;
        char *chatnet;

	rec = chat_protocol_find_net(optlist);
	if (rec == NULL)
                rec = chat_protocol_get_default();
	else {
		chatnet = g_hash_table_lookup(optlist, "network");
		if (chatnet == NULL && g_hash_table_lookup(optlist, rec->chatnet) != NULL)
			chatnet = rec->chatnet;
		if (chatnet_find(chatnet) == NULL) {
			printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
				    TXT_UNKNOWN_CHATNET, chatnet);
			return NULL;
		}
	}

	if (rec == NULL) {
		/* no protocols loaded, bail out */
		signal_emit("chat protocol unknown", 1, "(none)");
		return NULL;
	}

	server = rec->create_server_setup();
	server->chat_type = rec->id;
	server->tls_verify = TRUE;
	return server;
}

static void cmd_server_add_modify(const char *data, gboolean add)
{
        GHashTable *optlist;
	SERVER_SETUP_REC *rec, *tmp;
	char *addr, *portstr, *password, *value, *chatnet, *old_chatnet;
	void *free_arg;
	gboolean newrec;
	int port, old_port, add_port;

	if (!cmd_get_params(data, &free_arg, 3 | PARAM_FLAG_OPTIONS,
		"server add", &optlist, &addr, &portstr, &password))
		return;

	if (*addr == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	port = old_port = -1;

	value = g_hash_table_lookup(optlist, "port");
	if (value != NULL && *value != '\0')
		port = add_port = atoi(value);
	else if (g_hash_table_lookup(optlist, "tls") ||
		 g_hash_table_lookup(optlist, "ssl"))
		add_port = DEFAULT_SERVER_ADD_TLS_PORT;
	else
		add_port = DEFAULT_SERVER_ADD_PORT;

	if (*portstr != '\0')
		old_port = atoi(portstr);

	chatnet = g_hash_table_lookup(optlist, "network");

	rec = server_setup_find(addr, old_port != -1 ? old_port : add_port, chatnet);
	if (old_port == -1 && rec != NULL)
		old_port = rec->port;

	if (port == -1)
		port = old_port != -1 ? old_port : add_port;

	/* make sure the new port doesn't exist */
	tmp = server_setup_find(addr, port, chatnet);
	if (tmp != NULL && tmp->port == port)
		rec = tmp;

	if (rec == NULL || (rec->port != old_port && rec->port != port)) {
		newrec = TRUE;
		if (add == FALSE) {
			printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_SETUPSERVER_NOT_FOUND,
			            addr, old_port == -1 ? port : old_port);
			cmd_params_free(free_arg);
			return;
		}

		rec = create_server_setup(optlist);
		if (rec == NULL) {
			cmd_params_free(free_arg);
			return;
		}
		rec->address = g_strdup(addr);
		rec->port = port;
	} else {
		newrec = FALSE;
		old_chatnet = g_strdup(rec->chatnet);
		old_port = rec->port;
		rec->port = port;

		if (*password != '\0') g_free_and_null(rec->password);
		if (g_hash_table_lookup(optlist, "host")) {
			g_free_and_null(rec->own_host);
			rec->own_ip4 = rec->own_ip6 = NULL;
		}
	}

	if (g_hash_table_lookup(optlist, "6"))
		rec->family = AF_INET6;
        else if (g_hash_table_lookup(optlist, "4"))
		rec->family = AF_INET;

	value = g_hash_table_lookup(optlist, "tls_cert");
	if (value == NULL)
		value = g_hash_table_lookup(optlist, "ssl_cert");
	if (value != NULL && *value != '\0') {
		rec->tls_cert = g_strdup(value);
		if (newrec) {
			/* convenience and backward compatibility, turn on tls if tls_cert is given
			 */
			rec->use_tls = TRUE;
		}
	}

	value = g_hash_table_lookup(optlist, "tls_pkey");
	if (value == NULL)
		value = g_hash_table_lookup(optlist, "ssl_pkey");
	if (value != NULL && *value != '\0')
		rec->tls_pkey = g_strdup(value);

	value = g_hash_table_lookup(optlist, "tls_pass");
	if (value == NULL)
		value = g_hash_table_lookup(optlist, "ssl_pass");
	if (value != NULL && *value != '\0')
		rec->tls_pass = g_strdup(value);

	value = g_hash_table_lookup(optlist, "tls_cafile");
	if (value == NULL)
		value = g_hash_table_lookup(optlist, "ssl_cafile");
	if (value != NULL && *value != '\0')
		rec->tls_cafile = g_strdup(value);
	else if (value != NULL && *value == '\0')
		g_free_and_null(rec->tls_cafile);

	value = g_hash_table_lookup(optlist, "tls_capath");
	if (value == NULL)
		value = g_hash_table_lookup(optlist, "ssl_capath");
	if (value != NULL && *value != '\0')
		rec->tls_capath = g_strdup(value);
	else if (value != NULL && *value == '\0')
		g_free_and_null(rec->tls_capath);

	value = g_hash_table_lookup(optlist, "tls_ciphers");
	if (value == NULL)
		value = g_hash_table_lookup(optlist, "ssl_ciphers");
	if (value != NULL && *value != '\0')
		rec->tls_ciphers = g_strdup(value);

	value = g_hash_table_lookup(optlist, "tls_pinned_cert");
	if (value == NULL)
		value = g_hash_table_lookup(optlist, "ssl_pinned_cert");
	if (value != NULL && *value != '\0')
		rec->tls_pinned_cert = g_strdup(value);

	value = g_hash_table_lookup(optlist, "tls_pinned_pubkey");
	if (value == NULL)
		value = g_hash_table_lookup(optlist, "ssl_pinned_pubkey");
	if (value != NULL && *value != '\0')
		rec->tls_pinned_pubkey = g_strdup(value);

	if ((rec->tls_cafile != NULL && rec->tls_cafile[0] != '\0')
	||  (rec->tls_capath != NULL && rec->tls_capath[0] != '\0'))
		rec->tls_verify = TRUE;

	if (g_hash_table_lookup(optlist, "tls_verify") ||
	    g_hash_table_lookup(optlist, "ssl_verify")) {
		rec->tls_verify = TRUE;
		if (newrec) {
			/* convenience and backward compatibility, turn on tls if tls_verify is
			 * given */
			rec->use_tls = TRUE;
		}
	} else if (g_hash_table_lookup(optlist, "notls_verify") ||
	           g_hash_table_lookup(optlist, "nossl_verify")) {
		rec->tls_verify = FALSE;
	}

	if (g_hash_table_lookup(optlist, "tls") || g_hash_table_lookup(optlist, "ssl"))
		rec->use_tls = TRUE;
	else if (g_hash_table_lookup(optlist, "notls") || g_hash_table_lookup(optlist, "nossl"))
		rec->use_tls = FALSE;

	if (g_hash_table_lookup(optlist, "auto")) rec->autoconnect = TRUE;
	if (g_hash_table_lookup(optlist, "noauto")) rec->autoconnect = FALSE;
	if (g_hash_table_lookup(optlist, "proxy")) rec->no_proxy = FALSE;
	if (g_hash_table_lookup(optlist, "noproxy")) rec->no_proxy = TRUE;

	if (*password != '\0' && g_strcmp0(password, "-") != 0) rec->password = g_strdup(password);
	value = g_hash_table_lookup(optlist, "host");
	if (value != NULL && *value != '\0') {
		rec->own_host = g_strdup(value);
		rec->own_ip4 = rec->own_ip6 = NULL;
	}

	signal_emit("server add fill", 3, rec, optlist, GINT_TO_POINTER(add));

	if (newrec) {
		server_setup_add(rec);
	} else {
		server_setup_modify(rec, old_port, old_chatnet);
		g_free(old_chatnet);
	}

	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
		    TXT_SETUPSERVER_ADDED, addr, port);

	cmd_params_free(free_arg);
}

static void cmd_server_add(const char *data)
{
	cmd_server_add_modify(data, TRUE);
}

static void cmd_server_modify(const char *data)
{
	cmd_server_add_modify(data, FALSE);
}

/* SYNTAX: SERVER REMOVE <address> [<port>] [<network>] */
static void cmd_server_remove(const char *data)
{
	SERVER_SETUP_REC *rec;
	char *addr, *port, *chatnet;
	void *free_arg;
	int portnum;

	if (!cmd_get_params(data, &free_arg, 3, &addr, &port, &chatnet))
		return;
	if (*addr == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	if (*port == '\0') {
		portnum = DEFAULT_SERVER_ADD_PORT;
		if (*chatnet == '\0')
			rec = server_setup_find(addr, -1, NULL);
		else
			rec = server_setup_find(addr, -1, chatnet);
	}
	else
	{
		portnum = atoi(port);
		if (*chatnet == '\0')
			rec = server_setup_find(addr, portnum, NULL);
		else
			rec = server_setup_find(addr, portnum, chatnet);
	}

	if (rec == NULL)
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_SETUPSERVER_NOT_FOUND, addr,
		            portnum);
	else {
		portnum = rec->port;
		server_setup_remove(rec);
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_SETUPSERVER_REMOVED, addr,
		            portnum);
	}

	cmd_params_free(free_arg);
}

static void cmd_server(const char *data)
{
	if (*data != '\0')
		return;

	if (servers == NULL && lookup_servers == NULL &&
	    reconnects == NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
			    TXT_NO_CONNECTED_SERVERS);
	} else {
		print_servers();
		print_lookup_servers();
		print_reconnects();
	}

        signal_stop();
}

static void cmd_server_connect(const char *data)
{
	GHashTable *optlist;
	char *addr;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS,
			    "connect", &optlist, &addr))
		return;

	if (*addr == '\0' || g_strcmp0(addr, "+") == 0)
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
	if (*addr == '+') window_create(NULL, FALSE);

	cmd_params_free(free_arg);
}

static void server_command(const char *data, SERVER_REC *server,
			   WI_ITEM_REC *item)
{
	if (server == NULL) {
		/* this command accepts non-connected server too */
		server = active_win->connect_server;
	}

	signal_continue(3, data, server, item);
}

static void sig_server_looking(SERVER_REC *server)
{
	g_return_if_fail(server != NULL);

	printformat(server, NULL, MSGLEVEL_CLIENTNOTICE, TXT_LOOKING_UP, server->connrec->address);
}

static void sig_server_connecting(SERVER_REC *server, IPADDR *ip)
{
	char ipaddr[MAX_IP_LEN];

	g_return_if_fail(server != NULL);

	if (ip == NULL)
		ipaddr[0] = '\0';
	else
		net_ip2host(ip, ipaddr);

	printformat(server, NULL, MSGLEVEL_CLIENTNOTICE,
		    !server->connrec->reconnecting ?
		    TXT_CONNECTING : TXT_RECONNECTING,
		    server->connrec->address, ipaddr, server->connrec->port);
}

static void sig_server_connected(SERVER_REC *server)
{
	g_return_if_fail(server != NULL);

	printformat(server, NULL, MSGLEVEL_CLIENTNOTICE,
		    TXT_CONNECTION_ESTABLISHED, server->connrec->address);
}

static void sig_connect_failed(SERVER_REC *server, gchar *msg)
{
	g_return_if_fail(server != NULL);

	if (msg == NULL) {
		/* no message so this wasn't unexpected fail - send
		   connection_lost message instead */
		printformat(server, NULL, MSGLEVEL_CLIENTNOTICE,
			    TXT_CONNECTION_LOST, server->connrec->address);
	} else {
		printformat(server, NULL, MSGLEVEL_CLIENTERROR,
			    TXT_CANT_CONNECT, server->connrec->address, server->connrec->port, msg);
	}
}

static void sig_server_disconnected(SERVER_REC *server)
{
	g_return_if_fail(server != NULL);

	printformat(server, NULL, MSGLEVEL_CLIENTNOTICE,
		    TXT_CONNECTION_LOST, server->connrec->address);
}

static void sig_server_quit(SERVER_REC *server, const char *msg)
{
	g_return_if_fail(server != NULL);

	printformat(server, NULL, MSGLEVEL_CLIENTNOTICE,
		    TXT_SERVER_QUIT, server->connrec->address, msg);
}

static void sig_server_lag_disconnected(SERVER_REC *server)
{
	g_return_if_fail(server != NULL);

	printformat(server, NULL, MSGLEVEL_CLIENTNOTICE,
		    TXT_LAG_DISCONNECTED, server->connrec->address,
		    time(NULL)-(server->lag_sent / G_TIME_SPAN_SECOND));
}

static void sig_server_reconnect_removed(RECONNECT_REC *reconnect)
{
	g_return_if_fail(reconnect != NULL);

	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
		    TXT_RECONNECT_REMOVED, reconnect->conn->address, reconnect->conn->port,
		    reconnect->conn->chatnet == NULL ? "" : reconnect->conn->chatnet);
}

static void sig_server_reconnect_not_found(const char *tag)
{
	g_return_if_fail(tag != NULL);

	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
		    TXT_RECONNECT_NOT_FOUND, tag);
}

static void sig_chat_protocol_unknown(const char *protocol)
{
	g_return_if_fail(protocol != NULL);

	printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
                    TXT_UNKNOWN_CHAT_PROTOCOL, protocol);
}

void fe_server_init(void)
{
	command_bind("server", NULL, (SIGNAL_FUNC) cmd_server);
	command_bind("server connect", NULL, (SIGNAL_FUNC) cmd_server_connect);
	command_bind("server add", NULL, (SIGNAL_FUNC) cmd_server_add);
	command_bind("server modify", NULL, (SIGNAL_FUNC) cmd_server_modify);
	command_bind("server remove", NULL, (SIGNAL_FUNC) cmd_server_remove);
	command_bind_first("server", NULL, (SIGNAL_FUNC) server_command);
	command_bind_first("disconnect", NULL, (SIGNAL_FUNC) server_command);

	command_set_options(
	    "server add", "4 6 !! ~ssl ~nossl ~+ssl_cert ~+ssl_pkey ~+ssl_pass ~ssl_verify "
	                  "~nossl_verify ~+ssl_cafile ~+ssl_capath ~+ssl_ciphers ~+ssl_fingerprint "
	                  "tls notls +tls_cert +tls_pkey +tls_pass tls_verify notls_verify "
	                  "+tls_cafile +tls_capath +tls_ciphers +tls_pinned_cert "
	                  "+tls_pinned_pubkey auto noauto proxy noproxy -host -port noautosendcmd");
	command_set_options(
	    "server modify",
	    "4 6 !! ~ssl ~nossl ~+ssl_cert ~+ssl_pkey ~+ssl_pass ~ssl_verify ~nossl_verify "
	    "~+ssl_cafile ~+ssl_capath ~+ssl_ciphers ~+ssl_fingerprint tls notls +tls_cert "
	    "+tls_pkey +tls_pass tls_verify notls_verify +tls_cafile +tls_capath +tls_ciphers "
	    "+tls_pinned_cert +tls_pinned_pubkey auto noauto proxy noproxy -host -port "
	    "noautosendcmd");

	signal_add("server looking", (SIGNAL_FUNC) sig_server_looking);
	signal_add("server connecting", (SIGNAL_FUNC) sig_server_connecting);
	signal_add("server connected", (SIGNAL_FUNC) sig_server_connected);
	signal_add("server connect failed", (SIGNAL_FUNC) sig_connect_failed);
	signal_add("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);
	signal_add("server quit", (SIGNAL_FUNC) sig_server_quit);

	signal_add("server lag disconnect", (SIGNAL_FUNC) sig_server_lag_disconnected);
	signal_add("server reconnect remove", (SIGNAL_FUNC) sig_server_reconnect_removed);
	signal_add("server reconnect not found", (SIGNAL_FUNC) sig_server_reconnect_not_found);

	signal_add("chat protocol unknown", (SIGNAL_FUNC) sig_chat_protocol_unknown);
}

void fe_server_deinit(void)
{
	command_unbind("server", (SIGNAL_FUNC) cmd_server);
	command_unbind("server connect", (SIGNAL_FUNC) cmd_server_connect);
	command_unbind("server add", (SIGNAL_FUNC) cmd_server_add);
	command_unbind("server modify", (SIGNAL_FUNC) cmd_server_modify);
	command_unbind("server remove", (SIGNAL_FUNC) cmd_server_remove);
	command_unbind("server", (SIGNAL_FUNC) server_command);
	command_unbind("disconnect", (SIGNAL_FUNC) server_command);

	signal_remove("server looking", (SIGNAL_FUNC) sig_server_looking);
	signal_remove("server connecting", (SIGNAL_FUNC) sig_server_connecting);
	signal_remove("server connected", (SIGNAL_FUNC) sig_server_connected);
	signal_remove("server connect failed", (SIGNAL_FUNC) sig_connect_failed);
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);
	signal_remove("server quit", (SIGNAL_FUNC) sig_server_quit);

	signal_remove("server lag disconnect", (SIGNAL_FUNC) sig_server_lag_disconnected);
	signal_remove("server reconnect remove", (SIGNAL_FUNC) sig_server_reconnect_removed);
	signal_remove("server reconnect not found", (SIGNAL_FUNC) sig_server_reconnect_not_found);

	signal_remove("chat protocol unknown", (SIGNAL_FUNC) sig_chat_protocol_unknown);
}
