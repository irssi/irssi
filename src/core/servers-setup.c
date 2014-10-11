/*
 servers-setup.c : irssi

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
#include "signals.h"
#include "network.h"
#include "lib-config/iconfig.h"
#include "settings.h"

#include "chat-protocols.h"
#include "chatnets.h"
#include "servers.h"
#include "servers-setup.h"
#include "network-proxy.h"

GSList *setupservers;

static char *old_source_host;
int source_host_ok; /* Use source_host_ip .. */
IPADDR *source_host_ip4, *source_host_ip6; /* Resolved address */

static void save_ips(IPADDR *ip4, IPADDR *ip6,
		     IPADDR **save_ip4, IPADDR **save_ip6)
{
	if (ip4->family == 0)
		g_free_and_null(*save_ip4);
	else {
                if (*save_ip4 == NULL)
			*save_ip4 = g_new(IPADDR, 1);
		memcpy(*save_ip4, ip4, sizeof(IPADDR));
	}

	if (ip6->family == 0)
		g_free_and_null(*save_ip6);
	else {
                if (*save_ip6 == NULL)
			*save_ip6 = g_new(IPADDR, 1);
		memcpy(*save_ip6, ip6, sizeof(IPADDR));
	}
}

static void get_source_host_ip(void)
{
        const char *hostname;
	IPADDR ip4, ip6;

	if (source_host_ok)
		return;

	/* FIXME: This will block! */
        hostname = settings_get_str("hostname");
	source_host_ok = *hostname != '\0' &&
		net_gethostbyname(hostname, &ip4, &ip6) == 0;

	if (source_host_ok)
		save_ips(&ip4, &ip6, &source_host_ip4, &source_host_ip6);
	else {
                g_free_and_null(source_host_ip4);
                g_free_and_null(source_host_ip6);
	}
}

static void conn_set_ip(SERVER_CONNECT_REC *conn, const char *own_host,
			IPADDR **own_ip4, IPADDR **own_ip6)
{
	IPADDR ip4, ip6;

	if (*own_ip4 == NULL && *own_ip6 == NULL) {
		/* resolve the IP */
		if (net_gethostbyname(own_host, &ip4, &ip6) == 0)
                        save_ips(&ip4, &ip6, own_ip4, own_ip6);
	}

	server_connect_own_ip_save(conn, *own_ip4, *own_ip6);
}

/* Fill information to connection from server setup record */
void server_setup_fill_reconn(SERVER_CONNECT_REC *conn,
			      SERVER_SETUP_REC *sserver)
{
	g_return_if_fail(IS_SERVER_CONNECT(conn));
	g_return_if_fail(IS_SERVER_SETUP(sserver));

	if (sserver->own_host != NULL) {
		conn_set_ip(conn, sserver->own_host,
			    &sserver->own_ip4, &sserver->own_ip6);
	}

	if (sserver->chatnet != NULL && conn->chatnet == NULL)
		conn->chatnet = g_strdup(sserver->chatnet);

	if (sserver->password != NULL && conn->password == NULL)
		conn->password = g_strdup(sserver->password);

	signal_emit("server setup fill reconn", 2, conn, sserver);
}

static void server_setup_fill(SERVER_CONNECT_REC *conn,
			      const char *address, int port)
{
	g_return_if_fail(conn != NULL);
	g_return_if_fail(address != NULL);

	conn->type = module_get_uniq_id("SERVER CONNECT", 0);

	conn->address = g_strdup(address);
	if (port > 0) conn->port = port;

	if (!conn->nick) conn->nick = g_strdup(settings_get_str("nick"));
	conn->username = g_strdup(settings_get_str("user_name"));
	conn->realname = g_strdup(settings_get_str("real_name"));

	/* source IP */
	if (source_host_ip4 != NULL) {
		conn->own_ip4 = g_new(IPADDR, 1);
		memcpy(conn->own_ip4, source_host_ip4, sizeof(IPADDR));
	}
	if (source_host_ip6 != NULL) {
		conn->own_ip6 = g_new(IPADDR, 1);
		memcpy(conn->own_ip6, source_host_ip6, sizeof(IPADDR));
	}

	/* proxy settings */
	if (settings_get_bool("use_proxy"))
		conn->proxy = network_proxy_create(settings_get_str("proxy_type"));

	signal_emit("server setup fill connect", 1, conn);
}

static void server_setup_fill_server(SERVER_CONNECT_REC *conn,
				     SERVER_SETUP_REC *sserver)
{
	g_return_if_fail(IS_SERVER_CONNECT(conn));
	g_return_if_fail(IS_SERVER_SETUP(sserver));

	sserver->last_connect = time(NULL);

        if (sserver->no_proxy)
		g_free_and_null(conn->proxy);

	if (sserver->family != 0 && conn->family == 0)
                conn->family = sserver->family;
	if (sserver->port > 0 && conn->port <= 0)
		conn->port = sserver->port;

	conn->use_ssl = sserver->use_ssl;
	if (conn->ssl_cert == NULL && sserver->ssl_cert != NULL && sserver->ssl_cert[0] != '\0')
		conn->ssl_cert = g_strdup(sserver->ssl_cert);
	if (conn->ssl_pkey == NULL && sserver->ssl_pkey != NULL && sserver->ssl_pkey[0] != '\0')
		conn->ssl_pkey = g_strdup(sserver->ssl_pkey);
	if (conn->ssl_pass == NULL && sserver->ssl_pass != NULL && sserver->ssl_pass[0] != '\0')
		conn->ssl_pass = g_strdup(sserver->ssl_pass);
	conn->ssl_verify = sserver->ssl_verify;
	if (conn->ssl_cafile == NULL && sserver->ssl_cafile != NULL && sserver->ssl_cafile[0] != '\0')
		conn->ssl_cafile = g_strdup(sserver->ssl_cafile);
	if (conn->ssl_capath == NULL && sserver->ssl_capath != NULL && sserver->ssl_capath[0] != '\0')
		conn->ssl_capath = g_strdup(sserver->ssl_capath);

	server_setup_fill_reconn(conn, sserver);

	signal_emit("server setup fill server", 2, conn, sserver);
}

static void server_setup_fill_chatnet(SERVER_CONNECT_REC *conn,
				      CHATNET_REC *chatnet)
{
	g_return_if_fail(IS_SERVER_CONNECT(conn));
	g_return_if_fail(IS_CHATNET(chatnet));

	if (chatnet->nick != NULL) {
		g_free(conn->nick);
		conn->nick = g_strdup(chatnet->nick);;
	}
	if (chatnet->username != NULL) {
                g_free(conn->username);
		conn->username = g_strdup(chatnet->username);;
	}
	if (chatnet->realname != NULL) {
                g_free(conn->realname);
		conn->realname = g_strdup(chatnet->realname);;
	}
	if (chatnet->own_host != NULL) {
		conn_set_ip(conn, chatnet->own_host,
			    &chatnet->own_ip4, &chatnet->own_ip6);
	}

	signal_emit("server setup fill chatnet", 2, conn, chatnet);
}

static SERVER_CONNECT_REC *
create_addr_conn(int chat_type, const char *address, int port,
		 const char *chatnet, const char *password,
		 const char *nick)
{
        CHAT_PROTOCOL_REC *proto;
	SERVER_CONNECT_REC *conn;
	SERVER_SETUP_REC *sserver;
	CHATNET_REC *chatnetrec;

	g_return_val_if_fail(address != NULL, NULL);

	sserver = server_setup_find(address, port, chatnet);
	if (sserver != NULL) {
		if (chat_type < 0)
			chat_type = sserver->chat_type;
		else if (chat_type != sserver->chat_type)
                        sserver = NULL;
	}

	proto = chat_type >= 0 ? chat_protocol_find_id(chat_type) :
                chat_protocol_get_default();

	conn = proto->create_server_connect();
	server_connect_ref(conn);

	conn->chat_type = proto->id;
        if (chatnet != NULL && *chatnet != '\0')
		conn->chatnet = g_strdup(chatnet);

	/* fill in the defaults */
	server_setup_fill(conn, address, port);

	/* fill the rest from chat network settings */
	chatnetrec = chatnet != NULL ? chatnet_find(chatnet) :
		(sserver == NULL || sserver->chatnet == NULL ? NULL :
		 chatnet_find(sserver->chatnet));
	if (chatnetrec != NULL)
		server_setup_fill_chatnet(conn, chatnetrec);

	/* fill the information from setup */
	if (sserver != NULL)
		server_setup_fill_server(conn, sserver);

	/* nick / password given in command line overrides all settings */
	if (password && *password) {
		g_free_not_null(conn->password);
		conn->password = g_strdup(password);
	}
	if (nick && *nick) {
		g_free_not_null(conn->nick);
		conn->nick = g_strdup(nick);
	}

	return conn;
}

/* Connect to server where last connect succeeded (or we haven't tried to
   connect yet). If there's no such server, connect to server where we
   haven't connected for the longest time */
static SERVER_CONNECT_REC *
create_chatnet_conn(const char *dest, int port,
		    const char *password, const char *nick)
{
	SERVER_SETUP_REC *bestrec;
	GSList *tmp;
	time_t now, besttime;

	now = time(NULL);
	bestrec = NULL; besttime = now;
	for (tmp = setupservers; tmp != NULL; tmp = tmp->next) {
		SERVER_SETUP_REC *rec = tmp->data;

		if (rec->chatnet == NULL ||
		    g_ascii_strcasecmp(rec->chatnet, dest) != 0)
			continue;

		if (!rec->last_failed) {
			bestrec = rec;
			break;
		}

		if (bestrec == NULL || besttime > rec->last_connect) {
			bestrec = rec;
			besttime = rec->last_connect;
		}
	}

	return bestrec == NULL ? NULL :
		create_addr_conn(bestrec->chat_type, bestrec->address, 0,
				 dest, NULL, nick);
}

/* Create server connection record. `dest' is required, rest can be NULL.
   `dest' is either a server address or chat network */
SERVER_CONNECT_REC *
server_create_conn(int chat_type, const char *dest, int port,
		   const char *chatnet, const char *password,
		   const char *nick)
{
	SERVER_CONNECT_REC *rec;
        CHATNET_REC *chatrec;

	g_return_val_if_fail(dest != NULL, NULL);

        chatrec = chatnet_find(dest);
	if (chatrec != NULL) {
		rec = create_chatnet_conn(chatrec->name, port, password, nick);
		if (rec != NULL)
			return rec;
	}

	chatrec = chatnet == NULL ? NULL : chatnet_find(chatnet);
	if (chatrec != NULL)
		chatnet = chatrec->name;

	return create_addr_conn(chat_type, dest, port,
				chatnet, password, nick);
}

/* Find matching server from setup. Try to find record with a same port,
   but fallback to any server with the same address. */
SERVER_SETUP_REC *server_setup_find(const char *address, int port,
				    const char *chatnet)
{
	SERVER_SETUP_REC *server;
	GSList *tmp;

	g_return_val_if_fail(address != NULL, NULL);

	server = NULL;
	for (tmp = setupservers; tmp != NULL; tmp = tmp->next) {
		SERVER_SETUP_REC *rec = tmp->data;

		if (g_ascii_strcasecmp(rec->address, address) == 0 &&
		    (chatnet == NULL || rec->chatnet == NULL ||
		     g_ascii_strcasecmp(rec->chatnet, chatnet) == 0)) {
			server = rec;
			if (rec->port == port)
				break;
		}
	}

	return server;
}

static SERVER_SETUP_REC *server_setup_read(CONFIG_NODE *node)
{
	SERVER_SETUP_REC *rec;
        CHATNET_REC *chatnetrec;
	char *server, *chatnet, *family;
	int port;

	g_return_val_if_fail(node != NULL, NULL);

	server = config_node_get_str(node, "address", NULL);
	if (server == NULL)
		return NULL;

	port = config_node_get_int(node, "port", 0);
	chatnet = config_node_get_str(node, "chatnet", NULL);

	if (server_setup_find(server, port, chatnet) != NULL) {
		return NULL;
	}

	rec = NULL;

	chatnetrec = chatnet == NULL ? NULL : chatnet_find(chatnet);
	if (chatnetrec == NULL && chatnet != NULL) {
                /* chat network not found, create it. */
		chatnetrec = chat_protocol_get_default()->create_chatnet();
		chatnetrec->chat_type = chat_protocol_get_default()->id;
		chatnetrec->name = g_strdup(chatnet);
		chatnet_create(chatnetrec);
	}

        family = config_node_get_str(node, "family", "");

	rec = CHAT_PROTOCOL(chatnetrec)->create_server_setup();
	rec->type = module_get_uniq_id("SERVER SETUP", 0);
        rec->chat_type = CHAT_PROTOCOL(chatnetrec)->id;
	rec->chatnet = chatnetrec == NULL ? NULL : g_strdup(chatnetrec->name);
	rec->family = g_ascii_strcasecmp(family, "inet6") == 0 ? AF_INET6 :
		(g_ascii_strcasecmp(family, "inet") == 0 ? AF_INET : 0);
	rec->address = g_strdup(server);
	rec->password = g_strdup(config_node_get_str(node, "password", NULL));
	rec->use_ssl = config_node_get_bool(node, "use_ssl", FALSE);
	rec->ssl_cert = g_strdup(config_node_get_str(node, "ssl_cert", NULL));
	rec->ssl_pkey = g_strdup(config_node_get_str(node, "ssl_pkey", NULL));
	rec->ssl_pass = g_strdup(config_node_get_str(node, "ssl_pass", NULL));
	rec->ssl_verify = config_node_get_bool(node, "ssl_verify", FALSE);
	rec->ssl_cafile = g_strdup(config_node_get_str(node, "ssl_cafile", NULL));
	rec->ssl_capath = g_strdup(config_node_get_str(node, "ssl_capath", NULL));
	if (rec->ssl_cafile || rec->ssl_capath)
		rec->ssl_verify = TRUE;
	if (rec->ssl_cert != NULL || rec->ssl_verify)
		rec->use_ssl = TRUE;
	rec->port = port;
	rec->autoconnect = config_node_get_bool(node, "autoconnect", FALSE);
	rec->no_proxy = config_node_get_bool(node, "no_proxy", FALSE);
	rec->own_host = g_strdup(config_node_get_str(node, "own_host", NULL));

	signal_emit("server setup read", 2, rec, node);

	setupservers = g_slist_append(setupservers, rec);
	return rec;
}

static void server_setup_save(SERVER_SETUP_REC *rec)
{
	CONFIG_NODE *parentnode, *node;
	int index;

	index = g_slist_index(setupservers, rec);

	parentnode = iconfig_node_traverse("(servers", TRUE);
	node = config_node_nth(parentnode, index);
	if (node == NULL)
		node = config_node_section(parentnode, NULL, NODE_TYPE_BLOCK);

        iconfig_node_clear(node);
	iconfig_node_set_str(node, "address", rec->address);
	iconfig_node_set_str(node, "chatnet", rec->chatnet);

	iconfig_node_set_int(node, "port", rec->port);
	iconfig_node_set_str(node, "password", rec->password);
	iconfig_node_set_bool(node, "use_ssl", rec->use_ssl);
	iconfig_node_set_str(node, "ssl_cert", rec->ssl_cert);
	iconfig_node_set_str(node, "ssl_pkey", rec->ssl_pkey);
	iconfig_node_set_str(node, "ssl_pass", rec->ssl_pass);
	iconfig_node_set_bool(node, "ssl_verify", rec->ssl_verify);
	iconfig_node_set_str(node, "ssl_cafile", rec->ssl_cafile);
	iconfig_node_set_str(node, "ssl_capath", rec->ssl_capath);
	iconfig_node_set_str(node, "own_host", rec->own_host);

	iconfig_node_set_str(node, "family",
			     rec->family == AF_INET6 ? "inet6" :
			     rec->family == AF_INET ? "inet" : NULL);

	if (rec->autoconnect)
		iconfig_node_set_bool(node, "autoconnect", TRUE);
	if (rec->no_proxy)
		iconfig_node_set_bool(node, "no_proxy", TRUE);

	signal_emit("server setup saved", 2, rec, node);
}

static void server_setup_remove_config(SERVER_SETUP_REC *rec)
{
	CONFIG_NODE *node;
	int index;

	node = iconfig_node_traverse("servers", FALSE);
	if (node != NULL) {
		index = g_slist_index(setupservers, rec);
		iconfig_node_list_remove(node, index);
	}
}

static void server_setup_destroy(SERVER_SETUP_REC *rec)
{
	setupservers = g_slist_remove(setupservers, rec);
	signal_emit("server setup destroyed", 1, rec);

	g_free_not_null(rec->own_host);
	g_free_not_null(rec->own_ip4);
	g_free_not_null(rec->own_ip6);
	g_free_not_null(rec->chatnet);
	g_free_not_null(rec->password);
	g_free_not_null(rec->ssl_cert);
	g_free_not_null(rec->ssl_pkey);
	g_free_not_null(rec->ssl_pass);
	g_free_not_null(rec->ssl_cafile);
	g_free_not_null(rec->ssl_capath);
	g_free(rec->address);
	g_free(rec);
}

void server_setup_add(SERVER_SETUP_REC *rec)
{
	rec->type = module_get_uniq_id("SERVER SETUP", 0);
	if (g_slist_find(setupservers, rec) == NULL)
		setupservers = g_slist_append(setupservers, rec);
	server_setup_save(rec);

	signal_emit("server setup updated", 1, rec);
}

void server_setup_remove(SERVER_SETUP_REC *rec)
{
	server_setup_remove_config(rec);
	server_setup_destroy(rec);
}

static void read_servers(void)
{
	CONFIG_NODE *node;
	GSList *tmp;

	while (setupservers != NULL)
		server_setup_destroy(setupservers->data);

	/* Read servers */
	node = iconfig_node_traverse("servers", FALSE);
	if (node != NULL) {
		tmp = config_node_first(node->value);
		for (; tmp != NULL; tmp = config_node_next(tmp))
			server_setup_read(tmp->data);
	}
}

static void read_settings(void)
{
	if (old_source_host == NULL ||
	    strcmp(old_source_host, settings_get_str("hostname")) != 0) {
                g_free_not_null(old_source_host);
		old_source_host = g_strdup(settings_get_str("hostname"));

		source_host_ok = FALSE;
		get_source_host_ip();
	}
}

void servers_setup_init(void)
{
	settings_add_str("server", "hostname", "");

	settings_add_str("server", "nick", NULL);
	settings_add_str("server", "user_name", NULL);
	settings_add_str("server", "real_name", NULL);

	settings_add_bool("proxy", "use_proxy", FALSE);
	settings_add_str("proxy", "proxy_address", "");
	settings_add_int("proxy", "proxy_port", 6667);
	settings_add_str("proxy", "proxy_string", "CONNECT %s %d");
	settings_add_str("proxy", "proxy_string_after", "");
	settings_add_str("proxy", "proxy_username", "");
	settings_add_str("proxy", "proxy_password", "");
	settings_add_str("proxy", "proxy_type", "simple");

        setupservers = NULL;
	source_host_ip4 = source_host_ip6 = NULL;
        old_source_host = NULL;
	read_settings();

	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
	signal_add("setup reread", (SIGNAL_FUNC) read_servers);
        signal_add("irssi init read settings", (SIGNAL_FUNC) read_servers);
}

void servers_setup_deinit(void)
{
	g_free_not_null(source_host_ip4);
	g_free_not_null(source_host_ip6);
	g_free_not_null(old_source_host);

	while (setupservers != NULL)
		server_setup_destroy(setupservers->data);

	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
	signal_remove("setup reread", (SIGNAL_FUNC) read_servers);
        signal_remove("irssi init read settings", (SIGNAL_FUNC) read_servers);

	module_uniq_destroy("SERVER SETUP");
}
