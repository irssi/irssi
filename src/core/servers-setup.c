/*
 servers-setup.c : irssi

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
#include "signals.h"
#include "network.h"
#include "lib-config/iconfig.h"
#include "settings.h"

#include "servers.h"
#include "servers-setup.h"
#include "chatnets.h"

GSList *setupservers;

int source_host_ok; /* Use source_host_ip .. */
IPADDR *source_host_ip; /* Resolved address */

static void get_source_host_ip(void)
{
	IPADDR ip;

	if (source_host_ok)
		return;

	/* FIXME: This will block! */
	source_host_ok = *settings_get_str("hostname") != '\0' &&
		net_gethostbyname(settings_get_str("hostname"), &ip) == 0;
	if (source_host_ok) {
		if (source_host_ip == NULL)
			source_host_ip = g_new(IPADDR, 1);
		memcpy(source_host_ip, &ip, sizeof(IPADDR));
	}
}

static void conn_set_ip(SERVER_CONNECT_REC *conn,
			IPADDR **own_ip, const char *own_host)
{
	IPADDR ip;

	if (*own_ip != NULL) {
                /* use already resolved IP */
		if (conn->own_ip == NULL)
			conn->own_ip = g_new(IPADDR, 1);
		memcpy(conn->own_ip, *own_ip, sizeof(IPADDR));
		return;
	}


	/* resolve the IP and use it */
	if (net_gethostbyname(own_host, &ip) == 0) {
		if (conn->own_ip == NULL)
			conn->own_ip = g_new(IPADDR, 1);
		memcpy(conn->own_ip, &ip, sizeof(IPADDR));

		*own_ip = g_new(IPADDR, 1);
		memcpy(*own_ip, &ip, sizeof(IPADDR));
	}
}

/* Fill information to connection from server setup record */
void server_setup_fill_reconn(SERVER_CONNECT_REC *conn,
			      SERVER_SETUP_REC *sserver)
{
	g_return_if_fail(IS_SERVER_CONNECT(conn));
	g_return_if_fail(IS_SERVER_SETUP(sserver));

	if (sserver->own_host != NULL)
		conn_set_ip(conn, &sserver->own_ip, sserver->own_host);

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
	conn->port = port > 0 ? port : 6667;

	if (!conn->nick) conn->nick = g_strdup(settings_get_str("default_nick"));
	conn->username = g_strdup(settings_get_str("user_name"));
	conn->realname = g_strdup(settings_get_str("real_name"));

	/* proxy settings */
	if (settings_get_bool("use_proxy")) {
		conn->proxy = g_strdup(settings_get_str("proxy_address"));
		conn->proxy_port = settings_get_int("proxy_port");
		conn->proxy_string = g_strdup(settings_get_str("proxy_string"));
	}

	/* source IP */
	get_source_host_ip();
	if (source_host_ok) {
		conn->own_ip = g_new(IPADDR, 1);
		memcpy(conn->own_ip, source_host_ip, sizeof(IPADDR));
	}
}

static void server_setup_fill_server(SERVER_CONNECT_REC *conn,
				     SERVER_SETUP_REC *sserver)
{
	g_return_if_fail(IS_SERVER_CONNECT(conn));
	g_return_if_fail(IS_SERVER_SETUP(sserver));

	sserver->last_connect = time(NULL);

	if (sserver->port > 0) conn->port = sserver->port;
	server_setup_fill_reconn(conn, sserver);

	signal_emit("server setup fill server", 2, conn, sserver);
}

static void server_setup_fill_chatnet(SERVER_CONNECT_REC *conn,
				      CHATNET_REC *chatnet)
{
	g_return_if_fail(IS_SERVER_CONNECT(conn));
	g_return_if_fail(IS_CHATNET(chatnet));

	if (chatnet->nick) {
		g_free(conn->nick);
		conn->nick = g_strdup(chatnet->nick);;
	}
	if (chatnet->username) {
                g_free(conn->username);
		conn->username = g_strdup(chatnet->username);;
	}
	if (chatnet->realname) {
                g_free(conn->realname);
		conn->realname = g_strdup(chatnet->realname);;
	}
	if (chatnet->own_host != NULL)
		conn_set_ip(conn, &chatnet->own_ip, chatnet->own_host);

	signal_emit("server setup fill chatnet", 2, conn, chatnet);
}

static SERVER_CONNECT_REC *
create_addr_conn(const char *address, int port,
		 const char *password, const char *nick)
{
	SERVER_CONNECT_REC *conn;
	SERVER_SETUP_REC *sserver;
	CHATNET_REC *chatnet;

	g_return_val_if_fail(address != NULL, NULL);

	sserver = server_setup_find(address, port);
	chatnet = sserver->chatnet == NULL ? NULL :
		chatnet_find(sserver->chatnet);
        conn = NULL;
	signal_emit("server setup connect", 2, &conn, chatnet);
	if (conn == NULL) {
		/* no chat protocol wanted this server? */
		return NULL;
	}

	/* fill in the defaults */
	server_setup_fill(conn, address, port);

	/* fill the rest from chat network settings */
	if (chatnet != NULL)
		server_setup_fill_chatnet(conn, chatnet);

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
		    g_strcasecmp(rec->chatnet, dest) != 0)
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
		create_addr_conn(bestrec->address, 0, NULL, nick);
}

/* Create server connection record. `dest' is required, rest can be NULL.
   `dest' is either a server address or chat network */
SERVER_CONNECT_REC *
server_create_conn(const char *dest, int port,
		   const char *password, const char *nick)
{
	SERVER_CONNECT_REC *rec;

	g_return_val_if_fail(dest != NULL, NULL);

	if (chatnet_find(dest)) {
		rec = create_chatnet_conn(dest, port, password, nick);
		if (rec != NULL)
			return rec;
	}

	return create_addr_conn(dest, port, password, nick);
}

/* Find matching server from setup. Try to find record with a same port,
   but fallback to any server with the same address. */
SERVER_SETUP_REC *server_setup_find(const char *address, int port)
{
	SERVER_SETUP_REC *server;
	GSList *tmp;

	g_return_val_if_fail(address != NULL, NULL);

	server = NULL;
	for (tmp = setupservers; tmp != NULL; tmp = tmp->next) {
		SERVER_SETUP_REC *rec = tmp->data;

		if (g_strcasecmp(rec->address, address) == 0) {
			server = rec;
			if (rec->port == port)
				break;
		}
	}

	return server;
}

/* Find matching server from setup. Ports must match or NULL is returned. */
SERVER_SETUP_REC *server_setup_find_port(const char *address, int port)
{
	SERVER_SETUP_REC *rec;

	rec = server_setup_find(address, port);
	return rec == NULL || rec->port != port ? NULL : rec;
}

static SERVER_SETUP_REC *server_setup_read(CONFIG_NODE *node)
{
	SERVER_SETUP_REC *rec;
	char *server, *chatnet;
	int port;

	g_return_val_if_fail(node != NULL, NULL);

	server = config_node_get_str(node, "address", NULL);
	if (server == NULL)
		return NULL;

	port = config_node_get_int(node, "port", 6667);
	if (server_setup_find_port(server, port) != NULL) {
		/* already exists - don't let it get there twice or
		   server reconnects will screw up! */
		return NULL;
	}

	rec = NULL;
	chatnet = config_node_get_str(node, "chatnet", NULL);
	signal_emit("server setup read", 3, &rec, node,
		    chatnet == NULL ? NULL : chatnet_find(chatnet));
	if (rec == NULL) {
		/* no chat protocol wanted this server? */
		return NULL;
	}

	rec->type = module_get_uniq_id("SERVER SETUP", 0);
	rec->chatnet = g_strdup(chatnet);
	rec->address = g_strdup(server);
	rec->password = g_strdup(config_node_get_str(node, "password", NULL));
	rec->port = port;
	rec->autoconnect = config_node_get_bool(node, "autoconnect", FALSE);
	rec->own_host = g_strdup(config_node_get_str(node, "own_host", 0));

	setupservers = g_slist_append(setupservers, rec);
	return rec;
}

static void server_setup_save(SERVER_SETUP_REC *rec)
{
	CONFIG_NODE *parentnode, *node;
	int index;

	index = g_slist_index(setupservers, rec);

	parentnode = iconfig_node_traverse("(servers", TRUE);
	node = config_node_index(parentnode, index);
	if (node == NULL)
		node = config_node_section(parentnode, NULL, NODE_TYPE_BLOCK);

        iconfig_node_clear(node);
	iconfig_node_set_str(node, "address", rec->address);
	iconfig_node_set_str(node, "chatnet", rec->chatnet);

	config_node_set_int(node, "port", rec->port);
	iconfig_node_set_str(node, "password", rec->password);
	iconfig_node_set_str(node, "own_host", rec->own_host);

	if (rec->autoconnect)
		config_node_set_bool(node, "autoconnect", TRUE);

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
	g_free_not_null(rec->own_ip);
	g_free_not_null(rec->chatnet);
	g_free(rec->address);
	g_free_not_null(rec->password);
	g_free(rec);
}

void server_setup_add(SERVER_SETUP_REC *rec)
{
	if (g_slist_find(setupservers, rec) == NULL)
		setupservers = g_slist_append(setupservers, rec);
	server_setup_save(rec);
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
		for (tmp = node->value; tmp != NULL; tmp = tmp->next)
			server_setup_read(tmp->data);
	}
}

static void read_settings(void)
{
	g_free_and_null(source_host_ip);

	source_host_ok = FALSE;
        get_source_host_ip();
}

void servers_setup_init(void)
{
	settings_add_str("server", "hostname", "");

	settings_add_str("server", "default_nick", NULL);
	settings_add_str("server", "user_name", NULL);
	settings_add_str("server", "real_name", NULL);

	settings_add_bool("proxy", "use_proxy", FALSE);
	settings_add_str("proxy", "proxy_address", "");
	settings_add_int("proxy", "proxy_port", 6667);
	settings_add_str("proxy", "proxy_string", "CONNECT %s %d");

	source_host_ip = NULL;
	read_settings();

	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
	signal_add("setup reread", (SIGNAL_FUNC) read_servers);
        signal_add("irssi init read settings", (SIGNAL_FUNC) read_servers);
}

void servers_setup_deinit(void)
{
	g_free_not_null(source_host_ip);

	while (setupservers != NULL)
		server_setup_destroy(setupservers->data);

	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
	signal_remove("setup reread", (SIGNAL_FUNC) read_servers);
        signal_remove("irssi init read settings", (SIGNAL_FUNC) read_servers);

	module_uniq_destroy("SERVER SETUP");
}
