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
#include <irssi/src/core/signals.h>
#include <irssi/src/core/network.h>
#include <irssi/src/lib-config/iconfig.h>
#include <irssi/src/core/settings.h>

#include <irssi/src/core/chat-protocols.h>
#include <irssi/src/core/chatnets.h>
#include <irssi/src/core/servers.h>
#include <irssi/src/core/servers-setup.h>

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

	if (sserver->no_proxy)
		g_free_and_null(conn->proxy);

	if (sserver->family != 0 && conn->family == 0)
		conn->family = sserver->family;
	if (sserver->address && !conn->address)
		conn->address = g_strdup(sserver->address);
	if (sserver->port > 0 && conn->port <= 0)
		conn->port = sserver->port;

	conn->use_tls = sserver->use_tls;
	if (conn->tls_cert == NULL && sserver->tls_cert != NULL && sserver->tls_cert[0] != '\0')
		conn->tls_cert = g_strdup(sserver->tls_cert);
	if (conn->tls_pkey == NULL && sserver->tls_pkey != NULL && sserver->tls_pkey[0] != '\0')
		conn->tls_pkey = g_strdup(sserver->tls_pkey);
	if (conn->tls_pass == NULL && sserver->tls_pass != NULL && sserver->tls_pass[0] != '\0')
		conn->tls_pass = g_strdup(sserver->tls_pass);
	conn->tls_verify = sserver->tls_verify;
	if (conn->tls_cafile == NULL && sserver->tls_cafile != NULL && sserver->tls_cafile[0] != '\0')
		conn->tls_cafile = g_strdup(sserver->tls_cafile);
	if (conn->tls_capath == NULL && sserver->tls_capath != NULL && sserver->tls_capath[0] != '\0')
		conn->tls_capath = g_strdup(sserver->tls_capath);
	if (conn->tls_ciphers == NULL && sserver->tls_ciphers != NULL && sserver->tls_ciphers[0] != '\0')
		conn->tls_ciphers = g_strdup(sserver->tls_ciphers);
	if (conn->tls_pinned_cert == NULL && sserver->tls_pinned_cert != NULL && sserver->tls_pinned_cert[0] != '\0')
		conn->tls_pinned_cert = g_strdup(sserver->tls_pinned_cert);
	if (conn->tls_pinned_pubkey == NULL && sserver->tls_pinned_pubkey != NULL && sserver->tls_pinned_pubkey[0] != '\0')
		conn->tls_pinned_pubkey = g_strdup(sserver->tls_pinned_pubkey);

	signal_emit("server setup fill reconn", 2, conn, sserver);
}

static void server_setup_fill(SERVER_CONNECT_REC *conn, const char *address, int port,
                              GHashTable *optlist)
{
	g_return_if_fail(conn != NULL);
	g_return_if_fail(address != NULL);

	conn->type = module_get_uniq_id("SERVER CONNECT", 0);

	conn->address = g_strdup(address);
	if (port > 0) conn->port = port;

	if (strchr(address, '/') != NULL)
		conn->unix_socket = TRUE;

	if (!conn->nick) conn->nick = g_strdup(settings_get_str("nick"));
	conn->username = g_strdup(settings_get_str("user_name"));
	conn->realname = g_strdup(settings_get_str("real_name"));

	/* proxy settings */
	if (settings_get_bool("use_proxy")) {
		conn->proxy = g_strdup(settings_get_str("proxy_address"));
		conn->proxy_port = settings_get_int("proxy_port");
		conn->proxy_string = g_strdup(settings_get_str("proxy_string"));
		conn->proxy_string_after = g_strdup(settings_get_str("proxy_string_after"));
		conn->proxy_password = g_strdup(settings_get_str("proxy_password"));
	}

	/* source IP */
	if (source_host_ip4 != NULL) {
		conn->own_ip4 = g_new(IPADDR, 1);
		memcpy(conn->own_ip4, source_host_ip4, sizeof(IPADDR));
	}
	if (source_host_ip6 != NULL) {
		conn->own_ip6 = g_new(IPADDR, 1);
		memcpy(conn->own_ip6, source_host_ip6, sizeof(IPADDR));
	}

	signal_emit("server setup fill connect", 2, conn, optlist);
}

static void server_setup_fill_optlist(SERVER_CONNECT_REC *conn, GHashTable *optlist)
{
	char *tmp;

	if (g_hash_table_lookup(optlist, "6") != NULL)
		conn->family = AF_INET6;
	else if (g_hash_table_lookup(optlist, "4") != NULL)
		conn->family = AF_INET;

	/* ad-hoc TLS settings from command optlist */
	if ((tmp = g_hash_table_lookup(optlist, "tls_cert")) != NULL ||
	    (tmp = g_hash_table_lookup(optlist, "ssl_cert")) != NULL) {
		conn->tls_cert = g_strdup(tmp);
		conn->use_tls = TRUE;
	}
	if ((tmp = g_hash_table_lookup(optlist, "tls_pkey")) != NULL ||
	    (tmp = g_hash_table_lookup(optlist, "ssl_pkey")) != NULL)
		conn->tls_pkey = g_strdup(tmp);
	if ((tmp = g_hash_table_lookup(optlist, "tls_pass")) != NULL ||
	    (tmp = g_hash_table_lookup(optlist, "ssl_pass")) != NULL)
		conn->tls_pass = g_strdup(tmp);
	if ((tmp = g_hash_table_lookup(optlist, "tls_cafile")) != NULL ||
	    (tmp = g_hash_table_lookup(optlist, "ssl_cafile")) != NULL)
		conn->tls_cafile = g_strdup(tmp);
	if ((tmp = g_hash_table_lookup(optlist, "tls_capath")) != NULL ||
	    (tmp = g_hash_table_lookup(optlist, "ssl_capath")) != NULL)
		conn->tls_capath = g_strdup(tmp);
	if ((tmp = g_hash_table_lookup(optlist, "tls_ciphers")) != NULL ||
	    (tmp = g_hash_table_lookup(optlist, "ssl_ciphers")) != NULL)
		conn->tls_ciphers = g_strdup(tmp);
	if ((tmp = g_hash_table_lookup(optlist, "tls_pinned_cert")) != NULL ||
	    (tmp = g_hash_table_lookup(optlist, "ssl_pinned_cert")) != NULL)
		conn->tls_pinned_cert = g_strdup(tmp);
	if ((tmp = g_hash_table_lookup(optlist, "tls_pinned_pubkey")) != NULL ||
	    (tmp = g_hash_table_lookup(optlist, "ssl_pinned_pubkey")) != NULL)
		conn->tls_pinned_pubkey = g_strdup(tmp);
	if ((conn->tls_capath != NULL && conn->tls_capath[0] != '\0') ||
	    (conn->tls_cafile != NULL && conn->tls_cafile[0] != '\0'))
		conn->tls_verify = TRUE;
	if (g_hash_table_lookup(optlist, "notls_verify") != NULL)
		conn->tls_verify = FALSE;
	if (g_hash_table_lookup(optlist, "tls_verify") != NULL ||
	    g_hash_table_lookup(optlist, "ssl_verify") != NULL) {
		conn->tls_verify = TRUE;
		conn->use_tls = TRUE;
	}
	if (g_hash_table_lookup(optlist, "notls") != NULL)
		conn->use_tls = FALSE;
	if (g_hash_table_lookup(optlist, "tls") != NULL ||
	    g_hash_table_lookup(optlist, "ssl") != NULL)
		conn->use_tls = TRUE;

	if (g_hash_table_lookup(optlist, "!") != NULL)
		conn->no_autojoin_channels = TRUE;

	if (g_hash_table_lookup(optlist, "noautosendcmd") != NULL)
		conn->no_autosendcmd = TRUE;

	if (g_hash_table_lookup(optlist, "noproxy") != NULL)
		g_free_and_null(conn->proxy);

	signal_emit("server setup fill optlist", 2, conn, optlist);
}

static void server_setup_fill_server(SERVER_CONNECT_REC *conn,
				     SERVER_SETUP_REC *sserver)
{
	g_return_if_fail(IS_SERVER_CONNECT(conn));
	g_return_if_fail(IS_SERVER_SETUP(sserver));

	sserver->last_connect = time(NULL);

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

static SERVER_CONNECT_REC *create_addr_conn(int chat_type, const char *address, int port,
                                            const char *chatnet, const char *password,
                                            const char *nick, GHashTable *optlist)
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

	if (proto == NULL) {
		signal_stop();
		return NULL;
	}

	g_return_val_if_fail(proto != NULL, NULL);

	conn = proto->create_server_connect();
	server_connect_ref(conn);

	conn->chat_type = proto->id;
        if (chatnet != NULL && *chatnet != '\0')
		conn->chatnet = g_strdup(chatnet);

	/* fill in the defaults */
	server_setup_fill(conn, address, port, optlist);

	/* fill the rest from chat network settings */
	chatnetrec = chatnet != NULL ? chatnet_find(chatnet) :
		(sserver == NULL || sserver->chatnet == NULL ? NULL :
		 chatnet_find(sserver->chatnet));
	if (chatnetrec != NULL)
		server_setup_fill_chatnet(conn, chatnetrec);

	/* fill the information from setup */
	if (sserver != NULL)
		server_setup_fill_server(conn, sserver);

	/* fill the optlist overrides */
	if (g_hash_table_size(optlist))
		server_setup_fill_optlist(conn, optlist);

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
static SERVER_CONNECT_REC *create_chatnet_conn(const char *dest, int port, const char *password,
                                               const char *nick, GHashTable *optlist)
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
                                 create_addr_conn(bestrec->chat_type, bestrec->address, 0, dest,
	                                          NULL, nick, optlist);
}

/* Create server connection record. `dest' is required, rest can be NULL.
   `dest' is either a server address or chat network */
SERVER_CONNECT_REC *server_create_conn_opt(int chat_type, const char *dest, int port,
                                           const char *chatnet, const char *password,
                                           const char *nick, GHashTable *optlist)
{
	SERVER_CONNECT_REC *rec;
        CHATNET_REC *chatrec;

	g_return_val_if_fail(dest != NULL, NULL);

        chatrec = chatnet_find(dest);
	if (chatrec != NULL) {
		rec = create_chatnet_conn(chatrec->name, port, password, nick, optlist);
		/* If rec is NULL the chatnet has no url to connect to */
		return rec;
	}

	chatrec = chatnet == NULL ? NULL : chatnet_find(chatnet);
	if (chatrec != NULL)
		chatnet = chatrec->name;

	return create_addr_conn(chat_type, dest, port, chatnet, password, nick, optlist);
}

SERVER_CONNECT_REC *server_create_conn(int chat_type, const char *dest, int port,
                                       const char *chatnet, const char *password, const char *nick)
{
	SERVER_CONNECT_REC *ret;
	GHashTable *opt;

	opt = g_hash_table_new(NULL, NULL);
	ret = server_create_conn_opt(chat_type, dest, port, chatnet, password, nick, opt);
	g_hash_table_destroy(opt);

	return ret;
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
	CHAT_PROTOCOL_REC *proto;
	char *server, *chatnet, *family;
	int port;
	char *value = NULL;

	g_return_val_if_fail(node != NULL, NULL);

	server = config_node_get_str(node, "address", NULL);
	if (server == NULL)
		return NULL;

	port = config_node_get_int(node, "port", 0);
	chatnet = config_node_get_str(node, "chatnet", NULL);

	if ((rec = server_setup_find(server, port, chatnet)) != NULL && rec->port == port) {
		/* duplicate server setup */
		server_setup_remove(rec);
	}

	rec = NULL;

	if (chatnet != NULL) {
		chatnetrec = chatnet_find(chatnet);
		if (chatnetrec != NULL) {
			proto = CHAT_PROTOCOL(chatnetrec);
		} else {
			/* chat network not found, create it. */
			if (chatnet_find_unavailable(chatnet)) {
				/* no protocols loaded, skip loading servers */
				return NULL;
			}
			proto = chat_protocol_get_default();
			chatnetrec = proto->create_chatnet();
			chatnetrec->chat_type = chat_protocol_get_default()->id;
			chatnetrec->name = g_strdup(chatnet);
			chatnet_create(chatnetrec);
		}
	} else {
		chatnetrec = NULL;
		proto = chat_protocol_get_default();
		if (proto == NULL) {
			/* no protocols loaded, skip loading servers */
			return NULL;
		}
	}

	family = config_node_get_str(node, "family", "");

	rec = proto->create_server_setup();
	rec->type = module_get_uniq_id("SERVER SETUP", 0);
	rec->chat_type = proto->id;
	rec->chatnet = chatnetrec == NULL ? NULL : g_strdup(chatnetrec->name);
	rec->family = g_ascii_strcasecmp(family, "inet6") == 0 ?
	                  AF_INET6 :
	                  (g_ascii_strcasecmp(family, "inet") == 0 ? AF_INET : 0);
	rec->address = g_strdup(server);
	rec->password = g_strdup(config_node_get_str(node, "password", NULL));

	rec->use_tls = config_node_get_bool(node, "use_tls", FALSE) || config_node_get_bool(node, "use_ssl", FALSE);
	rec->tls_verify = config_node_find(node, "tls_verify") != NULL ?
                              config_node_get_bool(node, "tls_verify", TRUE) :
                              config_node_get_bool(node, "ssl_verify", TRUE);

	value = config_node_get_str(node, "tls_cert", NULL);
	if (value == NULL)
		value = config_node_get_str(node, "ssl_cert", NULL);
	rec->tls_cert = g_strdup(value);

	value = config_node_get_str(node, "tls_pkey", NULL);
	if (value == NULL)
		value = config_node_get_str(node, "ssl_pkey", NULL);
	rec->tls_pkey = g_strdup(value);

	value = config_node_get_str(node, "tls_pass", NULL);
	if (value == NULL)
		value = config_node_get_str(node, "ssl_pass", NULL);
	rec->tls_pass = g_strdup(value);

	value = config_node_get_str(node, "tls_cafile", NULL);
	if (value == NULL)
		value = config_node_get_str(node, "ssl_cafile", NULL);
	rec->tls_cafile = g_strdup(value);

	value = config_node_get_str(node, "tls_capath", NULL);
	if (value == NULL)
		value = config_node_get_str(node, "ssl_capath", NULL);
	rec->tls_capath = g_strdup(value);

	value = config_node_get_str(node, "tls_ciphers", NULL);
	if (value == NULL)
		value = config_node_get_str(node, "ssl_ciphers", NULL);
	rec->tls_ciphers = g_strdup(value);

	value = config_node_get_str(node, "tls_pinned_cert", NULL);
	if (value == NULL)
		value = config_node_get_str(node, "ssl_pinned_cert", NULL);
	rec->tls_pinned_cert = g_strdup(value);

	value = config_node_get_str(node, "tls_pinned_pubkey", NULL);
	if (value == NULL)
		value = config_node_get_str(node, "ssl_pinned_pubkey", NULL);
	rec->tls_pinned_pubkey = g_strdup(value);

	rec->port = port;
	rec->autoconnect = config_node_get_bool(node, "autoconnect", FALSE);
	rec->no_proxy = config_node_get_bool(node, "no_proxy", FALSE);
	rec->own_host = g_strdup(config_node_get_str(node, "own_host", NULL));

	signal_emit("server setup read", 2, rec, node);

	setupservers = g_slist_append(setupservers, rec);
	return rec;
}

static int compare_server_setup (CONFIG_NODE *node, SERVER_SETUP_REC *server)
{
	char *address, *chatnet;
	int port;

	/* skip comment nodes */
	if (node->type == NODE_TYPE_COMMENT)
		return -1;

	address = config_node_get_str(node, "address", NULL);
	chatnet = config_node_get_str(node, "chatnet", "");
	port = config_node_get_int(node, "port", 0);

	if (address == NULL || chatnet == NULL) {
		return 0;
	}

	if (g_ascii_strcasecmp(address, server->address) != 0 ||
	    g_ascii_strcasecmp(chatnet, server->chatnet != NULL ? server->chatnet : "") != 0 ||
	    port != server->port) {
		return 1;
	}

	return 0;
}

static void server_setup_save(SERVER_SETUP_REC *rec, int old_port, const char *old_chatnet)
{
	CONFIG_NODE *parent_node, *node;
	SERVER_SETUP_REC search_rec = { 0 };
	GSList *config_node;

	parent_node = iconfig_node_traverse("(servers", TRUE);

	/* Try to find this channel in the configuration */
	search_rec.address = rec->address;
	search_rec.chatnet = old_chatnet != NULL ? (char *) old_chatnet : rec->chatnet;
	search_rec.port = old_port;
	config_node = g_slist_find_custom(parent_node->value, &search_rec,
	                                  (GCompareFunc) compare_server_setup);
	if (config_node != NULL)
		/* Let's update this server record */
		node = config_node->data;
	else
		/* Create a brand-new server record */
		node = iconfig_node_section(parent_node, NULL, NODE_TYPE_BLOCK);

        iconfig_node_clear(node);
	iconfig_node_set_str(node, "address", rec->address);
	iconfig_node_set_str(node, "chatnet", rec->chatnet);

	iconfig_node_set_int(node, "port", rec->port);
	iconfig_node_set_str(node, "password", rec->password);

	iconfig_node_set_bool(node, "use_tls", rec->use_tls);
	iconfig_node_set_str(node, "tls_cert", rec->tls_cert);
	iconfig_node_set_str(node, "tls_pkey", rec->tls_pkey);
	iconfig_node_set_str(node, "tls_pass", rec->tls_pass);
	iconfig_node_set_bool(node, "tls_verify", rec->tls_verify);
	iconfig_node_set_str(node, "tls_cafile", rec->tls_cafile);
	iconfig_node_set_str(node, "tls_capath", rec->tls_capath);
	iconfig_node_set_str(node, "tls_ciphers", rec->tls_ciphers);
	iconfig_node_set_str(node, "tls_pinned_cert", rec->tls_pinned_cert);
	iconfig_node_set_str(node, "tls_pinned_pubkey", rec->tls_pinned_pubkey);

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
	CONFIG_NODE *parent_node;
	GSList *config_node;

	parent_node = iconfig_node_traverse("servers", FALSE);

	if (parent_node == NULL)
		return;

	/* Try to find this server in the configuration */
	config_node = g_slist_find_custom(parent_node->value, rec,
					  (GCompareFunc)compare_server_setup);

	if (config_node != NULL)
		/* Delete the server from the configuration */
		iconfig_node_remove(parent_node, config_node->data);
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
	g_free_not_null(rec->tls_cert);
	g_free_not_null(rec->tls_pkey);
	g_free_not_null(rec->tls_pass);
	g_free_not_null(rec->tls_cafile);
	g_free_not_null(rec->tls_capath);
	g_free_not_null(rec->tls_ciphers);
	g_free_not_null(rec->tls_pinned_cert);
	g_free_not_null(rec->tls_pinned_pubkey);
	g_free(rec->address);
	g_free(rec);
}

void server_setup_modify(SERVER_SETUP_REC *rec, int old_port, const char *old_chatnet)
{
	g_return_if_fail(g_slist_find(setupservers, rec) != NULL);

	rec->type = module_get_uniq_id("SERVER SETUP", 0);
	server_setup_save(rec, old_port, old_chatnet);

	signal_emit("server setup updated", 1, rec);
}

void server_setup_add(SERVER_SETUP_REC *rec)
{
	if (g_slist_find(setupservers, rec) == NULL)
		setupservers = g_slist_append(setupservers, rec);
	server_setup_modify(rec, -1, NULL);
}

void server_setup_remove_chatnet(const char *chatnet)
{
	GSList *tmp, *next;

	g_return_if_fail(chatnet != NULL);

	for (tmp = setupservers; tmp != NULL; tmp = next) {
		SERVER_SETUP_REC *rec = tmp->data;

		next = tmp->next;
		if (g_ascii_strcasecmp(rec->chatnet, chatnet) == 0)
			server_setup_remove(rec);
	}
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
		int i = 0;
		tmp = config_node_first(node->value);
		for (; tmp != NULL; tmp = config_node_next(tmp), i++) {
			node = tmp->data;
			if (node->type != NODE_TYPE_BLOCK) {
				g_critical("Expected block node at `servers[%d]' was of %s type. "
				           "Corrupt config?",
				           i, node->type == NODE_TYPE_LIST ? "list" : "scalar");
			} else {
				server_setup_read(node);
			}
		}
	}
}

static void read_settings(void)
{
	if (old_source_host == NULL ||
	    g_strcmp0(old_source_host, settings_get_str("hostname")) != 0) {
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
	settings_add_str("proxy", "proxy_password", "");

        setupservers = NULL;
	source_host_ip4 = source_host_ip6 = NULL;
        old_source_host = NULL;
	read_settings();

	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
	signal_add("setup reread servers", (SIGNAL_FUNC) read_servers);
}

void servers_setup_deinit(void)
{
	g_free_not_null(source_host_ip4);
	g_free_not_null(source_host_ip6);
	g_free_not_null(old_source_host);

	while (setupservers != NULL)
		server_setup_destroy(setupservers->data);

	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
	signal_remove("setup reread servers", (SIGNAL_FUNC) read_servers);

	module_uniq_destroy("SERVER SETUP");
}
