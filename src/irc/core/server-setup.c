/*
 server-setup.c : irssi

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
#include "common-setup.h"

#include "irc-server.h"
#include "server-setup.h"
#include "ircnet-setup.h"

GSList *setupservers; /* list of irc servers */

int source_host_ok; /* Use source_host_ip .. */
IPADDR *source_host_ip; /* Resolved address */

static void get_source_host_ip(void)
{
	IPADDR ip;

	/* FIXME: This will block! */
	if (!source_host_ok) {
		source_host_ok = *settings_get_str("hostname") != '\0' &&
			net_gethostname(settings_get_str("hostname"), &ip) == 0;
		if (source_host_ok) {
			source_host_ip = g_new(IPADDR, 1);
                        memcpy(source_host_ip, &ip, sizeof(IPADDR));
		}
	}
}

/* Create server connection record. `address' is required, rest can be NULL */
static IRC_SERVER_CONNECT_REC *
create_addr_conn(const char *address, int port, const char *password,
		 const char *nick)
{
	IRC_SERVER_CONNECT_REC *conn;
	SETUP_SERVER_REC *sserver;
	IRCNET_REC *ircnet;

	g_return_val_if_fail(address != NULL, NULL);

	conn = g_new0(IRC_SERVER_CONNECT_REC, 1);

	conn->address = g_strdup(address);
	conn->port = port > 0 ? port : 6667;

	if (password && *password) conn->password = g_strdup(password);
	if (nick && *nick) conn->nick = g_strdup(nick);

	if (!conn->nick) conn->nick = g_strdup(settings_get_str("default_nick"));
	conn->alternate_nick = g_strdup(settings_get_str("alternate_nick"));
	conn->username = g_strdup(settings_get_str("user_name"));
	conn->realname = g_strdup(settings_get_str("real_name"));

	/* proxy settings */
	if (settings_get_bool("use_ircproxy")) {
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

	/* fill the information from setup */
	sserver = server_setup_find(address, -1);
	if (sserver == NULL) return conn;

	if (sserver->own_ip != NULL) {
                /* use already resolved IP */
		if (conn->own_ip == NULL)
			conn->own_ip = g_new(IPADDR, 1);
		memcpy(conn->own_ip, sserver->own_ip, sizeof(IPADDR));
	} else if (sserver->own_host != NULL) {
		/* resolve the IP and use it */
		IPADDR ip;

		if (net_gethostname(sserver->own_host, &ip) == 0) {
			if (conn->own_ip == NULL)
				conn->own_ip = g_new(IPADDR, 1);
			memcpy(conn->own_ip, &ip, sizeof(IPADDR));

			sserver->own_ip = g_new(IPADDR, 1);
			memcpy(sserver->own_ip, &ip, sizeof(IPADDR));
		}
	}

	sserver->last_connect = time(NULL);

	if (sserver->ircnet) conn->ircnet = g_strdup(sserver->ircnet);
	if (sserver->password && !conn->password)
		conn->password = g_strdup(sserver->password);
	if (sserver->cmd_queue_speed > 0)
		conn->cmd_queue_speed = sserver->cmd_queue_speed;
	if (sserver->max_cmds_at_once > 0)
		conn->max_cmds_at_once = sserver->max_cmds_at_once;

	/* fill the rest from IRC network settings */
	ircnet = sserver->ircnet == NULL ? NULL : ircnet_find(sserver->ircnet);
	if (ircnet == NULL) return conn;

	if (ircnet->nick && !nick) {
                g_free(conn->nick);
		conn->nick = g_strdup(ircnet->nick);;
	}
	if (ircnet->username) {
                g_free(conn->username);
		conn->username = g_strdup(ircnet->username);;
	}
	if (ircnet->realname) {
                g_free(conn->realname);
		conn->realname = g_strdup(ircnet->realname);;
	}
	if (ircnet->max_kicks > 0) conn->max_kicks = ircnet->max_kicks;
	if (ircnet->max_msgs > 0) conn->max_msgs = ircnet->max_msgs;
	if (ircnet->max_modes > 0) conn->max_modes = ircnet->max_modes;
	if (ircnet->max_whois > 0) conn->max_whois = ircnet->max_whois;

        return conn;
}

/* Create server connection record. `dest' is required, rest can be NULL.
   `dest' is either a server address or irc network */
IRC_SERVER_CONNECT_REC *
irc_server_create_conn(const char *dest, int port, const char *password, const char *nick)
{
	GSList *tmp;
	time_t now;
	int n;

	g_return_val_if_fail(dest != NULL, NULL);

	/* check if `dest' is IRC network */
	if (ircnet_find(dest) == NULL)
		return create_addr_conn(dest, port, password, nick);

	/* first try to find a server that hasn't had any connection failures
	   for the past half an hour. If that isn't found, try any server. */
	now = time(NULL);
	for (n = 0; n < 2; n++) {
		for (tmp = setupservers; tmp != NULL; tmp = tmp->next) {
			SETUP_SERVER_REC *rec = tmp->data;

			if (rec->ircnet == NULL || g_strcasecmp(rec->ircnet, dest) != 0)
				continue;

			if (n == 1 || !rec->last_failed || rec->last_connect < now-FAILED_RECONNECT_WAIT)
				return create_addr_conn(rec->address, port, password, nick);
		}
	}

	return NULL;
}

/* Find matching server from setup. Set port to -1 if you don't care about it */
SETUP_SERVER_REC *server_setup_find(const char *address, int port)
{
	GSList *tmp;

	g_return_val_if_fail(address != NULL, NULL);

	for (tmp = setupservers; tmp != NULL; tmp = tmp->next) {
		SETUP_SERVER_REC *rec = tmp->data;

		if (g_strcasecmp(rec->address, address) == 0 &&
		    (port == -1 || rec->port == port)) return rec;
	}

	return NULL;
}

static void init_userinfo(void)
{
	const char *set, *default_nick, *user_name;
	char *str;

	/* check if nick/username/realname wasn't read from setup.. */
        set = settings_get_str("real_name");
	if (set == NULL || *set == '\0') {
		str = g_getenv("IRCNAME");
		iconfig_set_str("settings", "real_name",
				str != NULL ? str : g_get_real_name());
                g_free_not_null(str);
	}

	/* username */
        user_name = settings_get_str("user_name");
	if (user_name == NULL || *user_name == '\0') {
		str = g_getenv("IRCUSER");
		iconfig_set_str("settings", "user_name",
				str != NULL ? str : g_get_user_name());
                g_free_not_null(str);

		user_name = settings_get_str("user_name");
	}

	/* nick */
        default_nick = settings_get_str("default_nick");
	if (default_nick == NULL || *default_nick == '\0') {
		str = g_getenv("IRCNICK");
		iconfig_set_str("settings", "default_nick",
				str != NULL ? str : user_name);
                g_free_not_null(str);

		default_nick = settings_get_str("default_nick");
	}

	/* alternate nick */
        set = settings_get_str("alternate_nick");
	if (set == NULL || *set == '\0') {
		if (strlen(default_nick) < 9)
			str = g_strconcat(default_nick, "_", NULL);
		else {
			str = g_strdup(default_nick);
			str[strlen(str)-1] = '_';
		}
		iconfig_set_str("settings", "alternate_nick", str);
		g_free(str);
	}

	/* host name */
        set = settings_get_str("hostname");
	if (set == NULL || *set == '\0') {
		str = g_getenv("IRCHOST");
		if (str != NULL) {
			iconfig_set_str("settings", "hostname", str);
			g_free(str);
		}
	}
}

void setupserver_config_add(SETUP_SERVER_REC *rec)
{
	CONFIG_NODE *node;

	node = iconfig_node_traverse("(servers", TRUE);
	node = config_node_section(node, NULL, NODE_TYPE_BLOCK);

	config_node_set_str(node, "address", rec->address);
	config_node_set_str(node, "ircnet", rec->ircnet);

	config_node_set_int(node, "port", rec->port);
	config_node_set_str(node, "password", rec->password);
	config_node_set_str(node, "own_host", rec->own_host);

	if (rec->autoconnect)
		config_node_set_bool(node, "autoconnect", TRUE);

	if (rec->max_cmds_at_once > 0)
		config_node_set_int(node, "cmds_max_at_once", rec->max_cmds_at_once);
	if (rec->cmd_queue_speed > 0)
		config_node_set_int(node, "cmd_queue_speed", rec->cmd_queue_speed);
}

void setupserver_config_remove(SETUP_SERVER_REC *rec)
{
	CONFIG_NODE *node;

	node = iconfig_node_traverse("servers", FALSE);
	if (node != NULL) config_node_list_remove(node, g_slist_index(setupservers, rec));
}

static void setupserver_destroy(SETUP_SERVER_REC *rec)
{
	setupservers = g_slist_remove(setupservers, rec);

	g_free_not_null(rec->own_host);
	g_free_not_null(rec->own_ip);
	g_free(rec->ircnet);
	g_free(rec->address);
	g_free(rec->password);
	g_free(rec);
}

void server_setup_add(SETUP_SERVER_REC *rec)
{
	if (g_slist_find(setupservers, rec) != NULL) {
		setupserver_config_remove(rec);
		setupservers = g_slist_append(setupservers, rec);
	}

	setupservers = g_slist_append(setupservers, rec);
	setupserver_config_add(rec);
}

void server_setup_remove(SETUP_SERVER_REC *rec)
{
	setupserver_config_remove(rec);
	setupserver_destroy(rec);
}

static SETUP_SERVER_REC *setupserver_add_node(CONFIG_NODE *node)
{
	SETUP_SERVER_REC *rec;
	char *server;
	int port;

	g_return_val_if_fail(node != NULL, NULL);

	server = config_node_get_str(node, "address", NULL);
	if (server == NULL) return NULL;

	port = config_node_get_int(node, "port", 6667);
	if (server_setup_find(server, port) != NULL) {
		/* already exists - don't let it get there twice or
		   server reconnects will screw up! */
		return NULL;
	}

	rec = g_new0(SETUP_SERVER_REC, 1);
	rec->ircnet = g_strdup(config_node_get_str(node, "ircnet", NULL));
	rec->address = g_strdup(server);
	rec->password = g_strdup(config_node_get_str(node, "password", NULL));
	rec->port = port;
	rec->autoconnect = config_node_get_bool(node, "autoconnect", FALSE);
	rec->max_cmds_at_once = config_node_get_int(node, "cmds_max_at_once", 0);
	rec->cmd_queue_speed = config_node_get_int(node, "cmd_queue_speed", 0);
	rec->own_host = g_strdup(config_node_get_str(node, "own_host", 0));

	setupservers = g_slist_append(setupservers, rec);
	return rec;
}

static void read_servers(void)
{
	CONFIG_NODE *node;
	GSList *tmp;

	while (setupservers != NULL)
		setupserver_destroy(setupservers->data);

	/* Read servers */
	node = iconfig_node_traverse("servers", FALSE);
	if (node != NULL) {
		for (tmp = node->value; tmp != NULL; tmp = tmp->next)
			setupserver_add_node(tmp->data);
	}
}

void servers_setup_init(void)
{
	source_host_ok = FALSE;
	source_host_ip = NULL;

	settings_add_int("server", "server_reconnect_time", 300);
	settings_add_str("server", "hostname", "");
	settings_add_bool("server", "skip_motd", FALSE);

	settings_add_str("server", "default_nick", NULL);
	settings_add_str("server", "alternate_nick", NULL);
	settings_add_str("server", "user_name", NULL);
	settings_add_str("server", "real_name", NULL);

	settings_add_bool("ircproxy", "use_ircproxy", FALSE);
	settings_add_str("ircproxy", "proxy_address", "");
	settings_add_int("ircproxy", "proxy_port", 6667);
	settings_add_str("ircproxy", "proxy_string", "CONNECT %s %d");

	init_userinfo();

	read_servers();
	signal_add("setup reread", (SIGNAL_FUNC) read_servers);
}

void servers_setup_deinit(void)
{
	while (setupservers != NULL)
		setupserver_destroy(setupservers->data);

	signal_remove("setup reread", (SIGNAL_FUNC) read_servers);
}
