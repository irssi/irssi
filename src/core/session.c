/*
 session.c : irssi

    Copyright (C) 2001 Timo Sirainen

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
#include <irssi/src/core/args.h>
#include <irssi/src/core/network.h>
#include <irssi/src/core/net-sendbuffer.h>
#include <irssi/src/core/pidwait.h>
#include <irssi/src/lib-config/iconfig.h>
#include <irssi/src/core/misc.h>

#include <irssi/src/core/chat-protocols.h>
#include <irssi/src/core/servers.h>
#include <irssi/src/core/servers-setup.h>
#include <irssi/src/core/channels.h>
#include <irssi/src/core/nicklist.h>

static char *session_file;
char *irssi_binary = NULL;

static char **session_args;

void session_set_binary(const char *path)
{
	g_free_and_null(irssi_binary);

	irssi_binary = g_find_program_in_path(path);
}

void session_upgrade(void)
{
	if (session_args == NULL)
                return;

	execv(session_args[0], session_args);
	fprintf(stderr, "exec failed: %s: %s\n",
		session_args[0], g_strerror(errno));
}

/* SYNTAX: UPGRADE [<irssi binary path>] */
static void cmd_upgrade(const char *data)
{
	CONFIG_REC *session;
	char *session_file, *str, *name;
	char *binary;

	if (*data == '\0')
		name = irssi_binary;
	else
		name = convert_home(data);

	binary = g_find_program_in_path(name);
	if (name != irssi_binary)
		g_free(name);

	if (binary == NULL)
		cmd_return_error(CMDERR_PROGRAM_NOT_FOUND);

	/* save the session */
        session_file = g_strdup_printf("%s/session", get_irssi_dir());
	session = config_open(session_file, 0600);
        unlink(session_file);

	signal_emit("session save", 1, session);
        config_write(session, NULL, -1);
        config_close(session);

	/* data may contain some other program as well, like
	   /UPGRADE /usr/bin/screen irssi */
	str = g_strdup_printf("%s --noconnect --session=%s --home=%s --config=%s",
			      binary, session_file, get_irssi_dir(), get_irssi_config());
	g_free(binary);
	g_free(session_file);
        session_args = g_strsplit(str, " ", -1);
        g_free(str);

	signal_emit("gui exit", 0);
}

static void session_save_nick(CHANNEL_REC *channel, NICK_REC *nick,
			      CONFIG_REC *config, CONFIG_NODE *node)
{
	node = config_node_section(config, node, NULL, NODE_TYPE_BLOCK);

	config_node_set_str(config, node, "nick", nick->nick);
	config_node_set_bool(config, node, "op", nick->op);
	config_node_set_bool(config, node, "halfop", nick->halfop);
	config_node_set_bool(config, node, "voice", nick->voice);

	config_node_set_str(config, node, "prefixes", nick->prefixes);

	signal_emit("session save nick", 4, channel, nick, config, node);
}

static void session_save_channel_nicks(CHANNEL_REC *channel, CONFIG_REC *config,
				       CONFIG_NODE *node)
{
	GSList *tmp, *nicks;

	node = config_node_section(config, node, "nicks", NODE_TYPE_LIST);
        nicks = nicklist_getnicks(channel);
	for (tmp = nicks; tmp != NULL; tmp = tmp->next)
		session_save_nick(channel, tmp->data, config, node);
        g_slist_free(nicks);
}

static void session_save_channel(CHANNEL_REC *channel, CONFIG_REC *config,
				 CONFIG_NODE *node)
{
	node = config_node_section(config, node, NULL, NODE_TYPE_BLOCK);

	config_node_set_str(config, node, "name", channel->name);
	config_node_set_str(config, node, "visible_name", channel->visible_name);
	config_node_set_str(config, node, "topic", channel->topic);
	config_node_set_str(config, node, "topic_by", channel->topic_by);
	config_node_set_int(config, node, "topic_time", channel->topic_time);
	config_node_set_str(config, node, "key", channel->key);

	signal_emit("session save channel", 3, channel, config, node);
}

static void session_save_server_channels(SERVER_REC *server,
					 CONFIG_REC *config,
					 CONFIG_NODE *node)
{
	GSList *tmp;

	/* save channels */
	node = config_node_section(config, node, "channels", NODE_TYPE_LIST);
	for (tmp = server->channels; tmp != NULL; tmp = tmp->next)
		session_save_channel(tmp->data, config, node);
}

static void session_save_server(SERVER_REC *server, CONFIG_REC *config,
				CONFIG_NODE *node)
{
	int handle;

	node = config_node_section(config, node, NULL, NODE_TYPE_BLOCK);

	config_node_set_str(config, node, "chat_type", chat_protocol_find_id(server->chat_type)->name);
	config_node_set_str(config, node, "address", server->connrec->address);
	config_node_set_int(config, node, "port", server->connrec->port);
	config_node_set_str(config, node, "chatnet", server->connrec->chatnet);
	config_node_set_str(config, node, "password", server->connrec->password);
	config_node_set_str(config, node, "nick", server->nick);
	config_node_set_str(config, node, "version", server->version);

	config_node_set_bool(config, node, "use_tls", server->connrec->use_tls);
	config_node_set_str(config, node, "tls_cert", server->connrec->tls_cert);
	config_node_set_str(config, node, "tls_pkey", server->connrec->tls_pkey);
	config_node_set_bool(config, node, "tls_verify", server->connrec->tls_verify);
	config_node_set_str(config, node, "tls_cafile", server->connrec->tls_cafile);
	config_node_set_str(config, node, "tls_capath", server->connrec->tls_capath);
	config_node_set_str(config, node, "tls_ciphers", server->connrec->tls_ciphers);
	config_node_set_str(config, node, "tls_pinned_cert", server->connrec->tls_pinned_cert);
	config_node_set_str(config, node, "tls_pinned_pubkey", server->connrec->tls_pinned_pubkey);

	handle = g_io_channel_unix_get_fd(net_sendbuffer_handle(server->handle));
	config_node_set_int(config, node, "handle", handle);

	signal_emit("session save server", 3, server, config, node);

	/* fake the server disconnection */
	g_io_channel_unref(net_sendbuffer_handle(server->handle));
	net_sendbuffer_destroy(server->handle, FALSE);
	server->handle = NULL;

	server->connection_lost = TRUE;
        server->no_reconnect = TRUE;
        server_disconnect(server);
}

static void session_restore_channel_nicks(CHANNEL_REC *channel,
					  CONFIG_NODE *node)
{
	GSList *tmp;

	/* restore nicks */
	node = config_node_section(NULL, node, "nicks", -1);
	if (node != NULL && node->type == NODE_TYPE_LIST) {
		tmp = config_node_first(node->value);
		for (; tmp != NULL; tmp = config_node_next(tmp)) {
			signal_emit("session restore nick", 2,
				    channel, tmp->data);
		}
	}
}

static void session_restore_channel(SERVER_REC *server, CONFIG_NODE *node)
{
        CHANNEL_REC *channel;
	const char *name, *visible_name;

	name = config_node_get_str(node, "name", NULL);
	if (name == NULL)
		return;

	visible_name = config_node_get_str(node, "visible_name", NULL);
	channel = CHAT_PROTOCOL(server)->channel_create(server, name, visible_name, TRUE);
	channel->topic = g_strdup(config_node_get_str(node, "topic", NULL));
	channel->topic_by = g_strdup(config_node_get_str(node, "topic_by", NULL));
	channel->topic_time = config_node_get_int(node, "topic_time", 0);
        channel->key = g_strdup(config_node_get_str(node, "key", NULL));
        channel->session_rejoin = TRUE;

	signal_emit("session restore channel", 2, channel, node);
}

static void session_restore_server_channels(SERVER_REC *server,
					    CONFIG_NODE *node)
{
	GSList *tmp;

	/* restore channels */
	node = config_node_section(NULL, node, "channels", -1);
	if (node != NULL && node->type == NODE_TYPE_LIST) {
		tmp = config_node_first(node->value);
		for (; tmp != NULL; tmp = config_node_next(tmp))
			session_restore_channel(server, tmp->data);
	}
}

static void session_restore_server(CONFIG_NODE *node)
{
	CHAT_PROTOCOL_REC *proto;
	SERVER_CONNECT_REC *conn;
	SERVER_REC *server;
	const char *chat_type, *address, *chatnet, *password, *nick;
        int port, handle;

        chat_type = config_node_get_str(node, "chat_type", NULL);
	address = config_node_get_str(node, "address", NULL);
	port = config_node_get_int(node, "port", 0);
	chatnet = config_node_get_str(node, "chatnet", NULL);
	password = config_node_get_str(node, "password", NULL);
	nick = config_node_get_str(node, "nick", NULL);
	handle = config_node_get_int(node, "handle", -1);

	if (chat_type == NULL || address == NULL || nick == NULL || handle < 0)
		return;

	proto = chat_protocol_find(chat_type);
	if (proto == NULL || proto->not_initialized) {
		if (handle >= 0)
			close(handle);
		return;
	}

	conn = server_create_conn(proto->id, address, port,
				  chatnet, password, nick);
	if (conn == NULL)
		return;

	conn->use_tls = config_node_get_bool(node, "use_tls", FALSE);
	conn->tls_cert = g_strdup(config_node_get_str(node, "tls_cert", NULL));
	conn->tls_pkey = g_strdup(config_node_get_str(node, "tls_pkey", NULL));
	conn->tls_verify = config_node_get_bool(node, "tls_verify", TRUE);
	conn->tls_cafile = g_strdup(config_node_get_str(node, "tls_cafile", NULL));
	conn->tls_capath = g_strdup(config_node_get_str(node, "tls_capath", NULL));
	conn->tls_ciphers = g_strdup(config_node_get_str(node, "tls_ciphers", NULL));
	conn->tls_pinned_cert = g_strdup(config_node_get_str(node, "tls_pinned_cert", NULL));
	conn->tls_pinned_pubkey = g_strdup(config_node_get_str(node, "tls_pinned_pubkey", NULL));

	conn->reconnection = TRUE;
	conn->connect_handle = i_io_channel_new(handle);

	server = proto->server_init_connect(conn);
	server->version = g_strdup(config_node_get_str(node, "version", NULL));
	server->session_reconnect = TRUE;
	signal_emit("session restore server", 2, server, node);

	proto->server_connect(server);
}

static void sig_session_save(CONFIG_REC *config)
{
	CONFIG_NODE *node;
	GSList *tmp;
        GString *str;

        /* save servers */
	node = config_node_traverse(config, "(servers", TRUE);
	while (servers != NULL)
		session_save_server(servers->data, config, node);

	/* save pids */
        str = g_string_new(NULL);
	for (tmp = pidwait_get_pids(); tmp != NULL; tmp = tmp->next)
                g_string_append_printf(str, "%d ", GPOINTER_TO_INT(tmp->data));
        config_node_set_str(config, config->mainnode, "pids", str->str);
        g_string_free(str, TRUE);
}

static void sig_session_restore(CONFIG_REC *config)
{
	CONFIG_NODE *node;
        GSList *tmp;
        char **pids, **pid;

        /* restore servers */
	node = config_node_traverse(config, "(servers", FALSE);
	if (node != NULL) {
		tmp = config_node_first(node->value);
		for (; tmp != NULL; tmp = config_node_next(tmp))
			session_restore_server(tmp->data);
	}

	/* restore pids (so we don't leave zombies) */
	pids = g_strsplit(config_node_get_str(config->mainnode, "pids", ""), " ", -1);
	for (pid = pids; *pid != NULL; pid++)
                pidwait_add(atoi(*pid));
        g_strfreev(pids);
}

static void sig_init_finished(void)
{
	CONFIG_REC *session;

	if (session_file == NULL)
		return;

	session = config_open(session_file, -1);
	if (session == NULL)
		return;

	config_parse(session);
        signal_emit("session restore", 1, session);
	config_close(session);

	unlink(session_file);
}

void session_register_options(void)
{
	static GOptionEntry options[] = {
		{ "session", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_STRING, &session_file, "Used by /UPGRADE command", "PATH" },
		{ NULL }
	};

	session_file = NULL;
	args_register(options);
}

void session_init(void)
{
	command_bind("upgrade", NULL, (SIGNAL_FUNC) cmd_upgrade);

	signal_add("session save", (SIGNAL_FUNC) sig_session_save);
	signal_add("session restore", (SIGNAL_FUNC) sig_session_restore);
	signal_add("session save server", (SIGNAL_FUNC) session_save_server_channels);
	signal_add("session restore server", (SIGNAL_FUNC) session_restore_server_channels);
	signal_add("session save channel", (SIGNAL_FUNC) session_save_channel_nicks);
	signal_add("session restore channel", (SIGNAL_FUNC) session_restore_channel_nicks);
	signal_add("irssi init finished", (SIGNAL_FUNC) sig_init_finished);
}

void session_deinit(void)
{
	g_free_not_null(irssi_binary);

        command_unbind("upgrade", (SIGNAL_FUNC) cmd_upgrade);

	signal_remove("session save", (SIGNAL_FUNC) sig_session_save);
	signal_remove("session restore", (SIGNAL_FUNC) sig_session_restore);
	signal_remove("session save server", (SIGNAL_FUNC) session_save_server_channels);
	signal_remove("session restore server", (SIGNAL_FUNC) session_restore_server_channels);
	signal_remove("session save channel", (SIGNAL_FUNC) session_save_channel_nicks);
	signal_remove("session restore channel", (SIGNAL_FUNC) session_restore_channel_nicks);
	signal_remove("irssi init finished", (SIGNAL_FUNC) sig_init_finished);
}
