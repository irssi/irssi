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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "signals.h"
#include "commands.h"
#include "args.h"
#include "net-sendbuffer.h"
#include "pidwait.h"
#include "lib-config/iconfig.h"

#include "chat-protocols.h"
#include "servers.h"
#include "servers-setup.h"
#include "channels.h"
#include "nicklist.h"

static char *session_file;
static char *irssi_binary;

static char **session_args;

void session_set_binary(const char *path)
{
	char **paths, **tmp;
        char *str;

	g_free_and_null(irssi_binary);

	if (g_path_is_absolute(path)) {
                /* full path - easy */
		irssi_binary = g_strdup(path);
                return;
	}

	if (strchr(path, G_DIR_SEPARATOR) != NULL) {
		/* relative path */
                str = g_get_current_dir();
		irssi_binary = g_strconcat(str, G_DIR_SEPARATOR_S, path, NULL);
		g_free(str);
                return;
	}

	/* we'll need to find it from path. */
	str = g_getenv("PATH");
	if (str == NULL) return;

	paths = g_strsplit(str, ":", -1);
	for (tmp = paths; *tmp != NULL; tmp++) {
                str = g_strconcat(*tmp, G_DIR_SEPARATOR_S, path, NULL);
		if (access(str, X_OK) == 0) {
			irssi_binary = str;
                        break;
		}
                g_free(str);
	}
	g_strfreev(paths);
}

void session_upgrade(void)
{
	if (session_args == NULL)
                return;

	execvp(session_args[0], session_args);
	fprintf(stderr, "exec failed: %s: %s\n",
		session_args[0], g_strerror(errno));
}

/* SYNTAX: UPGRADE [<irssi binary path>] */
static void cmd_upgrade(const char *data)
{
	CONFIG_REC *session;
	char *session_file, *str;

	if (*data == '\0')
		data = irssi_binary;
	if (data == NULL)
                cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

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
			      data, session_file, get_irssi_dir(), get_irssi_config());
        session_args = g_strsplit(str, " ", -1);
        g_free(str);

	signal_emit("gui exit", 0);
}

static void session_save_nick(CHANNEL_REC *channel, NICK_REC *nick,
			      CONFIG_REC *config, CONFIG_NODE *node)
{
	node = config_node_section(node, NULL, NODE_TYPE_BLOCK);

	config_node_set_str(config, node, "nick", nick->nick);
	config_node_set_bool(config, node, "op", nick->op);
	config_node_set_bool(config, node, "halfop", nick->halfop);
	config_node_set_bool(config, node, "voice", nick->voice);

	signal_emit("session save nick", 4, channel, nick, config, node);
}

static void session_save_channel_nicks(CHANNEL_REC *channel, CONFIG_REC *config,
				       CONFIG_NODE *node)
{
	GSList *tmp, *nicks;

	node = config_node_section(node, "nicks", NODE_TYPE_LIST);
        nicks = nicklist_getnicks(channel);
	for (tmp = nicks; tmp != NULL; tmp = tmp->next)
		session_save_nick(channel, tmp->data, config, node);
        g_slist_free(nicks);
}

static void session_save_channel(CHANNEL_REC *channel, CONFIG_REC *config,
				 CONFIG_NODE *node)
{
	node = config_node_section(node, NULL, NODE_TYPE_BLOCK);

	config_node_set_str(config, node, "name", channel->name);
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
        node = config_node_section(node, "channels", NODE_TYPE_LIST);
	for (tmp = server->channels; tmp != NULL; tmp = tmp->next)
		session_save_channel(tmp->data, config, node);
}

static void session_save_server(SERVER_REC *server, CONFIG_REC *config,
				CONFIG_NODE *node)
{
	int handle;

	node = config_node_section(node, NULL, NODE_TYPE_BLOCK);

	config_node_set_str(config, node, "chat_type",
			    chat_protocol_find_id(server->chat_type)->name);
	config_node_set_str(config, node, "address", server->connrec->address);
	config_node_set_int(config, node, "port", server->connrec->port);
	config_node_set_str(config, node, "chatnet", server->connrec->chatnet);
	config_node_set_str(config, node, "password", server->connrec->password);
	config_node_set_str(config, node, "nick", server->nick);

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
	node = config_node_section(node, "nicks", -1);
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
	const char *name;

	name = config_node_get_str(node, "name", NULL);
	if (name == NULL)
		return;

	channel = CHAT_PROTOCOL(server)->channel_create(server, name, TRUE);
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
	node = config_node_section(node, "channels", -1);
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
		if (handle < 0) close(handle);
		return;
	}

	conn = server_create_conn(proto->id, address, port,
				  chatnet, password, nick);
	if (conn != NULL) {
		conn->reconnection = TRUE;

		server = proto->server_connect(conn);
                server->handle = net_sendbuffer_create(g_io_channel_unix_new(handle), 0);
		server->session_reconnect = TRUE;

		signal_emit("session restore server", 2, server, node);
	}
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
                g_string_sprintfa(str, "%d ", GPOINTER_TO_INT(tmp->data));
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
	session_file = NULL;
}

void session_init(void)
{
	static struct poptOption options[] = {
		{ "session", 0, POPT_ARG_STRING, &session_file, 0, "Used by /UPGRADE command", "PATH" },
		{ NULL, '\0', 0, NULL }
	};

        session_file = NULL;
	args_register(options);

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
