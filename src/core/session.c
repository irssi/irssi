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
#include "lib-config/iconfig.h"

#include "chat-protocols.h"
#include "servers.h"
#include "servers-setup.h"

static char *session_file;
static char *irssi_binary;

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
	paths = g_strsplit(g_getenv("PATH"), ":", -1);
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

/* SYNTAX: UPGRADE [<irssi binary path>] */
static void cmd_upgrade(const char *data)
{
	CONFIG_REC *session;
        GSList *file_handles;
	char *session_file, *str, **args;
        int i;

	if (*data == '\0')
		data = irssi_binary;
	if (data == NULL)
                cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

	/* save the session */
        session_file = g_strdup_printf("%s/session.%d", get_irssi_dir(), getpid());
	session = config_open(session_file, 0600);
        unlink(session_file);

        file_handles = NULL;
	signal_emit("session save", 2, session, &file_handles);
        config_write(session, NULL, -1);
        config_close(session);

        /* Cleanup the terminal etc. */
	signal_emit("session clean", 0);

        /* close the file handles we don't want to transfer to new client */
	for (i = 3; i < 256; i++) {
		if (g_slist_find(file_handles, GINT_TO_POINTER(i)) == NULL)
			close(i);
	}
	g_slist_free(file_handles),

	/* irssi -! --session ~/.irssi/session.<pid>
	   data may contain some other program as well, like
	   /UPGRADE /usr/bin/screen irssi */
	str = g_strdup_printf("%s -! --session %s", data, session_file);
        args = g_strsplit(str, " ", -1);
        g_free(str);

	execvp(args[0], (char **) args);

	fprintf(stderr, "exec: %s: %s\n", args[0], g_strerror(errno));
	_exit(-1);
}

static void session_save_server(SERVER_REC *server, CONFIG_REC *config,
				CONFIG_NODE *node, GSList **file_handles)
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
	*file_handles = g_slist_append(*file_handles, GINT_TO_POINTER(handle));
	config_node_set_int(config, node, "handle", handle);

	signal_emit("session save server", 4,
		    server, config, node, file_handles);
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
	if (proto == NULL || proto->not_initialized)
		return;

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

static void sig_session_save(CONFIG_REC *config, GSList **file_handles)
{
	CONFIG_NODE *node;
        GSList *tmp;

	node = config_node_traverse(config, "(servers", TRUE);
	for (tmp = servers; tmp != NULL; tmp = tmp->next)
                session_save_server(tmp->data, config, node, file_handles);
}

static void sig_session_restore(CONFIG_REC *config)
{
	CONFIG_NODE *node;
        GSList *tmp;

	node = config_node_traverse(config, "(servers", FALSE);
	if (node != NULL) {
		for (tmp = node->value; tmp != NULL; tmp = config_node_next(tmp))
			session_restore_server(tmp->data);
	}
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
		{ "session", 0, POPT_ARG_STRING, &session_file, 0, "", "" },
		{ NULL, '\0', 0, NULL }
	};

        session_file = NULL;
	args_register(options);

	command_bind("upgrade", NULL, (SIGNAL_FUNC) cmd_upgrade);

	signal_add("session save", (SIGNAL_FUNC) sig_session_save);
	signal_add("session restore", (SIGNAL_FUNC) sig_session_restore);
	signal_add("irssi init finished", (SIGNAL_FUNC) sig_init_finished);
}

void session_deinit(void)
{
	g_free_not_null(irssi_binary);

        command_unbind("upgrade", (SIGNAL_FUNC) cmd_upgrade);

	signal_remove("session save", (SIGNAL_FUNC) sig_session_save);
	signal_remove("session restore", (SIGNAL_FUNC) sig_session_restore);
	signal_remove("irssi init finished", (SIGNAL_FUNC) sig_init_finished);
}
