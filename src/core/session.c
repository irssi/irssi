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
static const char *irssi_binary; /* from argv[0] */

static GIOChannel *next_handle;

void session_set_binary(const char *path)
{
        irssi_binary = path;
}

static void cmd_upgrade(const char *data)
{
	CONFIG_REC *session;
        GSList *file_handles;
	const char *args[10];
	char *session_file;
        int n;

	if (*data == '\0')
		data = irssi_binary;

        /* make sure we can execute it */
	if (access(data, X_OK) != 0)
		cmd_return_error(CMDERR_ERRNO);

	/* save the session */
        session_file = g_strdup_printf("%s/session.%d", get_irssi_dir(), getpid());
        unlink(session_file);
	session = config_open(session_file, 0600);

        file_handles = NULL;
	signal_emit("session save", 2, session, &file_handles);
        config_write(session, NULL, -1);
        config_close(session);

        /* Cleanup the terminal etc. */
	signal_emit("session clean", 0);

        /* close the file handles we don't want to transfer to new client */
	for (n = 3; n < 256; n++) {
		if (g_slist_find(file_handles, GINT_TO_POINTER(n)) == NULL)
			close(n);
	}
	g_slist_free(file_handles),

        /* irssi --session ~/.irssi/session.<pid> -! */
	args[0] = data;
	args[1] = "--session";
	args[2] = session_file;
	args[3] = "-!";
	args[4] = NULL;
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
		next_handle = g_io_channel_unix_new(handle);
		conn->reconnection = TRUE;

		server = proto->server_connect(conn);
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

static void sig_connecting(SERVER_REC *server, IPADDR *ip, GIOChannel **handle)
{
        *handle = next_handle;
	next_handle = NULL;
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

	signal_add("server connecting", (SIGNAL_FUNC) sig_connecting);
}

void session_deinit(void)
{
        command_unbind("upgrade", (SIGNAL_FUNC) cmd_upgrade);

	signal_remove("session save", (SIGNAL_FUNC) sig_session_save);
	signal_remove("session restore", (SIGNAL_FUNC) sig_session_restore);
	signal_remove("irssi init finished", (SIGNAL_FUNC) sig_init_finished);

	signal_remove("server connecting", (SIGNAL_FUNC) sig_connecting);
}
