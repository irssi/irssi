/*
 server.c : irssi

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
#include "commands.h"
#include "line-split.h"
#include "net-nonblock.h"
#include "net-sendbuffer.h"
#include "misc.h"
#include "rawlog.h"
#include "settings.h"

#include "chat-protocols.h"
#include "servers.h"
#include "servers-reconnect.h"
#include "servers-redirect.h"
#include "servers-setup.h"
#include "channels.h"
#include "queries.h"

GSList *servers, *lookup_servers;

/* connection to server failed */
void server_connect_failed(SERVER_REC *server, const char *msg)
{
	g_return_if_fail(IS_SERVER(server));

	lookup_servers = g_slist_remove(lookup_servers, server);

	signal_emit("server connect failed", 2, server, msg);
	if (server->connect_tag != -1)
		g_source_remove(server->connect_tag);
	if (server->handle != NULL)
		net_sendbuffer_destroy(server->handle, TRUE);

	if (server->connect_pipe[0] != NULL) {
		g_io_channel_close(server->connect_pipe[0]);
		g_io_channel_unref(server->connect_pipe[0]);
		g_io_channel_close(server->connect_pipe[1]);
		g_io_channel_unref(server->connect_pipe[1]);
	}

	MODULE_DATA_DEINIT(server);
	server_connect_free(server->connrec);
	g_free_not_null(server->nick);
	g_free(server->tag);
	g_free(server);
}

/* generate tag from server's address */
static char *server_create_address_tag(const char *address)
{
	const char *start, *end;

	g_return_val_if_fail(address != NULL, NULL);

	/* try to generate a reasonable server tag */
	if (strchr(address, '.') == NULL) {
		start = end = NULL;
	} else if (g_strncasecmp(address, "irc", 3) == 0 ||
	    g_strncasecmp(address, "chat", 4) == 0) {
		/* irc-2.cs.hut.fi -> hut, chat.bt.net -> bt */
		end = strrchr(address, '.');
		start = end-1;
		while (start > address && *start != '.') start--;
	} else {
		/* efnet.cs.hut.fi -> efnet */
		end = strchr(address, '.');
		start = end;
	}

	if (start == end) start = address; else start++;
	if (end == NULL) end = address + strlen(address);

	return g_strndup(start, (int) (end-start));
}

/* create unique tag for server. prefer ircnet's name or
   generate it from server's address */
static char *server_create_tag(SERVER_CONNECT_REC *conn)
{
	GString *str;
	char *tag;
	int num;

        g_return_val_if_fail(IS_SERVER_CONNECT(conn), NULL);

	tag = conn->chatnet != NULL ? g_strdup(conn->chatnet) :
		server_create_address_tag(conn->address);

	/* then just append numbers after tag until unused is found.. */
	str = g_string_new(tag);
	for (num = 2; server_find_tag(str->str) != NULL; num++)
		g_string_sprintf(str, "%s%d", tag, num);
	g_free(tag);

	tag = str->str;
	g_string_free(str, FALSE);
	return tag;
}

/* Connection to server finished, fill the rest of the fields */
void server_connect_finished(SERVER_REC *server)
{
	server->connect_time = time(NULL);
	server->rawlog = rawlog_create();

	server->eventtable = g_hash_table_new((GHashFunc) g_istr_hash, (GCompareFunc) g_istr_equal);
	server->eventgrouptable = g_hash_table_new((GHashFunc) g_direct_hash, (GCompareFunc) g_direct_equal);
	server->cmdtable = g_hash_table_new((GHashFunc) g_istr_hash, (GCompareFunc) g_istr_equal);

	servers = g_slist_append(servers, server);
	signal_emit("server connected", 1, server);
}

static void server_connect_callback_init(SERVER_REC *server, GIOChannel *handle)
{
	int error;

	g_return_if_fail(IS_SERVER(server));

	error = net_geterror(handle);
	if (error != 0) {
		server->connection_lost = TRUE;
		server_connect_failed(server, g_strerror(error));
		return;
	}

	lookup_servers = g_slist_remove(lookup_servers, server);
	g_source_remove(server->connect_tag);
	server->connect_tag = -1;

	server_connect_finished(server);
}

static void server_connect_callback_readpipe(SERVER_REC *server)
{
	SERVER_CONNECT_REC *conn;
	RESOLVED_IP_REC iprec;
	const char *errormsg;
	GIOChannel *handle;

	g_return_if_fail(IS_SERVER(server));

	g_source_remove(server->connect_tag);
	server->connect_tag = -1;

	net_gethostbyname_return(server->connect_pipe[0], &iprec);

	g_io_channel_close(server->connect_pipe[0]);
	g_io_channel_unref(server->connect_pipe[0]);
	g_io_channel_close(server->connect_pipe[1]);
	g_io_channel_unref(server->connect_pipe[1]);

	server->connect_pipe[0] = NULL;
	server->connect_pipe[1] = NULL;

	conn = server->connrec;
	handle = iprec.error != 0 ? NULL :
		net_connect_ip(&iprec.ip, conn->proxy != NULL ?
			       conn->proxy_port : conn->port,
			       conn->own_ip != NULL ? conn->own_ip : NULL);
	if (handle == NULL) {
		/* failed */
		if (iprec.error == 0 || !net_hosterror_notfound(iprec.error)) {
			/* reconnect back only if either
                            1) connect() failed
                            2) host name lookup failed not because the host
                               wasn't found, but because there was some
                               other error in nameserver */
			server->connection_lost = TRUE;
		}

		if (iprec.error == 0) {
			/* connect() failed */
			errormsg = g_strerror(errno);
		} else {
			/* gethostbyname() failed */
			errormsg = iprec.errorstr != NULL ? iprec.errorstr :
				"Host lookup failed";
		}
		server_connect_failed(server, errormsg);
		g_free_not_null(iprec.errorstr);
		return;
	}

	server->handle = net_sendbuffer_create(handle, 0);
	server->connect_tag =
		g_input_add(handle, G_INPUT_WRITE | G_INPUT_READ,
			    (GInputFunction) server_connect_callback_init,
			    server);
	signal_emit("server connecting", 2, server, &iprec.ip);
}

/* initializes server record but doesn't start connecting */
void server_connect_init(SERVER_REC *server)
{
	g_return_if_fail(server != NULL);

	MODULE_DATA_INIT(server);
	server->type = module_get_uniq_id("SERVER", 0);

	server->nick = g_strdup(server->connrec->nick);
	if (server->connrec->username == NULL || *server->connrec->username == '\0') {
		g_free_not_null(server->connrec->username);

		server->connrec->username = g_get_user_name();
		if (*server->connrec->username == '\0') server->connrec->username = "-";
		server->connrec->username = g_strdup(server->connrec->username);
	}
	if (server->connrec->realname == NULL || *server->connrec->realname == '\0') {
		g_free_not_null(server->connrec->realname);

		server->connrec->realname = g_get_real_name();
		if (*server->connrec->realname == '\0') server->connrec->realname = "-";
		server->connrec->realname = g_strdup(server->connrec->realname);
	}

	server->tag = server_create_tag(server->connrec);
}

/* starts connecting to server */
int server_start_connect(SERVER_REC *server)
{
	const char *connect_address;
        int fd[2];

	g_return_val_if_fail(server != NULL, FALSE);
	if (server->connrec->port <= 0) return FALSE;

	server_connect_init(server);

	if (pipe(fd) != 0) {
		g_warning("server_connect(): pipe() failed.");
                g_free(server->tag);
		g_free(server->nick);
		return FALSE;
	}

        server->connect_pipe[0] = g_io_channel_unix_new(fd[0]);
	server->connect_pipe[1] = g_io_channel_unix_new(fd[1]);

	if (server->connrec->family == 0 && server->connrec->own_ip != NULL)
                server->connrec->family = server->connrec->own_ip->family;

	connect_address = server->connrec->proxy != NULL ?
		server->connrec->proxy : server->connrec->address;
	server->connect_pid =
		net_gethostbyname_nonblock(connect_address,
					   server->connect_pipe[1],
					   server->connrec->family);
	server->connect_tag =
		g_input_add(server->connect_pipe[0], G_INPUT_READ,
			    (GInputFunction) server_connect_callback_readpipe,
			    server);

	lookup_servers = g_slist_append(lookup_servers, server);

	signal_emit("server looking", 1, server);
	return TRUE;
}

/* Connect to server */
SERVER_REC *server_connect(SERVER_CONNECT_REC *conn)
{
	g_return_val_if_fail(IS_SERVER_CONNECT(conn), NULL);

        return CHAT_PROTOCOL(conn)->server_connect(conn);
}

static int server_remove_channels(SERVER_REC *server)
{
	GSList *tmp;
	int found;

	g_return_val_if_fail(server != NULL, FALSE);

	found = FALSE;
	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *channel = tmp->data;

		channel->server = NULL;
		channel_destroy(channel);
		found = TRUE;
	}

	while (server->queries != NULL)
		query_change_server(server->queries->data, NULL);

	g_slist_free(server->channels);
	g_slist_free(server->queries);

	return found;
}

void server_disconnect(SERVER_REC *server)
{
	int chans;

	g_return_if_fail(IS_SERVER(server));

	if (server->connect_tag != -1) {
		/* still connecting to server.. */
		if (server->connect_pid != -1)
			net_disconnect_nonblock(server->connect_pid);
		server_connect_failed(server, NULL);
		return;
	}

	servers = g_slist_remove(servers, server);

	signal_emit("server disconnected", 1, server);

	/* close all channels */
	chans = server_remove_channels(server);

	if (server->handle != NULL) {
		if (!chans || server->connection_lost)
			net_sendbuffer_destroy(server->handle, TRUE);
		else {
			/* we were on some channels, try to let the server
			   disconnect so that our quit message is guaranteed
			   to get displayed */
			net_disconnect_later(net_sendbuffer_handle(server->handle));
			net_sendbuffer_destroy(server->handle, FALSE);
		}
		server->handle = NULL;
	}

	if (server->readtag > 0)
		g_source_remove(server->readtag);

        MODULE_DATA_DEINIT(server);
	server_connect_free(server->connrec);
	rawlog_destroy(server->rawlog);
	line_split_free(server->buffer);
	g_free_not_null(server->version);
	g_free_not_null(server->away_reason);
	g_free(server->nick);
	g_free(server->tag);
	g_free(server);
}

SERVER_REC *server_find_tag(const char *tag)
{
	GSList *tmp;

	g_return_val_if_fail(tag != NULL, NULL);
	if (*tag == '\0') return NULL;

	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		SERVER_REC *server = tmp->data;

		if (g_strcasecmp(server->tag, tag) == 0)
			return server;
	}

	for (tmp = lookup_servers; tmp != NULL; tmp = tmp->next) {
		SERVER_REC *server = tmp->data;

		if (g_strcasecmp(server->tag, tag) == 0)
			return server;
	}

	return NULL;
}

SERVER_REC *server_find_chatnet(const char *chatnet)
{
	GSList *tmp;

	g_return_val_if_fail(chatnet != NULL, NULL);
	if (*chatnet == '\0') return NULL;

	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		SERVER_REC *server = tmp->data;

		if (server->connrec->chatnet != NULL &&
		    g_strcasecmp(server->connrec->chatnet, chatnet) == 0)
			return server;
	}

	return NULL;
}

void server_connect_free(SERVER_CONNECT_REC *conn)
{
	g_return_if_fail(IS_SERVER_CONNECT(conn));

	signal_emit("server connect free", 1, conn);
        g_free_not_null(conn->proxy);
	g_free_not_null(conn->proxy_string);

	g_free_not_null(conn->address);
	g_free_not_null(conn->chatnet);

	g_free_not_null(conn->own_ip);

        g_free_not_null(conn->password);
        g_free_not_null(conn->nick);
        g_free_not_null(conn->username);
	g_free_not_null(conn->realname);

	g_free_not_null(conn->channels);
        g_free_not_null(conn->away_reason);
        g_free_not_null(conn->usermode);
        g_free(conn);
}

/* `optlist' should contain only one unknown key - the server tag.
   returns NULL if there was unknown -option */
SERVER_REC *cmd_options_get_server(const char *cmd,
				   GHashTable *optlist,
				   SERVER_REC *defserver)
{
	SERVER_REC *server;
	GSList *list, *tmp, *next;

	/* get all the options, then remove the known ones. there should
	   be only one left - the server tag. */
	list = hashtable_get_keys(optlist);
	if (cmd != NULL) {
		for (tmp = list; tmp != NULL; tmp = next) {
			char *option = tmp->data;
			next = tmp->next;

			if (command_have_option(cmd, option))
				list = g_slist_remove(list, option);
		}
	}

	if (list == NULL)
		return defserver;

	server = server_find_tag(list->data);
	if (server == NULL || list->next != NULL) {
		/* unknown option (not server tag) */
		signal_emit("error command", 2,
			    GINT_TO_POINTER(CMDERR_OPTION_UNKNOWN),
			    server == NULL ? list->data : list->next->data);
		signal_stop();

		server = NULL;
	}

	g_slist_free(list);
	return server;
}

/* SYNTAX: DISCONNECT *|<tag> [<message>] */
static void cmd_disconnect(const char *data, SERVER_REC *server)
{
	char *tag, *msg;
	void *free_arg;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST, &tag, &msg))
		return;

	if (*tag != '\0' && strcmp(tag, "*") != 0)
		server = server_find_tag(tag);
	if (server == NULL) cmd_param_error(CMDERR_NOT_CONNECTED);

	if (*msg == '\0') msg = (char *) settings_get_str("quit_message");
	signal_emit("server quit", 2, server, msg);

	cmd_params_free(free_arg);
	server_disconnect(server);
}

/* SYNTAX: QUIT [<message>] */
static void cmd_quit(const char *data)
{
	GSList *tmp, *next;
	const char *quitmsg;
	char *str;

	g_return_if_fail(data != NULL);

	quitmsg = *data != '\0' ? data :
		settings_get_str("quit_message");

	/* disconnect from every server */
	for (tmp = servers; tmp != NULL; tmp = next) {
		next = tmp->next;

		str = g_strdup_printf("* %s", quitmsg);
		cmd_disconnect(str, tmp->data);
		g_free(str);
	}

	signal_emit("gui exit", 0);
}

void servers_init(void)
{
	lookup_servers = servers = NULL;

	servers_reconnect_init();
	servers_redirect_init();
	servers_setup_init();

	command_bind("disconnect", NULL, (SIGNAL_FUNC) cmd_disconnect);
	command_bind("quit", NULL, (SIGNAL_FUNC) cmd_quit);
}

void servers_deinit(void)
{
	command_unbind("disconnect", (SIGNAL_FUNC) cmd_disconnect);
	command_unbind("quit", (SIGNAL_FUNC) cmd_quit);

	while (servers != NULL)
		server_disconnect(servers->data);
	while (lookup_servers != NULL)
		server_connect_failed(lookup_servers->data, NULL);

	servers_setup_deinit();
	servers_redirect_deinit();
	servers_reconnect_deinit();

	module_uniq_destroy("SERVER");
	module_uniq_destroy("SERVER CONNECT");
}
