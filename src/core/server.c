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

#include "modules.h"
#include "signals.h"
#include "line-split.h"
#include "net-nonblock.h"
#include "net-sendbuffer.h"
#include "rawlog.h"
#include "misc.h"
#include "server.h"
#include "server-redirect.h"
#include "settings.h"

GSList *servers, *lookup_servers;

/* connection to server failed */
static void server_cant_connect(SERVER_REC *server, const char *msg)
{
	g_return_if_fail(server != NULL);

	lookup_servers = g_slist_remove(lookup_servers, server);

	signal_emit("server connect failed", 2, server, msg);
	if (server->connect_tag != -1)
		g_source_remove(server->connect_tag);

	if (server->connect_pipe[0] != -1) {
		close(server->connect_pipe[0]);
		close(server->connect_pipe[1]);
	}

	MODULE_DATA_DEINIT(server);
	g_free(server->tag);
	g_free(server->nick);
	g_free(server);
}

/* generate tag from server's address */
static char *server_create_address_tag(const char *address)
{
	const char *start, *end;

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

	tag = conn->ircnet != NULL ? g_strdup(conn->ircnet) :
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

static void server_connect_callback_init(SERVER_REC *server, int handle)
{
	int error;

	error = net_geterror(handle);
	if (error != 0) {
		server->connection_lost = TRUE;
		server_cant_connect(server, g_strerror(error));
		return;
	}

	lookup_servers = g_slist_remove(lookup_servers, server);

	g_source_remove(server->connect_tag);
	server->connect_tag = -1;
	server->connect_time = time(NULL);
	server->rawlog = rawlog_create();
	servers = g_slist_append(servers, server);

	signal_emit("server connected", 1, server);
}

static void server_connect_callback_readpipe(SERVER_REC *server)
{
	SERVER_CONNECT_REC *conn;
	RESOLVED_IP_REC iprec;
	const char *errormsg;
	int handle;

	g_source_remove(server->connect_tag);
	server->connect_tag = -1;

	net_gethostbyname_return(server->connect_pipe[0], &iprec);

	close(server->connect_pipe[0]);
	close(server->connect_pipe[1]);

	server->connect_pipe[0] = -1;
	server->connect_pipe[1] = -1;

	conn = server->connrec;
	handle = iprec.error != 0 ? -1 :
		net_connect_ip(&iprec.ip, conn->proxy != NULL ?
			       conn->proxy_port : conn->port,
			       conn->own_ip != NULL ? conn->own_ip : NULL);
	if (handle == -1) {
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
		server_cant_connect(server, errormsg);
		g_free_not_null(iprec.errorstr);
		return;
	}

	server->handle = net_sendbuffer_create(handle, 0);
	server->connect_tag =
		g_input_add(handle, G_INPUT_WRITE | G_INPUT_READ |
			    G_INPUT_EXCEPTION,
			    (GInputFunction) server_connect_callback_init,
			    server);
	signal_emit("server connecting", 2, server, &iprec.ip);
}

int server_connect(SERVER_REC *server)
{
	const char *connect_address;

	g_return_val_if_fail(server != NULL, FALSE);

	MODULE_DATA_INIT(server);

	if (pipe(server->connect_pipe) != 0) {
		g_warning("server_connect(): pipe() failed.");
		return FALSE;
	}

	server->tag = server_create_tag(server->connrec);

	connect_address = server->connrec->proxy != NULL ?
		server->connrec->proxy : server->connrec->address;
	server->connect_pid =
		net_gethostbyname_nonblock(connect_address,
					   server->connect_pipe[1]);
	server->connect_tag =
		g_input_add(server->connect_pipe[0], G_INPUT_READ,
			    (GInputFunction) server_connect_callback_readpipe, server);

	lookup_servers = g_slist_append(lookup_servers, server);

	signal_emit("server looking", 1, server);
	return TRUE;
}

void server_disconnect(SERVER_REC *server)
{
	g_return_if_fail(server != NULL);

	if (server->connect_tag != -1) {
		/* still connecting to server.. */
		if (server->connect_pid != -1)
			net_disconnect_nonblock(server->connect_pid);
		server_cant_connect(server, NULL);
		return;
	}

	servers = g_slist_remove(servers, server);

	signal_emit("server disconnected", 1, server);

	if (server->handle != NULL)
		net_sendbuffer_destroy(server->handle, TRUE);
	if (server->readtag > 0)
		g_source_remove(server->readtag);

        MODULE_DATA_DEINIT(server);
	rawlog_destroy(server->rawlog);
	line_split_free(server->buffer);
	g_free(server->tag);
	g_free(server->nick);
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

SERVER_REC *server_find_ircnet(const char *ircnet)
{
	GSList *tmp;

	g_return_val_if_fail(ircnet != NULL, NULL);
	if (*ircnet == '\0') return NULL;

	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		SERVER_REC *server = tmp->data;

		if (server->connrec->ircnet != NULL &&
		    g_strcasecmp(server->connrec->ircnet, ircnet) == 0) return server;
	}

	return NULL;
}

void servers_init(void)
{
	lookup_servers = servers = NULL;

	servers_redirect_init();
}

void servers_deinit(void)
{
	while (servers != NULL)
		server_disconnect(servers->data);
	while (lookup_servers != NULL)
		server_cant_connect(lookup_servers->data, NULL);

	servers_redirect_deinit();
}
