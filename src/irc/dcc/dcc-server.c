/*
 dcc-server.c : irssi

    Copyright (C) 2003 Mark Trumbull

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
#include <irssi/src/core/network.h>
#include <irssi/src/core/net-sendbuffer.h>
#include <irssi/src/core/misc.h>

#include <irssi/src/irc/core/irc-servers.h>

#include <irssi/src/irc/dcc/dcc-chat.h>
#include <irssi/src/irc/dcc/dcc-get.h>
#include <irssi/src/irc/dcc/dcc-server.h>

void sig_dccget_connected(GET_DCC_REC *dcc);
GET_DCC_REC *dcc_get_create(IRC_SERVER_REC *server, CHAT_DCC_REC *chat,
			    const char *nick, const char *arg);

void dcc_chat_input(CHAT_DCC_REC *dcc);
CHAT_DCC_REC *dcc_chat_create(IRC_SERVER_REC *server, CHAT_DCC_REC *chat,
			      const char *nick, const char *arg);

static void sig_dcc_destroyed(SERVER_DCC_REC *dcc)
{
	if (!IS_DCC_SERVER(dcc))
		return;

	if (dcc->sendbuf != NULL)
		net_sendbuffer_destroy(dcc->sendbuf, FALSE);
}

/* Start listening for incoming connections */
static GIOChannel *dcc_listen_port(GIOChannel *iface, IPADDR *ip, int port)
{
	if (net_getsockname(iface, ip, NULL) == -1)
		return NULL;

	if (IPADDR_IS_V6(ip))
		return net_listen(NULL, &port);
	else
		return net_listen(&ip4_any, &port);
}

/* input function: DCC SERVER received some data.. */
static void dcc_server_input(SERVER_DCC_REC *dcc)
{
	char *str;
	int ret;

	g_return_if_fail(IS_DCC_SERVER(dcc));

	do {
		ret = net_sendbuffer_receive_line(dcc->sendbuf, &str, 1);

		if (ret == -1) {
			/* connection lost */
			dcc_close(DCC(dcc));
			break;
		}

		if (ret > 0) {
			dcc->transfd += ret;
			signal_emit("dcc server message", 2, dcc, str);
		}

		if (dcc->connection_established) {
			/* We set handle to NULL first because the new (chat/get) is using the same */
			/* handle and we don't want dcc_close to disconnect it.*/
			dcc->handle = NULL;
			dcc_close(DCC(dcc));
			break;
		}
	} while (ret > 0);
}

static void dcc_server_update_flags(SERVER_DCC_REC *dcc, const char *flags)
{
	g_return_if_fail(dcc != NULL);
	g_return_if_fail(IS_DCC_SERVER(dcc));

	if (*flags == '+' || *flags == '-') {
		const char *ptr = flags + 1;
		unsigned int value = (*flags == '+') ? 1 : 0;

		while (*ptr) {
			if (*ptr == 's' || *ptr == 'S')      { dcc->accept_send = value;   }
			else if (*ptr == 'c' || *ptr == 'C') { dcc->accept_chat = value;   }
			else if (*ptr == 'f' || *ptr == 'F') { dcc->accept_fserve = value; }
			ptr++;
		}
	}
}

/* Initialize DCC record */
static void dcc_init_server_rec(SERVER_DCC_REC *dcc, IRC_SERVER_REC *server,
				const char *mynick, const char *servertag)
{
	g_return_if_fail(dcc != NULL);
	g_return_if_fail(IS_DCC_SERVER(dcc));

	MODULE_DATA_INIT(dcc);
	dcc->created = time(NULL);
	dcc->chat = NULL;
	dcc->arg = NULL;
	dcc->nick = NULL;
	dcc->tagconn = dcc->tagread = dcc->tagwrite = -1;
	dcc->server = server;
	dcc->mynick = g_strdup(mynick);
	dcc->servertag = g_strdup(servertag);

	dcc_conns = g_slist_append(dcc_conns, dcc);
	signal_emit("dcc created", 1, dcc);
}

static SERVER_DCC_REC *dcc_server_create(IRC_SERVER_REC *server, const char *flags)
{
	SERVER_DCC_REC *dcc;

	dcc = g_new0(SERVER_DCC_REC, 1);
	dcc->orig_type = dcc->type = DCC_SERVER_TYPE;
	dcc_server_update_flags(dcc, flags);

	dcc_init_server_rec(dcc, server, dcc->mynick, dcc->servertag);
	return dcc;
}

static SERVER_DCC_REC *dcc_server_clone(SERVER_DCC_REC *dcc)
{
	SERVER_DCC_REC *newdcc;

	g_return_val_if_fail(IS_DCC_SERVER(dcc), NULL);

	newdcc = g_new0(SERVER_DCC_REC, 1);
	newdcc->orig_type = newdcc->type = DCC_SERVER_TYPE;
	newdcc->accept_send = dcc->accept_send;
	newdcc->accept_chat = dcc->accept_chat;
	newdcc->accept_fserve = dcc->accept_fserve;

	dcc_init_server_rec(newdcc, dcc->server, dcc->mynick, dcc->servertag);
	return newdcc;
}

/* input function: DCC SERVER - someone tried to connect to our socket */
static void dcc_server_listen(SERVER_DCC_REC *dcc)
{
	SERVER_DCC_REC *newdcc;
	IPADDR ip;
	GIOChannel *handle;
	int port;

	g_return_if_fail(IS_DCC_SERVER(dcc));

	/* accept connection */
	handle = net_accept(dcc->handle, &ip, &port);
	if (handle == NULL)
		return;

	/* Create a new DCC SERVER to handle this connection */
	newdcc = dcc_server_clone(dcc);

	newdcc->starttime = time(NULL);
	newdcc->handle = handle;
	newdcc->sendbuf = net_sendbuffer_create(handle, 0);
	memcpy(&newdcc->addr, &ip, sizeof(IPADDR));
	net_ip2host(&newdcc->addr, newdcc->addrstr);
	newdcc->port = port;
	newdcc->tagread =
	    i_input_add(handle, I_INPUT_READ, (GInputFunction) dcc_server_input, newdcc);

	signal_emit("dcc connected", 1, newdcc);
}

/* DCC SERVER: text received */
static void dcc_server_msg(SERVER_DCC_REC *dcc, const char *msg)
{
	g_return_if_fail(IS_DCC_SERVER(dcc));
	g_return_if_fail(msg != NULL);

	/* Check for CHAT protocol */
	if (g_ascii_strncasecmp(msg, "100 ", 4) == 0) {
		msg += 4;
		/* Check if this server is accepting chat requests.*/
		if (dcc->accept_chat) {
			/* Connect and start DCC Chat */
			char *str;
			CHAT_DCC_REC *dccchat = dcc_chat_create(dcc->server, NULL, msg, "chat");

			dccchat->starttime = time(NULL);
			dccchat->handle = dcc->handle;
			dccchat->sendbuf = net_sendbuffer_create(dccchat->handle, 0);
			memcpy(&dccchat->addr, &dcc->addr, sizeof(IPADDR));
			net_ip2host(&dccchat->addr, dccchat->addrstr);
			dccchat->port = dcc->port;
			dccchat->tagread = i_input_add(dccchat->handle, I_INPUT_READ,
			                               (GInputFunction) dcc_chat_input, dccchat);

			dcc->connection_established = 1;
			signal_emit("dcc connected", 1, dccchat);

			str = g_strdup_printf("101 %s\n",
					      (dccchat->server) ? dccchat->server->nick : "??");
			net_sendbuffer_send(dccchat->sendbuf, str, strlen(str));
			g_free(str);
		}
	}

	/* Check for FSERVE protocol */
	if (g_ascii_strncasecmp(msg, "110 ", 4) == 0) {
		msg += 4;
		/* Check if this server is accepting fserve requests.*/
		if (dcc->accept_fserve) {
			/* TODO - Connect and start DCC Fserve */
		}
	}

	/* Check for SEND protocol */
	if (g_ascii_strncasecmp(msg, "120 ", 4) == 0) {
		msg += 4;
		/* Check if this server is accepting send requests.*/
		if (dcc->accept_send) {
			/* Connect and start DCC Send */
			GET_DCC_REC *dccget;
			char **params, *fname, *nick;
			int paramcount, len, quoted = FALSE;
			uoff_t size;

			/* 120 clientnickname filesize filename */
			params = g_strsplit(msg, " ", -1);
			paramcount = g_strv_length(params);

			if (paramcount < 3) {
				g_strfreev(params);
				signal_stop();
				return;
			}

			nick = params[0];
			size = str_to_uofft(params[1]);
			fname = g_strjoinv(" ", &params[2]);

			len = strlen(fname);
			if (len > 1 && *fname == '"' && fname[len-1] == '"') {
				/* "file name" - MIRC sends filenames with spaces like this */
				fname[len-1] = '\0';
				memmove(fname, fname+1, len);
				quoted = TRUE;
			}

			dccget = dcc_get_create(dcc->server, NULL, nick, fname);
			dccget->handle = dcc->handle;
			dccget->target = g_strdup(dcc->server ? dcc->server->nick : "??");
			memcpy(&dccget->addr, &dcc->addr, sizeof(dcc->addr));
			if (dccget->addr.family == AF_INET) {
				net_ip2host(&dccget->addr, dccget->addrstr);
			} else {
				/* with IPv6, show it to us as it was sent */
				memcpy(dccget->addrstr, dcc->addrstr, sizeof(dccget->addrstr));
			}
			dccget->port = dcc->port;
			dccget->size = size;
			dccget->file_quoted = quoted;
			dccget->from_dccserver = 1;

			dcc->connection_established = 1;
			signal_emit("dcc request", 2, dccget, dccget->addrstr);

			g_strfreev(params);
			g_free(fname);
		}
	}

	signal_stop();
}

SERVER_DCC_REC *dcc_server_find_port(const char *port_str)
{
	GSList *tmp;
	unsigned int port = 0;

	g_return_val_if_fail(port_str != NULL, NULL);

	port = atoi(port_str);

	for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next) {
		SERVER_DCC_REC *dcc = tmp->data;

		if (IS_DCC_SERVER(dcc) && dcc->port == port)
			return dcc;
	}

	return NULL;
}

/* SYNTAX: DCC SERVER [+|-scf] [port] */
static void cmd_dcc_server(const char *data, IRC_SERVER_REC *server)
{
	void *free_arg;
	GIOChannel *handle;
	SERVER_DCC_REC *dcc;
	IPADDR own_ip;
	char *flags, *port;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 2, &flags, &port))
		return;

	dcc = dcc_server_find_port(port);
	if (dcc != NULL) {
		/* Server is already running, update it */
		dcc_server_update_flags(dcc, flags);
		cmd_params_free(free_arg);
		return;
	}

	/* start listening */
	if (!IS_IRC_SERVER(server) || !server->connected) {
		cmd_param_error(CMDERR_NOT_CONNECTED);
	}

	handle = dcc_listen_port(net_sendbuffer_handle(server->handle),
				 &own_ip, atoi(port));

	if (handle == NULL) {
		cmd_param_error(CMDERR_ERRNO);
	}

	dcc = dcc_server_create(server, flags);
	dcc->handle = handle;
	dcc->port = atoi(port);
	dcc->tagconn =
	    i_input_add(dcc->handle, I_INPUT_READ, (GInputFunction) dcc_server_listen, dcc);

	signal_emit("dcc server started", 1, dcc);

	cmd_params_free(free_arg);
}

/* DCC CLOSE SERVER <port> */
static void cmd_dcc_close(char *data, SERVER_REC *server)
{
	GSList *tmp, *next;
	char *port_str;
	void *free_arg;
	int found, port;

	g_return_if_fail(data != NULL);

	if (g_ascii_strncasecmp(data, "SERVER ", 7) != 0 ||
	    !cmd_get_params(data, &free_arg, 2, NULL, &port_str)) {
		return;
	}

	if (*port_str == '\0') {
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
	}

	port = atoi(port_str);
	found = FALSE;
	for (tmp = dcc_conns; tmp != NULL; tmp = next) {
		SERVER_DCC_REC *dcc = tmp->data;

		next = tmp->next;
		if (IS_DCC_SERVER(dcc) && dcc->port == port) {
			found = TRUE;
			dcc_close(DCC(dcc));
		}
	}

	if (found) {
		signal_stop();
	}

	cmd_params_free(free_arg);
}

void dcc_server_init(void)
{
	dcc_register_type("SERVER");
	command_bind("dcc server", NULL, (SIGNAL_FUNC) cmd_dcc_server);
	command_bind("dcc close", NULL, (SIGNAL_FUNC) cmd_dcc_close);
	signal_add("dcc destroyed", (SIGNAL_FUNC) sig_dcc_destroyed);
	signal_add_first("dcc server message", (SIGNAL_FUNC) dcc_server_msg);
}

void dcc_server_deinit(void)
{
	dcc_unregister_type("SERVER");
	command_unbind("dcc server", (SIGNAL_FUNC) cmd_dcc_server);
	command_unbind("dcc close", (SIGNAL_FUNC) cmd_dcc_close);
	signal_remove("dcc destroyed", (SIGNAL_FUNC) sig_dcc_destroyed);
	signal_remove("dcc server message", (SIGNAL_FUNC) dcc_server_msg);
}

