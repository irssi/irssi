/*
 dcc-chat.c : irssi

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
#include "network.h"
#include "net-nonblock.h"
#include "line-split.h"
#include "settings.h"

#include "masks.h"
#include "irc.h"
#include "server-setup.h"
#include "query.h"

#include "dcc.h"

/* Send `data' to dcc chat. */
void dcc_chat_send(DCC_REC *dcc, const char *data)
{
        g_return_if_fail(dcc != NULL);
	g_return_if_fail(data != NULL);

	/* FIXME: we need output queue! */
	net_transmit(dcc->handle, data, strlen(data));
	net_transmit(dcc->handle, "\n", 1);
}

/* If `item' is a query of a =nick, return DCC chat record of nick */
DCC_REC *item_get_dcc(void *item)
{
	QUERY_REC *query;

	query = irc_item_query(item);
	if (query == NULL || *query->nick != '=') return NULL;

	return dcc_find_item(DCC_TYPE_CHAT, query->nick+1, NULL);
}

/* Send text to DCC chat */
static void cmd_msg(const char *data)
{
	DCC_REC *dcc;
	char *params, *text, *target;

	g_return_if_fail(text != NULL);

	if (*data != '=') {
		/* handle only DCC messages */
		return;
	}

	params = cmd_get_params(data, 2 | PARAM_FLAG_GETREST, &target, &text);

	dcc = dcc_find_item(DCC_TYPE_CHAT, ++target, NULL);
	if (dcc != NULL) dcc_chat_send(dcc, text);

	g_free(params);
	signal_stop();
}

static void cmd_me(const char *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	DCC_REC *dcc;
	char *str;

	g_return_if_fail(data != NULL);

	dcc = item_get_dcc(item);
	if (dcc == NULL) return;

	str = g_strdup_printf("ACTION %s", data);
	dcc_ctcp_message(dcc->nick, NULL, dcc, FALSE, str);
	g_free(str);

	signal_stop();
}

static void cmd_action(const char *data, IRC_SERVER_REC *server)
{
	char *params, *target, *text;
	DCC_REC *dcc;
	char *str;

	g_return_if_fail(data != NULL);

	if (*data != '=') {
		/* handle only DCC actions */
		return;
	}

	params = cmd_get_params(data, 3 | PARAM_FLAG_GETREST, &target, &text);
	if (*target == '\0' || *text == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	dcc = dcc_find_item(DCC_TYPE_CHAT, target+1, NULL);
	if (dcc != NULL) {
		str = g_strdup_printf("ACTION %s", text);
		dcc_ctcp_message(dcc->nick, NULL, dcc, FALSE, str);
		g_free(str);
	}

	g_free(params);
	signal_stop();
}

static void cmd_ctcp(const char *data, IRC_SERVER_REC *server)
{
	char *params, *target, *ctcpcmd, *ctcpdata;
	DCC_REC *dcc;
	char *str;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected) cmd_return_error(CMDERR_NOT_CONNECTED);

	params = cmd_get_params(data, 3 | PARAM_FLAG_GETREST, &target, &ctcpcmd, &ctcpdata);
	if (*target == '\0' || *ctcpcmd == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	if (*target != '=') {
		/* handle only DCC CTCPs */
		g_free(params);
		return;
	}

	dcc = dcc_find_item(DCC_TYPE_CHAT, target+1, NULL);
	if (dcc != NULL) {
		g_strup(ctcpcmd);

		str = g_strdup_printf("%s %s", ctcpcmd, ctcpdata);
		dcc_ctcp_message(dcc->nick, NULL, dcc, FALSE, str);
		g_free(str);
	}

	g_free(params);
	signal_stop();
}

/* input function: DCC CHAT received some data.. */
static void dcc_chat_input(DCC_REC *dcc)
{
        char tmpbuf[512], *str;
	int recvlen, ret;

	g_return_if_fail(dcc != NULL);

	do {
		recvlen = net_receive(dcc->handle, tmpbuf, sizeof(tmpbuf));

		ret = line_split(tmpbuf, recvlen, &str, (LINEBUF_REC **) &dcc->databuf);
		if (ret == -1) {
			/* connection lost */
                        dcc->connection_lost = TRUE;
			signal_emit("dcc closed", 1, dcc);
			dcc_destroy(dcc);
			break;
		}

		if (ret > 0) {
			dcc->transfd += ret;
			signal_emit("dcc chat message", 2, dcc, str);
		}
	} while (ret > 0);
}

/* input function: DCC CHAT - someone tried to connect to our socket */
static void dcc_chat_listen(DCC_REC *dcc)
{
	IPADDR ip;
	int handle, port;

	g_return_if_fail(dcc != NULL);

	/* accept connection */
	handle = net_accept(dcc->handle, &ip, &port);
	if (handle == -1)
		return;

	/* TODO: add paranoia check - see dcc-files.c */

	g_source_remove(dcc->tagread);
	close(dcc->handle);

	dcc->starttime = time(NULL);
	dcc->handle = handle;
	memcpy(&dcc->addr, &ip, sizeof(IPADDR));
	net_ip2host(&dcc->addr, dcc->addrstr);
	dcc->port = port;
	dcc->tagread = g_input_add(handle, G_INPUT_READ,
				   (GInputFunction) dcc_chat_input, dcc);

	signal_emit("dcc connected", 1, dcc);
}

/* callback: DCC CHAT - net_connect_nonblock() finished */
static void sig_chat_connected(DCC_REC *dcc)
{
	g_return_if_fail(dcc != NULL);

	g_source_remove(dcc->tagread);
	if (net_geterror(dcc->handle) != 0) {
		/* error connecting */
		signal_emit("dcc error connect", 1, dcc);
		dcc_destroy(dcc);
		return;
	}

	/* connect ok. */
	dcc->starttime = time(NULL);
	dcc->tagread = g_input_add(dcc->handle, G_INPUT_READ,
				   (GInputFunction) dcc_chat_input, dcc);

	signal_emit("dcc connected", 1, dcc);
}

static void dcc_chat_connect(DCC_REC *dcc)
{
	g_return_if_fail(dcc != NULL);

	if (dcc->addrstr[0] == '\0' || dcc->starttime != 0) {
		/* already sent a chat request / already chatting */
		return;
	}

	dcc->handle = net_connect_ip(&dcc->addr, dcc->port,
				     source_host_ok ? source_host_ip : NULL);
	if (dcc->handle != -1) {
		dcc->tagread = g_input_add(dcc->handle, G_INPUT_WRITE|G_INPUT_READ|G_INPUT_EXCEPTION,
					   (GInputFunction) sig_chat_connected, dcc);
	} else {
		/* error connecting */
		signal_emit("dcc error connect", 1, dcc);
		dcc_destroy(dcc);
	}
}

/* command: DCC CHAT */
static void cmd_dcc_chat(const char *data, IRC_SERVER_REC *server)
{
	DCC_REC *dcc;
	IPADDR own_ip;
	char *str, host[MAX_IP_LEN];
	int port, handle;

	g_return_if_fail(data != NULL);
	if (*data == '\0') cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

	dcc = dcc_find_item(DCC_TYPE_CHAT, data, NULL);
	if (dcc != NULL) {
		/* found from dcc list - so we're the connecting side.. */
		dcc_chat_connect(dcc);
		return;
	}

	/* send dcc chat request */
	if (server == NULL || !server->connected)
		cmd_return_error(CMDERR_NOT_CONNECTED);

	if (net_getsockname(server->handle, &own_ip, NULL) == -1)
		cmd_return_error(CMDERR_ERRNO);

	port = settings_get_int("dcc_port");
	handle = net_listen(&own_ip, &port);
	if (handle == -1)
		cmd_return_error(CMDERR_ERRNO);

	dcc = dcc_create(DCC_TYPE_CHAT, handle, data, "chat", server, NULL);
	dcc->tagread = g_input_add(dcc->handle, G_INPUT_READ,
				   (GInputFunction) dcc_chat_listen, dcc);

	/* send the request */
	dcc_make_address(&own_ip, host);
	str = g_strdup_printf("PRIVMSG %s :\001DCC CHAT CHAT %s %d\001",
			      data, host, port);
	irc_send_cmd(server, str);
	g_free(str);
}

static void cmd_mircdcc(gchar *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	DCC_REC *dcc;

	g_return_if_fail(data != NULL);

	dcc = item_get_dcc(item);
	if (dcc == NULL) return;

	dcc->mirc_ctcp = toupper(*data) == 'N' ? FALSE : TRUE;
}

/* DCC CHAT: text received */
static void dcc_chat_msg(DCC_REC *dcc, const char *msg)
{
	char *cmd, *ptr;
	int reply;

	g_return_if_fail(dcc != NULL);
	g_return_if_fail(msg != NULL);

	reply = FALSE;
	if (g_strncasecmp(msg, "CTCP_MESSAGE ", 13) == 0) {
		/* bitchx (and ircii?) sends this */
		msg += 13;
		dcc->mirc_ctcp = FALSE;
	} else if (g_strncasecmp(msg, "CTCP_REPLY ", 11) == 0) {
		/* bitchx (and ircii?) sends this */
		msg += 11;
		reply = TRUE;
		dcc->mirc_ctcp = FALSE;
	} else if (*msg == 1) {
		/* Use the mirc style CTCPs from now on.. */
		dcc->mirc_ctcp = TRUE;
	}

	/* Handle only DCC CTCPs */
	if (*msg != 1)
		return;

	/* get ctcp command, remove \001 chars */
	cmd = g_strconcat(reply ? "dcc reply " : "dcc ctcp ", msg+1, NULL);
	if (cmd[strlen(cmd)-1] == 1) cmd[strlen(cmd)-1] = '\0';

	ptr = strchr(cmd+9, ' ');
	if (ptr != NULL) *ptr++ = '\0'; else ptr = "";

	g_strdown(cmd+9);
	if (!signal_emit(cmd, 2, ptr, dcc))
		signal_emit(reply ? "default dcc reply" : "default dcc ctcp", 2, msg, dcc);
	g_free(cmd);

	signal_stop();
}

static void dcc_ctcp_redirect(gchar *msg, DCC_REC *dcc)
{
	g_return_if_fail(msg != NULL);
	g_return_if_fail(dcc != NULL);

	signal_emit("ctcp msg dcc", 6, msg, dcc->server, dcc->nick, "dcc", dcc->mynick, dcc);
}

void dcc_chat_init(void)
{
	command_bind("msg", NULL, (SIGNAL_FUNC) cmd_msg);
	command_bind("me", NULL, (SIGNAL_FUNC) cmd_me);
	command_bind("action", NULL, (SIGNAL_FUNC) cmd_action);
	command_bind("ctcp", NULL, (SIGNAL_FUNC) cmd_ctcp);
	command_bind("dcc chat", NULL, (SIGNAL_FUNC) cmd_dcc_chat);
	command_bind("mircdcc", NULL, (SIGNAL_FUNC) cmd_mircdcc);
	signal_add_first("dcc chat message", (SIGNAL_FUNC) dcc_chat_msg);
	signal_add("dcc ctcp dcc", (SIGNAL_FUNC) dcc_ctcp_redirect);
}

void dcc_chat_deinit(void)
{
	command_unbind("msg", (SIGNAL_FUNC) cmd_msg);
	command_unbind("me", (SIGNAL_FUNC) cmd_me);
	command_unbind("action", (SIGNAL_FUNC) cmd_action);
	command_unbind("ctcp", (SIGNAL_FUNC) cmd_ctcp);
	command_unbind("dcc chat", (SIGNAL_FUNC) cmd_dcc_chat);
	command_unbind("mircdcc", (SIGNAL_FUNC) cmd_mircdcc);
	signal_remove("dcc chat message", (SIGNAL_FUNC) dcc_chat_msg);
	signal_remove("dcc ctcp dcc", (SIGNAL_FUNC) dcc_ctcp_redirect);
}
