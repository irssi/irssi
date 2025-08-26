/*
 dcc-chat.c : irssi

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
#include <irssi/src/core/commands.h>
#include <irssi/src/core/recode.h>
#include <irssi/src/core/network.h>
#include <irssi/src/core/net-sendbuffer.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/settings.h>

#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/irc/core/irc-queries.h>
#include <irssi/src/core/masks.h>

#include <irssi/src/irc/dcc/dcc-chat.h>

static char *dcc_chat_get_new_id(const char *nick)
{
        char *id;
	int num;

        g_return_val_if_fail(nick != NULL, NULL);

	if (dcc_chat_find_id(nick) == NULL) {
		/* same as nick, good */
                return g_strdup(nick);
	}

	/* keep adding numbers after nick until some of them isn't found */
	for (num = 2;; num++) {
                id = g_strdup_printf("%s%d", nick, num);
		if (dcc_chat_find_id(id) == NULL)
                        return id;
                g_free(id);
	}
}

CHAT_DCC_REC *dcc_chat_create(IRC_SERVER_REC *server,
				     CHAT_DCC_REC *chat,
				     const char *nick, const char *arg)
{
	CHAT_DCC_REC *dcc;

	dcc = g_new0(CHAT_DCC_REC, 1);
	dcc->orig_type = dcc->type = DCC_CHAT_TYPE;
	dcc->mirc_ctcp = settings_get_bool("dcc_mirc_ctcp");
        dcc->id = dcc_chat_get_new_id(nick);

	dcc_init_rec(DCC(dcc), server, chat, nick, arg);
	if (dcc->module_data == NULL) {
		/* failed to successfully init; TODO: change init_rec API */
		g_free(dcc->id);
		g_free(dcc);
		return NULL;
	}

        return dcc;
}

static void dcc_remove_chat_refs(CHAT_DCC_REC *dcc)
{
	GSList *tmp;

	g_return_if_fail(dcc != NULL);

	for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next) {
		DCC_REC *rec = tmp->data;

		if (rec->chat == dcc)
			rec->chat = NULL;
	}
}

static void sig_dcc_destroyed(CHAT_DCC_REC *dcc)
{
	if (!IS_DCC_CHAT(dcc)) return;

	dcc_remove_chat_refs(dcc);

	if (dcc->sendbuf != NULL) net_sendbuffer_destroy(dcc->sendbuf, FALSE);
	g_free(dcc->id);
}

CHAT_DCC_REC *dcc_chat_find_id(const char *id)
{
	GSList *tmp;

	g_return_val_if_fail(id != NULL, NULL);

	for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next) {
		CHAT_DCC_REC *dcc = tmp->data;

		if (IS_DCC_CHAT(dcc) && dcc->id != NULL &&
		    g_ascii_strcasecmp(dcc->id, id) == 0)
			return dcc;
	}

	return NULL;
}

static CHAT_DCC_REC *dcc_chat_find_nick(IRC_SERVER_REC *server,
					const char *nick)
{
	GSList *tmp;

	g_return_val_if_fail(nick != NULL, NULL);

	for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next) {
		CHAT_DCC_REC *dcc = tmp->data;

		if (IS_DCC_CHAT(dcc) && dcc->server == server &&
		    g_ascii_strcasecmp(dcc->nick, nick) == 0)
			return dcc;
	}

	return NULL;
}

/* Send `data' to dcc chat. */
void dcc_chat_send(CHAT_DCC_REC *dcc, const char *data)
{
	g_return_if_fail(IS_DCC_CHAT(dcc));
        g_return_if_fail(dcc->sendbuf != NULL);
	g_return_if_fail(data != NULL);

	net_sendbuffer_send(dcc->sendbuf, data, strlen(data));
	net_sendbuffer_send(dcc->sendbuf, "\n", 1);
}

/* Send a CTCP message/notify to target.
   Send the CTCP via DCC chat if `chat' is specified. */
void dcc_ctcp_message(IRC_SERVER_REC *server, const char *target,
		      CHAT_DCC_REC *chat, int notice, const char *msg)
{
	char *str;
	char *recoded;

	if (chat != NULL && chat->sendbuf != NULL) {
		/* send it via open DCC chat */
		recoded = recode_out(SERVER(server), msg, chat->nick);
		str = g_strdup_printf("%s\001%s\001", chat->mirc_ctcp ? "" :
				      notice ? "CTCP_REPLY " :
				      "CTCP_MESSAGE ", recoded);
                dcc_chat_send(chat, str);
		g_free(str);
	} else {
		recoded = recode_out(SERVER(server), msg, target);
		irc_send_cmdv(server, "%s %s :\001%s\001",
			      notice ? "NOTICE" : "PRIVMSG", target, recoded);
	}
	g_free(recoded);
}

/* If `item' is a query of a =nick, return DCC chat record of nick */
CHAT_DCC_REC *item_get_dcc(WI_ITEM_REC *item)
{
	QUERY_REC *query;

	query = IRC_QUERY(item);
	if (query == NULL || *query->name != '=')
		return NULL;

	return dcc_chat_find_id(query->name+1);
}

/* Send text to DCC chat */
static void cmd_msg(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	CHAT_DCC_REC *dcc;
        GHashTable *optlist;
	char *text, *target;
	void *free_arg;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_UNKNOWN_OPTIONS |
			    PARAM_FLAG_OPTIONS | PARAM_FLAG_GETREST, "msg",
			    &optlist, &target, &text))
		return;

	/* handle only DCC messages */
	if (g_strcmp0(target, "*") == 0)
		dcc = item_get_dcc(item);
	else if (*target == '=')
		dcc = dcc_chat_find_id(target+1);
	else
		dcc = NULL;

	if (dcc != NULL && dcc->sendbuf != NULL) {
		char *recoded;

		recoded = recode_out(server, text, dcc->nick);
		dcc_chat_send(dcc, recoded);
		g_free(recoded);
	}

	if (dcc != NULL || *target == '=')
		signal_stop();

	cmd_params_free(free_arg);
}

static void cmd_me(const char *data, IRC_SERVER_REC *server, WI_ITEM_REC *item)
{
	CHAT_DCC_REC *dcc;
	char *str;

	g_return_if_fail(data != NULL);

	dcc = item_get_dcc(item);
	if (dcc == NULL) return;

	str = g_strconcat("ACTION ", data, NULL);
	dcc_ctcp_message(server, dcc->nick, dcc, FALSE, str);
	g_free(str);

	signal_stop();
}

static void cmd_action(const char *data, IRC_SERVER_REC *server)
{
	CHAT_DCC_REC *dcc;
	char *target, *text, *str;
	void *free_arg;

	g_return_if_fail(data != NULL);

	if (*data != '=') {
		/* handle only DCC actions */
		return;
	}

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST,
			    &target, &text))
		return;
	if (*target == '\0' || *text == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	dcc = dcc_chat_find_id(target+1);
	if (dcc != NULL) {
		str = g_strconcat("ACTION ", text, NULL);
		dcc_ctcp_message(server, dcc->nick, dcc, FALSE, str);
		g_free(str);
	}

	cmd_params_free(free_arg);
	signal_stop();
}

static void cmd_ctcp(const char *data, IRC_SERVER_REC *server)
{
	CHAT_DCC_REC *dcc;
	char *target, *ctcpcmd, *ctcpdata, *str;
	void *free_arg;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 3 | PARAM_FLAG_GETREST,
			    &target, &ctcpcmd, &ctcpdata))
		return;
	if (*target == '\0' || *ctcpcmd == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	if (*target != '=') {
		/* handle only DCC CTCPs */
		cmd_params_free(free_arg);
		return;
	}

	dcc = dcc_chat_find_id(target+1);
	if (dcc != NULL) {
		ascii_strup(ctcpcmd);

		str = g_strconcat(ctcpcmd, " ", ctcpdata, NULL);
		dcc_ctcp_message(server, dcc->nick, dcc, FALSE, str);
		g_free(str);
	}

	cmd_params_free(free_arg);
	signal_stop();
}

/* input function: DCC CHAT received some data.. */
void dcc_chat_input(CHAT_DCC_REC *dcc)
{
	char *str;
	int ret;

	g_return_if_fail(IS_DCC_CHAT(dcc));

	do {
		ret = net_sendbuffer_receive_line(dcc->sendbuf, &str, 1);

		if (ret == -1) {
			/* connection lost */
                        dcc->connection_lost = TRUE;
			dcc_close(DCC(dcc));
			break;
		}

		if (ret > 0) {
			SERVER_REC *server;
			char *recoded;

			dcc->transfd += ret;

			server = SERVER(dcc->server);
			recoded = recode_in(server, str, dcc->nick);
			signal_emit("dcc chat message", 2, dcc, recoded);
			g_free(recoded);
			if (server != NULL)
				server_meta_clear_all(server);
		}
	} while (ret > 0);
}

/* input function: DCC CHAT - someone tried to connect to our socket */
static void dcc_chat_listen(CHAT_DCC_REC *dcc)
{
	IPADDR ip;
        GIOChannel *handle;
	int port;

	g_return_if_fail(IS_DCC_CHAT(dcc));

	/* accept connection */
	handle = net_accept(dcc->handle, &ip, &port);
	if (handle == NULL)
		return;

	/* TODO: add paranoia check - see dcc-files.c */

	net_disconnect(dcc->handle);
	g_source_remove(dcc->tagconn);
	dcc->tagconn = -1;

	dcc->starttime = time(NULL);
	dcc->handle = handle;
	dcc->sendbuf = net_sendbuffer_create(handle, 0);
	memcpy(&dcc->addr, &ip, sizeof(IPADDR));
	net_ip2host(&dcc->addr, dcc->addrstr);
	dcc->port = port;
	dcc->tagread = i_input_add(handle, I_INPUT_READ, (GInputFunction) dcc_chat_input, dcc);

	signal_emit("dcc connected", 1, dcc);
}

/* callback: DCC CHAT - connect finished */
static void sig_chat_connected(CHAT_DCC_REC *dcc)
{
	g_return_if_fail(IS_DCC_CHAT(dcc));

	if (net_geterror(dcc->handle) != 0) {
		/* error connecting */
		signal_emit("dcc error connect", 1, dcc);
		dcc_destroy(DCC(dcc));
		return;
	}

	/* connect ok. */
	g_source_remove(dcc->tagconn);
	dcc->tagconn = -1;

	dcc->starttime = time(NULL);
	dcc->sendbuf = net_sendbuffer_create(dcc->handle, 0);
	dcc->tagread = i_input_add(dcc->handle, I_INPUT_READ, (GInputFunction) dcc_chat_input, dcc);

	signal_emit("dcc connected", 1, dcc);
}

static void dcc_chat_connect(CHAT_DCC_REC *dcc)
{
	g_return_if_fail(IS_DCC_CHAT(dcc));

	if (dcc->addrstr[0] == '\0' ||
	    dcc->starttime != 0 || dcc->handle != NULL) {
		/* already sent a chat request / already chatting */
		return;
	}

	dcc->handle = dcc_connect_ip(&dcc->addr, dcc->port);
	if (dcc->handle != NULL) {
		dcc->tagconn = i_input_add(dcc->handle, I_INPUT_WRITE | I_INPUT_READ,
		                           (GInputFunction) sig_chat_connected, dcc);
	} else {
		/* error connecting */
		signal_emit("dcc error connect", 1, dcc);
		dcc_destroy(DCC(dcc));
	}
}

static void dcc_chat_passive(CHAT_DCC_REC *dcc)
{
	IPADDR own_ip;
	int port;
	GIOChannel *handle;
	char host[MAX_IP_LEN];

	g_return_if_fail(IS_DCC_CHAT(dcc));

	if (dcc->addrstr[0] == '\0' ||
	    dcc->starttime != 0 || dcc->handle != NULL) {
		/* already sent a chat request / already chatting */
		return;
	}

	handle = dcc_listen(net_sendbuffer_handle(dcc->server->handle),
			    &own_ip, &port);
	if (handle == NULL)
		cmd_return_error(CMDERR_ERRNO);

	dcc->handle = handle;
	dcc->tagconn =
	    i_input_add(dcc->handle, I_INPUT_READ, (GInputFunction) dcc_chat_listen, dcc);

	/* Let's send the reply to the other client! */
	dcc_ip2str(&own_ip, host);
	irc_send_cmdv(dcc->server, "PRIVMSG %s :\001DCC CHAT CHAT %s %d %d\001",
		      dcc->nick, host, port, dcc->pasv_id);

}

/* SYNTAX: DCC CHAT [-passive] [<nick>] */
static void cmd_dcc_chat(const char *data, IRC_SERVER_REC *server)
{
	void *free_arg;
	CHAT_DCC_REC *dcc;
	IPADDR own_ip;
	GIOChannel *handle;
	GHashTable *optlist;
	int p_id;
	char *nick, host[MAX_IP_LEN];
	int port;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS,
			    "dcc chat", &optlist, &nick))
		return;

	if (*nick == '\0') {
		dcc = DCC_CHAT(dcc_find_request_latest(DCC_CHAT_TYPE));
		if (dcc != NULL) {
			if (!dcc_is_passive(dcc))
				dcc_chat_connect(dcc);
			else
				dcc_chat_passive(dcc);
		}
		cmd_params_free(free_arg);
		return;
	}

	dcc = dcc_chat_find_id(nick);
	if (dcc != NULL && dcc_is_waiting_user(dcc)) {
		if (!dcc_is_passive(dcc)) {
			/* found from dcc chat requests,
			   we're the connecting side */
			dcc_chat_connect(dcc);
		} else {
			/* We are accepting a passive DCC CHAT. */
			dcc_chat_passive(dcc);
		}
		cmd_params_free(free_arg);
		return;
	}

	if (dcc != NULL && dcc_is_listening(dcc) &&
	    dcc->server == server) {
		/* sending request again even while old request is
		   still waiting, remove it. */
		dcc_destroy(DCC(dcc));
	}

	if (!IS_IRC_SERVER(server) || !server->connected)
		cmd_param_error(CMDERR_NOT_CONNECTED);

	dcc = dcc_chat_create(server, NULL, nick, "chat");
	if (dcc == NULL) {
		cmd_params_free(free_arg);
		g_warn_if_reached();
		return;
	}

	if (g_hash_table_lookup(optlist, "passive") == NULL) {
		/* Standard DCC CHAT... let's listen for incoming connections */
		handle = dcc_listen(net_sendbuffer_handle(server->handle),
				    &own_ip, &port);
		if (handle == NULL)
			cmd_param_error(CMDERR_ERRNO);

		dcc->handle = handle;
		dcc->tagconn =
		    i_input_add(dcc->handle, I_INPUT_READ, (GInputFunction) dcc_chat_listen, dcc);

		/* send the chat request */
		signal_emit("dcc request send", 1, dcc);

		dcc_ip2str(&own_ip, host);
		irc_send_cmdv(server, "PRIVMSG %s :\001DCC CHAT CHAT %s %d\001",
			      nick, host, port);
	} else {
		/* Passive protocol... we want the other side to listen */
		/* send the chat request */
		dcc->port = 0;
		signal_emit("dcc request send", 1, dcc);

		/* generate a random id */
		p_id = rand() % 64;
		dcc->pasv_id = p_id;

		/* 16843009 is the long format of 1.1.1.1, we use a fake IP
		   since the other side shouldn't care of it: they will send
		   the address for us to connect to in the reply */
		irc_send_cmdv(server,
			      "PRIVMSG %s :\001DCC CHAT CHAT 16843009 0 %d\001",
			      nick, p_id);
	}
	cmd_params_free(free_arg);
}

/* SYNTAX: MIRCDCC ON|OFF */
static void cmd_mircdcc(const char *data, SERVER_REC *server,
			QUERY_REC *item)
{
	CHAT_DCC_REC *dcc;

	g_return_if_fail(data != NULL);

	dcc = item_get_dcc((WI_ITEM_REC *) item);
	if (dcc == NULL) return;

	dcc->mirc_ctcp = i_toupper(*data) != 'N' &&
		g_ascii_strncasecmp(data, "OF", 2) != 0;
}

/* DCC CLOSE CHAT <nick> - check only from chat_ids in open DCC chats,
   the default handler will check from DCC chat requests */
static void cmd_dcc_close(char *data, SERVER_REC *server)
{
	GSList *tmp, *next;
	char *nick;
	void *free_arg;
	int found;

	g_return_if_fail(data != NULL);

	if (g_ascii_strncasecmp(data, "CHAT ", 5) != 0 ||
	    !cmd_get_params(data, &free_arg, 2, NULL, &nick))
		return;

	if (*nick == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	found = FALSE;
	for (tmp = dcc_conns; tmp != NULL; tmp = next) {
		CHAT_DCC_REC *dcc = tmp->data;

		next = tmp->next;
		if (IS_DCC_CHAT(dcc) && dcc->id != NULL &&
		    g_ascii_strcasecmp(dcc->id, nick) == 0) {
			found = TRUE;
			if (!dcc_is_connected(dcc) && IS_IRC_SERVER(server))
				dcc_reject(DCC(dcc), IRC_SERVER(server));
			else {
				/* don't send DCC REJECT after DCC chat
				   is already open */
				dcc_close(DCC(dcc));
			}
		}
	}

	if (found) signal_stop();

	cmd_params_free(free_arg);
}

static void cmd_whois(const char *data, SERVER_REC *server,
		      WI_ITEM_REC *item)
{
	CHAT_DCC_REC *dcc;

	g_return_if_fail(data != NULL);

        /* /WHOIS without target in DCC CHAT query? */
	if (*data == '\0') {
		dcc = item_get_dcc(item);
		if (dcc != NULL) {
			signal_emit("command whois", 3,
				    dcc->nick, server, item);
                        signal_stop();
		}
	}
}

#define DCC_AUTOACCEPT_PORT(dcc) \
	((dcc)->port >= 1024 || settings_get_bool("dcc_autoaccept_lowports"))

#define DCC_CHAT_AUTOACCEPT(dcc, server, nick, addr) \
	(DCC_AUTOACCEPT_PORT(dcc) && \
	masks_match(SERVER(server), \
		settings_get_str("dcc_autochat_masks"), (nick), (addr)))


/* CTCP: DCC CHAT */
static void ctcp_msg_dcc_chat(IRC_SERVER_REC *server, const char *data,
			      const char *nick, const char *addr,
			      const char *target, CHAT_DCC_REC *chat)
{
        CHAT_DCC_REC *dcc;
	char **params;
	int paramcount;
        int passive, autoallow = FALSE;

        /* CHAT <unused> <address> <port> */
	/* CHAT <unused> <address> 0 <id> (DCC CHAT passive protocol) */
	params = g_strsplit(data, " ", -1);
	paramcount = g_strv_length(params);

	if (paramcount < 3) {
		g_strfreev(params);
		return;
	}
	passive = paramcount == 4 && g_strcmp0(params[2], "0") == 0;

	if (nick == NULL)
		nick = "";

	dcc = DCC_CHAT(dcc_find_request(DCC_CHAT_TYPE, nick, NULL));
	if (dcc != NULL) {
		if (dcc_is_listening(dcc)) {
			/* we requested dcc chat, they requested
			   dcc chat from us .. allow it. */
			dcc_destroy(DCC(dcc));
			autoallow = TRUE;
		} else if (!dcc_is_passive(dcc)) {
			/* we already have one dcc chat request
			   from this nick, remove it. */
			dcc_destroy(DCC(dcc));
		} else if (passive) {
			if (dcc->pasv_id != atoi(params[3])) {
				/* IDs don't match! */
				dcc_destroy(DCC(dcc));
			} else {
				/* IDs are ok! Update address and port and
				   connect! */
				dcc->target = g_strdup(target);
				dcc->port = atoi(params[2]);
				dcc_str2ip(params[1], &dcc->addr);
				net_ip2host(&dcc->addr, dcc->addrstr);

				dcc_chat_connect(dcc);
				g_strfreev(params);
				return;
			}
		}
	}

	dcc = dcc_chat_create(server, chat, nick, params[0]);
	if (dcc == NULL) {
		g_strfreev(params);
		g_warn_if_reached();
		return;
	}
	dcc->target = g_strdup(target);
	dcc->port = atoi(params[2]);

	if (passive)
		dcc->pasv_id = atoi(params[3]);

	dcc_str2ip(params[1], &dcc->addr);
	net_ip2host(&dcc->addr, dcc->addrstr);

	signal_emit("dcc request", 2, dcc, addr);

	if (autoallow || DCC_CHAT_AUTOACCEPT(dcc, server, nick, addr)) {
		if (passive) {
			/* Passive DCC... let's set up a listening socket
			   and send reply back */
			dcc_chat_passive(dcc);
		} else {
			dcc_chat_connect(dcc);
		}
	}
	g_strfreev(params);
}

/* DCC CHAT: text received */
static void dcc_chat_msg(CHAT_DCC_REC *dcc, const char *msg)
{
	char *event, *cmd, *ptr;
	int reply;

	g_return_if_fail(IS_DCC_CHAT(dcc));
	g_return_if_fail(msg != NULL);

	reply = FALSE;
	if (g_ascii_strncasecmp(msg, "CTCP_MESSAGE ", 13) == 0) {
		/* bitchx (and ircii?) sends this */
		msg += 13;
		dcc->mirc_ctcp = FALSE;
	} else if (g_ascii_strncasecmp(msg, "CTCP_REPLY ", 11) == 0) {
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
	event = g_strconcat(reply ? "dcc reply " : "dcc ctcp ", msg+1, NULL);
	if (event[strlen(event)-1] == 1) event[strlen(event)-1] = '\0';

        cmd = event + (reply ? 10 : 9);
	ptr = strchr(cmd, ' ');
	if (ptr != NULL) *ptr++ = '\0'; else ptr = "";

	cmd = g_ascii_strup(cmd, -1);

	ascii_strdown(event+9);
	if (!signal_emit(event, 2, dcc, ptr)) {
		signal_emit(reply ? "default dcc reply" :
			    "default dcc ctcp", 3, dcc, cmd, ptr);
	}

        g_free(cmd);
	g_free(event);

	signal_stop();
}

static void dcc_ctcp_redirect(CHAT_DCC_REC *dcc, const char *msg)
{
	g_return_if_fail(msg != NULL);
	g_return_if_fail(IS_DCC_CHAT(dcc));

	signal_emit("ctcp msg dcc", 6, dcc->server, msg,
		    dcc->nick, "dcc", dcc->mynick, dcc);
}

static void dcc_ctcp_reply_redirect(CHAT_DCC_REC *dcc, const char *msg)
{
	g_return_if_fail(msg != NULL);
	g_return_if_fail(IS_DCC_CHAT(dcc));

	signal_emit("ctcp reply dcc", 6, dcc->server, msg,
		    dcc->nick, "dcc", dcc->mynick, dcc);
}

/* CTCP REPLY: REJECT */
static void ctcp_reply_dcc_reject(IRC_SERVER_REC *server, const char *data,
				  const char *nick, const char *addr,
				  DCC_REC *chat)
{
        DCC_REC *dcc;

	/* default REJECT handler checks args too -
	   we don't care about it in DCC chats. */
	if (g_ascii_strncasecmp(data, "CHAT", 4) == 0 &&
	    (data[4] == '\0' || data[4] == ' ')) {
		dcc = dcc_find_request(DCC_CHAT_TYPE, nick, NULL);
		if (dcc != NULL) dcc_close(dcc);
		signal_stop();
	}
}

static void event_nick(IRC_SERVER_REC *server, const char *data,
		       const char *orignick)
{
        QUERY_REC *query;
        CHAT_DCC_REC *dcc;
	char *params, *nick, *tag;

	g_return_if_fail(data != NULL);
	g_return_if_fail(orignick != NULL);

	params = event_get_params(data, 1, &nick);
	if (g_ascii_strcasecmp(nick, orignick) == 0) {
		/* shouldn't happen, but just to be sure irssi doesn't
		   get into infinite loop */
                g_free(params);
		return;
	}

	while ((dcc = dcc_chat_find_nick(server, orignick)) != NULL) {
		g_free(dcc->nick);
		dcc->nick = g_strdup(nick);

		tag = g_strconcat("=", dcc->id, NULL);
		query = irc_query_find(server, tag);
                g_free(tag);

                /* change the id too */
		g_free(dcc->id);
		dcc->id = NULL;
		dcc->id = dcc_chat_get_new_id(nick);

		if (query != NULL) {
			tag = g_strconcat("=", dcc->id, NULL);
			query_change_nick(query, tag);
                        g_free(tag);
		}
	}

	g_free(params);
}

void dcc_chat_init(void)
{
        dcc_register_type("CHAT");
	settings_add_bool("dcc", "dcc_mirc_ctcp", FALSE);
	settings_add_str("dcc", "dcc_autochat_masks", "");

	command_bind("msg", NULL, (SIGNAL_FUNC) cmd_msg);
	command_bind("me", NULL, (SIGNAL_FUNC) cmd_me);
	command_bind("action", NULL, (SIGNAL_FUNC) cmd_action);
	command_bind("ctcp", NULL, (SIGNAL_FUNC) cmd_ctcp);
	command_bind("dcc chat", NULL, (SIGNAL_FUNC) cmd_dcc_chat);
	command_set_options("dcc chat", "passive");
	command_bind("mircdcc", NULL, (SIGNAL_FUNC) cmd_mircdcc);
	command_bind("dcc close", NULL, (SIGNAL_FUNC) cmd_dcc_close);
	command_bind("whois", NULL, (SIGNAL_FUNC) cmd_whois);
	signal_add("dcc destroyed", (SIGNAL_FUNC) sig_dcc_destroyed);
	signal_add("ctcp msg dcc chat", (SIGNAL_FUNC) ctcp_msg_dcc_chat);
	signal_add_first("dcc chat message", (SIGNAL_FUNC) dcc_chat_msg);
	signal_add("dcc ctcp dcc", (SIGNAL_FUNC) dcc_ctcp_redirect);
	signal_add("dcc reply dcc", (SIGNAL_FUNC) dcc_ctcp_reply_redirect);
	signal_add("ctcp reply dcc reject", (SIGNAL_FUNC) ctcp_reply_dcc_reject);
	signal_add("event nick", (SIGNAL_FUNC) event_nick);
}

void dcc_chat_deinit(void)
{
        dcc_unregister_type("CHAT");
	command_unbind("msg", (SIGNAL_FUNC) cmd_msg);
	command_unbind("me", (SIGNAL_FUNC) cmd_me);
	command_unbind("action", (SIGNAL_FUNC) cmd_action);
	command_unbind("ctcp", (SIGNAL_FUNC) cmd_ctcp);
	command_unbind("dcc chat", (SIGNAL_FUNC) cmd_dcc_chat);
	command_unbind("mircdcc", (SIGNAL_FUNC) cmd_mircdcc);
	command_unbind("dcc close", (SIGNAL_FUNC) cmd_dcc_close);
	command_unbind("whois", (SIGNAL_FUNC) cmd_whois);
	signal_remove("dcc destroyed", (SIGNAL_FUNC) sig_dcc_destroyed);
	signal_remove("ctcp msg dcc chat", (SIGNAL_FUNC) ctcp_msg_dcc_chat);
	signal_remove("dcc chat message", (SIGNAL_FUNC) dcc_chat_msg);
	signal_remove("dcc ctcp dcc", (SIGNAL_FUNC) dcc_ctcp_redirect);
	signal_remove("dcc reply dcc", (SIGNAL_FUNC) dcc_ctcp_reply_redirect);
	signal_remove("ctcp reply dcc reject", (SIGNAL_FUNC) ctcp_reply_dcc_reject);
	signal_remove("event nick", (SIGNAL_FUNC) event_nick);
}
