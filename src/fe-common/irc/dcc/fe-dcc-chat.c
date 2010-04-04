/*
 fe-dcc-chat.c : irssi

    Copyright (C) 1999-2002 Timo Sirainen

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
#include "signals.h"
#include "commands.h"
#include "levels.h"
#include "settings.h"
#include "misc.h"

#include "irc.h"
#include "irc-servers.h"
#include "irc-queries.h"
#include "dcc-chat.h"

#include "module-formats.h"
#include "printtext.h"
#include "fe-messages.h"

#include "chat-completion.h"

void fe_dcc_chat_messages_init(void);
void fe_dcc_chat_messages_deinit(void);

static void dcc_request(CHAT_DCC_REC *dcc)
{
        if (!IS_DCC_CHAT(dcc)) return;

	printformat(dcc->server, NULL, MSGLEVEL_DCC,
		    ischannel(*dcc->target) ? IRCTXT_DCC_CHAT_CHANNEL :
		    IRCTXT_DCC_CHAT, dcc->id, dcc->addrstr,
		    dcc->port, dcc->target);
}

static void dcc_connected(CHAT_DCC_REC *dcc)
{
	char *sender;

        if (!IS_DCC_CHAT(dcc)) return;

	sender = g_strconcat("=", dcc->id, NULL);
	printformat(dcc->server, NULL, MSGLEVEL_DCC,
		    IRCTXT_DCC_CHAT_CONNECTED,
		    dcc->id, dcc->addrstr, dcc->port);

	if (query_find(NULL, sender) == NULL) {
		int level = settings_get_level("autocreate_query_level");
		int autocreate_dccquery = (level & MSGLEVEL_DCCMSGS) != 0;

		if (!autocreate_dccquery)
			completion_last_message_add(sender);
		else
			irc_query_create(dcc->servertag, sender, TRUE);
	}
	g_free(sender);
}

static void dcc_closed(CHAT_DCC_REC *dcc)
{
	char *sender;

        if (!IS_DCC_CHAT(dcc)) return;

	sender = g_strconcat("=", dcc->id, NULL);
	printformat(dcc->server, NULL, MSGLEVEL_DCC,
		    IRCTXT_DCC_CHAT_DISCONNECTED, dcc->id);
	g_free(sender);
}

static void dcc_chat_msg(CHAT_DCC_REC *dcc, const char *msg)
{
        QUERY_REC *query;
	char *sender, *freemsg;

	g_return_if_fail(IS_DCC_CHAT(dcc));
	g_return_if_fail(msg != NULL);

	sender = g_strconcat("=", dcc->id, NULL);
        query = query_find(NULL, sender);

	if (settings_get_bool("emphasis"))
		msg = freemsg = expand_emphasis((WI_ITEM_REC *) query, msg);
        else
		freemsg = NULL;

	if (query == NULL)
		completion_last_message_add(sender);
	signal_emit("message dcc", 2, dcc, msg);

	g_free_not_null(freemsg);
	g_free(sender);
}

static void dcc_chat_action(CHAT_DCC_REC *dcc, const char *msg)
{
	char *sender;

	g_return_if_fail(IS_DCC_CHAT(dcc));
	g_return_if_fail(msg != NULL);

	sender = g_strconcat("=", dcc->id, NULL);
	if (query_find(NULL, sender) == NULL)
		completion_last_message_add(sender);

	signal_emit("message dcc action", 2, dcc, msg);
	g_free(sender);
}

static void dcc_chat_ctcp(CHAT_DCC_REC *dcc, const char *cmd, const char *data)
{
	g_return_if_fail(IS_DCC_CHAT(dcc));

	signal_emit("message dcc ctcp", 3, dcc, cmd, data);
}

static void dcc_error_ctcp(const char *type, const char *data,
                           const char *nick, const char *addr,
			   const char *target)
{
	printformat(NULL, NULL, MSGLEVEL_DCC,
                    IRCTXT_DCC_INVALID_CTCP, type, nick, addr, target);
}

static void dcc_unknown_ctcp(IRC_SERVER_REC *server, const char *data,
			     const char *nick, const char *addr,
			     const char *target, CHAT_DCC_REC *chat)
{
	char *type, *args;
	void *free_arg;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST,
			    &type, &args))
		return;

	printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_UNKNOWN_CTCP,
		    type, nick, args);
	cmd_params_free(free_arg);
}

static void dcc_unknown_reply(IRC_SERVER_REC *server, const char *data,
			      const char *nick)
{
	char *type, *args;
	void *free_arg;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST,
			    &type, &args))
		return;

	printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_UNKNOWN_REPLY,
		    type, nick, args);
	cmd_params_free(free_arg);
}

static void sig_dcc_destroyed(CHAT_DCC_REC *dcc)
{
	QUERY_REC *query;
	char *nick;

	if (!IS_DCC_CHAT(dcc)) return;

        nick = g_strconcat("=", dcc->id, NULL);
	query = query_find(NULL, nick);
	if (query != NULL) {
		/* DCC chat closed, close the query with it. */
		if (dcc->connection_lost) query->unwanted = TRUE;
		query_destroy(query);
	} else {
		/* remove nick from msg completion
		   since it won't work anymore */
		completion_last_message_remove(nick);
	}

	g_free(nick);
}

static void sig_query_destroyed(QUERY_REC *query)
{
	CHAT_DCC_REC *dcc;

	if (*query->name != '=')
		return;

	dcc = dcc_chat_find_id(query->name+1);
	if (dcc != NULL && !dcc->destroyed) {
		/* DCC query window closed, close the dcc chat too. */
		dcc_close(DCC(dcc));
	}
}

static void dcc_error_close_not_found(const char *type, const char *nick,
				      const char *fname)
{
	g_return_if_fail(type != NULL);
	g_return_if_fail(nick != NULL);
	if (g_ascii_strcasecmp(type, "CHAT") != 0) return;

	printformat(NULL, NULL, MSGLEVEL_DCC,
		    IRCTXT_DCC_CHAT_NOT_FOUND, nick);
}

static void sig_dcc_list_print(CHAT_DCC_REC *dcc)
{
	if (!IS_DCC_CHAT(dcc)) return;

	printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_LIST_LINE_CHAT,
		    dcc->id, "CHAT");
}

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
	if (strcmp(target, "*") == 0)
		dcc = item_get_dcc(item);
	else if (*target == '=')
		dcc = dcc_chat_find_id(target+1);
	else
		dcc = NULL;

	if (dcc == NULL && *target == '=') {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			    IRCTXT_DCC_CHAT_NOT_FOUND, target+1);
	} else if (dcc != NULL) {
		if (query_find(NULL, target) == NULL)
			completion_last_message_add(target);

		signal_emit("message dcc own", 2, dcc, text);
	}

	cmd_params_free(free_arg);
}

static void cmd_me(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	CHAT_DCC_REC *dcc;

	dcc = item_get_dcc(item);
	if (dcc != NULL)
		signal_emit("message dcc own_action", 2, dcc, data);
}

static void cmd_action(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	CHAT_DCC_REC *dcc;
	char *target, *text;
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
	if (dcc == NULL || dcc->sendbuf == NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			    IRCTXT_DCC_CHAT_NOT_FOUND, target+1);
	} else {
		if (query_find(NULL, target) == NULL)
			completion_last_message_add(target);

		signal_emit("message dcc own_action", 2, dcc, text);
	}
	cmd_params_free(free_arg);
}

static void cmd_ctcp(const char *data, SERVER_REC *server)
{
	CHAT_DCC_REC *dcc;
	char *target, *ctcpcmd, *ctcpdata;
	void *free_arg;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected)
		cmd_return_error(CMDERR_NOT_CONNECTED);

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
	if (dcc == NULL || dcc->sendbuf == NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			    IRCTXT_DCC_CHAT_NOT_FOUND, target+1);
	} else {
		ascii_strup(ctcpcmd);
		signal_emit("message dcc own_ctcp", 3, dcc, ctcpcmd, ctcpdata);
	}

	cmd_params_free(free_arg);
}

void fe_dcc_chat_init(void)
{
	fe_dcc_chat_messages_init();

	signal_add("dcc request", (SIGNAL_FUNC) dcc_request);
	signal_add("dcc connected", (SIGNAL_FUNC) dcc_connected);
	signal_add("dcc closed", (SIGNAL_FUNC) dcc_closed);
	signal_add("dcc chat message", (SIGNAL_FUNC) dcc_chat_msg);
	signal_add("dcc ctcp action", (SIGNAL_FUNC) dcc_chat_action);
	signal_add("default dcc ctcp", (SIGNAL_FUNC) dcc_chat_ctcp);
	signal_add("dcc error ctcp", (SIGNAL_FUNC) dcc_error_ctcp);
	signal_add("default ctcp msg dcc", (SIGNAL_FUNC) dcc_unknown_ctcp);
	signal_add("default ctcp reply dcc", (SIGNAL_FUNC) dcc_unknown_reply);
	signal_add("dcc destroyed", (SIGNAL_FUNC) sig_dcc_destroyed);
	signal_add("query destroyed", (SIGNAL_FUNC) sig_query_destroyed);
        signal_add("dcc list print", (SIGNAL_FUNC) sig_dcc_list_print);
	command_bind("msg", NULL, (SIGNAL_FUNC) cmd_msg);
	command_bind("me", NULL, (SIGNAL_FUNC) cmd_me);
	command_bind("action", NULL, (SIGNAL_FUNC) cmd_action);
	command_bind("ctcp", NULL, (SIGNAL_FUNC) cmd_ctcp);
	signal_add("dcc error close not found", (SIGNAL_FUNC) dcc_error_close_not_found);
}

void fe_dcc_chat_deinit(void)
{
	fe_dcc_chat_messages_deinit();

	signal_remove("dcc request", (SIGNAL_FUNC) dcc_request);
	signal_remove("dcc connected", (SIGNAL_FUNC) dcc_connected);
	signal_remove("dcc closed", (SIGNAL_FUNC) dcc_closed);
	signal_remove("dcc chat message", (SIGNAL_FUNC) dcc_chat_msg);
	signal_remove("dcc ctcp action", (SIGNAL_FUNC) dcc_chat_action);
	signal_remove("default dcc ctcp", (SIGNAL_FUNC) dcc_chat_ctcp);
	signal_remove("dcc error ctcp", (SIGNAL_FUNC) dcc_error_ctcp);
	signal_remove("default ctcp msg dcc", (SIGNAL_FUNC) dcc_unknown_ctcp);
	signal_remove("default ctcp reply dcc", (SIGNAL_FUNC) dcc_unknown_reply);
	signal_remove("dcc destroyed", (SIGNAL_FUNC) sig_dcc_destroyed);
	signal_remove("query destroyed", (SIGNAL_FUNC) sig_query_destroyed);
        signal_remove("dcc list print", (SIGNAL_FUNC) sig_dcc_list_print);
	command_unbind("msg", (SIGNAL_FUNC) cmd_msg);
	command_unbind("me", (SIGNAL_FUNC) cmd_me);
	command_unbind("action", (SIGNAL_FUNC) cmd_action);
	command_unbind("ctcp", (SIGNAL_FUNC) cmd_ctcp);
	signal_remove("dcc error close not found", (SIGNAL_FUNC) dcc_error_close_not_found);
}
