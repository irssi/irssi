/*
 fe-dcc.c : irssi

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
#include "settings.h"

#include "levels.h"
#include "irc.h"
#include "channels.h"
#include "irc-queries.h"

#include "irc/dcc/dcc.h"

#include "completion.h"
#include "themes.h"
#include "fe-windows.h"

#include "module-formats.h"
#include "printtext.h"
#include "fe-messages.h"

static int autocreate_dccquery;

static void dcc_connected(DCC_REC *dcc)
{
	char *sender;

	g_return_if_fail(dcc != NULL);

	switch (dcc->type) {
	case DCC_TYPE_CHAT:
		sender = g_strconcat("=", dcc->nick, NULL);
		printformat(dcc->server, NULL, MSGLEVEL_DCC, IRCTXT_DCC_CHAT_CONNECTED,
			    dcc->nick, dcc->addrstr, dcc->port);
		if (autocreate_dccquery && query_find(NULL, sender) == NULL)
			irc_query_create(dcc->server, sender, TRUE);
		g_free(sender);
		break;
	case DCC_TYPE_SEND:
		printformat(dcc->server, NULL, MSGLEVEL_DCC, IRCTXT_DCC_SEND_CONNECTED,
			    dcc->arg, dcc->nick, dcc->addrstr, dcc->port);
		break;
	case DCC_TYPE_GET:
		printformat(dcc->server, NULL, MSGLEVEL_DCC, IRCTXT_DCC_GET_CONNECTED,
			    dcc->arg, dcc->nick, dcc->addrstr, dcc->port);
		break;
	}
}

static void dcc_rejected(DCC_REC *dcc)
{
	g_return_if_fail(dcc != NULL);

	printformat(dcc->server, NULL, MSGLEVEL_DCC, IRCTXT_DCC_CLOSE,
		    dcc_type2str(dcc->type), dcc->nick, dcc->arg);
}

static void dcc_closed(DCC_REC *dcc)
{
	char *sender;
	double kbs;
	time_t secs;

	g_return_if_fail(dcc != NULL);

	secs = dcc->starttime == 0 ? -1 : time(NULL)-dcc->starttime;
	kbs = (double) (dcc->transfd-dcc->skipped) / (secs == 0 ? 1 : secs) / 1024.0;

	switch (dcc->type) {
	case DCC_TYPE_CHAT:
		sender = g_strconcat("=", dcc->nick, NULL);
		printformat(dcc->server, NULL, MSGLEVEL_DCC,
			    IRCTXT_DCC_CHAT_DISCONNECTED, dcc->nick);
		g_free(sender);
		break;
	case DCC_TYPE_SEND:
		if (secs == -1) {
			/* aborted */
			printformat(dcc->server, NULL, MSGLEVEL_DCC, IRCTXT_DCC_SEND_ABORTED,
				    dcc->arg, dcc->nick);
		} else {
			printformat(dcc->server, NULL, MSGLEVEL_DCC, IRCTXT_DCC_SEND_COMPLETE,
				    dcc->arg, dcc->transfd/1024, dcc->nick, (long) secs, kbs);
		}
		break;
	case DCC_TYPE_GET:
		if (secs == -1) {
			/* aborted */
			printformat(dcc->server, NULL, MSGLEVEL_DCC, IRCTXT_DCC_GET_ABORTED,
				    dcc->arg, dcc->nick);
		} else {
			printformat(dcc->server, NULL, MSGLEVEL_DCC, IRCTXT_DCC_GET_COMPLETE,
				    dcc->arg, dcc->transfd/1024, dcc->nick, (long) secs, kbs);
		}
		break;
	}
}

static void dcc_chat_action(const char *msg, DCC_REC *dcc)
{
	char *sender;

	g_return_if_fail(dcc != NULL);
	g_return_if_fail(msg != NULL);

	sender = g_strconcat("=", dcc->nick, NULL);
	printformat(NULL, sender, MSGLEVEL_DCCMSGS,
		    IRCTXT_ACTION_DCC, dcc->nick, msg);
	g_free(sender);
}

static void dcc_chat_ctcp(const char *msg, DCC_REC *dcc)
{
	char *sender;

	g_return_if_fail(dcc != NULL);
	g_return_if_fail(msg != NULL);

	sender = g_strconcat("=", dcc->nick, NULL);
	printformat(NULL, sender, MSGLEVEL_DCC, IRCTXT_DCC_CTCP, dcc->nick, msg);
	g_free(sender);
}

static void dcc_chat_msg(DCC_REC *dcc, const char *msg)
{
	char *sender, *freemsg;

	g_return_if_fail(dcc != NULL);
	g_return_if_fail(msg != NULL);

	if (settings_get_bool("emphasis"))
		msg = freemsg = expand_emphasis(msg);
        else
		freemsg = NULL;

	sender = g_strconcat("=", dcc->nick, NULL);
	printformat(NULL, sender, MSGLEVEL_DCCMSGS,
		    query_find(NULL, sender) ? IRCTXT_DCC_MSG_QUERY :
		    IRCTXT_DCC_MSG, dcc->nick, msg);
	g_free(sender);
        g_free_not_null(freemsg);
}

static void dcc_request(DCC_REC *dcc)
{
	g_return_if_fail(dcc != NULL);

	switch (dcc->type) {
	case DCC_TYPE_CHAT:
		printformat(dcc->server, NULL, MSGLEVEL_DCC, IRCTXT_DCC_CHAT,
			    dcc->nick, dcc->addrstr, dcc->port);
		break;
	case DCC_TYPE_GET:
		printformat(dcc->server, NULL, MSGLEVEL_DCC, IRCTXT_DCC_SEND,
			    dcc->nick, dcc->addrstr, dcc->port, dcc->arg, dcc->size);
		break;
	}
}

static void dcc_error_connect(DCC_REC *dcc)
{
	g_return_if_fail(dcc != NULL);

        printformat(dcc->server, NULL, MSGLEVEL_DCC,
                    IRCTXT_DCC_CONNECT_ERROR, dcc->addrstr, dcc->port);
}

static void dcc_error_file_create(DCC_REC *dcc, const char *fname)
{
	g_return_if_fail(dcc != NULL);

	printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_CANT_CREATE, fname);
}

static void dcc_error_file_not_found(const char *nick, const char *fname)
{
	g_return_if_fail(nick != NULL);
	g_return_if_fail(fname != NULL);

	printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_SEND_FILE_NOT_FOUND, fname);
}

static void dcc_error_get_not_found(const char *nick)
{
	g_return_if_fail(nick != NULL);

	printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_GET_NOT_FOUND, nick);
}

static void dcc_error_send_exists(const char *nick, const char *fname)
{
	g_return_if_fail(nick != NULL);
	g_return_if_fail(fname != NULL);

	printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_SEND_EXISTS, fname, nick);
}

static void dcc_error_unknown_type(const char *type)
{
	g_return_if_fail(type != NULL);

	printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_UNKNOWN_TYPE, type);
}

static void dcc_error_close_not_found(const char *type, const char *nick, const char *fname)
{
	g_return_if_fail(type != NULL);
	g_return_if_fail(nick != NULL);
	g_return_if_fail(fname != NULL);

	if (fname == '\0') fname = "(ANY)";
	switch (dcc_str2type(type)) {
	case DCC_TYPE_CHAT:
		printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_CHAT_NOT_FOUND, nick);
		break;
	case DCC_TYPE_SEND:
		printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_SEND_NOT_FOUND, nick, fname);
		break;
	case DCC_TYPE_GET:
		printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_GET_NOT_FOUND, nick, fname);
		break;
	}
}

static void dcc_unknown_ctcp(const char *data, const char *sender)
{
	char *type, *args;
	void *free_arg;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST, &type, &args))
		return;
	printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_UNKNOWN_CTCP, type, sender, args);
	cmd_params_free(free_arg);
}

static void dcc_unknown_reply(const char *data, const char *sender)
{
	char *type, *args;
	void *free_arg;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST, &type, &args))
		return;
	printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_UNKNOWN_REPLY, type, sender, args);
	cmd_params_free(free_arg);
}

static void sig_dcc_destroyed(DCC_REC *dcc)
{
	QUERY_REC *query;
	char *nick;

	if (dcc->type != DCC_TYPE_CHAT)
		return;

        nick = g_strconcat("=", dcc->nick, NULL);
	query = query_find(NULL, nick);
	g_free(nick);

	if (query != NULL) {
		/* DCC chat closed, close the query with it. */
		if (dcc->connection_lost) query->unwanted = TRUE;
		query_destroy(query);
	}
}

static void sig_query_destroyed(QUERY_REC *query)
{
	DCC_REC *dcc;

	if (*query->name != '=')
		return;

	dcc = dcc_find_item(DCC_TYPE_CHAT, query->name+1, NULL);
	if (dcc != NULL && !dcc->destroyed) {
		/* DCC query window closed, close the dcc chat too. */
		signal_emit("dcc closed", 1, dcc);
		dcc_destroy(dcc);
	}
}

static void cmd_msg(const char *data)
{
	DCC_REC *dcc;
	char *text, *target;
	void *free_arg;

	g_return_if_fail(data != NULL);

	if (*data != '=') {
		/* handle only DCC messages */
		return;
	}

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST, &target, &text))
		return;

	dcc = dcc_find_item(DCC_TYPE_CHAT, target+1, NULL);
	if (dcc == NULL || dcc->sendbuf == NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			    IRCTXT_DCC_CHAT_NOT_FOUND, target+1);
	} else {
		printformat(NULL, target, MSGLEVEL_DCCMSGS | MSGLEVEL_NOHILIGHT,
			    query_find(NULL, target) ? IRCTXT_OWN_DCC_QUERY :
			    IRCTXT_OWN_DCC, dcc->mynick, target+1, text);
	}

	cmd_params_free(free_arg);
}

static void cmd_me(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	DCC_REC *dcc;

	g_return_if_fail(data != NULL);

	dcc = item_get_dcc(item);
	if (dcc == NULL) return;

        printformat(NULL, item->name, MSGLEVEL_DCCMSGS | MSGLEVEL_NOHILIGHT,
                    IRCTXT_OWN_DCC_ACTION, dcc->mynick, data);
}

static void cmd_action(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	DCC_REC *dcc;
	char *target, *text;
	void *free_arg;

	g_return_if_fail(data != NULL);

	if (*data != '=') {
		/* handle only DCC actions */
		return;
	}

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST, &target, &text))
		return;
	if (*target == '\0' || *text == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	dcc = dcc_find_item(DCC_TYPE_CHAT, target+1, NULL);
	if (dcc == NULL || dcc->sendbuf == NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			    IRCTXT_DCC_CHAT_NOT_FOUND, target+1);
	} else {
		printformat(NULL, target, MSGLEVEL_DCCMSGS | MSGLEVEL_NOHILIGHT,
			    IRCTXT_OWN_DCC_ACTION, dcc->mynick, text);
	}
	cmd_params_free(free_arg);
}

static void cmd_ctcp(const char *data, SERVER_REC *server)
{
	DCC_REC *dcc;
	char *target, *ctcpcmd, *ctcpdata;
	void *free_arg;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected) cmd_return_error(CMDERR_NOT_CONNECTED);

	if (!cmd_get_params(data, &free_arg, 3 | PARAM_FLAG_GETREST, &target, &ctcpcmd, &ctcpdata))
		return;
	if (*target == '\0' || *ctcpcmd == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	if (*target != '=') {
		/* handle only DCC CTCPs */
		cmd_params_free(free_arg);
		return;
	}

	dcc = dcc_find_item(DCC_TYPE_CHAT, target+1, NULL);
	if (dcc == NULL || dcc->sendbuf == NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			    IRCTXT_DCC_CHAT_NOT_FOUND, target+1);
	} else {
		g_strup(ctcpcmd);
		printformat(server, target, MSGLEVEL_DCC, IRCTXT_OWN_DCC_CTCP,
			    target, ctcpcmd, ctcpdata);
	}

	cmd_params_free(free_arg);
}

static void cmd_dcc_list(const char *data)
{
	GSList *tmp;
	time_t going;

	g_return_if_fail(data != NULL);

	printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_LIST_HEADER);
	for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next) {
		DCC_REC *dcc = tmp->data;

		going = time(NULL) - dcc->starttime;
		if (going == 0) going = 1; /* no division by zeros :) */

		if (dcc->type == DCC_TYPE_CHAT)
			printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_LIST_LINE_CHAT, dcc->nick, dcc_type2str(dcc->type));
		else
			printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_LIST_LINE_FILE,
				  dcc->nick, dcc_type2str(dcc->type), dcc->transfd/1024, dcc->size/1024,
				  dcc->size == 0 ? 0 : (int)((double)dcc->transfd/(double)dcc->size*100.0),
				  (double) (dcc->transfd-dcc->skipped)/going/1024, dcc->arg);
	}
	printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_LIST_FOOTER);
}

static void cmd_dcc(const char *data)
{
	if (*data == '\0') {
		cmd_dcc_list(data);
		signal_stop();
	}
}

static void sig_dcc_send_complete(GList **list, WINDOW_REC *window,
				  const char *word, const char *line, int *want_space)
{
	g_return_if_fail(list != NULL);
	g_return_if_fail(word != NULL);
	g_return_if_fail(line != NULL);

	if (*line == '\0' || strchr(line, ' ') != NULL)
		return;

	/* completing filename parameter for /DCC SEND */
	*list = filename_complete(word);
	if (*list != NULL) {
		*want_space = FALSE;
		signal_stop();
	}
}

static void read_settings(void)
{
	int level;

	level = level2bits(settings_get_str("autocreate_query_level"));
	autocreate_dccquery = (level & MSGLEVEL_DCCMSGS) != 0;
}

void fe_irc_dcc_init(void)
{
	signal_add("dcc connected", (SIGNAL_FUNC) dcc_connected);
	signal_add("dcc rejected", (SIGNAL_FUNC) dcc_rejected);
	signal_add("dcc closed", (SIGNAL_FUNC) dcc_closed);
	signal_add("dcc chat message", (SIGNAL_FUNC) dcc_chat_msg);
	signal_add("dcc ctcp action", (SIGNAL_FUNC) dcc_chat_action);
	signal_add("default dcc ctcp", (SIGNAL_FUNC) dcc_chat_ctcp);
	signal_add("dcc request", (SIGNAL_FUNC) dcc_request);
	signal_add("dcc error connect", (SIGNAL_FUNC) dcc_error_connect);
	signal_add("dcc error file create", (SIGNAL_FUNC) dcc_error_file_create);
	signal_add("dcc error file not found", (SIGNAL_FUNC) dcc_error_file_not_found);
	signal_add("dcc error get not found", (SIGNAL_FUNC) dcc_error_get_not_found);
	signal_add("dcc error send exists", (SIGNAL_FUNC) dcc_error_send_exists);
	signal_add("dcc error unknown type", (SIGNAL_FUNC) dcc_error_unknown_type);
	signal_add("dcc error close not found", (SIGNAL_FUNC) dcc_error_close_not_found);
	signal_add("dcc unknown ctcp", (SIGNAL_FUNC) dcc_unknown_ctcp);
	signal_add("dcc unknown reply", (SIGNAL_FUNC) dcc_unknown_reply);
	signal_add("dcc destroyed", (SIGNAL_FUNC) sig_dcc_destroyed);
	signal_add("query destroyed", (SIGNAL_FUNC) sig_query_destroyed);
	signal_add("complete command dcc send", (SIGNAL_FUNC) sig_dcc_send_complete);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
	command_bind("msg", NULL, (SIGNAL_FUNC) cmd_msg);
	command_bind("me", NULL, (SIGNAL_FUNC) cmd_me);
	command_bind("action", NULL, (SIGNAL_FUNC) cmd_action);
	command_bind("ctcp", NULL, (SIGNAL_FUNC) cmd_ctcp);
	command_bind("dcc", NULL, (SIGNAL_FUNC) cmd_dcc);
	command_bind("dcc list", NULL, (SIGNAL_FUNC) cmd_dcc_list);

	theme_register(fecommon_irc_dcc_formats);
	read_settings();
}

void fe_irc_dcc_deinit(void)
{
	theme_unregister();

	signal_remove("dcc connected", (SIGNAL_FUNC) dcc_connected);
	signal_remove("dcc rejected", (SIGNAL_FUNC) dcc_rejected);
	signal_remove("dcc closed", (SIGNAL_FUNC) dcc_closed);
	signal_remove("dcc chat message", (SIGNAL_FUNC) dcc_chat_msg);
	signal_remove("dcc ctcp action", (SIGNAL_FUNC) dcc_chat_action);
	signal_remove("default dcc ctcp", (SIGNAL_FUNC) dcc_chat_ctcp);
	signal_remove("dcc request", (SIGNAL_FUNC) dcc_request);
	signal_remove("dcc error connect", (SIGNAL_FUNC) dcc_error_connect);
	signal_remove("dcc error file create", (SIGNAL_FUNC) dcc_error_file_create);
	signal_remove("dcc error file not found", (SIGNAL_FUNC) dcc_error_file_not_found);
	signal_remove("dcc error get not found", (SIGNAL_FUNC) dcc_error_get_not_found);
	signal_remove("dcc error send exists", (SIGNAL_FUNC) dcc_error_send_exists);
	signal_remove("dcc error unknown type", (SIGNAL_FUNC) dcc_error_unknown_type);
	signal_remove("dcc error close not found", (SIGNAL_FUNC) dcc_error_close_not_found);
	signal_remove("dcc unknown ctcp", (SIGNAL_FUNC) dcc_unknown_ctcp);
	signal_remove("dcc unknown reply", (SIGNAL_FUNC) dcc_unknown_reply);
	signal_remove("dcc destroyed", (SIGNAL_FUNC) sig_dcc_destroyed);
	signal_remove("query destroyed", (SIGNAL_FUNC) sig_query_destroyed);
	signal_remove("complete command dcc send", (SIGNAL_FUNC) sig_dcc_send_complete);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
	command_unbind("msg", (SIGNAL_FUNC) cmd_msg);
	command_unbind("me", (SIGNAL_FUNC) cmd_me);
	command_unbind("action", (SIGNAL_FUNC) cmd_action);
	command_unbind("ctcp", (SIGNAL_FUNC) cmd_ctcp);
	command_unbind("dcc", (SIGNAL_FUNC) cmd_dcc);
	command_unbind("dcc list", (SIGNAL_FUNC) cmd_dcc_list);
}
