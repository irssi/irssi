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
#include "./module-formats.h"
#include "signals.h"
#include "commands.h"
#include "network.h"

#include "levels.h"
#include "irc.h"
#include "channels.h"

#include "irc/dcc/dcc.h"

#include "windows.h"

static void dcc_connected(DCC_REC *dcc)
{
    gchar *str;

    g_return_if_fail(dcc != NULL);

    switch (dcc->dcc_type)
    {
        case DCC_TYPE_CHAT:
            printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_CHAT_CONNECTED,
                        dcc->nick, dcc->addrstr, dcc->port);

            str = g_strconcat("=", dcc->nick, NULL);
	    /*FIXME: dcc_chat_create(dcc->server, str, FALSE);*/
            g_free(str);
            break;
        case DCC_TYPE_SEND:
            printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_SEND_CONNECTED,
                        dcc->arg, dcc->nick, dcc->addrstr, dcc->port);
            break;
        case DCC_TYPE_GET:
            printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_GET_CONNECTED,
                        dcc->arg, dcc->nick, dcc->addrstr, dcc->port);
            break;
    }
}

static void dcc_rejected(DCC_REC *dcc)
{
    g_return_if_fail(dcc != NULL);

    printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_CLOSE,
                dcc_type2str(dcc->dcc_type), dcc->nick, dcc->arg);
}

static void dcc_closed(DCC_REC *dcc)
{
    time_t secs;
    gdouble kbs;

    g_return_if_fail(dcc != NULL);

    secs = dcc->starttime == 0 ? -1 : time(NULL)-dcc->starttime;
    kbs = (gdouble) (dcc->transfd-dcc->skipped) / (secs == 0 ? 1 : secs) / 1024.0;

    switch (dcc->dcc_type)
    {
        case DCC_TYPE_CHAT:
            {
                /* nice kludge :) if connection was lost, close the channel.
                   after closed channel (can be done with /unquery too)
                   prints the disconnected-text.. */
                CHANNEL_REC *channel;
                gchar *str;

                str = g_strdup_printf("=%s", dcc->nick);
                printformat(dcc->server, str, MSGLEVEL_DCC,
                            IRCTXT_DCC_CHAT_DISCONNECTED, dcc->nick);

                channel = channel_find(dcc->server, str);
                if (channel != NULL)
                    channel_destroy(channel);
                g_free(str);
            }
            break;
        case DCC_TYPE_SEND:
            if (secs == -1)
            {
                /* aborted */
                printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_SEND_ABORTED,
                            dcc->arg, dcc->nick);
            }
            else
            {
                printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_SEND_COMPLETE,
                            dcc->arg, dcc->transfd/1024, dcc->nick, (glong) secs, kbs);
            }
            break;
        case DCC_TYPE_GET:
            if (secs == -1)
            {
                /* aborted */
                printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_GET_ABORTED,
                            dcc->arg, dcc->nick);
            }
            else
            {
                printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_GET_COMPLETE,
                            dcc->arg, dcc->transfd/1024, dcc->nick, (glong) secs, kbs);
            }
            break;
    }
}

static void dcc_chat_in_action(gchar *msg, DCC_REC *dcc)
{
    gchar *sender;

    g_return_if_fail(dcc != NULL);
    g_return_if_fail(msg != NULL);

    sender = g_strconcat("=", dcc->nick, NULL);
    printformat(NULL, sender, MSGLEVEL_DCC,
                IRCTXT_ACTION_DCC, dcc->nick, msg);
    g_free(sender);
}

static void dcc_chat_ctcp(gchar *msg, DCC_REC *dcc)
{
    gchar *sender;

    g_return_if_fail(dcc != NULL);
    g_return_if_fail(msg != NULL);

    sender = g_strconcat("=", dcc->nick, NULL);
    printformat(NULL, sender, MSGLEVEL_DCC, IRCTXT_DCC_CTCP, dcc->nick, msg);
    g_free(sender);
}

static void dcc_chat_msg(DCC_REC *dcc, gchar *msg)
{
    gchar *nick;

    g_return_if_fail(dcc != NULL);
    g_return_if_fail(msg != NULL);

    nick = g_strconcat("=", dcc->nick, NULL);
    printformat(NULL, nick, MSGLEVEL_DCC, IRCTXT_DCC_MSG, dcc->nick, msg);
    g_free(nick);
}

static void dcc_request(DCC_REC *dcc)
{
    g_return_if_fail(dcc != NULL);

    switch (dcc->dcc_type)
    {
        case DCC_TYPE_CHAT:
            printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_CHAT,
                        dcc->nick, dcc->addrstr, dcc->port);
            break;
        case DCC_TYPE_GET:
            printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_SEND,
                        dcc->nick, dcc->addrstr, dcc->port, dcc->arg, dcc->size);
            break;
    }
}

static void dcc_error_connect(DCC_REC *dcc)
{
    g_return_if_fail(dcc != NULL);

    printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_CONNECT_ERROR, dcc->addrstr, dcc->port);
}

static void dcc_error_file_create(DCC_REC *dcc, gchar *fname)
{
    g_return_if_fail(dcc != NULL);

    printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_CANT_CREATE, fname);
}

static void dcc_error_file_not_found(gchar *nick, gchar *fname)
{
    g_return_if_fail(nick != NULL);
    g_return_if_fail(fname != NULL);

    printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_SEND_FILE_NOT_FOUND, fname);
}

static void dcc_error_get_not_found(gchar *nick)
{
    g_return_if_fail(nick != NULL);

    printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_GET_NOT_FOUND, nick);
}

static void dcc_error_send_exists(gchar *nick, gchar *fname)
{
    g_return_if_fail(nick != NULL);
    g_return_if_fail(fname != NULL);

    printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_SEND_EXISTS, fname, nick);
}

static void dcc_error_unknown_type(gchar *type)
{
    g_return_if_fail(type != NULL);

    printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_UNKNOWN_TYPE, type);
}

static void dcc_error_close_not_found(gchar *type, gchar *nick, gchar *fname)
{
    g_return_if_fail(type != NULL);
    g_return_if_fail(nick != NULL);
    g_return_if_fail(fname != NULL);

    if (fname == '\0') fname = "(ANY)";
    switch (dcc_str2type(type))
    {
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

static void dcc_unknown_ctcp(gchar *data, gchar *sender)
{
    gchar *params, *type, *args;

    g_return_if_fail(data != NULL);

    params = cmd_get_params(data, 2 | PARAM_FLAG_GETREST, &type, &args);
    printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_UNKNOWN_CTCP, type, sender, args);
    g_free(params);
}

static void dcc_unknown_reply(gchar *data, gchar *sender)
{
    gchar *params, *type, *args;

    g_return_if_fail(data != NULL);

    params = cmd_get_params(data, 2 | PARAM_FLAG_GETREST, &type, &args);
    printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_UNKNOWN_REPLY, type, sender, args);
    g_free(params);
}

static void dcc_chat_write(gchar *data)
{
    DCC_REC *dcc;
    gchar *params, *text, *target;

    g_return_if_fail(data != NULL);

    params = cmd_get_params(data, 2 | PARAM_FLAG_GETREST, &target, &text);

    if (*target == '=')
    {
        /* dcc msg */
        dcc = dcc_find_item(DCC_TYPE_CHAT, target+1, NULL);
        if (dcc == NULL)
        {
            printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
                        IRCTXT_DCC_CHAT_NOT_FOUND, target+1);
            return;
        }

        printformat(NULL, target, MSGLEVEL_DCC, IRCTXT_OWN_DCC, target+1, text);
    }

    g_free(params);
}

static void dcc_chat_out_me(gchar *data, SERVER_REC *server, WI_IRC_REC *item)
{
	DCC_REC *dcc;

	g_return_if_fail(data != NULL);

	dcc = irc_item_dcc_chat(item);
	if (dcc == NULL) return;

        printformat(NULL, item->name, MSGLEVEL_DCC,
                    IRCTXT_OWN_DCC_ME, dcc->mynick, data);
}

static void dcc_chat_out_action(const char *data, SERVER_REC *server, WI_IRC_REC *item)
{
	char *params, *target, *text;
	DCC_REC *dcc;

	g_return_if_fail(data != NULL);

	if (*data != '=') {
		/* handle only DCC actions */
		return;
	}

	params = cmd_get_params(data, 3 | PARAM_FLAG_GETREST, &target, &text);
	if (*target == '\0' || *text == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	dcc = dcc_find_item(DCC_TYPE_CHAT, target+1, NULL);
	if (dcc == NULL){
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			    IRCTXT_DCC_CHAT_NOT_FOUND, target+1);
	} else {
		printformat(NULL, item->name, MSGLEVEL_DCC,
			    IRCTXT_OWN_DCC_ME, dcc->mynick, text);
	}
	g_free(params);
}

static void dcc_chat_out_ctcp(gchar *data, SERVER_REC *server)
{
	char *params, *target, *ctcpcmd, *ctcpdata;
	DCC_REC *dcc;

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
	if (dcc == NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			    IRCTXT_DCC_CHAT_NOT_FOUND, target+1);
	} else {
		g_strup(ctcpcmd);
		printformat(server, target, MSGLEVEL_DCC, IRCTXT_OWN_DCC_CTCP,
			    target, ctcpcmd, ctcpdata);
	}

	g_free(params);
}

static void cmd_dcc_list(gchar *data)
{
    GSList *tmp;
    time_t going;

    g_return_if_fail(data != NULL);

    printtext(NULL, NULL, MSGLEVEL_DCC, "%gDCC connections");
    for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next)
    {
        DCC_REC *dcc = tmp->data;

        going = time(NULL) - dcc->starttime;
        if (going == 0) going = 1; /* no division by zeros :) */

        if (dcc->dcc_type == DCC_TYPE_CHAT)
            printtext(NULL, NULL, MSGLEVEL_DCC, "%g %s %s", dcc->nick, dcc_type2str(dcc->dcc_type));
        else
            printtext(NULL, NULL, MSGLEVEL_DCC, "%g %s %s: %luk of %luk (%d%%) - %fkB/s - %s",
                      dcc->nick, dcc_type2str(dcc->dcc_type), dcc->transfd/1024, dcc->size/1024,
		      dcc->size == 0 ? 0 : (100*dcc->transfd/dcc->size),
		      (gdouble) (dcc->transfd-dcc->skipped)/going/1024, dcc->arg);
    }
}

static void dcc_chat_closed(WINDOW_REC *window, WI_IRC_REC *item)
{
	DCC_REC *dcc;

	dcc = irc_item_dcc_chat(item);
	if (dcc == NULL) return;

	/* check that we haven't got here from dcc_destroy() so we won't try to
	   close the dcc again.. */
	if (!dcc->destroyed) {
		/* DCC query window closed, close the dcc chat too. */
		dcc_destroy(dcc);
	}
}

void fe_dcc_init(void)
{
    signal_add("dcc connected", (SIGNAL_FUNC) dcc_connected);
    signal_add("dcc rejected", (SIGNAL_FUNC) dcc_rejected);
    signal_add("dcc closed", (SIGNAL_FUNC) dcc_closed);
    signal_add("dcc chat message", (SIGNAL_FUNC) dcc_chat_msg);
    signal_add("dcc ctcp action", (SIGNAL_FUNC) dcc_chat_in_action);
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
    command_bind("msg", NULL, (SIGNAL_FUNC) dcc_chat_write);
    command_bind("me", NULL, (SIGNAL_FUNC) dcc_chat_out_me);
    command_bind("action", NULL, (SIGNAL_FUNC) dcc_chat_out_action);
    command_bind("ctcp", NULL, (SIGNAL_FUNC) dcc_chat_out_ctcp);
    command_bind("dcc ", NULL, (SIGNAL_FUNC) cmd_dcc_list);
    command_bind("dcc list", NULL, (SIGNAL_FUNC) cmd_dcc_list);
    signal_add("window item remove", (SIGNAL_FUNC) dcc_chat_closed);
}

void fe_dcc_deinit(void)
{
    signal_remove("dcc connected", (SIGNAL_FUNC) dcc_connected);
    signal_remove("dcc rejected", (SIGNAL_FUNC) dcc_rejected);
    signal_remove("dcc closed", (SIGNAL_FUNC) dcc_closed);
    signal_remove("dcc chat message", (SIGNAL_FUNC) dcc_chat_msg);
    signal_remove("dcc ctcp action", (SIGNAL_FUNC) dcc_chat_in_action);
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
    command_unbind("msg", (SIGNAL_FUNC) dcc_chat_write);
    command_unbind("me", (SIGNAL_FUNC) dcc_chat_out_me);
    command_unbind("action", (SIGNAL_FUNC) dcc_chat_out_action);
    command_unbind("ctcp", (SIGNAL_FUNC) dcc_chat_out_ctcp);
    command_unbind("dcc ", (SIGNAL_FUNC) cmd_dcc_list);
    command_unbind("dcc list", (SIGNAL_FUNC) cmd_dcc_list);
    signal_remove("window item remove", (SIGNAL_FUNC) dcc_chat_closed);
}
