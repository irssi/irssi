/*
 fe-dcc-chat-messages.c : irssi

    Copyright (C) 2002 Timo Sirainen

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
#include <irssi/src/core/levels.h>

#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/irc/core/irc-queries.h>
#include <irssi/src/irc/dcc/dcc-chat.h>
#include <irssi/src/core/ignore.h>

#include <irssi/src/fe-common/irc/dcc/module-formats.h>
#include <irssi/src/fe-common/core/printtext.h>

static void sig_message_dcc_own(CHAT_DCC_REC *dcc, const char *msg)
{
        TEXT_DEST_REC dest;
        QUERY_REC *query;
	char *tag;

	tag = g_strconcat("=", dcc->id, NULL);
	query = query_find(NULL, tag);

	format_create_dest_tag(&dest, dcc->server, dcc->servertag, tag,
			       MSGLEVEL_DCCMSGS | MSGLEVEL_NOHILIGHT |
			       MSGLEVEL_NO_ACT, NULL);

	printformat_dest(&dest, query != NULL ? IRCTXT_OWN_DCC_QUERY :
			 IRCTXT_OWN_DCC, dcc->mynick, dcc->id, msg);
        g_free(tag);
}

static void sig_message_dcc_own_action(CHAT_DCC_REC *dcc, const char *msg)
{
        TEXT_DEST_REC dest;
        QUERY_REC *query;
	char *tag;

	tag = g_strconcat("=", dcc->id, NULL);
	query = query_find(NULL, tag);

	format_create_dest_tag(&dest, dcc->server, dcc->servertag, tag,
			       MSGLEVEL_DCCMSGS | MSGLEVEL_ACTIONS |
			       MSGLEVEL_NOHILIGHT | MSGLEVEL_NO_ACT, NULL);

        printformat_dest(&dest, query != NULL ? IRCTXT_OWN_DCC_ACTION_QUERY :
			 IRCTXT_OWN_DCC_ACTION, dcc->mynick, dcc->id, msg);
        g_free(tag);
}

static void sig_message_dcc_own_ctcp(CHAT_DCC_REC *dcc, const char *cmd,
				     const char *data)
{
        TEXT_DEST_REC dest;
	char *tag;

	tag = g_strconcat("=", dcc->id, NULL);

	format_create_dest_tag(&dest, dcc->server, dcc->servertag, tag,
			       MSGLEVEL_DCC | MSGLEVEL_CTCPS |
			       MSGLEVEL_NOHILIGHT | MSGLEVEL_NO_ACT, NULL);

	printformat_dest(&dest, IRCTXT_OWN_DCC_CTCP, dcc->id, cmd, data);
        g_free(tag);
}

static void sig_message_dcc(CHAT_DCC_REC *dcc, const char *msg)
{
        TEXT_DEST_REC dest;
        QUERY_REC *query;
	char *tag;
	int level = MSGLEVEL_DCCMSGS;

	tag = g_strconcat("=", dcc->id, NULL);
	query = query_find(NULL, tag);

	ignore_check_plus(SERVER(dcc->server), tag, dcc->addrstr, NULL, msg,
			  &level, FALSE);

	format_create_dest_tag(&dest, dcc->server, dcc->servertag, tag,
			       level, NULL);

	printformat_dest(&dest, query != NULL ? IRCTXT_DCC_MSG_QUERY :
			 IRCTXT_DCC_MSG, dcc->id, msg);
        g_free(tag);
}

static void sig_message_dcc_action(CHAT_DCC_REC *dcc, const char *msg)
{
        TEXT_DEST_REC dest;
        QUERY_REC *query;
	char *tag;
	int level = MSGLEVEL_DCCMSGS | MSGLEVEL_ACTIONS;

	tag = g_strconcat("=", dcc->id, NULL);
	query = query_find(NULL, tag);

	ignore_check_plus(SERVER(dcc->server), tag, dcc->addrstr, NULL, msg,
			  &level, FALSE);

	format_create_dest_tag(&dest, dcc->server, dcc->servertag, tag,
			       level, NULL);

	printformat_dest(&dest, query != NULL ? IRCTXT_ACTION_DCC_QUERY :
			 IRCTXT_ACTION_DCC, dcc->id, msg);
	g_free(tag);
}

static void sig_message_dcc_ctcp(CHAT_DCC_REC *dcc, const char *cmd,
				 const char *data)
{
        TEXT_DEST_REC dest;
	char *tag;
	int level = MSGLEVEL_DCCMSGS | MSGLEVEL_CTCPS;

	tag = g_strconcat("=", dcc->id, NULL);

	ignore_check_plus(SERVER(dcc->server), tag, dcc->addrstr, NULL, cmd,
			  &level, FALSE);

	format_create_dest_tag(&dest, dcc->server, dcc->servertag, tag,
			       level, NULL);

	printformat_dest(&dest, IRCTXT_DCC_CTCP, dcc->id, cmd, data);
        g_free(tag);
}

void fe_dcc_chat_messages_init(void)
{
        signal_add("message dcc own", (SIGNAL_FUNC) sig_message_dcc_own);
        signal_add("message dcc own_action", (SIGNAL_FUNC) sig_message_dcc_own_action);
        signal_add("message dcc own_ctcp", (SIGNAL_FUNC) sig_message_dcc_own_ctcp);
        signal_add("message dcc", (SIGNAL_FUNC) sig_message_dcc);
        signal_add("message dcc action", (SIGNAL_FUNC) sig_message_dcc_action);
        signal_add("message dcc ctcp", (SIGNAL_FUNC) sig_message_dcc_ctcp);
}

void fe_dcc_chat_messages_deinit(void)
{
        signal_remove("message dcc own", (SIGNAL_FUNC) sig_message_dcc_own);
        signal_remove("message dcc own_action", (SIGNAL_FUNC) sig_message_dcc_own_action);
        signal_remove("message dcc own_ctcp", (SIGNAL_FUNC) sig_message_dcc_own_ctcp);
        signal_remove("message dcc", (SIGNAL_FUNC) sig_message_dcc);
        signal_remove("message dcc action", (SIGNAL_FUNC) sig_message_dcc_action);
        signal_remove("message dcc ctcp", (SIGNAL_FUNC) sig_message_dcc_ctcp);
}
