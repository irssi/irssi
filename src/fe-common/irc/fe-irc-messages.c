/*
 fe-irc-messages.c : irssi

    Copyright (C) 2001 Timo Sirainen

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
#include "levels.h"
#include "channels.h"
#include "ignore.h"
#include "settings.h"

#include "irc-servers.h"
#include "irc-channels.h"
#include "irc-queries.h"

#include "../core/module-formats.h"
#include "module-formats.h"
#include "printtext.h"
#include "fe-messages.h"

#include "fe-queries.h"
#include "window-items.h"

static const char *skip_target(IRC_SERVER_REC *server, const char *target)
{
	int i = 0;
	const char *val, *chars;

	/* Quick check */
	if (server == NULL || server->prefix[(int)(unsigned char)*target] == 0)
		return target;

	/* Hack: for bahamut 1.4 which sends neither STATUSMSG nor
	 * WALLCHOPS in 005, accept @#chan and @+#chan (but not +#chan) */
	val = g_hash_table_lookup(server->isupport, "STATUSMSG");
	if (val == NULL && *target != '@')
		return target;
	chars = val ? val : "@+";
	for(i = 0; target[i] != '\0'; i++) {
		if (strchr(chars, target[i]) == NULL)
			break;
	};

	if(ischannel(target[i]))
		target += i;

	return target;
}

static void sig_message_own_public(SERVER_REC *server, const char *msg,
				   const char *target, const char *origtarget)
{
	const char *oldtarget;
	char *nickmode;

	if (!IS_IRC_SERVER(server))
		return;
	oldtarget = target;
	target = skip_target(IRC_SERVER(server), target);
	if (target != oldtarget) {
		/* Hybrid 6 / Bahamut feature, send msg to all
		   ops / ops+voices in channel */
		nickmode = channel_get_nickmode(channel_find(server, target),
						server->nick);

		printformat_module("fe-common/core", server, target,
				   MSGLEVEL_PUBLIC | MSGLEVEL_NOHILIGHT |
				   MSGLEVEL_NO_ACT,
				   TXT_OWN_MSG_CHANNEL,
				   server->nick, oldtarget, msg, nickmode);
		g_free(nickmode);
                signal_stop();
	}
	
}

/* received msg to all ops in channel */
static void sig_message_irc_op_public(SERVER_REC *server, const char *msg,
				      const char *nick, const char *address,
				      const char *target)
{
	char *nickmode, *optarget;

	nickmode = channel_get_nickmode(channel_find(server, target),
					nick);

        optarget = g_strconcat("@", target, NULL);
	printformat_module("fe-common/core", server, target,
			   MSGLEVEL_PUBLIC,
			   TXT_PUBMSG_CHANNEL,
			   nick, optarget, msg, nickmode);
	g_free(nickmode);
        g_free(optarget);
}

static void sig_message_own_wall(SERVER_REC *server, const char *msg,
				 const char *target)
{
        char *nickmode, *optarget;

	nickmode = channel_get_nickmode(channel_find(server, target),
					server->nick);

        optarget = g_strconcat("@", target, NULL);
	printformat_module("fe-common/core", server, target,
			   MSGLEVEL_PUBLIC | MSGLEVEL_NOHILIGHT |
			   MSGLEVEL_NO_ACT,
			   TXT_OWN_MSG_CHANNEL,
			   server->nick, optarget, msg, nickmode);
	g_free(nickmode);
        g_free(optarget);
}

static void sig_message_own_action(IRC_SERVER_REC *server, const char *msg,
                                   const char *target)
{
	void *item;
	const char *oldtarget;
        char *freemsg = NULL;

	oldtarget = target;
	target = skip_target(IRC_SERVER(server), target);
        if (ischannel(*target))
		item = irc_channel_find(server, target);
	else
		item = irc_query_find(server, target);

	if (settings_get_bool("emphasis"))
		msg = freemsg = expand_emphasis(item, msg);

	printformat(server, target,
		    MSGLEVEL_ACTIONS | MSGLEVEL_NOHILIGHT | MSGLEVEL_NO_ACT |
		    (ischannel(*target) ? MSGLEVEL_PUBLIC : MSGLEVEL_MSGS),
		    item != NULL && oldtarget == target ? IRCTXT_OWN_ACTION : IRCTXT_OWN_ACTION_TARGET,
		    server->nick, msg, oldtarget);
        g_free_not_null(freemsg);
}

static void sig_message_irc_action(IRC_SERVER_REC *server, const char *msg,
				   const char *nick, const char *address,
				   const char *target)
{
	void *item;
	const char *oldtarget;
        char *freemsg = NULL;
	int level;

	oldtarget = target;
	target = skip_target(IRC_SERVER(server), target);

	level = MSGLEVEL_ACTIONS |
		(ischannel(*target) ? MSGLEVEL_PUBLIC : MSGLEVEL_MSGS);

	if (ignore_check(SERVER(server), nick, address, target, msg, level))
		return;

	if (ischannel(*target))
		item = irc_channel_find(server, target);
        else
		item = privmsg_get_query(SERVER(server), nick, FALSE, level);

	if (settings_get_bool("emphasis"))
		msg = freemsg = expand_emphasis(item, msg);

	if (ischannel(*target)) {
		/* channel action */
		if (window_item_is_active(item) && target == oldtarget) {
			/* message to active channel in window */
			printformat(server, target, level,
				    IRCTXT_ACTION_PUBLIC, nick, msg);
		} else {
			/* message to not existing/active channel, or to @/+ */
			printformat(server, target, level,
				    IRCTXT_ACTION_PUBLIC_CHANNEL,
				    nick, oldtarget, msg);
		}
	} else {
		/* private action */
		printformat(server, nick, MSGLEVEL_ACTIONS | MSGLEVEL_MSGS,
			    item == NULL ? IRCTXT_ACTION_PRIVATE :
			    IRCTXT_ACTION_PRIVATE_QUERY,
			    nick, address == NULL ? "" : address, msg);
	}
	
	g_free_not_null(freemsg);
}

static void sig_message_own_notice(IRC_SERVER_REC *server, const char *msg,
				   const char *target)
{
	printformat(server, skip_target(server, target), MSGLEVEL_NOTICES |
		    MSGLEVEL_NOHILIGHT | MSGLEVEL_NO_ACT,
		    IRCTXT_OWN_NOTICE, target, msg);
}

static void sig_message_irc_notice(SERVER_REC *server, const char *msg,
				   const char *nick, const char *address,
				   const char *target)
{
	const char *oldtarget;
	
	oldtarget = target;
	target = skip_target(IRC_SERVER(server), target);

	if (address == NULL || *address == '\0') {
		/* notice from server */
		if (!ignore_check(server, nick, "",
				  target, msg, MSGLEVEL_SNOTES)) {
			printformat(server, target, MSGLEVEL_SNOTES,
				    IRCTXT_NOTICE_SERVER, nick, msg);
		}
                return;
	}

	if (ignore_check(server, nick, address,
			 ischannel(*target) ? target : NULL,
			 msg, MSGLEVEL_NOTICES))
		return;

        if (ischannel(*target)) {
		/* notice in some channel */
		printformat(server, target, MSGLEVEL_NOTICES,
			    IRCTXT_NOTICE_PUBLIC, nick, oldtarget, msg);
	} else {
		/* private notice */
		privmsg_get_query(SERVER(server), nick, FALSE,
				  MSGLEVEL_NOTICES);
		printformat(server, nick, MSGLEVEL_NOTICES,
			    IRCTXT_NOTICE_PRIVATE, nick, address, msg);
	}
}

static void sig_message_own_ctcp(IRC_SERVER_REC *server, const char *cmd,
				 const char *data, const char *target)
{
	printformat(server, skip_target(server, target), MSGLEVEL_CTCPS |
		    MSGLEVEL_NOHILIGHT | MSGLEVEL_NO_ACT,
		    IRCTXT_OWN_CTCP, target, cmd, data);
}

static void sig_message_irc_ctcp(IRC_SERVER_REC *server, const char *cmd,
				 const char *data, const char *nick,
				 const char *addr, const char *target)
{
	const char *oldtarget;

	oldtarget = target;
	target = skip_target(server, target);
	printformat(server, ischannel(*target) ? target : nick, MSGLEVEL_CTCPS,
		    IRCTXT_CTCP_REQUESTED, nick, addr, cmd, data, oldtarget);
}

void fe_irc_messages_init(void)
{
        signal_add_last("message own_public", (SIGNAL_FUNC) sig_message_own_public);
        signal_add_last("message irc op_public", (SIGNAL_FUNC) sig_message_irc_op_public);
        signal_add_last("message irc own_wall", (SIGNAL_FUNC) sig_message_own_wall);
        signal_add_last("message irc own_action", (SIGNAL_FUNC) sig_message_own_action);
        signal_add_last("message irc action", (SIGNAL_FUNC) sig_message_irc_action);
        signal_add_last("message irc own_notice", (SIGNAL_FUNC) sig_message_own_notice);
        signal_add_last("message irc notice", (SIGNAL_FUNC) sig_message_irc_notice);
        signal_add_last("message irc own_ctcp", (SIGNAL_FUNC) sig_message_own_ctcp);
        signal_add_last("message irc ctcp", (SIGNAL_FUNC) sig_message_irc_ctcp);
}

void fe_irc_messages_deinit(void)
{
        signal_remove("message own_public", (SIGNAL_FUNC) sig_message_own_public);
        signal_remove("message irc op_public", (SIGNAL_FUNC) sig_message_irc_op_public);
        signal_remove("message irc own_wall", (SIGNAL_FUNC) sig_message_own_wall);
        signal_remove("message irc own_action", (SIGNAL_FUNC) sig_message_own_action);
        signal_remove("message irc action", (SIGNAL_FUNC) sig_message_irc_action);
        signal_remove("message irc own_notice", (SIGNAL_FUNC) sig_message_own_notice);
        signal_remove("message irc notice", (SIGNAL_FUNC) sig_message_irc_notice);
        signal_remove("message irc own_ctcp", (SIGNAL_FUNC) sig_message_own_ctcp);
        signal_remove("message irc ctcp", (SIGNAL_FUNC) sig_message_irc_ctcp);
}
