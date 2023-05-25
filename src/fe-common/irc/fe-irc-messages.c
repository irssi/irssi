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
#include <irssi/src/core/signals.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/core/channels.h>
#include <irssi/src/core/ignore.h>
#include <irssi/src/core/settings.h>

#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/irc/core/irc-channels.h>
#include <irssi/src/irc/core/irc-queries.h>

#include <irssi/src/fe-common/core/module-formats.h>
#include <irssi/src/fe-common/irc/module-formats.h>
#include <irssi/src/fe-common/core/printtext.h>
#include <irssi/src/fe-common/core/fe-messages.h>

#include <irssi/src/fe-common/core/fe-queries.h>
#include <irssi/src/fe-common/core/hilight-text.h>
#include <irssi/src/fe-common/core/window-items.h>
#include <irssi/src/fe-common/irc/fe-irc-channels.h>
#include <irssi/src/fe-common/irc/fe-irc-server.h>

static void sig_message_own_public(SERVER_REC *server, const char *msg,
				   const char *target, const char *origtarget)
{
	const char *oldtarget;
	char *nickmode;

	if (!IS_IRC_SERVER(server))
		return;
	oldtarget = target;
	target = fe_channel_skip_prefix(IRC_SERVER(server), target);
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

/* received msg to all ops in channel.
   TODO: this code is a duplication of sig_message_public */
static void sig_message_irc_op_public(SERVER_REC *server, const char *msg,
				      const char *nick, const char *address,
				      const char *target)
{
	CHANNEL_REC *chanrec;
	char *nickmode, *optarget, *prefix, *color, *freemsg = NULL;
	const char *cleantarget;
	int for_me, level;
	HILIGHT_REC *hilight;
	TEXT_DEST_REC dest;

	/* only skip here so the difference can be stored in prefix */
	cleantarget = fe_channel_skip_prefix(IRC_SERVER(server), target);
	prefix = g_strndup(target, cleantarget - target);

	/* and clean the rest here */
	cleantarget = get_visible_target(IRC_SERVER(server), cleantarget);

	chanrec = channel_find(server, cleantarget);

	nickmode = channel_get_nickmode(chanrec, nick);

	optarget = g_strconcat(prefix, cleantarget, NULL);

	/* Check for hilights */
	for_me = !settings_get_bool("hilight_nick_matches") ? FALSE :
		!settings_get_bool("hilight_nick_matches_everywhere") ?
		nick_match_msg(chanrec, msg, server->nick) :
		nick_match_msg_everywhere(chanrec, msg, server->nick);
	hilight = for_me ? NULL :
		hilight_match_nick(server, cleantarget, nick, address, MSGLEVEL_PUBLIC, msg);
	color = (hilight == NULL) ? NULL : hilight_get_color(hilight);

	level = MSGLEVEL_PUBLIC;
	if (for_me)
		level |= MSGLEVEL_HILIGHT;

	if (ignore_check_plus(server, nick, address, cleantarget, msg, &level, TRUE)) {
		g_free(nickmode);
		g_free(color);
		g_free(optarget);
		g_free(prefix);
		return;
	}

	if (level & MSGLEVEL_NOHILIGHT) {
		for_me = FALSE;
		g_free_and_null(color);
		level &= ~MSGLEVEL_HILIGHT;
	}

	if (settings_get_bool("emphasis"))
		msg = freemsg = expand_emphasis((WI_ITEM_REC *) chanrec, msg);

	if (color != NULL) {
		format_create_dest(&dest, server, cleantarget, level, NULL);
		dest.address = address;
		dest.nick = nick;
		hilight_update_text_dest(&dest,hilight);
		printformat_module_dest("fe-common/core", &dest,
			TXT_PUBMSG_HILIGHT_CHANNEL,
			color, nick, optarget, msg, nickmode);
	} else {
		printformat_module("fe-common/core", server, cleantarget, level,
			for_me ? TXT_PUBMSG_ME_CHANNEL : TXT_PUBMSG_CHANNEL,
			nick, optarget, msg, nickmode);
	}

	g_free(nickmode);
	g_free(freemsg);
	g_free(color);
	g_free(optarget);
	g_free(prefix);
}

static void sig_message_own_wall(SERVER_REC *server, const char *msg,
				 const char *target)
{
        char *nickmode, *optarget;

	nickmode = channel_get_nickmode(channel_find(server, target),
					server->nick);

	/* this is always @, skip_prefix is not needed here */
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
	target = fe_channel_skip_prefix(IRC_SERVER(server), target);
	if (server_ischannel(SERVER(server), target))
		item = channel_find(SERVER(server), target);
	else
		item = irc_query_find(server, target);

	if (settings_get_bool("emphasis"))
		msg = freemsg = expand_emphasis(item, msg);

	printformat(server, target,
		    MSGLEVEL_ACTIONS | MSGLEVEL_NOHILIGHT | MSGLEVEL_NO_ACT |
		    (server_ischannel(SERVER(server), target) ? MSGLEVEL_PUBLIC : MSGLEVEL_MSGS),
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
	int own = FALSE;

	oldtarget = target;
	target = fe_channel_skip_prefix(IRC_SERVER(server), target);

	level = MSGLEVEL_ACTIONS |
		(server_ischannel(SERVER(server), target) ? MSGLEVEL_PUBLIC : MSGLEVEL_MSGS);

	if (ignore_check_plus(SERVER(server), nick, address, target, msg, &level, TRUE))
		return;

	if (server_ischannel(SERVER(server), target)) {
		item = channel_find(SERVER(server), target);
	} else {
		own = (!g_strcmp0(nick, server->nick));
		item = privmsg_get_query(SERVER(server), own ? target : nick, FALSE, level);
	}

	if (settings_get_bool("emphasis"))
		msg = freemsg = expand_emphasis(item, msg);

	if (server_ischannel(SERVER(server), target)) {
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
		if (own) {
			/* own action bounced */
			printformat(server, target,
				    MSGLEVEL_ACTIONS | MSGLEVEL_MSGS,
				    item != NULL && oldtarget == target ? IRCTXT_OWN_ACTION : IRCTXT_OWN_ACTION_TARGET,
				    server->nick, msg, oldtarget);
		} else {
			/* private action */
			printformat(server, nick, MSGLEVEL_ACTIONS | MSGLEVEL_MSGS,
				    item == NULL ? IRCTXT_ACTION_PRIVATE :
				    IRCTXT_ACTION_PRIVATE_QUERY,
				    nick, address == NULL ? "" : address, msg);
		}
	}

	g_free_not_null(freemsg);
}

static char *notice_channel_context(SERVER_REC *server, const char *msg)
{
	if (!settings_get_bool("notice_channel_context"))
		return NULL;

	if (*msg == '[') {
		char *end, *channel;
		end = strpbrk(msg, " ,]");
		if (end != NULL && *end == ']') {
			channel = g_strndup(msg + 1, end - msg - 1);
			if (server_ischannel(server, channel)) {
				return channel;
			}
			g_free(channel);
		}
	}
	return NULL;
}

static void sig_message_own_notice(IRC_SERVER_REC *server, const char *msg, const char *target)
{
	gboolean is_public;
	const char *cleantarget;
	char *context_channel;

	cleantarget = fe_channel_skip_prefix(server, target);
	is_public = server_ischannel(SERVER(server), cleantarget);
	/* check if this is a cnotice */
	context_channel = is_public ? NULL : notice_channel_context((SERVER_REC *) server, msg);

	printformat(
	    server, context_channel != NULL ? context_channel : cleantarget,
	    (is_public || context_channel != NULL ? MSGLEVEL_PUBNOTICES : MSGLEVEL_NOTICES) |
	        MSGLEVEL_NOHILIGHT | MSGLEVEL_NO_ACT,
	    IRCTXT_OWN_NOTICE, target, msg);

	g_free(context_channel);
}

static void sig_message_irc_notice(SERVER_REC *server, const char *msg,
				   const char *nick, const char *address,
				   const char *target)
{
	const char *oldtarget;
	char *context_channel;
	int level;
	gboolean is_public;

	oldtarget = target;
	target = fe_channel_skip_prefix(IRC_SERVER(server), target);

	if (address == NULL || *address == '\0') {
		level = MSGLEVEL_SNOTES;
		/* notice from server */
		if (!ignore_check_plus(server, nick, "",
				       target, msg, &level, TRUE)) {
			printformat(server, target, level,
				    IRCTXT_NOTICE_SERVER, nick, msg);
		}
                return;
	}

	is_public = server_ischannel(SERVER(server), target);
	/* check if this is a cnotice */
	context_channel = is_public ? NULL : notice_channel_context(server, msg);
	level = (is_public || context_channel != NULL) ? MSGLEVEL_PUBNOTICES : MSGLEVEL_NOTICES;

	if (ignore_check_plus(server, nick, address, is_public ? target : context_channel, msg,
	                      &level, TRUE)) {
		g_free(context_channel);
		return;
	}

	if (is_public) {
		/* notice in some channel */
		char *nickmode;
		nickmode = channel_get_nickmode(channel_find(server, target), nick);
		printformat(server, target, level, IRCTXT_NOTICE_PUBLIC, nick, oldtarget, msg,
		            nickmode);
	} else {
		if (context_channel == NULL) {
			/* private notice */
			privmsg_get_query(SERVER(server), nick, FALSE, MSGLEVEL_NOTICES);
		}
		printformat(server, context_channel == NULL ? nick : context_channel, level,
		            IRCTXT_NOTICE_PRIVATE, nick, address, msg);
	}
	g_free(context_channel);
}

static void sig_message_own_ctcp(IRC_SERVER_REC *server, const char *cmd,
				 const char *data, const char *target)
{
	printformat(server, fe_channel_skip_prefix(server, target), MSGLEVEL_CTCPS |
		    MSGLEVEL_NOHILIGHT | MSGLEVEL_NO_ACT,
		    IRCTXT_OWN_CTCP, target, cmd, data);
}

static void sig_message_irc_ctcp(IRC_SERVER_REC *server, const char *cmd,
				 const char *data, const char *nick,
				 const char *addr, const char *target)
{
	const char *oldtarget;

	oldtarget = target;
	target = fe_channel_skip_prefix(server, target);
	printformat(server, server_ischannel(SERVER(server), target) ? target : nick, MSGLEVEL_CTCPS,
		    IRCTXT_CTCP_REQUESTED, nick, addr, cmd, data, oldtarget);
}

void fe_irc_messages_init(void)
{
	settings_add_bool("misc", "notice_channel_context", TRUE);

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
