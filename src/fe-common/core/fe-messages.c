/*
 fe-messages.c : irssi

    Copyright (C) 2000 Timo Sirainen

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
#include "module-formats.h"
#include "signals.h"
#include "commands.h"
#include "levels.h"
#include "special-vars.h"
#include "settings.h"

#include "window-items.h"
#include "fe-queries.h"
#include "channels.h"
#include "nicklist.h"
#include "hilight-text.h"

static char *get_nickmode(CHANNEL_REC *channel, const char *nick)
{
	NICK_REC *nickrec;

	g_return_val_if_fail(nick != NULL, NULL);

	nickrec = channel == NULL ? NULL :
		nicklist_find(channel, nick);
	return (nickrec == NULL || !settings_get_bool("show_nickmode")) ?
		"" : (nickrec->op ? "@" : (nickrec->voice ? "+" : " "));
}

static void sig_message_public(SERVER_REC *server, const char *msg,
			       const char *nick, const char *address,
			       const char *target)
{
	CHANNEL_REC *chanrec;
	const char *nickmode;
	int for_me, print_channel, level;
	char *color;

	chanrec = channel_find(server, target);
	for_me = nick_match_msg(server, msg, server->nick);
	color = for_me ? NULL :
		hilight_find_nick(target, nick, address, MSGLEVEL_PUBLIC, msg);

	print_channel = !window_item_is_active((WI_ITEM_REC *) chanrec);
	if (!print_channel && settings_get_bool("print_active_channel") &&
	    window_item_window((WI_ITEM_REC *) chanrec)->items->next != NULL)
		print_channel = TRUE;

	level = MSGLEVEL_PUBLIC |
		(color != NULL ? MSGLEVEL_HILIGHT :
		 (for_me ? MSGLEVEL_HILIGHT : MSGLEVEL_NOHILIGHT));

	nickmode = get_nickmode(chanrec, nick);
	if (!print_channel) {
		/* message to active channel in window */
		if (color != NULL) {
			/* highlighted nick */
			printformat(server, target, level,
				    IRCTXT_PUBMSG_HILIGHT,
				    color, nick, msg, nickmode);
		} else {
			printformat(server, target, level,
				    for_me ? IRCTXT_PUBMSG_ME : IRCTXT_PUBMSG,
				    nick, msg, nickmode);
		}
	} else {
		/* message to not existing/active channel */
		if (color != NULL) {
			/* highlighted nick */
			printformat(server, target, level,
				    IRCTXT_PUBMSG_HILIGHT_CHANNEL,
				    color, nick, target, msg, nickmode);
		} else {
			printformat(server, target, level,
				    for_me ? IRCTXT_PUBMSG_ME_CHANNEL :
				    IRCTXT_PUBMSG_CHANNEL,
				    nick, target, msg, nickmode);
		}
	}

	g_free_not_null(color);
}

static void sig_message_private(SERVER_REC *server, const char *msg,
				const char *nick, const char *address)
{
	QUERY_REC *query;

	query = privmsg_get_query(server, nick, FALSE, MSGLEVEL_MSGS);
	printformat(server, nick, MSGLEVEL_MSGS,
		    query == NULL ? IRCTXT_MSG_PRIVATE :
		    IRCTXT_MSG_PRIVATE_QUERY, nick, address, msg);
}

static void print_own_channel_message(SERVER_REC *server, CHANNEL_REC *channel,
				      const char *target, const char *msg)
{
	WINDOW_REC *window;
	const char *nickmode;
	int print_channel;

	nickmode = get_nickmode(channel, server->nick);

	window = channel == NULL ? NULL :
		window_item_window((WI_ITEM_REC *) channel);

	print_channel = window == NULL ||
		window->active != (WI_ITEM_REC *) channel;

	if (!print_channel && settings_get_bool("print_active_channel") &&
	    window != NULL && g_slist_length(window->items) > 1)
		print_channel = TRUE;

	if (!print_channel) {
		printformat(server, target, MSGLEVEL_PUBLIC | MSGLEVEL_NOHILIGHT | MSGLEVEL_NO_ACT,
			    IRCTXT_OWN_MSG, server->nick, msg, nickmode);
	} else {
		printformat(server, target, MSGLEVEL_PUBLIC | MSGLEVEL_NOHILIGHT | MSGLEVEL_NO_ACT,
			    IRCTXT_OWN_MSG_CHANNEL, server->nick, target, msg, nickmode);
	}
}

static void cmd_msg(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	GHashTable *optlist;
	CHANNEL_REC *channel;
	char *target, *msg, *freestr, *newtarget;
	void *free_arg;
	int free_ret;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_OPTIONS |
			    PARAM_FLAG_UNKNOWN_OPTIONS | PARAM_FLAG_GETREST,
			    "msg", &optlist, &target, &msg))
		return;
	if (*target == '\0' || *msg == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
	server = cmd_options_get_server("msg", optlist, server);

	free_ret = FALSE;
	if (strcmp(target, ",") == 0 || strcmp(target, ".") == 0) {
                /* , and . are handled specially */
		newtarget = parse_special(&target, server, item,
					  NULL, &free_ret, NULL);
		if (newtarget == NULL) {
			printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
				    *target == ',' ? IRCTXT_NO_MSGS_GOT :
				    IRCTXT_NO_MSGS_SENT);
			cmd_params_free(free_arg);
			signal_stop();
			return;
		}
		target = newtarget;
	} else if (strcmp(target, "*") == 0 && item != NULL) {
                /* * means active channel */
		target = item->name;
	}

	if (server == NULL || !server->connected)
		cmd_param_error(CMDERR_NOT_CONNECTED);
	channel = channel_find(server, target);

	freestr = !free_ret ? NULL : target;
	if (*target == '@' && server->ischannel(target[1])) {
		/* Hybrid 6 feature, send msg to all ops in channel
		   FIXME: this shouldn't really be here in core.. */
		target++;
	}

	if (server->ischannel(*target)) {
		/* msg to channel */
		print_own_channel_message(server, channel, target, msg);
	} else {
		/* private message */
		QUERY_REC *query;

		query = privmsg_get_query(server, target, TRUE, MSGLEVEL_MSGS);
		printformat(server, target, MSGLEVEL_MSGS |
			    MSGLEVEL_NOHILIGHT | MSGLEVEL_NO_ACT,
			    query == NULL ? IRCTXT_OWN_MSG_PRIVATE :
			    IRCTXT_OWN_MSG_PRIVATE_QUERY,
			    target, msg, server->nick);
	}
	g_free_not_null(freestr);

	cmd_params_free(free_arg);
}

void fe_messages_init(void)
{
	settings_add_bool("lookandfeel", "show_nickmode", TRUE);
	settings_add_bool("lookandfeel", "print_active_channel", FALSE);

	signal_add("message public", (SIGNAL_FUNC) sig_message_public);
	signal_add("message private", (SIGNAL_FUNC) sig_message_private);
	command_bind_last("msg", NULL, (SIGNAL_FUNC) cmd_msg);
}

void fe_messages_deinit(void)
{
	signal_remove("message public", (SIGNAL_FUNC) sig_message_public);
	signal_remove("message private", (SIGNAL_FUNC) sig_message_private);
	command_unbind("msg", (SIGNAL_FUNC) cmd_msg);
}
