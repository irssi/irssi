/*
 fe-irc-commands.c : irssi

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
#include "module-formats.h"
#include "signals.h"
#include "commands.h"
#include "special-vars.h"
#include "settings.h"

#include "levels.h"
#include "irc.h"
#include "server.h"
#include "mode-lists.h"
#include "nicklist.h"
#include "channels.h"
#include "query.h"

#include "fe-query.h"
#include "windows.h"
#include "window-items.h"

static void cmd_unquery(const char *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	QUERY_REC *query;

	g_return_if_fail(data != NULL);

	if (*data == '\0') {
		/* remove current query */
		query = irc_item_query(item);
		if (query == NULL) return;
	} else {
		query = query_find(server, data);
		if (query == NULL) {
			printformat(server, NULL, MSGLEVEL_CLIENTERROR, IRCTXT_NO_QUERY, data);
			return;
		}
	}

	query_destroy(query);
}

static void cmd_query(gchar *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	WINDOW_REC *window;
	QUERY_REC *query;

	g_return_if_fail(data != NULL);

	if (*data == '\0') {
		/* remove current query */
		cmd_unquery("", server, item);
		return;
	}

	if (*data != '=' && (server == NULL || !server->connected))
		cmd_return_error(CMDERR_NOT_CONNECTED);

	query = query_find(server, data);
	if (query != NULL) {
		/* query already existed - change to query window */
		window = window_item_window((WI_ITEM_REC *) query);
		g_return_if_fail(window != NULL);

		window_set_active(window);
		window_item_set_active(window, (WI_ITEM_REC *) query);
		return;
	}

	query_create(server, data, FALSE);
}

static void cmd_msg(gchar *data, IRC_SERVER_REC *server, WI_ITEM_REC *item)
{
    WINDOW_REC *window;
    CHANNEL_REC *channel;
    NICK_REC *nickrec;
    char *params, *target, *msg, *nickmode, *freestr, *newtarget;
    int free_ret;

    g_return_if_fail(data != NULL);

    params = cmd_get_params(data, 2 | PARAM_FLAG_GETREST, &target, &msg);
    if (*target == '\0' || *msg == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

    if (*target == '=')
    {
        /* dcc msg - handled in fe-dcc.c */
        g_free(params);
        return;
    }

    free_ret = FALSE;
    if (strcmp(target, ",") == 0 || strcmp(target, ".") == 0)
	    newtarget = parse_special(&target, server, item, NULL, &free_ret, NULL);
    else if (strcmp(target, "*") == 0 &&
	     (irc_item_channel(item) || irc_item_query(item)))
	    newtarget = item->name;
    else newtarget = target;

    if (newtarget == NULL) {
	    printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, *target == ',' ?
			IRCTXT_NO_MSGS_GOT : IRCTXT_NO_MSGS_SENT);
	    g_free(params);
	    signal_stop();
	    return;
    }
    target = newtarget;

    if (server == NULL || !server->connected) cmd_param_error(CMDERR_NOT_CONNECTED);
    channel = channel_find(server, target);

    freestr = !free_ret ? NULL : target;
    if (*target == '@' && ischannel(target[1]))
	target++; /* Hybrid 6 feature, send msg to all ops in channel */

    if (ischannel(*target))
    {
	/* msg to channel */
	nickrec = channel == NULL ? NULL : nicklist_find(channel, server->nick);
	nickmode = !settings_get_bool("show_nickmode") || nickrec == NULL ? "" :
	    nickrec->op ? "@" : nickrec->voice ? "+" : " ";

	window = channel == NULL ? NULL : window_item_window((WI_ITEM_REC *) channel);
	if (window != NULL && window->active == (WI_ITEM_REC *) channel)
	{
	    printformat(server, target, MSGLEVEL_PUBLIC | MSGLEVEL_NOHILIGHT,
			IRCTXT_OWN_MSG, server->nick, msg, nickmode);
	}
	else
	{
	    printformat(server, target, MSGLEVEL_PUBLIC | MSGLEVEL_NOHILIGHT,
			IRCTXT_OWN_MSG_CHANNEL, server->nick, target, msg, nickmode);
	}
    }
    else
    {
        /* private message */
        item = (WI_ITEM_REC *) privmsg_get_query(server, target, TRUE);
	printformat(server, target, MSGLEVEL_MSGS | MSGLEVEL_NOHILIGHT,
		    item == NULL ? IRCTXT_OWN_MSG_PRIVATE : IRCTXT_OWN_MSG_PRIVATE_QUERY, target, msg, server->nick);
    }
    g_free_not_null(freestr);

    g_free(params);
}

static void cmd_me(gchar *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	g_return_if_fail(data != NULL);

	if (!irc_item_check(item))
		return;

	if (server == NULL || !server->connected) cmd_return_error(CMDERR_NOT_CONNECTED);

	printformat(server, item->name, MSGLEVEL_ACTIONS,
		    IRCTXT_OWN_ME, server->nick, data);

	irc_send_cmdv(server, "PRIVMSG %s :\001ACTION %s\001", item->name, data);
}

static void cmd_action(const char *data, IRC_SERVER_REC *server)
{
	char *params, *target, *text;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected) cmd_return_error(CMDERR_NOT_CONNECTED);

	params = cmd_get_params(data, 3 | PARAM_FLAG_GETREST, &target, &text);
	if (*target == '\0' || *text == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	printformat(server, target, MSGLEVEL_ACTIONS, IRCTXT_OWN_ME, server->nick, text);
	irc_send_cmdv(server, "PRIVMSG %s :\001ACTION %s\001", target, text);
	g_free(params);
}

static void cmd_notice(gchar *data, IRC_SERVER_REC *server)
{
	char *params, *target, *msg;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected) cmd_return_error(CMDERR_NOT_CONNECTED);

	params = cmd_get_params(data, 2 | PARAM_FLAG_GETREST, &target, &msg);
	if (*target == '\0' || *msg == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	if (*target == '@' && ischannel(target[1]))
		target++; /* Hybrid 6 feature, send notice to all ops in channel */

	printformat(server, target, MSGLEVEL_NOTICES | MSGLEVEL_NOHILIGHT,
		    IRCTXT_OWN_NOTICE, target, msg);

	g_free(params);
}

static void cmd_ctcp(const char *data, IRC_SERVER_REC *server)
{
	char *params, *target, *ctcpcmd, *ctcpdata;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected) cmd_return_error(CMDERR_NOT_CONNECTED);

	params = cmd_get_params(data, 3 | PARAM_FLAG_GETREST, &target, &ctcpcmd, &ctcpdata);
	if (*target == '\0' || *ctcpcmd == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	if (*target == '@' && ischannel(target[1]))
		target++; /* Hybrid 6 feature, send ctcp to all ops in channel */

	g_strup(ctcpcmd);
	printformat(server, target, MSGLEVEL_CTCPS, IRCTXT_OWN_CTCP, target, ctcpcmd, ctcpdata);

	g_free(params);
}

static void cmd_nctcp(const char *data, IRC_SERVER_REC *server)
{
	gchar *params, *target, *ctcpcmd, *ctcpdata;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected) cmd_return_error(CMDERR_NOT_CONNECTED);

	params = cmd_get_params(data, 3 | PARAM_FLAG_GETREST, &target, &ctcpcmd, &ctcpdata);
	if (*target == '\0' || *ctcpcmd == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	if (*target == '@' && ischannel(target[1]))
		target++; /* Hybrid 6 feature, send notice to all ops in channel */

	g_strup(ctcpcmd);
	printformat(server, target, MSGLEVEL_NOTICES, IRCTXT_OWN_NOTICE, target, ctcpcmd, ctcpdata);

	g_free(params);
}

static void cmd_wall(const char *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	char *params, *channame, *msg;
	CHANNEL_REC *chanrec;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !irc_server_check(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);

	params = cmd_get_params(data, 2 | PARAM_FLAG_OPTCHAN | PARAM_FLAG_GETREST, item, &channame, &msg);
	if (*msg == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	chanrec = channel_find(server, channame);
	if (chanrec == NULL) cmd_param_error(CMDERR_CHAN_NOT_FOUND);

	printformat(server, chanrec->name, MSGLEVEL_NOTICES, IRCTXT_OWN_WALL, chanrec->name, msg);

	g_free(params);
}

static void cmd_ban(const char *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	CHANNEL_REC *cur_channel, *channel;
	GSList *tmp;

	g_return_if_fail(data != NULL);
	if (*data != '\0')
		return; /* setting ban - don't handle here */

	if (server == NULL || !server->connected) cmd_return_error(CMDERR_NOT_CONNECTED);

	/* display bans */
	cur_channel = irc_item_channel(item);
	if (cur_channel == NULL) cmd_return_error(CMDERR_NOT_JOINED);

	if (strcmp(data, "*") == 0 || *data == '\0')
		channel = cur_channel;
	else {
		channel = channel_find(server, data);
		if (channel == NULL) {
			/* not joined to such channel, but ask ban lists from server */
			GString *str;

			str = g_string_new(NULL);
			g_string_sprintf(str, "%s b", data);
			signal_emit("command mode", 3, str->str, server, cur_channel);
			g_string_sprintf(str, "%s e", data);
			signal_emit("command mode", 3, str->str, server, cur_channel);
			g_string_free(str, TRUE);
			return;
		}
	}

	if (channel == NULL) cmd_return_error(CMDERR_CHAN_NOT_FOUND);

	/* show bans.. */
	for (tmp = channel->banlist; tmp != NULL; tmp = tmp->next) {
		BAN_REC *rec;

		rec = (BAN_REC *) tmp->data;
		if (*rec->setby == '\0')
			printformat(server, channel->name, MSGLEVEL_CRAP, IRCTXT_BANLIST, channel->name, rec->ban);
		else
			printformat(server, channel->name, MSGLEVEL_CRAP, IRCTXT_BANLIST,
				    channel->name, rec->ban, rec->setby, (gint) (time(NULL)-rec->time));
	}

	/* ..and show ban exceptions.. */
	for (tmp = channel->ebanlist; tmp != NULL; tmp = tmp->next) {
		BAN_REC *rec;

		rec = (BAN_REC *) tmp->data;
		if (*rec->setby == '\0')
			printformat(server, channel->name, MSGLEVEL_CRAP, IRCTXT_EBANLIST, channel->name, rec->ban);
		else
			printformat(server, channel->name, MSGLEVEL_CRAP, IRCTXT_EBANLIST,
				    channel->name, rec->ban, rec->setby, (gint) (time(NULL)-rec->time));
	}

	signal_stop();
}

static void cmd_invitelist(const char *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	CHANNEL_REC *channel, *cur_channel;
	GSList *tmp;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected) cmd_return_error(CMDERR_NOT_CONNECTED);

	cur_channel = irc_item_channel(item);
	if (cur_channel == NULL) cmd_return_error(CMDERR_NOT_JOINED);

	if (strcmp(data, "*") == 0 || *data == '\0')
		channel = cur_channel;
	else
		channel = channel_find(server, data);
	if (channel == NULL) cmd_return_error(CMDERR_CHAN_NOT_FOUND);

	for (tmp = channel->invitelist; tmp != NULL; tmp = tmp->next)
		printformat(server, channel->name, MSGLEVEL_CRAP, IRCTXT_INVITELIST, channel->name, tmp->data);
}

static void cmd_join(const char *data, IRC_SERVER_REC *server)
{
	if ((*data == '\0' || g_strncasecmp(data, "-invite", 7) == 0) &&
	    server->last_invite == NULL) {
                printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_NOT_INVITED);
		signal_stop();
	}
}

static void cmd_nick(const char *data, IRC_SERVER_REC *server)
{
	g_return_if_fail(data != NULL);

	if (*data != '\0') return;
	if (server == NULL || !server->connected)
		cmd_return_error(CMDERR_NOT_CONNECTED);

	/* display current nick */
	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_YOUR_NICK, server->nick);
	signal_stop();
}

static void cmd_ver(gchar *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	char *str;

	g_return_if_fail(data != NULL);

	if (!irc_server_check(server))
                cmd_return_error(CMDERR_NOT_CONNECTED);
	if (*data == '\0' && !irc_item_check(item))
		cmd_return_error(CMDERR_NOT_JOINED);

	str = g_strdup_printf("%s VERSION", *data == '\0' ? item->name : data);
	signal_emit("command ctcp", 3, str, server, item);
	g_free(str);
}

static void cmd_ts(const char *data)
{
	GSList *tmp;

	g_return_if_fail(data != NULL);

	for (tmp = channels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *rec = tmp->data;

		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_TOPIC,
			    rec->name, rec->topic == NULL ? "" : rec->topic);
	}
}

void fe_irc_commands_init(void)
{
	command_bind("query", NULL, (SIGNAL_FUNC) cmd_query);
	command_bind("unquery", NULL, (SIGNAL_FUNC) cmd_unquery);
	command_bind_last("msg", NULL, (SIGNAL_FUNC) cmd_msg);
	command_bind_last("me", NULL, (SIGNAL_FUNC) cmd_me);
	command_bind_last("action", NULL, (SIGNAL_FUNC) cmd_action);
	command_bind("notice", NULL, (SIGNAL_FUNC) cmd_notice);
	command_bind("ctcp", NULL, (SIGNAL_FUNC) cmd_ctcp);
	command_bind("nctcp", NULL, (SIGNAL_FUNC) cmd_nctcp);
	command_bind("wall", NULL, (SIGNAL_FUNC) cmd_wall);
	command_bind("ban", NULL, (SIGNAL_FUNC) cmd_ban);
	command_bind("invitelist", NULL, (SIGNAL_FUNC) cmd_invitelist);
	command_bind("join", NULL, (SIGNAL_FUNC) cmd_join);
	command_bind("nick", NULL, (SIGNAL_FUNC) cmd_nick);
	command_bind("ver", NULL, (SIGNAL_FUNC) cmd_ver);
	command_bind("ts", NULL, (SIGNAL_FUNC) cmd_ts);
}

void fe_irc_commands_deinit(void)
{
	command_unbind("query", (SIGNAL_FUNC) cmd_query);
	command_unbind("unquery", (SIGNAL_FUNC) cmd_unquery);
	command_unbind("msg", (SIGNAL_FUNC) cmd_msg);
	command_unbind("me", (SIGNAL_FUNC) cmd_me);
	command_unbind("action", (SIGNAL_FUNC) cmd_action);
	command_unbind("notice", (SIGNAL_FUNC) cmd_notice);
	command_unbind("ctcp", (SIGNAL_FUNC) cmd_ctcp);
	command_unbind("nctcp", (SIGNAL_FUNC) cmd_nctcp);
	command_unbind("wall", (SIGNAL_FUNC) cmd_wall);
	command_unbind("ban", (SIGNAL_FUNC) cmd_ban);
	command_unbind("invitelist", (SIGNAL_FUNC) cmd_invitelist);
	command_unbind("join", (SIGNAL_FUNC) cmd_join);
	command_unbind("nick", (SIGNAL_FUNC) cmd_nick);
	command_unbind("ver", (SIGNAL_FUNC) cmd_ver);
	command_unbind("ts", (SIGNAL_FUNC) cmd_ts);
}
