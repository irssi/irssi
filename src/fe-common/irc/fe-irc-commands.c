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
#include "servers.h"
#include "mode-lists.h"
#include "nicklist.h"
#include "irc-channels.h"
#include "irc-queries.h"

#include "fe-queries.h"
#include "windows.h"
#include "window-items.h"

/* SYNTAX: ME <message> */
static void cmd_me(gchar *data, IRC_SERVER_REC *server, WI_ITEM_REC *item)
{
	g_return_if_fail(data != NULL);

	if (!IS_IRC_ITEM(item))
		return;

	if (server == NULL || !server->connected)
		cmd_return_error(CMDERR_NOT_CONNECTED);

	printformat(server, item->name, MSGLEVEL_ACTIONS | MSGLEVEL_NOHILIGHT | MSGLEVEL_NO_ACT |
		    (ischannel(*item->name) ? MSGLEVEL_PUBLIC : MSGLEVEL_MSGS),
		    IRCTXT_OWN_ME, server->nick, data);

	irc_send_cmdv(server, "PRIVMSG %s :\001ACTION %s\001", item->name, data);
}

/* SYNTAX: ACTION [<target>] <message> */
static void cmd_action(const char *data, IRC_SERVER_REC *server)
{
	char *target, *text;
	void *free_arg;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected)
		cmd_return_error(CMDERR_NOT_CONNECTED);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST, &target, &text))
		return;
	if (*target == '\0' || *text == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	printformat(server, target, MSGLEVEL_ACTIONS | MSGLEVEL_NOHILIGHT | MSGLEVEL_NO_ACT |
		    (ischannel(*target) ? MSGLEVEL_PUBLIC : MSGLEVEL_MSGS),
		    IRCTXT_OWN_ME, server->nick, text);
	irc_send_cmdv(server, "PRIVMSG %s :\001ACTION %s\001", target, text);
	cmd_params_free(free_arg);
}

/* SYNTAX: NOTICE [<target>] <message> */
static void cmd_notice(const char *data, IRC_SERVER_REC *server)
{
	char *target, *msg;
	void *free_arg;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected) cmd_return_error(CMDERR_NOT_CONNECTED);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST, &target, &msg))
		return;
	if (*target == '\0' || *msg == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	if (*target == '@' && ischannel(target[1]))
		target++; /* Hybrid 6 feature, send notice to all ops in channel */

	printformat(server, target, MSGLEVEL_NOTICES | MSGLEVEL_NOHILIGHT | MSGLEVEL_NO_ACT,
		    IRCTXT_OWN_NOTICE, target, msg);

	cmd_params_free(free_arg);
}

static void cmd_ctcp(const char *data, IRC_SERVER_REC *server)
{
	char *target, *ctcpcmd, *ctcpdata;
	void *free_arg;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected) cmd_return_error(CMDERR_NOT_CONNECTED);

	if (!cmd_get_params(data, &free_arg, 3 | PARAM_FLAG_GETREST, &target, &ctcpcmd, &ctcpdata))
		return;
	if (*target == '\0' || *ctcpcmd == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	if (*target == '=') {
		/* don't handle DCC CTCPs */
		cmd_params_free(free_arg);
		return;
	}

	if (*target == '@' && ischannel(target[1]))
		target++; /* Hybrid 6 feature, send ctcp to all ops in channel */

	g_strup(ctcpcmd);
	printformat(server, target, MSGLEVEL_CTCPS, IRCTXT_OWN_CTCP, target, ctcpcmd, ctcpdata);

	cmd_params_free(free_arg);
}

static void cmd_nctcp(const char *data, IRC_SERVER_REC *server)
{
	char *target, *ctcpcmd, *ctcpdata;
	void *free_arg;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected) cmd_return_error(CMDERR_NOT_CONNECTED);

	if (!cmd_get_params(data, &free_arg, 3 | PARAM_FLAG_GETREST, &target, &ctcpcmd, &ctcpdata))
		return;
	if (*target == '\0' || *ctcpcmd == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	if (*target == '@' && ischannel(target[1]))
		target++; /* Hybrid 6 feature, send notice to all ops in channel */

	g_strup(ctcpcmd);
	printformat(server, target, MSGLEVEL_NOTICES, IRCTXT_OWN_NOTICE, target, ctcpcmd, ctcpdata);

	cmd_params_free(free_arg);
}

static void cmd_wall(const char *data, IRC_SERVER_REC *server, WI_ITEM_REC *item)
{
	IRC_CHANNEL_REC *chanrec;
	char *channame, *msg;
	void *free_arg;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !IS_IRC_SERVER(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_OPTCHAN | PARAM_FLAG_GETREST, item, &channame, &msg))
		return;
	if (*msg == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	chanrec = irc_channel_find(server, channame);
	if (chanrec == NULL) cmd_param_error(CMDERR_CHAN_NOT_FOUND);

	printformat(server, chanrec->name, MSGLEVEL_NOTICES, IRCTXT_OWN_WALL, chanrec->name, msg);

	cmd_params_free(free_arg);
}

static void bans_ask_channel(const char *channel, IRC_SERVER_REC *server,
			     WI_ITEM_REC *item)
{
	GString *str;

	str = g_string_new(NULL);
	g_string_sprintf(str, "%s b", channel);
	signal_emit("command mode", 3, str->str, server, item);
	if (server->emode_known) {
		g_string_sprintf(str, "%s e", channel);
		signal_emit("command mode", 3, str->str, server, item);
	}
	g_string_free(str, TRUE);
}

static void bans_show_channel(IRC_CHANNEL_REC *channel, IRC_SERVER_REC *server)
{
	GSList *tmp;

	if (channel->banlist == NULL && channel->ebanlist == NULL) {
		printformat(server, channel->name, MSGLEVEL_CRAP,
			    IRCTXT_NO_BANS, channel->name);
		return;
	}

	/* show bans.. */
	for (tmp = channel->banlist; tmp != NULL; tmp = tmp->next) {
		BAN_REC *rec = tmp->data;

		printformat(server, channel->name, MSGLEVEL_CRAP,
			    (rec->setby == NULL || *rec->setby == '\0') ?
			    IRCTXT_BANLIST : IRCTXT_BANLIST_LONG,
			    channel->name, rec->ban, rec->setby,
			    (int) (time(NULL)-rec->time));
	}

	/* ..and show ban exceptions.. */
	for (tmp = channel->ebanlist; tmp != NULL; tmp = tmp->next) {
		BAN_REC *rec = tmp->data;

		printformat(server, channel->name, MSGLEVEL_CRAP,
			    (rec->setby == NULL || *rec->setby == '\0') ?
			    IRCTXT_EBANLIST : IRCTXT_EBANLIST_LONG,
			    channel->name, rec->ban, rec->setby,
			    (int) (time(NULL)-rec->time));
	}
}

/* SYNTAX: BAN [<channel>] [<nicks>] */
static void cmd_ban(const char *data, IRC_SERVER_REC *server,
		    WI_ITEM_REC *item)
{
	IRC_CHANNEL_REC *chanrec;
	char *channel, *nicks;
	void *free_arg;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected)
		cmd_return_error(CMDERR_NOT_CONNECTED);

	if (!cmd_get_params(data, &free_arg, 2 |
			    PARAM_FLAG_OPTCHAN | PARAM_FLAG_GETREST,
			    item, &channel, &nicks))
		return;

	if (*nicks != '\0') {
		/* setting ban - don't handle here */
		cmd_params_free(free_arg);
		return;
	}

	/* display bans */
	chanrec = IRC_CHANNEL(item);
	if (chanrec == NULL && *channel == '\0')
		cmd_param_error(CMDERR_NOT_JOINED);

	if (*channel != '\0' && strcmp(channel, "*") != 0)
		chanrec = irc_channel_find(server, channel);

	if (chanrec == NULL) {
		/* not joined to such channel,
		   but ask ban lists from server */
		bans_ask_channel(channel, server, item);
	} else {
		bans_show_channel(chanrec, server);
	}

	signal_stop();
	cmd_params_free(free_arg);
}

/* SYNTAX: INVITELIST [<channel>] */
static void cmd_invitelist(const char *data, IRC_SERVER_REC *server, WI_ITEM_REC *item)
{
	IRC_CHANNEL_REC *channel, *cur_channel;
	GSList *tmp;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected) cmd_return_error(CMDERR_NOT_CONNECTED);

	cur_channel = IRC_CHANNEL(item);
	if (cur_channel == NULL) cmd_return_error(CMDERR_NOT_JOINED);

	if (strcmp(data, "*") == 0 || *data == '\0')
		channel = cur_channel;
	else
		channel = irc_channel_find(server, data);
	if (channel == NULL) cmd_return_error(CMDERR_CHAN_NOT_FOUND);

	for (tmp = channel->invitelist; tmp != NULL; tmp = tmp->next)
		printformat(server, channel->name, MSGLEVEL_CRAP, IRCTXT_INVITELIST, channel->name, tmp->data);
}

static void cmd_join(const char *data, IRC_SERVER_REC *server)
{
	if ((*data == '\0' || g_strncasecmp(data, "-invite", 7) == 0) &&
	    server != NULL && server->last_invite == NULL) {
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

/* SYNTAX: VER [<target>] */
static void cmd_ver(gchar *data, IRC_SERVER_REC *server, WI_ITEM_REC *item)
{
	char *str;

	g_return_if_fail(data != NULL);

	if (!IS_IRC_SERVER(server) || !server->connected)
                cmd_return_error(CMDERR_NOT_CONNECTED);
	if (*data == '\0' && !IS_IRC_ITEM(item))
		cmd_return_error(CMDERR_NOT_JOINED);

	str = g_strdup_printf("%s VERSION", *data == '\0' ? item->name : data);
	signal_emit("command ctcp", 3, str, server, item);
	g_free(str);
}

/* SYNTAX: TS */
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
