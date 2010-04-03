/*
 fe-irc-commands.c : irssi

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
#include "module-formats.h"
#include "signals.h"
#include "misc.h"
#include "special-vars.h"
#include "settings.h"

#include "levels.h"
#include "servers.h"
#include "mode-lists.h"
#include "nicklist.h"
#include "irc-commands.h"
#include "irc-servers.h"
#include "irc-channels.h"
#include "irc-queries.h"

#include "fe-queries.h"
#include "fe-windows.h"
#include "window-items.h"
#include "printtext.h"
#include "keyboard.h"

/* SYNTAX: ME <message> */
static void cmd_me(const char *data, IRC_SERVER_REC *server, WI_ITEM_REC *item)
{
	const char *target;

        CMD_IRC_SERVER(server);
	if (!IS_IRC_ITEM(item))
		return;

	if (server == NULL || !server->connected)
		cmd_return_error(CMDERR_NOT_CONNECTED);

	target = window_item_get_target(item);
	irc_server_send_action(server, target, data);

	signal_emit("message irc own_action", 3, server, data,
		    item->visible_name);
}

/* SYNTAX: ACTION [-<server tag>] <target> <message> */
static void cmd_action(const char *data, IRC_SERVER_REC *server)
{
	GHashTable *optlist;
	const char *target, *text;
	void *free_arg;

        CMD_IRC_SERVER(server);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_OPTIONS |
			    PARAM_FLAG_UNKNOWN_OPTIONS | PARAM_FLAG_GETREST,
			    "action", &optlist, &target, &text))
		return;
	if (*target == '\0' || *text == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	server = IRC_SERVER(cmd_options_get_server("action", optlist, SERVER(server)));
	if (server == NULL || !server->connected)
		cmd_param_error(CMDERR_NOT_CONNECTED);

	irc_server_send_action(server, target, text);

	signal_emit("message irc own_action", 3, server, text, target);

	cmd_params_free(free_arg);
}

static void cmd_notice(const char *data, IRC_SERVER_REC *server,
		       WI_ITEM_REC *item)
{
	const char *target, *msg;
	void *free_arg;

        CMD_IRC_SERVER(server);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST,
			    &target, &msg))
		return;
	if (strcmp(target, "*") == 0)
		target = item == NULL ? "" : window_item_get_target(item);

	if (*target == '\0' || *msg == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
		
	signal_emit("message irc own_notice", 3, server, msg, target);
	
	cmd_params_free(free_arg);
}

static void cmd_ctcp(const char *data, IRC_SERVER_REC *server,
		     WI_ITEM_REC *item)
{
	const char *target;
	char *ctcpcmd, *ctcpdata;
	void *free_arg;

        CMD_IRC_SERVER(server);

	if (!cmd_get_params(data, &free_arg, 3 | PARAM_FLAG_GETREST,
			    &target, &ctcpcmd, &ctcpdata))
		return;
	if (strcmp(target, "*") == 0)
		target = item == NULL ? "" : window_item_get_target(item);
	if (*target == '\0' || *ctcpcmd == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	if (*target == '=') {
		/* don't handle DCC CTCPs */
		cmd_params_free(free_arg);
		return;
	}

	ascii_strup(ctcpcmd);
	signal_emit("message irc own_ctcp", 4,
		    server, ctcpcmd, ctcpdata, target);

	cmd_params_free(free_arg);
}

static void cmd_nctcp(const char *data, IRC_SERVER_REC *server,
		      WI_ITEM_REC *item)
{
	const char *target, *text;
	void *free_arg;

        CMD_IRC_SERVER(server);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST,
			    &target, &text))
		return;
	if (strcmp(target, "*") == 0)
		target = item == NULL ? "" : window_item_get_target(item);
	if (*target == '\0' || *text == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	signal_emit("message irc own_notice", 3, server, text, target);
	cmd_params_free(free_arg);
}

static void cmd_wall(const char *data, IRC_SERVER_REC *server,
		     WI_ITEM_REC *item)
{
	IRC_CHANNEL_REC *chanrec;
	const char *channame, *msg;
	void *free_arg;

        CMD_IRC_SERVER(server);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_OPTCHAN |
			    PARAM_FLAG_GETREST, item, &channame, &msg))
		return;
	if (*msg == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	chanrec = irc_channel_find(server, channame);
	if (chanrec == NULL) cmd_param_error(CMDERR_CHAN_NOT_FOUND);

	signal_emit("message irc own_wall", 3, server, msg,
		    chanrec->visible_name);

	cmd_params_free(free_arg);
}

static void bans_ask_channel(const char *channel, IRC_SERVER_REC *server,
			     WI_ITEM_REC *item)
{
	GString *str;

	str = g_string_new(NULL);
	g_string_printf(str, "%s b", channel);
	signal_emit("command mode", 3, str->str, server, item);
	if (server->emode_known) {
		g_string_printf(str, "%s e", channel);
		signal_emit("command mode", 3, str->str, server, item);
	}
	g_string_free(str, TRUE);
}

static void bans_show_channel(IRC_CHANNEL_REC *channel, IRC_SERVER_REC *server)
{
	GSList *tmp;
        int counter;

	if (channel->banlist == NULL) {
		printformat(server, channel->visible_name,
			    MSGLEVEL_CLIENTNOTICE,
			    IRCTXT_NO_BANS, channel->visible_name);
		return;
	}

	/* show bans.. */
        counter = 1;
	for (tmp = channel->banlist; tmp != NULL; tmp = tmp->next) {
		BAN_REC *rec = tmp->data;

		printformat(server, channel->visible_name, MSGLEVEL_CRAP,
			    (rec->setby == NULL || *rec->setby == '\0') ?
			    IRCTXT_BANLIST : IRCTXT_BANLIST_LONG,
			    counter, channel->visible_name,
			    rec->ban, rec->setby,
			    (int) (time(NULL)-rec->time));
                counter++;
	}
}

/* SYNTAX: BAN [<channel>] [<nicks>] */
static void cmd_ban(const char *data, IRC_SERVER_REC *server,
		    WI_ITEM_REC *item)
{
	IRC_CHANNEL_REC *chanrec;
	char *channel, *nicks;
	void *free_arg;

        CMD_IRC_SERVER(server);

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

	if (chanrec == NULL || !chanrec->synced) {
		/* not joined to such channel or not yet synced,
		   ask ban lists from server */
		bans_ask_channel(channel, server, item);
	} else {
		bans_show_channel(chanrec, server);
	}

	signal_stop();
	cmd_params_free(free_arg);
}

/* SYNTAX: VER [<nick> | <channel> | *] */
static void cmd_ver(gchar *data, IRC_SERVER_REC *server, WI_ITEM_REC *item)
{
	char *str;

	g_return_if_fail(data != NULL);

        CMD_IRC_SERVER(server);
	if (*data == '\0' && !IS_QUERY(item))
		cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

	str = g_strdup_printf("%s VERSION", *data == '\0' ?
			      window_item_get_target(item) : data);
	signal_emit("command ctcp", 3, str, server, item);
	g_free(str);
}

static void cmd_topic(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	CHANNEL_REC *channel;
	char *timestr, *bynick, *byhost;

	g_return_if_fail(data != NULL);

	channel = *data != '\0' ? channel_find(server, data) : CHANNEL(item);
	if (channel == NULL) return;

	printformat(server, channel->visible_name, MSGLEVEL_CRAP,
		    channel->topic == NULL ? IRCTXT_NO_TOPIC : IRCTXT_TOPIC,
		    channel->visible_name, channel->topic);

	if (channel->topic_time > 0) {
		byhost = strchr(channel->topic_by, '!');
		if (byhost == NULL) {
			bynick = g_strdup(channel->topic_by);
			byhost = "";
		} else {
			bynick = g_strndup(channel->topic_by,
					   (int) (byhost-channel->topic_by));
			byhost++;
		}

		timestr = my_asctime(channel->topic_time);
		printformat(server, channel->visible_name, MSGLEVEL_CRAP,
			    IRCTXT_TOPIC_INFO, bynick, timestr, byhost);
		g_free(timestr);
		g_free(bynick);
	}
	signal_stop();
}

/* SYNTAX: TS */
static void cmd_ts(const char *data)
{
	GSList *tmp;

	g_return_if_fail(data != NULL);

	for (tmp = channels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *rec = tmp->data;

		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_TOPIC,
			    rec->visible_name,
			    rec->topic == NULL ? "" : rec->topic);
	}
}

typedef struct {
	IRC_SERVER_REC *server;
	char *nick;
} OPER_PASS_REC;

static void cmd_oper_got_pass(const char *password, OPER_PASS_REC *rec)
{
        if (*password != '\0')
		irc_send_cmdv(rec->server, "OPER %s %s", rec->nick, password);
	g_free(rec->nick);
        g_free(rec);
}

static void cmd_oper(const char *data, IRC_SERVER_REC *server)
{
	char *nick, *password, *format;
	void *free_arg;

	g_return_if_fail(data != NULL);
	if (!IS_IRC_SERVER(server) || !server->connected)
		cmd_return_error(CMDERR_NOT_CONNECTED);

	if (!cmd_get_params(data, &free_arg, 2, &nick, &password))
		return;
	if (*password == '\0') {
		/* password not given, ask it.
		   irc/core handles the /OPER when password is given */
		OPER_PASS_REC *rec;

		rec = g_new(OPER_PASS_REC, 1);
		rec->server = server;
		rec->nick = g_strdup(*nick != '\0' ? nick : server->nick);

		format = format_get_text(MODULE_NAME, NULL, server, NULL,
					 IRCTXT_ASK_OPER_PASS);

		keyboard_entry_redirect((SIGNAL_FUNC) cmd_oper_got_pass,
					format,
					ENTRY_REDIRECT_FLAG_HIDDEN, rec);
                g_free(format);

		signal_stop();
	}

	cmd_params_free(free_arg);
}

/* SYNTAX: SETHOST <host> <password> (non-ircops)
           SETHOST <ident> <host> (ircops) */
static void cmd_sethost(const char *data, IRC_SERVER_REC *server)
{
	GSList *tmp;

	g_return_if_fail(data != NULL);
	if (!IS_IRC_SERVER(server) || !server->connected)
		cmd_return_error(CMDERR_NOT_CONNECTED);

	/* Save all the joined channels in server to window binds, since
	   the server will soon /PART + /JOIN us in all channels. */
	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *channel = tmp->data;

		window_bind_add(window_item_window(channel),
				server->tag, channel->visible_name);
	}

        irc_send_cmdv(server, "SETHOST %s", data);
}

void fe_irc_commands_init(void)
{
	command_bind_irc_last("me", NULL, (SIGNAL_FUNC) cmd_me);
	command_bind_irc_last("action", NULL, (SIGNAL_FUNC) cmd_action);
	command_bind_irc("notice", NULL, (SIGNAL_FUNC) cmd_notice);
	command_bind_irc("ctcp", NULL, (SIGNAL_FUNC) cmd_ctcp);
	command_bind_irc("nctcp", NULL, (SIGNAL_FUNC) cmd_nctcp);
	command_bind_irc("wall", NULL, (SIGNAL_FUNC) cmd_wall);
	command_bind_irc("ban", NULL, (SIGNAL_FUNC) cmd_ban);
	command_bind_irc("ver", NULL, (SIGNAL_FUNC) cmd_ver);
	command_bind_irc("topic", NULL, (SIGNAL_FUNC) cmd_topic);
	command_bind_irc("ts", NULL, (SIGNAL_FUNC) cmd_ts);
	command_bind_irc("oper", NULL, (SIGNAL_FUNC) cmd_oper);
	command_bind_irc("sethost", NULL, (SIGNAL_FUNC) cmd_sethost);
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
	command_unbind("ver", (SIGNAL_FUNC) cmd_ver);
	command_unbind("topic", (SIGNAL_FUNC) cmd_topic);
	command_unbind("ts", (SIGNAL_FUNC) cmd_ts);
	command_unbind("oper", (SIGNAL_FUNC) cmd_oper);
	command_unbind("sethost", (SIGNAL_FUNC) cmd_sethost);
}
