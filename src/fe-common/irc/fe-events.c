/*
 fe-events.c : irssi

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
#include "misc.h"
#include "settings.h"

#include "irc.h"
#include "levels.h"
#include "servers.h"
#include "servers-redirect.h"
#include "servers-reconnect.h"
#include "queries.h"
#include "ignore.h"

#include "fe-queries.h"
#include "irc-channels.h"
#include "irc-nicklist.h"
#include "irc-hilight-text.h"
#include "windows.h"

#include "completion.h"

#define target_level(target) \
	(ischannel((target)[0]) ? MSGLEVEL_PUBLIC : MSGLEVEL_MSGS)

static void print_channel_msg(IRC_SERVER_REC *server, const char *msg,
			      const char *nick, const char *addr,
			      const char *target)
{
	IRC_CHANNEL_REC *chanrec;
	NICK_REC *nickrec;
	const char *nickmode;
	int for_me, print_channel, level;
	char *color;

	chanrec = irc_channel_find(server, target);
	for_me = irc_nick_match(server->nick, msg);
	color = for_me ? NULL : irc_hilight_find_nick(target, nick, addr, MSGLEVEL_PUBLIC, msg);

	nickrec = chanrec == NULL ? NULL :
		nicklist_find(CHANNEL(chanrec), nick);
	nickmode = (!settings_get_bool("show_nickmode") || nickrec == NULL) ? "" :
		(nickrec->op ? "@" : nickrec->voice ? "+" : " ");

	print_channel = !window_item_is_active((WI_ITEM_REC *) chanrec);
	if (!print_channel && settings_get_bool("print_active_channel") &&
	    window_item_window((WI_ITEM_REC *) chanrec)->items->next != NULL)
		print_channel = TRUE;

	level = MSGLEVEL_PUBLIC |
		(color != NULL ? MSGLEVEL_HILIGHT :
		 (for_me ? MSGLEVEL_HILIGHT : MSGLEVEL_NOHILIGHT));
	if (!print_channel) {
		/* message to active channel in window */
		if (color != NULL) {
			/* highlighted nick */
			printformat(server, target, level, IRCTXT_PUBMSG_HILIGHT,
				    color, nick, msg, nickmode);
		} else {
			printformat(server, target, level,
				    for_me ? IRCTXT_PUBMSG_ME : IRCTXT_PUBMSG, nick, msg, nickmode);
		}
	} else {
		/* message to not existing/active channel */
		if (color != NULL) {
			/* highlighted nick */
			printformat(server, target, level, IRCTXT_PUBMSG_HILIGHT_CHANNEL,
				    color, nick, target, msg, nickmode);
		} else {
			printformat(server, target, level,
				    for_me ? IRCTXT_PUBMSG_ME_CHANNEL : IRCTXT_PUBMSG_CHANNEL,
				    nick, target, msg, nickmode);
		}
	}

	g_free_not_null(color);
}

static void event_privmsg(const char *data, IRC_SERVER_REC *server, const char *nick, const char *addr)
{
	WI_ITEM_REC *item;
	char *params, *target, *msg;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST, &target, &msg);
	if (nick == NULL) nick = server->real_address;
	if (addr == NULL) addr = "";

	if (!ignore_check(server, nick, addr, target, msg, target_level(target))) {
		if (ischannel(*target)) {
                        /* message to channel */
			print_channel_msg(server, msg, nick, addr, target);
		} else {
			/* private message */
			item = (WI_ITEM_REC *) privmsg_get_query(server, nick, FALSE);
			printformat(server, nick, MSGLEVEL_MSGS,
				    item == NULL ? IRCTXT_MSG_PRIVATE : IRCTXT_MSG_PRIVATE_QUERY, nick, addr, msg);
		}
	}

	g_free(params);
}

/* we use "ctcp msg" here because "ctcp msg action" can be ignored with
   /IGNORE * CTCPS, and we don't want that.. */
static void ctcp_msg_check_action(const char *data, IRC_SERVER_REC *server,
				  const char *nick, const char *addr, const char *target)
{
	WI_ITEM_REC *item;
	int level;

	g_return_if_fail(data != NULL);

	if (g_strncasecmp(data, "ACTION ", 7) != 0)
		return;
	data += 7;

	level = MSGLEVEL_ACTIONS |
		(ischannel(*target) ? MSGLEVEL_PUBLIC : MSGLEVEL_MSGS);
	if (ignore_check(server, nick, addr, target, data, level))
		return;

	if (ischannel(*target)) {
		/* channel action */
		item = (WI_ITEM_REC *) irc_channel_find(server, target);

		if (window_item_is_active(item)) {
			/* message to active channel in window */
			printformat(server, target, level,
				    IRCTXT_ACTION_PUBLIC, nick, data);
		} else {
			/* message to not existing/active channel */
			printformat(server, target, level,
				    IRCTXT_ACTION_PUBLIC_CHANNEL, nick, target, data);
		}
	} else {
		/* private action */
		item = (WI_ITEM_REC *) privmsg_get_query(server, nick, FALSE);
		printformat(server, nick, level,
			    item == NULL ? IRCTXT_ACTION_PRIVATE : IRCTXT_ACTION_PRIVATE_QUERY,
			    nick, addr == NULL ? "" : addr, data);
	}
}

static void event_notice(const char *data, IRC_SERVER_REC *server, const char *nick, const char *addr)
{
	char *params, *target, *msg;
	int op_notice;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST, &target, &msg);
	if (nick == NULL) {
		nick = server->real_address == NULL ?
			server->connrec->address :
			server->real_address;
	}

	if (addr == NULL) {
		/* notice from server */
		if (*msg != 1 && !ignore_check(server, nick, "", target, msg, MSGLEVEL_SNOTES))
			printformat(server, target, MSGLEVEL_SNOTES, IRCTXT_NOTICE_SERVER, nick, msg);
	} else {
		op_notice = *target == '@' && ischannel(target[1]);
		if (op_notice) target++;

		if (ischannel(*target)) {
			/* notice in some channel */
			if (!ignore_check(server, nick, addr, target, msg, MSGLEVEL_NOTICES))
				printformat(server, target, MSGLEVEL_NOTICES,
					    op_notice ? IRCTXT_NOTICE_PUBLIC_OPS : IRCTXT_NOTICE_PUBLIC,
					    nick, target, msg);
		} else {
			/* private notice */
			if (!ignore_check(server, nick, addr, NULL, msg, MSGLEVEL_NOTICES))
				printformat(server, nick, MSGLEVEL_NOTICES, IRCTXT_NOTICE_PRIVATE, nick, addr, msg);
		}
	}

	g_free(params);
}

static void event_join(const char *data, IRC_SERVER_REC *server, const char *nick, const char *addr)
{
	char *params, *channel, *tmp;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 1, &channel);
	tmp = strchr(channel, 7); /* ^G does something weird.. */
	if (tmp != NULL) *tmp = '\0';

	if (!ignore_check(server, nick, addr, channel, NULL, MSGLEVEL_JOINS))
		printformat(server, channel, MSGLEVEL_JOINS, IRCTXT_JOIN, nick, addr, channel);
	g_free(params);
}

static void event_part(const char *data, IRC_SERVER_REC *server, const char *nick, const char *addr)
{
	char *params, *channel, *reason;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST, &channel, &reason);

	if (!ignore_check(server, nick, addr, channel, NULL, MSGLEVEL_PARTS))
		printformat(server, channel, MSGLEVEL_PARTS, IRCTXT_PART, nick, addr, channel, reason);
	g_free(params);
}

static void event_quit(const char *data, IRC_SERVER_REC *server, const char *nick, const char *addr)
{
	WINDOW_REC *window;
	GString *chans;
	GSList *tmp, *windows;
	char *print_channel;
	int once, count;

	g_return_if_fail(data != NULL);

	if (*data == ':') data++; /* quit message */
	if (ignore_check(server, nick, addr, NULL, data, MSGLEVEL_QUITS))
		return;

	print_channel = NULL;
	once = settings_get_bool("show_quit_once");

	count = 0; windows = NULL;
	chans = !once ? NULL : g_string_new(NULL);
	for (tmp = channels; tmp != NULL; tmp = tmp->next) {
		IRC_CHANNEL_REC *rec = tmp->data;

		if (!IS_IRC_CHANNEL(rec) || rec->server != server ||
		    !nicklist_find(CHANNEL(rec), nick) ||
		    ignore_check(server, nick, addr, rec->name, data, MSGLEVEL_QUITS))
			continue;

		if (print_channel == NULL || active_win->active == (WI_ITEM_REC *) rec)
			print_channel = rec->name;

		if (!once) {
			window = window_item_window((WI_ITEM_REC *) rec);
			if (g_slist_find(windows, window) == NULL) {
				windows = g_slist_append(windows, window);
				printformat(server, rec->name, MSGLEVEL_QUITS, IRCTXT_QUIT, nick, addr, data);
			}
		} else {
			g_string_sprintfa(chans, "%s,", rec->name);
			count++;
		}
	}
	g_slist_free(windows);

	if (once) {
		g_string_truncate(chans, chans->len-1);
		printformat(server, print_channel, MSGLEVEL_QUITS,
			    count <= 1 ? IRCTXT_QUIT : IRCTXT_QUIT_ONCE,
			    nick, addr, data, chans->str);
		g_string_free(chans, TRUE);
	}
}

static void event_kick(const char *data, IRC_SERVER_REC *server, const char *kicker, const char *addr)
{
	char *params, *channel, *nick, *reason;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3 | PARAM_FLAG_GETREST, &channel, &nick, &reason);
	if (!ignore_check(server, kicker, addr, channel, reason, MSGLEVEL_KICKS)) {
		printformat(server, channel, MSGLEVEL_KICKS,
			    IRCTXT_KICK, nick, channel, kicker, reason);
	}
	g_free(params);
}

static void print_nick_change(IRC_SERVER_REC *server, const char *target, const char *newnick, const char *oldnick, const char *addr, int ownnick)
{
	if (ignore_check(server, oldnick, addr, target, newnick, MSGLEVEL_NICKS))
		return;

	if (ownnick)
		printformat(server, target, MSGLEVEL_NICKS, IRCTXT_YOUR_NICK_CHANGED, newnick);
	else
		printformat(server, target, MSGLEVEL_NICKS, IRCTXT_NICK_CHANGED, oldnick, newnick);
}

static void event_nick(gchar *data, IRC_SERVER_REC *server, gchar *sender, gchar *addr)
{
	GSList *tmp, *windows;
	char *params, *newnick;
	int ownnick, msgprint;

	g_return_if_fail(data != NULL);

	if (ignore_check(server, sender, addr, NULL, NULL, MSGLEVEL_NICKS))
		return;

	params = event_get_params(data, 1, &newnick);

	msgprint = FALSE;
	ownnick = g_strcasecmp(sender, server->nick) == 0;

	/* Print to each channel/query where the nick is.
	   Don't print more than once to the same window. */
	windows = NULL;
	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *channel = tmp->data;
		WINDOW_REC *window =
			window_item_window((WI_ITEM_REC *) channel);

		if (nicklist_find(channel, sender) &&
		    g_slist_find(windows, window) == NULL) {
			windows = g_slist_append(windows, window);
			print_nick_change(server, channel->name, newnick, sender, addr, ownnick);
			msgprint = TRUE;
		}
	}

	for (tmp = server->queries; tmp != NULL; tmp = tmp->next) {
		QUERY_REC *query = tmp->data;
		WINDOW_REC *window =
			window_item_window((WI_ITEM_REC *) query);

		if (g_strcasecmp(query->name, sender) == 0 &&
		    g_slist_find(windows, window) == NULL) {
			windows = g_slist_append(windows, window);
			print_nick_change(server, query->name, newnick, sender, addr, ownnick);
			msgprint = TRUE;
		}
	}
	g_slist_free(windows);

	if (!msgprint && ownnick)
		printformat(server, NULL, MSGLEVEL_NICKS, IRCTXT_YOUR_NICK_CHANGED, newnick);
	g_free(params);
}

static void event_mode(const char *data, IRC_SERVER_REC *server, const char *nick, const char *addr)
{
	char *params, *channel, *mode;

	g_return_if_fail(data != NULL);
	if (nick == NULL) nick = server->real_address;

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST, &channel, &mode);
	if (ignore_check(server, nick, addr, channel, mode, MSGLEVEL_MODES)) {
		g_free(params);
		return;
	}

	if (!ischannel(*channel)) {
		/* user mode change */
		printformat(server, NULL, MSGLEVEL_MODES, IRCTXT_USERMODE_CHANGE, mode, channel);
	} else if (addr == NULL) {
		/* channel mode changed by server */
		printformat(server, channel, MSGLEVEL_MODES,
			    IRCTXT_SERVER_CHANMODE_CHANGE, channel, mode, nick);
	} else {
		/* channel mode changed by normal user */
		printformat(server, channel, MSGLEVEL_MODES,
			    IRCTXT_CHANMODE_CHANGE, channel, mode, nick);
	}

	g_free(params);
}

static void event_pong(const char *data, IRC_SERVER_REC *server, const char *nick)
{
	char *params, *host, *reply;

	g_return_if_fail(data != NULL);
	if (nick == NULL) nick = server->real_address;

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST, &host, &reply);
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_PONG, host, reply);
	g_free(params);
}

static void event_invite(const char *data, IRC_SERVER_REC *server, const char *nick, const char *addr)
{
	char *params, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);
	if (*channel != '\0' && !ignore_check(server, nick, addr, channel, NULL, MSGLEVEL_INVITES)) {
		channel = show_lowascii(channel);
		printformat(server, NULL, MSGLEVEL_INVITES, IRCTXT_INVITE, nick, channel);
		g_free(channel);
	}
	g_free(params);
}

static void event_topic(const char *data, IRC_SERVER_REC *server, const char *nick, const char *addr)
{
	char *params, *channel, *topic;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST, &channel, &topic);

	if (!ignore_check(server, nick, addr, channel, topic, MSGLEVEL_TOPICS))
		printformat(server, channel, MSGLEVEL_TOPICS,
			    *topic != '\0' ? IRCTXT_NEW_TOPIC : IRCTXT_TOPIC_UNSET,
			    nick, channel, topic);
	g_free(params);
}

static void event_error(const char *data, IRC_SERVER_REC *server)
{
	g_return_if_fail(data != NULL);

	if (*data == ':') data++;
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_ERROR, data);
}

static void event_wallops(const char *data, IRC_SERVER_REC *server, const char *nick, const char *addr)
{
	g_return_if_fail(data != NULL);

	if (*data == ':') data++;
	if (ignore_check(server, nick, addr, NULL, data, MSGLEVEL_WALLOPS))
		return;

	if (g_strncasecmp(data, "\001ACTION", 7) != 0)
		printformat(server, NULL, MSGLEVEL_WALLOPS, IRCTXT_WALLOPS, nick, data);
	else {
		/* Action in WALLOP */
		int len;
		char *tmp;

		tmp = g_strdup(data);
		len = strlen(tmp);
		if (tmp[len-1] == 1) tmp[len-1] = '\0';
		printformat(server, NULL, MSGLEVEL_WALLOPS, IRCTXT_ACTION_WALLOPS, nick, tmp);
		g_free(tmp);
	}
}

static void channel_sync(CHANNEL_REC *channel)
{
	g_return_if_fail(channel != NULL);

	printformat(channel->server, channel->name, MSGLEVEL_CLIENTNOTICE|MSGLEVEL_NO_ACT,
		    IRCTXT_CHANNEL_SYNCED, channel->name, (long) (time(NULL)-channel->createtime));
}

static void event_connected(IRC_SERVER_REC *server)
{
	const char *nick;

	g_return_if_fail(server != NULL);

	nick = settings_get_str("default_nick");
	if (*nick == '\0' || g_strcasecmp(server->nick, nick) == 0)
		return;

	/* someone has our nick, find out who. */
	irc_send_cmdv(server, "WHOIS %s", nick);
	server_redirect_event((SERVER_REC *) server, nick, 1,
			      "event 318", "event empty", 1,
			      "event 401", "event empty", 1,
			      "event 311", "nickfind event whois", 1,
			      "event 301", "event empty", 1,
			      "event 312", "event empty", 1,
			      "event 313", "event empty", 1,
			      "event 317", "event empty", 1,
			      "event 319", "event empty", 1, NULL);

}

static void event_nickfind_whois(const char *data, IRC_SERVER_REC *server)
{
	char *params, *nick, *user, *host, *realname;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 6, NULL, &nick, &user, &host, NULL, &realname);
	printformat(server, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_YOUR_NICK_OWNED, nick, user, host, realname);
	g_free(params);
}

static void event_ban_type_changed(const char *bantype)
{
	GString *str;

	g_return_if_fail(bantype != NULL);

	if (strcmp(bantype, "UD") == 0)
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_BANTYPE, "Normal");
	else if (strcmp(bantype, "HD") == 0 || strcmp(bantype, "H") == 0)
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_BANTYPE, "Host");
	else if (strcmp(bantype, "D") == 0)
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_BANTYPE, "Domain");
	else {
		str = g_string_new("Custom:");
		if (*bantype == 'N') {
			g_string_append(str, " Nick");
			bantype++;
		}
		if (*bantype == 'U') {
			g_string_append(str, " User");
			bantype++;
		}
		if (*bantype == 'H') {
			g_string_append(str, " Host");
			bantype++;
		}
		if (*bantype == 'D')
			g_string_append(str, " Domain");

		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_BANTYPE, str->str);
		g_string_free(str, TRUE);
	}
}

static void sig_whowas_event_end(const char *data, IRC_SERVER_REC *server, const char *sender, const char *addr)
{
	char *params, *nick;

	g_return_if_fail(data != NULL);

	if (server->whowas_found) {
		signal_emit("event 369", 4, data, server, sender, addr);
		return;
	}

	params = event_get_params(data, 2, NULL, &nick);
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_WHOIS_NOT_FOUND, nick);
	g_free(params);
}

static void sig_server_lag_disconnected(IRC_SERVER_REC *server)
{
	g_return_if_fail(server != NULL);

	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
		    IRCTXT_LAG_DISCONNECTED, server->connrec->address, time(NULL)-server->lag_sent);
}

static void sig_server_reconnect_removed(RECONNECT_REC *reconnect)
{
	g_return_if_fail(reconnect != NULL);

	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
		    IRCTXT_RECONNECT_REMOVED, reconnect->conn->address, reconnect->conn->port,
		    reconnect->conn->chatnet == NULL ? "" : reconnect->conn->chatnet);
}

static void sig_server_reconnect_not_found(const char *tag)
{
	g_return_if_fail(tag != NULL);

	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
		    IRCTXT_RECONNECT_NOT_FOUND, tag);
}

static void event_received(const char *data, IRC_SERVER_REC *server, const char *nick, const char *addr)
{
	char *params, *cmd, *args, *ptr;

	g_return_if_fail(data != NULL);

	if (!isdigit((gint) *data)) {
		printtext(server, NULL, MSGLEVEL_CRAP, "%s", data);
		return;
	}

	/* numeric event. */
	params = event_get_params(data, 3 | PARAM_FLAG_GETREST, &cmd, NULL, &args);
	ptr = strstr(args, " :");
	if (ptr != NULL) *(ptr+1) = ' ';
        printtext(server, NULL, MSGLEVEL_CRAP, "%s", args);
        g_free(params);
}

static void sig_empty(void)
{
}

void fe_events_init(void)
{
	signal_add("event privmsg", (SIGNAL_FUNC) event_privmsg);
	signal_add("ctcp msg", (SIGNAL_FUNC) ctcp_msg_check_action);
	signal_add("ctcp msg action", (SIGNAL_FUNC) sig_empty);
	signal_add("event notice", (SIGNAL_FUNC) event_notice);
	signal_add("event join", (SIGNAL_FUNC) event_join);
	signal_add("event part", (SIGNAL_FUNC) event_part);
	signal_add("event quit", (SIGNAL_FUNC) event_quit);
	signal_add("event kick", (SIGNAL_FUNC) event_kick);
	signal_add("event nick", (SIGNAL_FUNC) event_nick);
	signal_add("event mode", (SIGNAL_FUNC) event_mode);
	signal_add("event pong", (SIGNAL_FUNC) event_pong);
	signal_add("event invite", (SIGNAL_FUNC) event_invite);
	signal_add("event topic", (SIGNAL_FUNC) event_topic);
	signal_add("event error", (SIGNAL_FUNC) event_error);
	signal_add("event wallops", (SIGNAL_FUNC) event_wallops);

	signal_add("default event", (SIGNAL_FUNC) event_received);

	signal_add("channel sync", (SIGNAL_FUNC) channel_sync);
	signal_add("event connected", (SIGNAL_FUNC) event_connected);
	signal_add("nickfind event whois", (SIGNAL_FUNC) event_nickfind_whois);
	signal_add("ban type changed", (SIGNAL_FUNC) event_ban_type_changed);
	signal_add("whowas event end", (SIGNAL_FUNC) sig_whowas_event_end);

	signal_add("server lag disconnect", (SIGNAL_FUNC) sig_server_lag_disconnected);
	signal_add("server reconnect remove", (SIGNAL_FUNC) sig_server_reconnect_removed);
	signal_add("server reconnect not found", (SIGNAL_FUNC) sig_server_reconnect_not_found);
}

void fe_events_deinit(void)
{
	signal_remove("event privmsg", (SIGNAL_FUNC) event_privmsg);
	signal_remove("ctcp msg", (SIGNAL_FUNC) ctcp_msg_check_action);
	signal_remove("ctcp msg action", (SIGNAL_FUNC) sig_empty);
	signal_remove("event notice", (SIGNAL_FUNC) event_notice);
	signal_remove("event join", (SIGNAL_FUNC) event_join);
	signal_remove("event part", (SIGNAL_FUNC) event_part);
	signal_remove("event quit", (SIGNAL_FUNC) event_quit);
	signal_remove("event kick", (SIGNAL_FUNC) event_kick);
	signal_remove("event nick", (SIGNAL_FUNC) event_nick);
	signal_remove("event mode", (SIGNAL_FUNC) event_mode);
	signal_remove("event pong", (SIGNAL_FUNC) event_pong);
	signal_remove("event invite", (SIGNAL_FUNC) event_invite);
	signal_remove("event topic", (SIGNAL_FUNC) event_topic);
	signal_remove("event error", (SIGNAL_FUNC) event_error);
	signal_remove("event wallops", (SIGNAL_FUNC) event_wallops);

	signal_remove("default event", (SIGNAL_FUNC) event_received);

	signal_remove("channel sync", (SIGNAL_FUNC) channel_sync);
	signal_remove("event connected", (SIGNAL_FUNC) event_connected);
	signal_remove("nickfind event whois", (SIGNAL_FUNC) event_nickfind_whois);
	signal_remove("ban type changed", (SIGNAL_FUNC) event_ban_type_changed);
	signal_remove("whowas event end", (SIGNAL_FUNC) sig_whowas_event_end);

	signal_remove("server lag disconnect", (SIGNAL_FUNC) sig_server_lag_disconnected);
	signal_remove("server reconnect remove", (SIGNAL_FUNC) sig_server_reconnect_removed);
	signal_remove("server reconnect not found", (SIGNAL_FUNC) sig_server_reconnect_not_found);
}
