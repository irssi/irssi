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
#include "fe-windows.h"
#include "printtext.h"

#include "completion.h"

static void event_privmsg(const char *data, IRC_SERVER_REC *server,
			  const char *nick, const char *addr)
{
	char *params, *target, *msg;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST, &target, &msg);
	if (nick == NULL) nick = server->real_address;
	if (addr == NULL) addr = "";

	signal_emit(ischannel(*target) ?
		    "message public" : "message private", 5,
		    server, msg, nick, addr, target);

	g_free(params);
}

/* we use "ctcp msg" here because "ctcp msg action" can be ignored with
   /IGNORE * CTCPS, and we don't want that.. */
static void ctcp_msg_check_action(const char *data, IRC_SERVER_REC *server,
				  const char *nick, const char *addr,
				  const char *target)
{
	void *item;
	int level;

	g_return_if_fail(data != NULL);

	if (g_strncasecmp(data, "ACTION ", 7) != 0)
		return;
	data += 7;

	level = MSGLEVEL_ACTIONS |
		(ischannel(*target) ? MSGLEVEL_PUBLIC : MSGLEVEL_MSGS);
	if (ignore_check(SERVER(server), nick, addr, target, data, level))
		return;

	if (ischannel(*target)) {
		/* channel action */
		item = irc_channel_find(server, target);

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
		item = privmsg_get_query(SERVER(server), nick, FALSE, MSGLEVEL_MSGS);
		printformat(server, nick, level,
			    item == NULL ? IRCTXT_ACTION_PRIVATE : IRCTXT_ACTION_PRIVATE_QUERY,
			    nick, addr == NULL ? "" : addr, data);
	}
}

static void event_notice(const char *data, IRC_SERVER_REC *server,
			 const char *nick, const char *addr)
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
		if (*msg != 1 && !ignore_check(SERVER(server), nick, "", target, msg, MSGLEVEL_SNOTES))
			printformat(server, target, MSGLEVEL_SNOTES, IRCTXT_NOTICE_SERVER, nick, msg);
	} else {
		op_notice = *target == '@' && ischannel(target[1]);
		if (op_notice) target++;

		if (ignore_check(SERVER(server), nick, addr, ischannel(*target) ?
				 target : NULL, msg, MSGLEVEL_NOTICES))
			return;

		if (ischannel(*target)) {
			/* notice in some channel */
			printformat(server, target, MSGLEVEL_NOTICES,
				    op_notice ? IRCTXT_NOTICE_PUBLIC_OPS : IRCTXT_NOTICE_PUBLIC,
				    nick, target, msg);
		} else {
			/* private notice */
			privmsg_get_query(SERVER(server), nick, FALSE, MSGLEVEL_NOTICES);
			printformat(server, nick, MSGLEVEL_NOTICES, IRCTXT_NOTICE_PRIVATE, nick, addr, msg);
		}
	}

	g_free(params);
}

static void event_join(const char *data, IRC_SERVER_REC *server,
		       const char *nick, const char *addr)
{
	char *params, *channel, *tmp;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 1, &channel);
	tmp = strchr(channel, 7); /* ^G does something weird.. */
	if (tmp != NULL) *tmp = '\0';

	signal_emit("message join", 4, server, channel, nick, addr);
	g_free(params);
}

static void event_part(const char *data, IRC_SERVER_REC *server,
		       const char *nick, const char *addr)
{
	char *params, *channel, *reason;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST,
				  &channel, &reason);
	signal_emit("message part", 5, server, channel, nick, addr, reason);
	g_free(params);
}

static void event_quit(const char *data, IRC_SERVER_REC *server,
		       const char *nick, const char *addr)
{
	g_return_if_fail(data != NULL);

	if (*data == ':') data++; /* quit message */
	signal_emit("message quit", 4, server, nick, addr, data);
}

static void event_kick(const char *data, IRC_SERVER_REC *server,
		       const char *kicker, const char *addr)
{
	char *params, *channel, *nick, *reason;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3 | PARAM_FLAG_GETREST,
				  &channel, &nick, &reason);
	signal_emit("message kick", 6, server, channel, nick,
		    kicker, addr, reason);
	g_free(params);
}

static void event_kill(const char *data, IRC_SERVER_REC *server,
		       const char *nick, const char *addr)
{
	char *params, *path, *reason;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST,
				  NULL, &path);
	reason = strstr(path, " (");
	if (reason == NULL || reason[strlen(reason)-1] != ')') {
		/* weird server, maybe it didn't give path */
                reason = path;
		path = "";
	} else {
		/* reason inside (...) */
		*reason = '\0';
		reason += 2;
		reason[strlen(reason)-1] = '\0';
	}

	if (addr != NULL) {
		printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_KILL,
			    nick, addr, reason, path);
	} else {
		printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_KILL_SERVER,
			    nick, reason, path);
	}

	g_free(params);
}

static void event_nick(const char *data, IRC_SERVER_REC *server,
		       const char *sender, const char *addr)
{
	char *params, *newnick;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 1, &newnick);

	signal_emit(g_strcasecmp(sender, server->nick) == 0 ?
		    "message own_nick" : "message nick", 4,
		    server, newnick, sender, addr);

	g_free(params);
}

static void event_mode(const char *data, IRC_SERVER_REC *server,
		       const char *nick, const char *addr)
{
	char *params, *channel, *mode;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST,
				  &channel, &mode);

	signal_emit("message mode", 5, server, channel, nick, addr,
		    g_strchomp(mode));
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

static void event_invite(const char *data, IRC_SERVER_REC *server,
			 const char *nick, const char *addr)
{
	char *params, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);
	signal_emit("message invite", 4, server, channel, nick, addr);
	g_free(params);
}

static void event_topic(const char *data, IRC_SERVER_REC *server,
			const char *nick, const char *addr)
{
	char *params, *channel, *topic;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST,
				  &channel, &topic);
	signal_emit("message topic", 5, server, channel, topic, nick, addr);
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
	if (ignore_check(SERVER(server), nick, addr, NULL, data, MSGLEVEL_WALLOPS))
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

static void event_silence(const char *data, IRC_SERVER_REC *server, const char *nick, const char *addr)
{
	g_return_if_fail(data != NULL);

	g_return_if_fail(*data == '+' || *data == '-');

	printformat(server, NULL, MSGLEVEL_CRAP, *data == '+' ? IRCTXT_SILENCED : IRCTXT_UNSILENCED, data+1);
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

	nick = settings_get_str("nick");
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

static void sig_whois_event_no_server(const char *data, IRC_SERVER_REC *server)
{
	char *params, *nick;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &nick);
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_WHOIS_NOT_FOUND, nick);
	g_free(params);
}

static void sig_whowas_event_end(const char *data, IRC_SERVER_REC *server,
				 const char *sender, const char *addr)
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
	signal_add("event kill", (SIGNAL_FUNC) event_kill);
	signal_add("event nick", (SIGNAL_FUNC) event_nick);
	signal_add("event mode", (SIGNAL_FUNC) event_mode);
	signal_add("event pong", (SIGNAL_FUNC) event_pong);
	signal_add("event invite", (SIGNAL_FUNC) event_invite);
	signal_add("event topic", (SIGNAL_FUNC) event_topic);
	signal_add("event error", (SIGNAL_FUNC) event_error);
	signal_add("event wallops", (SIGNAL_FUNC) event_wallops);
	signal_add("event silence", (SIGNAL_FUNC) event_silence);

	signal_add("default event", (SIGNAL_FUNC) event_received);

	signal_add("channel sync", (SIGNAL_FUNC) channel_sync);
	signal_add("event connected", (SIGNAL_FUNC) event_connected);
	signal_add("nickfind event whois", (SIGNAL_FUNC) event_nickfind_whois);
	signal_add("ban type changed", (SIGNAL_FUNC) event_ban_type_changed);
	signal_add("whois event noserver", (SIGNAL_FUNC) sig_whois_event_no_server);
	signal_add("whowas event end", (SIGNAL_FUNC) sig_whowas_event_end);
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
	signal_remove("event kill", (SIGNAL_FUNC) event_kill);
	signal_remove("event nick", (SIGNAL_FUNC) event_nick);
	signal_remove("event mode", (SIGNAL_FUNC) event_mode);
	signal_remove("event pong", (SIGNAL_FUNC) event_pong);
	signal_remove("event invite", (SIGNAL_FUNC) event_invite);
	signal_remove("event topic", (SIGNAL_FUNC) event_topic);
	signal_remove("event error", (SIGNAL_FUNC) event_error);
	signal_remove("event wallops", (SIGNAL_FUNC) event_wallops);
	signal_remove("event silence", (SIGNAL_FUNC) event_silence);

	signal_remove("default event", (SIGNAL_FUNC) event_received);

	signal_remove("channel sync", (SIGNAL_FUNC) channel_sync);
	signal_remove("event connected", (SIGNAL_FUNC) event_connected);
	signal_remove("nickfind event whois", (SIGNAL_FUNC) event_nickfind_whois);
	signal_remove("ban type changed", (SIGNAL_FUNC) event_ban_type_changed);
	signal_remove("whois event noserver", (SIGNAL_FUNC) sig_whois_event_no_server);
	signal_remove("whowas event end", (SIGNAL_FUNC) sig_whowas_event_end);
}
