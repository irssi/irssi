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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include "module-formats.h"
#include "signals.h"
#include "misc.h"
#include "settings.h"

#include "levels.h"
#include "servers.h"
#include "servers-redirect.h"
#include "servers-reconnect.h"
#include "queries.h"
#include "ignore.h"
#include "recode.h"

#include "irc-servers.h"
#include "irc-channels.h"
#include "irc-nicklist.h"
#include "irc-masks.h"

#include "printtext.h"
#include "fe-queries.h"
#include "fe-windows.h"
#include "fe-irc-server.h"

static void event_privmsg(IRC_SERVER_REC *server, const char *data,
			  const char *nick, const char *addr)
{
	char *params, *target, *msg, *recoded;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST, &target, &msg);
	if (nick == NULL) nick = server->real_address;
	if (addr == NULL) addr = "";
	if (*target == '@' && ischannel(target[1])) {
		/* Hybrid 6 feature, send msg to all ops in channel */
		recoded = recode_in(SERVER(server), msg, target+1);
		signal_emit("message irc op_public", 5,
			    server, recoded, nick, addr,
			    get_visible_target(server, target+1));
	} else {
		recoded = recode_in(SERVER(server), msg, ischannel(*target) ? target : nick);
		signal_emit(ischannel(*target) ?
			    "message public" : "message private", 5,
			    server, recoded, nick, addr,
			    get_visible_target(server, target));
	}

	g_free(params);
	g_free(recoded);
}

static void ctcp_action(IRC_SERVER_REC *server, const char *data,
			const char *nick, const char *addr,
			const char *target)
{
	char *recoded;

	g_return_if_fail(data != NULL);
	recoded = recode_in(SERVER(server), data, target);
	signal_emit("message irc action", 5,
		    server, recoded, nick, addr,
		    get_visible_target(server, target));
	g_free(recoded);
}

static void event_notice(IRC_SERVER_REC *server, const char *data,
			 const char *nick, const char *addr)
{
	char *params, *target, *msg, *recoded;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST, &target, &msg);
	recoded = recode_in(SERVER(server), msg, target);
	if (nick == NULL) {
		nick = server->real_address == NULL ?
			server->connrec->address :
			server->real_address;
	}

	signal_emit("message irc notice", 5, server, recoded, nick, addr,
		    get_visible_target(server, target));
	g_free(params);
	g_free(recoded);
}

static void event_join(IRC_SERVER_REC *server, const char *data,
		       const char *nick, const char *addr)
{
	char *params, *channel, *tmp;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 1, &channel);
	tmp = strchr(channel, 7); /* ^G does something weird.. */
	if (tmp != NULL) *tmp = '\0';

	signal_emit("message join", 4, server,
		    get_visible_target(server, channel), nick, addr);
	g_free(params);
}

static void event_part(IRC_SERVER_REC *server, const char *data,
		       const char *nick, const char *addr)
{
	char *params, *channel, *reason, *recoded;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST,
				  &channel, &reason);
	recoded = recode_in(SERVER(server), reason, channel);
	signal_emit("message part", 5, server,
		    get_visible_target(server, channel), nick, addr, recoded);
	g_free(params);
	g_free(recoded);
}

static void event_quit(IRC_SERVER_REC *server, const char *data,
		       const char *nick, const char *addr)
{
	char *recoded;

	g_return_if_fail(data != NULL);

	if (*data == ':') data++; /* quit message */
	recoded = recode_in(SERVER(server), data, nick);
	signal_emit("message quit", 4, server, nick, addr, recoded);
	g_free(recoded);
}

static void event_kick(IRC_SERVER_REC *server, const char *data,
		       const char *kicker, const char *addr)
{
	char *params, *channel, *nick, *reason, *recoded;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3 | PARAM_FLAG_GETREST,
				  &channel, &nick, &reason);
	recoded = recode_in(SERVER(server), reason, channel);
	signal_emit("message kick", 6,
		    server, get_visible_target(server, channel),
		    nick, kicker, addr, recoded);
	g_free(params);
	g_free(recoded);
}

static void event_kill(IRC_SERVER_REC *server, const char *data,
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

static void event_nick(IRC_SERVER_REC *server, const char *data,
		       const char *sender, const char *addr)
{
	char *params, *newnick;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 1, &newnick);

	/* NOTE: server->nick was already changed in irc/core/irc-nicklist.c */
	signal_emit(g_strcasecmp(newnick, server->nick) == 0 ?
		    "message own_nick" : "message nick", 4,
		    server, newnick, sender, addr);

	g_free(params);
}

static void event_mode(IRC_SERVER_REC *server, const char *data,
		       const char *nick, const char *addr)
{
	char *params, *channel, *mode;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST,
				  &channel, &mode);

	signal_emit("message irc mode", 5,
		    server, get_visible_target(server, channel),
		    nick, addr, g_strchomp(mode));
	g_free(params);
}

static void event_pong(IRC_SERVER_REC *server, const char *data, const char *nick)
{
	char *params, *host, *reply;

	g_return_if_fail(data != NULL);
	if (nick == NULL) nick = server->real_address;

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST, &host, &reply);
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_PONG, host, reply);
	g_free(params);
}

static void event_invite(IRC_SERVER_REC *server, const char *data,
			 const char *nick, const char *addr)
{
	char *params, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);
	signal_emit("message invite", 4,
		    server, get_visible_target(server, channel), nick, addr);
	g_free(params);
}

static void event_topic(IRC_SERVER_REC *server, const char *data,
			const char *nick, const char *addr)
{
	char *params, *channel, *topic, *recoded;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST,
				  &channel, &topic);
	recoded = recode_in(SERVER(server), topic, channel);
	signal_emit("message topic", 5, server,
		    get_visible_target(server, channel), recoded, nick, addr);
	g_free(params);
	g_free(recoded);
}

static void event_error(IRC_SERVER_REC *server, const char *data)
{
	g_return_if_fail(data != NULL);

	if (*data == ':') data++;
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_ERROR, data);
}

static void event_wallops(IRC_SERVER_REC *server, const char *data, const char *nick, const char *addr)
{
	g_return_if_fail(data != NULL);

	if (*data == ':') data++;
	if (ignore_check(SERVER(server), nick, addr, NULL, data, MSGLEVEL_WALLOPS))
		return;

	if (g_ascii_strncasecmp(data, "\001ACTION ", 8) != 0)
		printformat(server, NULL, MSGLEVEL_WALLOPS, IRCTXT_WALLOPS, nick, data);
	else {
		/* Action in WALLOP */
		int len;
		char *tmp;

		tmp = g_strdup(data+8);
		len = strlen(tmp);
		if (len >= 1 && tmp[len-1] == 1) tmp[len-1] = '\0';
		printformat(server, NULL, MSGLEVEL_WALLOPS, IRCTXT_ACTION_WALLOPS, nick, tmp);
		g_free(tmp);
	}
}

static void event_silence(IRC_SERVER_REC *server, const char *data, const char *nick, const char *addr)
{
	g_return_if_fail(data != NULL);

	g_return_if_fail(*data == '+' || *data == '-');

	printformat(server, NULL, MSGLEVEL_CRAP, *data == '+' ? IRCTXT_SILENCED : IRCTXT_UNSILENCED, data+1);
}

static void channel_sync(CHANNEL_REC *channel)
{
	g_return_if_fail(channel != NULL);

	printformat(channel->server, channel->visible_name,
		    MSGLEVEL_CLIENTNOTICE|MSGLEVEL_NO_ACT,
		    IRCTXT_CHANNEL_SYNCED, channel->visible_name,
		    (long) (time(NULL)-channel->createtime));
}

static void event_connected(IRC_SERVER_REC *server)
{
	const char *nick;

	g_return_if_fail(server != NULL);

        nick = server->connrec->nick;
	if (g_strcasecmp(server->nick, nick) == 0)
		return;

	/* someone has our nick, find out who. */
	server_redirect_event(server, "whois", 1, nick, TRUE, NULL,
			      "event 311", "nickfind event whois",
			      "", "event empty", NULL);
	irc_send_cmdv(server, "WHOIS %s", nick);
}

static void event_nickfind_whois(IRC_SERVER_REC *server, const char *data)
{
	char *params, *nick, *user, *host, *realname;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 6, NULL, &nick, &user, &host, NULL, &realname);
	printformat(server, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_YOUR_NICK_OWNED, nick, user, host, realname);
	g_free(params);
}

static void event_ban_type_changed(void *ban_typep)
{
	GString *str;
	int ban_type;

	ban_type = GPOINTER_TO_INT(ban_typep);

	if (ban_type == 0) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			    IRCTXT_BANTYPE, "Error, using Normal");
                return;
	}

	if (ban_type == (IRC_MASK_USER|IRC_MASK_DOMAIN)) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
			    IRCTXT_BANTYPE, "Normal");
	} else if (ban_type == (IRC_MASK_HOST|IRC_MASK_DOMAIN)) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
			    IRCTXT_BANTYPE, "Host");
	} else if (ban_type == IRC_MASK_DOMAIN) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
			    IRCTXT_BANTYPE, "Domain");
	} else {
		str = g_string_new("Custom:");
		if (ban_type & IRC_MASK_NICK)
			g_string_append(str, " Nick");
		if (ban_type & IRC_MASK_USER)
			g_string_append(str, " User");
		if (ban_type & IRC_MASK_HOST)
			g_string_append(str, " Host");
		if (ban_type & IRC_MASK_DOMAIN)
			g_string_append(str, " Domain");

		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
			    IRCTXT_BANTYPE, str->str);
		g_string_free(str, TRUE);
	}
}

static void sig_whois_event_not_found(IRC_SERVER_REC *server, const char *data)
{
	char *params, *nick;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &nick);
	printformat(server, nick, MSGLEVEL_CRAP, IRCTXT_WHOIS_NOT_FOUND, nick);
	g_free(params);
}

static void sig_whowas_event_end(IRC_SERVER_REC *server, const char *data,
				 const char *sender, const char *addr)
{
	char *params, *nick;

	g_return_if_fail(data != NULL);

	if (server->whowas_found) {
		signal_emit("event 369", 4, server, data, sender, addr);
		return;
	}

	params = event_get_params(data, 2, NULL, &nick);
	printformat(server, nick, MSGLEVEL_CRAP, IRCTXT_WHOIS_NOT_FOUND, nick);
	g_free(params);
}

static void event_received(IRC_SERVER_REC *server, const char *data,
			   const char *nick, const char *addr)
{
	if (!i_isdigit(*data)) {
		printtext(server, NULL, MSGLEVEL_CRAP, "%s", data);
		return;
	}

	/* numeric event. */
        signal_emit("default event numeric", 4, server, data, nick, addr);
}

void fe_events_init(void)
{
	signal_add("event privmsg", (SIGNAL_FUNC) event_privmsg);
	signal_add("ctcp action", (SIGNAL_FUNC) ctcp_action);
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
	signal_add("whois event not found", (SIGNAL_FUNC) sig_whois_event_not_found);
	signal_add("whowas event end", (SIGNAL_FUNC) sig_whowas_event_end);
}

void fe_events_deinit(void)
{
	signal_remove("event privmsg", (SIGNAL_FUNC) event_privmsg);
	signal_remove("ctcp action", (SIGNAL_FUNC) ctcp_action);
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
	signal_remove("whois event not found", (SIGNAL_FUNC) sig_whois_event_not_found);
	signal_remove("whowas event end", (SIGNAL_FUNC) sig_whowas_event_end);
}
