/*
 ctcp.c : irssi

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
#include "signals.h"
#include "levels.h"
#include "special-vars.h"
#include "settings.h"

#include "irc.h"
#include "irc-servers.h"
#include "server-idle.h"
#include "ignore.h"

static void ctcp_queue_clean(IRC_SERVER_REC *server)
{
	GSList *tmp, *next;

	for (tmp = server->ctcpqueue; tmp != NULL; tmp = next) {
		next = tmp->next;
		if (!server_idle_find(server, GPOINTER_TO_INT(tmp->data))) {
			server->ctcpqueue =
				g_slist_remove(server->ctcpqueue, tmp->data);
		}
	}
}

/* Send CTCP reply with flood protection */
void ctcp_send_reply(IRC_SERVER_REC *server, const char *data)
{
	int tag;

	g_return_if_fail(server != NULL);
	g_return_if_fail(data != NULL);

	ctcp_queue_clean(server);

	if ((int)g_slist_length(server->ctcpqueue) >=
	    settings_get_int("max_ctcp_queue"))
		return;

	/* Add to first in idle queue */
	tag = server_idle_add(server, data, NULL, 0, NULL);
	server->ctcpqueue =
		g_slist_append(server->ctcpqueue, GINT_TO_POINTER(tag));
}

/* CTCP ping */
static void ctcp_ping(IRC_SERVER_REC *server, const char *data,
		      const char *nick)
{
	char *str;

	g_return_if_fail(data != NULL);
	g_return_if_fail(server != NULL);
	g_return_if_fail(nick != NULL);

	str = g_strdup_printf("NOTICE %s :\001PING %s\001", nick, data);
	ctcp_send_reply(server, str);
	g_free(str);
}

/* CTCP version */
static void ctcp_version(IRC_SERVER_REC *server, const char *data,
			 const char *nick)
{
	char *str, *reply;

	g_return_if_fail(server != NULL);
	g_return_if_fail(nick != NULL);

	reply = parse_special_string(settings_get_str("ctcp_version_reply"),
				     SERVER(server), NULL, "", NULL);
	str = g_strdup_printf("NOTICE %s :\001VERSION %s\001", nick, reply);
	ctcp_send_reply(server, str);
	g_free(str);
	g_free(reply);
}

/* CTCP version */
static void ctcp_time(IRC_SERVER_REC *server, const char *data,
		      const char *nick)
{
	char *str, *reply;
	struct tm *tm;
	time_t t;

	g_return_if_fail(server != NULL);
	g_return_if_fail(nick != NULL);

        t = time(NULL);
	tm = localtime(&t);
	reply = g_strdup(asctime(tm));
	if (reply[strlen(reply)-1] == '\n') reply[strlen(reply)-1] = '\0';

	str = g_strdup_printf("NOTICE %s :\001TIME %s\001", nick, reply);
	ctcp_send_reply(server, str);
	g_free(str);
	g_free(reply);
}

static void ctcp_msg(IRC_SERVER_REC *server, const char *data,
		     const char *nick, const char *addr, const char *target)
{
	char *args, *str;

	if (ignore_check(SERVER(server), nick, addr, target, data, MSGLEVEL_CTCPS))
		return;

	str = g_strconcat("ctcp msg ", data, NULL);
	args = strchr(str+9, ' ');
	if (args != NULL) *args++ = '\0'; else args = "";

	g_strdown(str+9);
	if (!signal_emit(str, 5, server, args, nick, addr, target)) {
		signal_emit("default ctcp msg", 5,
			    server, data, nick, addr, target);
	}
	g_free(str);
}

static void ctcp_reply(IRC_SERVER_REC *server, const char *data,
		       const char *nick, const char *addr, const char *target)
{
	char *args, *str;

	if (ignore_check(SERVER(server), nick, addr, target, data, MSGLEVEL_CTCPS))
		return;

	str = g_strconcat("ctcp reply ", data, NULL);
	args = strchr(str+11, ' ');
	if (args != NULL) *args++ = '\0'; else args = "";

	g_strdown(str+11);
	if (!signal_emit(str, 5, server, args, nick, addr, target)) {
		signal_emit("default ctcp reply", 5,
			    server, data, nick, addr, target);
	}
	g_free(str);
}

static void event_privmsg(IRC_SERVER_REC *server, const char *data,
			  const char *nick, const char *addr)
{
	char *params, *target, *msg, *ptr;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, &target, &msg);

	/* handle only ctcp messages.. */
	if (*msg == 1) {
		/* remove the later \001 */
		ptr = strrchr(++msg, 1);
		if (ptr != NULL) *ptr = '\0';

		signal_emit("ctcp msg", 5, server, msg, nick, addr, target);
		signal_stop();
	}

	g_free(params);
}

static void event_notice(IRC_SERVER_REC *server, const char *data,
			 const char *nick, const char *addr)
{
	char *params, *target, *ptr, *msg;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, &target, &msg);

	/* handle only ctcp replies */
	if (*msg == 1) {
		ptr = strrchr(++msg, 1);
		if (ptr != NULL) *ptr = '\0';

		signal_emit("ctcp reply", 5, server, msg, nick, addr, target);
		signal_stop();
	}

	g_free(params);
}

static void sig_disconnected(IRC_SERVER_REC *server)
{
	g_return_if_fail(server != NULL);

	if (!IS_IRC_SERVER(server))
		return;

	g_slist_free(server->ctcpqueue);
}

void ctcp_init(void)
{
	settings_add_str("misc", "ctcp_version_reply",
			 PACKAGE" v$J - running on $sysname");
	settings_add_int("flood", "max_ctcp_queue", 5);

	signal_add("server disconnected", (SIGNAL_FUNC) sig_disconnected);
	signal_add_first("event privmsg", (SIGNAL_FUNC) event_privmsg);
	signal_add_first("event notice", (SIGNAL_FUNC) event_notice);
	signal_add("ctcp msg", (SIGNAL_FUNC) ctcp_msg);
	signal_add("ctcp reply", (SIGNAL_FUNC) ctcp_reply);
	signal_add("ctcp msg ping", (SIGNAL_FUNC) ctcp_ping);
	signal_add("ctcp msg version", (SIGNAL_FUNC) ctcp_version);
	signal_add("ctcp msg time", (SIGNAL_FUNC) ctcp_time);
}

void ctcp_deinit(void)
{
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_disconnected);
	signal_remove("event privmsg", (SIGNAL_FUNC) event_privmsg);
	signal_remove("event notice", (SIGNAL_FUNC) event_notice);
	signal_remove("ctcp msg", (SIGNAL_FUNC) ctcp_msg);
	signal_remove("ctcp reply", (SIGNAL_FUNC) ctcp_reply);
	signal_remove("ctcp msg ping", (SIGNAL_FUNC) ctcp_ping);
	signal_remove("ctcp msg version", (SIGNAL_FUNC) ctcp_version);
	signal_remove("ctcp msg time", (SIGNAL_FUNC) ctcp_time);
}
