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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include "signals.h"
#include "levels.h"
#include "misc.h"
#include "special-vars.h"
#include "settings.h"

#include "irc-servers.h"
#include "servers-idle.h"
#include "ignore.h"
#include "ctcp.h"

typedef struct {
	char *name;
        int refcount;
} CTCP_CMD_REC;

static GSList *ctcp_cmds;

static CTCP_CMD_REC *ctcp_cmd_find(const char *name)
{
	GSList *tmp;

	for (tmp = ctcp_cmds; tmp != NULL; tmp = tmp->next) {
		CTCP_CMD_REC *rec = tmp->data;

		if (g_strcasecmp(rec->name, name) == 0)
                        return rec;
	}

        return NULL;
}

void ctcp_register(const char *name)
{
	CTCP_CMD_REC *rec;

	rec = ctcp_cmd_find(name);
	if (rec == NULL) {
		rec = g_new0(CTCP_CMD_REC, 1);
		rec->name = g_ascii_strup(name, -1);

		ctcp_cmds = g_slist_append(ctcp_cmds, rec);
	}

	rec->refcount++;
}

static void ctcp_cmd_destroy(CTCP_CMD_REC *rec)
{
	ctcp_cmds = g_slist_remove(ctcp_cmds, rec);
	g_free(rec->name);
	g_free(rec);
}

void ctcp_unregister(const char *name)
{
	CTCP_CMD_REC *rec;

	rec = ctcp_cmd_find(name);
	if (rec != NULL && --rec->refcount == 0)
                ctcp_cmd_destroy(rec);
}

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
	tag = server_idle_add(server, data);
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

	if (strlen(data) > 100) {
		/* Yes, this is kind of a kludge, but people who PING you
		   with messages this long deserve not to get the reply.

		   The problem with long messages is that when you send lots
		   of data to server, it's input buffer gets full and you get
		   killed from server because of "excess flood".

		   Irssi's current flood protection doesn't count the message
		   length, but even if it did, the CTCP flooder would still
		   be able to at least slow down your possibility to send
		   messages to server. */
                return;
	}

	str = g_strdup_printf("NOTICE %s :\001PING %s\001", nick, data);
	ctcp_send_reply(server, str);
	g_free(str);
}

static void ctcp_send_parsed_reply(IRC_SERVER_REC *server, const char *nick,
				   const char *cmd, const char *args)
{
	char *str, *pstr;

	g_return_if_fail(server != NULL);
	g_return_if_fail(nick != NULL);

	if (*args == '\0')
                return;

	pstr = parse_special_string(args, SERVER(server), NULL, "", NULL, 0);
	str = g_strdup_printf("NOTICE %s :\001%s %s\001", nick, cmd, pstr);
	ctcp_send_reply(server, str);
	g_free(str);
	g_free(pstr);
}

/* CTCP version */
static void ctcp_version(IRC_SERVER_REC *server, const char *data,
			 const char *nick)
{
	ctcp_send_parsed_reply(server, nick, "VERSION",
			       settings_get_str("ctcp_version_reply"));
}

/* CTCP time */
static void ctcp_time(IRC_SERVER_REC *server, const char *data,
		      const char *nick)
{
	char *str, *reply;

	g_return_if_fail(server != NULL);
	g_return_if_fail(nick != NULL);

        reply = my_asctime(time(NULL));
	str = g_strdup_printf("NOTICE %s :\001TIME %s\001", nick, reply);
	ctcp_send_reply(server, str);
	g_free(str);
	g_free(reply);
}

/* CTCP userinfo */
static void ctcp_userinfo(IRC_SERVER_REC *server, const char *data,
			  const char *nick)
{
	ctcp_send_parsed_reply(server, nick, "USERINFO",
			       settings_get_str("ctcp_userinfo_reply"));
}

/* CTCP clientinfo */
static void ctcp_clientinfo(IRC_SERVER_REC *server, const char *data,
			    const char *nick)
{
	GString *str;
        GSList *tmp;

	g_return_if_fail(server != NULL);
	g_return_if_fail(nick != NULL);

	str = g_string_new(NULL);
        g_string_printf(str, "NOTICE %s :\001CLIENTINFO", nick);
	for (tmp = ctcp_cmds; tmp != NULL; tmp = tmp->next) {
		CTCP_CMD_REC *rec = tmp->data;

                g_string_append_c(str, ' ');
                g_string_append(str, rec->name);
	}
	g_string_append_c(str, '\001');

	ctcp_send_reply(server, str->str);
	g_string_free(str, TRUE);
}

static void ctcp_msg(IRC_SERVER_REC *server, const char *data,
		     const char *nick, const char *addr, const char *target)
{
	char *args, *str;

	if (g_ascii_strncasecmp(data, "ACTION ", 7) == 0) {
                /* special treatment for actions */
		signal_emit("ctcp action", 5, server, data+7,
			    nick, addr, target);
                return;
	}

	if (ignore_check(SERVER(server), nick, addr, target, data, MSGLEVEL_CTCPS))
		return;

	str = g_strconcat("ctcp msg ", data, NULL);
	args = strchr(str+9, ' ');
	if (args != NULL) *args++ = '\0'; else args = "";

	ascii_strdown(str+9);
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

	ascii_strdown(str+11);
	if (!signal_emit(str, 5, server, args, nick, addr, target)) {
		signal_emit("default ctcp reply", 5,
			    server, data, nick, addr, target);
	}
	g_free(str);
}

static void event_privmsg(IRC_SERVER_REC *server, const char *data,
			  const char *nick, const char *addr)
{
	char *params, *target, *msg;
	int len;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, &target, &msg);

	/* handle only ctcp messages.. */
	if (*msg == 1) {
		/* remove the \001 at beginning and end */
		msg++;
		len = strlen(msg);
		if (msg[len-1] == '\001')
			msg[len-1] = '\0';

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
        server->ctcpqueue = NULL;
}

void ctcp_init(void)
{
	ctcp_cmds = NULL;

	settings_add_str("misc", "ctcp_version_reply",
			 PACKAGE_TARNAME" v$J - running on $sysname $sysarch");
	settings_add_str("misc", "ctcp_userinfo_reply", "$Y");
	settings_add_int("flood", "max_ctcp_queue", 5);

	signal_add("server disconnected", (SIGNAL_FUNC) sig_disconnected);
	signal_add_first("event privmsg", (SIGNAL_FUNC) event_privmsg);
	signal_add_first("event notice", (SIGNAL_FUNC) event_notice);
	signal_add("ctcp msg", (SIGNAL_FUNC) ctcp_msg);
	signal_add("ctcp reply", (SIGNAL_FUNC) ctcp_reply);
	signal_add("ctcp msg ping", (SIGNAL_FUNC) ctcp_ping);
	signal_add("ctcp msg version", (SIGNAL_FUNC) ctcp_version);
	signal_add("ctcp msg time", (SIGNAL_FUNC) ctcp_time);
	signal_add("ctcp msg userinfo", (SIGNAL_FUNC) ctcp_userinfo);
	signal_add("ctcp msg clientinfo", (SIGNAL_FUNC) ctcp_clientinfo);

        ctcp_register("ping");
        ctcp_register("version");
        ctcp_register("time");
        ctcp_register("userinfo");
        ctcp_register("clientinfo");
}

void ctcp_deinit(void)
{
	while (ctcp_cmds != NULL)
		ctcp_cmd_destroy(ctcp_cmds->data);

	signal_remove("server disconnected", (SIGNAL_FUNC) sig_disconnected);
	signal_remove("event privmsg", (SIGNAL_FUNC) event_privmsg);
	signal_remove("event notice", (SIGNAL_FUNC) event_notice);
	signal_remove("ctcp msg", (SIGNAL_FUNC) ctcp_msg);
	signal_remove("ctcp reply", (SIGNAL_FUNC) ctcp_reply);
	signal_remove("ctcp msg ping", (SIGNAL_FUNC) ctcp_ping);
	signal_remove("ctcp msg version", (SIGNAL_FUNC) ctcp_version);
	signal_remove("ctcp msg time", (SIGNAL_FUNC) ctcp_time);
	signal_remove("ctcp msg userinfo", (SIGNAL_FUNC) ctcp_userinfo);
	signal_remove("ctcp msg clientinfo", (SIGNAL_FUNC) ctcp_clientinfo);
}
