/*
 notify-ison.c : irssi

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
#include <irssi/src/core/signals.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/settings.h>

#include <irssi/src/irc/core/irc.h>
#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/irc/core/servers-redirect.h>

#include <irssi/src/irc/notifylist/notifylist.h>

#define DEFAULT_NOTIFY_CHECK_TIME "1min"
#define DEFAULT_NOTIFY_WHOIS_TIME "5min"

static int notify_tag;
static int notify_whois_time;

NOTIFY_NICK_REC *notify_nick_create(IRC_SERVER_REC *server, const char *nick)
{
	MODULE_SERVER_REC *mserver;
	NOTIFY_NICK_REC *rec;

	mserver = MODULE_DATA(server);

	rec = g_new0(NOTIFY_NICK_REC, 1);
	rec->nick = g_strdup(nick);

	mserver->notify_users = g_slist_append(mserver->notify_users, rec);
	return rec;
}

void notify_nick_destroy(NOTIFY_NICK_REC *rec)
{
	g_free(rec->nick);
	g_free_not_null(rec->user);
	g_free_not_null(rec->host);
	g_free_not_null(rec->realname);
	g_free_not_null(rec->awaymsg);
	g_free(rec);
}

NOTIFY_NICK_REC *notify_nick_find(IRC_SERVER_REC *server, const char *nick)
{
	MODULE_SERVER_REC *mserver;
	NOTIFY_NICK_REC *rec;
	GSList *tmp;

	mserver = MODULE_DATA(server);
	for (tmp = mserver->notify_users; tmp != NULL; tmp = tmp->next) {
		rec = tmp->data;

		if (g_ascii_strcasecmp(rec->nick, nick) == 0)
			return rec;
	}

	return NULL;
}

static void ison_send(IRC_SERVER_REC *server, GString *cmd)
{
	MODULE_SERVER_REC *mserver;

	if (!server->connected) {
		return;
	}

	mserver = MODULE_DATA(server);
	mserver->ison_count++;

	g_string_truncate(cmd, cmd->len-1);
	g_string_prepend(cmd, "ISON :");

	server_redirect_event(server, "ison", 1, NULL, -1, NULL,
			      "event 303", "notifylist event", NULL);
	irc_send_cmd_later(server, cmd->str);

	g_string_truncate(cmd, 0);
}

/* timeout function: send /ISON commands to server to check if someone in
   notify list is in IRC */
static void notifylist_timeout_server(IRC_SERVER_REC *server)
{
	MODULE_SERVER_REC *mserver;
	GSList *tmp;
	GString *cmd;
	char *nick, *ptr;
	int len;

	g_return_if_fail(server != NULL);

	if (!IS_IRC_SERVER(server))
		return;

	mserver = MODULE_DATA(server);
	if (mserver->ison_count > 0) {
		/* still not received all replies to previous /ISON commands.. */
		return;
	}

	cmd = g_string_new(NULL);
	for (tmp = notifies; tmp != NULL; tmp = tmp->next) {
		NOTIFYLIST_REC *rec = tmp->data;

		if (!notifylist_ircnets_match(rec, server->connrec->chatnet))
                        continue;

		nick = g_strdup(rec->mask);
		ptr = strchr(nick, '!');
		if (ptr != NULL) *ptr = '\0';

		len = strlen(nick);

		if (cmd->len+len+1 > server->max_message_len)
                        ison_send(server, cmd);

		g_string_append_printf(cmd, "%s ", nick);
		g_free(nick);
	}

	if (cmd->len > 0)
		ison_send(server, cmd);
	g_string_free(cmd, TRUE);
}

static int notifylist_timeout_func(void)
{
	g_slist_foreach(servers, (GFunc) notifylist_timeout_server, NULL);
	return 1;
}

static void ison_save_users(MODULE_SERVER_REC *mserver, char *online)
{
	char *ptr;

	while (online != NULL && *online != '\0') {
		ptr = strchr(online, ' ');
		if (ptr != NULL) *ptr++ = '\0';

		mserver->ison_tempusers =
			g_slist_append(mserver->ison_tempusers, g_strdup(online));
		online = ptr;
	}
}

static void whois_send(IRC_SERVER_REC *server, const char *nicks,
		       const char *whois_request)
{
	char *p, *str;

	/* "nick1,nick2" -> "nick1,nick2 nick1 nick2" because
	   End of WHOIS give nick1,nick2 while other whois events give
	   nick1 or nick2 */
        str = g_strconcat(nicks, " ", nicks, NULL);
	for (p = str+strlen(nicks)+1; *p != '\0'; p++)
		if (*p == ',') *p = ' ';

	server_redirect_event(server, "whois", 1, str, TRUE,
                              "notifylist event whois end",
			      "event 318", "notifylist event whois end",
			      "event 311", "notifylist event whois",
			      "event 301", "notifylist event whois away",
			      "", "event empty", NULL);
	g_free(str);

	str = g_strdup_printf("WHOIS %s", whois_request);
	irc_send_cmd_later(server, str);
	g_free(str);
}

static void whois_send_server(IRC_SERVER_REC *server, char *nick)
{
	char *str;

	str = g_strdup_printf("%s %s", nick, nick);
	whois_send(server, nick, str);
	g_free(str);
}

/* try to send as many nicks in one WHOIS as possible */
static void whois_list_send(IRC_SERVER_REC *server, GSList *nicks)
{
	GSList *tmp;
	GString *str;
	char *nick;
        int count;

	str = g_string_new(NULL);
	count = 0;

	for (tmp = nicks; tmp != NULL; tmp = tmp->next) {
		nick = tmp->data;

		count++;
		g_string_append_printf(str, "%s,", nick);

		if (count >= server->max_whois_in_cmd) {
			g_string_truncate(str, str->len-1);
			whois_send(server, str->str, str->str);
			g_string_truncate(str, 0);
                        count = 0;
		}
	}

	if (str->len > 0) {
		g_string_truncate(str, str->len-1);
		whois_send(server, str->str, str->str);
	}

	g_string_free(str, TRUE);
}

static void ison_check_joins(IRC_SERVER_REC *server)
{
	MODULE_SERVER_REC *mserver;
	NOTIFYLIST_REC *notify;
	NOTIFY_NICK_REC *rec;
	GSList *tmp, *newnicks;
	int send_whois;
	time_t now;

	mserver = MODULE_DATA(server);

	now = time(NULL);
	newnicks = NULL;
	for (tmp = mserver->ison_tempusers; tmp != NULL; tmp = tmp->next) {
		char *nick = tmp->data;

		notify = notifylist_find(nick, server->connrec->chatnet);
		send_whois = notify != NULL && notify->away_check;

		rec = notify_nick_find(server, nick);
		if (rec != NULL) {
			/* check if we want to send WHOIS yet.. */
			if (now-rec->last_whois < notify_whois_time)
				continue;
		} else {
			rec = notify_nick_create(server, nick);
			if (!send_whois) newnicks = g_slist_append(newnicks, nick);
		}

		if (send_whois) {
			/* we need away message -
			   send the WHOIS reply to the nick's server */
                        rec->last_whois = now;
			whois_send_server(server, nick);
		}
	}

	whois_list_send(server, newnicks);
	g_slist_free(newnicks);
}

static void ison_check_parts(IRC_SERVER_REC *server)
{
	MODULE_SERVER_REC *mserver;
	GSList *tmp, *next;

	mserver = MODULE_DATA(server);
	for (tmp = mserver->notify_users; tmp != NULL; tmp = next) {
		NOTIFY_NICK_REC *rec = tmp->data;
		next = tmp->next;

		if (i_slist_find_icase_string(mserver->ison_tempusers, rec->nick) != NULL)
			continue;

                notifylist_left(server, rec);
	}
}

static void event_ison(IRC_SERVER_REC *server, const char *data)
{
	MODULE_SERVER_REC *mserver;
	char *params, *online;

	g_return_if_fail(data != NULL);
	g_return_if_fail(server != NULL);

	params = event_get_params(data, 2, NULL, &online);

	mserver = MODULE_DATA(server);
	ison_save_users(mserver, online);

	if (--mserver->ison_count > 0) {
		/* wait for the rest of the /ISON replies */
		g_free(params);
                return;
	}

        ison_check_joins(server);
        ison_check_parts(server);

	/* free memory used by temp list */
	g_slist_foreach(mserver->ison_tempusers, (GFunc) g_free, NULL);
	g_slist_free(mserver->ison_tempusers);
	mserver->ison_tempusers = NULL;

	g_free(params);
}

static void read_settings(void)
{
	if (notify_tag != -1) g_source_remove(notify_tag);
	notify_tag = g_timeout_add(settings_get_time("notify_check_time"),
				   (GSourceFunc) notifylist_timeout_func, NULL);

	notify_whois_time = settings_get_time("notify_whois_time")/1000;
}

void notifylist_ison_init(void)
{
	settings_add_time("misc", "notify_check_time", DEFAULT_NOTIFY_CHECK_TIME);
	settings_add_time("misc", "notify_whois_time", DEFAULT_NOTIFY_WHOIS_TIME);

	notify_tag = -1;
	read_settings();

	signal_add("notifylist event", (SIGNAL_FUNC) event_ison);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
}

void notifylist_ison_deinit(void)
{
	g_source_remove(notify_tag);

	signal_remove("notifylist event", (SIGNAL_FUNC) event_ison);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
}
