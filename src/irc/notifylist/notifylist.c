/*
 notifylist.c : irssi

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
#include "modules.h"
#include "signals.h"
#include "settings.h"

#include "irc.h"
#include "irc-channels.h"
#include "servers-redirect.h"
#include "masks.h"
#include "nicklist.h"

#include "notifylist.h"
#include "notify-setup.h"

GSList *notifies;

NOTIFYLIST_REC *notifylist_add(const char *mask, const char *ircnets,
			       int away_check)
{
	NOTIFYLIST_REC *rec;

	g_return_val_if_fail(mask != NULL, NULL);

	rec = g_new0(NOTIFYLIST_REC, 1);
        rec->mask = g_strdup(mask);
	rec->ircnets = ircnets == NULL || *ircnets == '\0' ? NULL :
		g_strsplit(ircnets, " ", -1);
	rec->away_check = away_check;

        notifylist_add_config(rec);

        notifies = g_slist_append(notifies, rec);
	signal_emit("notifylist new", 1, rec);
	return rec;
}

static void notify_destroy(NOTIFYLIST_REC *rec)
{
	if (rec->ircnets != NULL) g_strfreev(rec->ircnets);
	g_free(rec->mask);
        g_free(rec);
}

void notifylist_destroy_all(void)
{
	g_slist_foreach(notifies, (GFunc) notify_destroy, NULL);
	g_slist_free(notifies);

	notifies = NULL;
}

void notifylist_remove(const char *mask)
{
	NOTIFYLIST_REC *rec;

	g_return_if_fail(mask != NULL);

	rec = notifylist_find(mask, "*");
	if (rec == NULL) return;

	notifylist_remove_config(rec);
	notifies = g_slist_remove(notifies, rec);
	signal_emit("notifylist remove", 1, rec);

        notify_destroy(rec);
}

int notifylist_ircnets_match(NOTIFYLIST_REC *rec, const char *ircnet)
{
	char **tmp;

	if (rec->ircnets == NULL) return TRUE;
	if (ircnet == NULL) return FALSE;
	if (strcmp(ircnet, "*") == 0) return TRUE;

	for (tmp = rec->ircnets; *tmp != NULL; tmp++) {
		if (g_strcasecmp(*tmp, ircnet) == 0)
			return TRUE;
	}

	return FALSE;
}

NOTIFYLIST_REC *notifylist_find(const char *mask, const char *ircnet)
{
	NOTIFYLIST_REC *best;
	GSList *tmp;
	int len;

	best = NULL;
	len = strlen(mask);
	for (tmp = notifies; tmp != NULL; tmp = tmp->next) {
		NOTIFYLIST_REC *rec = tmp->data;

		/* check mask */
		if (g_strncasecmp(rec->mask, mask, len) != 0 ||
		    (rec->mask[len] != '\0' && rec->mask[len] != '!')) continue;

		/* check ircnet */
		if (rec->ircnets == NULL) {
			best = rec;
			continue;
		}

		if (notifylist_ircnets_match(rec, ircnet))
			return rec;
	}

	return best;
}

int notifylist_ison_server(IRC_SERVER_REC *server, const char *nick)
{
	NOTIFY_NICK_REC *rec;

	g_return_val_if_fail(nick != NULL, FALSE);
	g_return_val_if_fail(IS_IRC_SERVER(server), FALSE);

	rec = notify_nick_find(server, nick);
	return rec != NULL && rec->host_ok && rec->away_ok;
}

static IRC_SERVER_REC *notifylist_ison_serverlist(const char *nick, const char *taglist)
{
	IRC_SERVER_REC *server;
	char **list, **tmp;

	g_return_val_if_fail(nick != NULL, NULL);
	g_return_val_if_fail(taglist != NULL, NULL);

	list = g_strsplit(taglist, " ", -1);

	server = NULL;
	for (tmp = list; *tmp != NULL; tmp++) {
		server = (IRC_SERVER_REC *) server_find_chatnet(*tmp);

		if (IS_IRC_SERVER(server) &&
		    notifylist_ison_server(server, nick))
			break;
	}
	g_strfreev(list);

	return tmp == NULL ? NULL : server;
}

IRC_SERVER_REC *notifylist_ison(const char *nick, const char *serverlist)
{
	GSList *tmp;

	g_return_val_if_fail(nick != NULL, FALSE);
	g_return_val_if_fail(serverlist != NULL, FALSE);

	if (*serverlist != '\0')
		return notifylist_ison_serverlist(nick, serverlist);

	/* any server.. */
	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		IRC_SERVER_REC *server = tmp->data;

		if (IS_IRC_SERVER(server) &&
		    notifylist_ison_server(server, nick))
			return tmp->data;
	}

	return NULL;
}

static void notifylist_init_server(IRC_SERVER_REC *server)
{
	MODULE_SERVER_REC *rec;

	g_return_if_fail(server != NULL);

	if (!IS_IRC_SERVER(server))
		return;

	rec = g_new0(MODULE_SERVER_REC,1 );
	MODULE_DATA_SET(server, rec);
}

static void notifylist_deinit_server(IRC_SERVER_REC *server)
{
	MODULE_SERVER_REC *mserver;
	NOTIFY_NICK_REC *rec;

	g_return_if_fail(server != NULL);

	if (!IS_IRC_SERVER(server))
		return;

	mserver = MODULE_DATA(server);
	while (mserver->notify_users != NULL) {
		rec = mserver->notify_users->data;

		mserver->notify_users = g_slist_remove(mserver->notify_users, rec);
		notify_nick_destroy(rec);
	}
	g_free(mserver);
	MODULE_DATA_UNSET(server);
}

void notifylist_left(IRC_SERVER_REC *server, NOTIFY_NICK_REC *rec)
{
	MODULE_SERVER_REC *mserver;

	mserver = MODULE_DATA(server);
	mserver->notify_users = g_slist_remove(mserver->notify_users, rec);

	if (rec->host_ok && rec->away_ok) {
		signal_emit("notifylist left", 6,
			    server, rec->nick,
			    rec->user, rec->host,
			    rec->realname, rec->awaymsg);
	}

	notify_nick_destroy(rec);
}

static void event_quit(IRC_SERVER_REC *server, const char *data,
		       const char *nick)
{
	NOTIFY_NICK_REC *rec;

	if (*data == ':') data++; /* quit message */

	rec = notify_nick_find(server, nick);
	if (rec != NULL) notifylist_left(server, rec);
}

static void notifylist_check_join(IRC_SERVER_REC *server, const char *nick,
				  const char *userhost, const char *realname, int away)
{
	NOTIFYLIST_REC *notify;
	NOTIFY_NICK_REC *rec;
	char *user, *host;

	if (nick == NULL)
		return;

	notify = notifylist_find(nick, server->connrec->chatnet);
	if (notify == NULL) return;

	rec = notify_nick_find(server, nick);
	if (rec != NULL && rec->join_announced) return;
	if (rec == NULL) rec = notify_nick_create(server, nick);

	user = g_strdup(userhost == NULL ? "" : userhost);
	host = strchr(user, '@');
	if (host != NULL) *host++ = '\0'; else host = "";

	if (!mask_match(SERVER(server), notify->mask, nick, user, host)) {
		g_free(user);
		return;
	}

	if (notify->away_check && away == -1) {
		/* we need to know if the nick is away */
		g_free(user);
		return;
	}

	g_free_not_null(rec->user);
	g_free_not_null(rec->host);
	g_free_not_null(rec->realname);
	rec->user = g_strdup(user);
	rec->host = g_strdup(host);
	rec->realname = realname == NULL || *realname == '\0' ? NULL : g_strdup(realname);

	if (away != -1) rec->away = away;
	rec->host_ok = TRUE;
	rec->join_announced = TRUE;
	rec->away_ok = !notify->away_check || !rec->away;

	signal_emit("notifylist joined", 6,
		    server, rec->nick, rec->user, rec->host, realname, NULL);
	g_free(user);
}

static void event_privmsg(IRC_SERVER_REC *server, const char *data,
			  const char *nick, const char *address)
{
	if (nick != NULL) {
		notifylist_check_join(server, nick, address, "", -1);
	}
}

static void event_join(IRC_SERVER_REC *server, const char *data,
		       const char *nick, const char *address)
{
	notifylist_check_join(server, nick, address, "", -1);
}

static void sig_channel_wholist(IRC_CHANNEL_REC *channel)
{
	GSList *nicks, *tmp;

	nicks = nicklist_getnicks(CHANNEL(channel));
	for (tmp = nicks; tmp != NULL; tmp = tmp->next) {
		NICK_REC *rec = tmp->data;

		notifylist_check_join(channel->server, rec->nick, rec->host, rec->realname, rec->gone);
	}
        g_slist_free(nicks);
}

void irc_notifylist_init(void)
{
	notifylist_read_config();

	notifylist_commands_init();
	notifylist_ison_init();
	notifylist_whois_init();
	signal_add("server connected", (SIGNAL_FUNC) notifylist_init_server);
	signal_add("server disconnected", (SIGNAL_FUNC) notifylist_deinit_server);
	signal_add("event quit", (SIGNAL_FUNC) event_quit);
	signal_add("event privmsg", (SIGNAL_FUNC) event_privmsg);
	signal_add("event join", (SIGNAL_FUNC) event_join);
	signal_add("channel wholist", (SIGNAL_FUNC) sig_channel_wholist);
	signal_add("setup reread", (SIGNAL_FUNC) notifylist_read_config);

	settings_check();
	module_register("notifylist", "irc");
}

void irc_notifylist_deinit(void)
{
	notifylist_commands_deinit();
	notifylist_ison_deinit();
	notifylist_whois_deinit();

	signal_remove("server connected", (SIGNAL_FUNC) notifylist_init_server);
	signal_remove("server disconnected", (SIGNAL_FUNC) notifylist_deinit_server);
	signal_remove("event quit", (SIGNAL_FUNC) event_quit);
	signal_remove("event privmsg", (SIGNAL_FUNC) event_privmsg);
	signal_remove("event join", (SIGNAL_FUNC) event_join);
	signal_remove("channel wholist", (SIGNAL_FUNC) sig_channel_wholist);
	signal_remove("setup reread", (SIGNAL_FUNC) notifylist_read_config);

	notifylist_destroy_all();
}
