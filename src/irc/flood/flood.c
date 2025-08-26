/*
 flood.c : Flood protection

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
#include <irssi/src/core/modules.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/settings.h>

#include <irssi/src/irc/core/irc.h>
#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/core/ignore.h>

void autoignore_init(void);
void autoignore_deinit(void);

typedef struct {
	char *target;
	int level;

	GSList *msgtimes;
} FLOOD_ITEM_REC;

typedef struct {
	char *nick;
        GSList *items;
} FLOOD_REC;

static int flood_tag;
static int flood_max_msgs, flood_timecheck;

static int flood_hash_check_remove(const char *key, FLOOD_REC *flood,
				   time_t *now)
{
	GSList *tmp, *next, *times, *tnext;

	g_return_val_if_fail(key != NULL, FALSE);
	g_return_val_if_fail(flood != NULL, FALSE);

	for (tmp = flood->items; tmp != NULL; tmp = next) {
		FLOOD_ITEM_REC *rec = tmp->data;

		next = tmp->next;
		/* remove old time entries for current rec item */
		for (times = rec->msgtimes; times != NULL; times = tnext) {
                        time_t *data = times->data;
			tnext = times->next;

			if (*now-*((time_t *) times->data) >= flood_timecheck) {
				rec->msgtimes = g_slist_remove(rec->msgtimes, data);
				g_free(data);
			}
		}
		/* if no more time entries remove rec item */
		if (rec->msgtimes == NULL) {
			flood->items = g_slist_remove(flood->items, rec);
			g_free(rec->target);
			g_free(rec);
		}
	}

	if (flood->items != NULL)
		return FALSE;

	g_free(flood->nick);
	g_free(flood);
	return TRUE;
}

static int flood_timeout(void)
{
	MODULE_SERVER_REC *mserver;
	GSList *tmp;
	time_t now;

	/* remove the old people from flood lists */
	now = time(NULL);
	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		IRC_SERVER_REC *rec = tmp->data;

		if (!IS_IRC_SERVER(rec))
                        continue;

		mserver = MODULE_DATA(rec);
		g_hash_table_foreach_remove(mserver->floodlist,
					    (GHRFunc) flood_hash_check_remove,
					    &now);
	}
	return 1;
}

/* Initialize flood protection */
static void flood_init_server(IRC_SERVER_REC *server)
{
	MODULE_SERVER_REC *rec;

	g_return_if_fail(server != NULL);

	if (!IS_IRC_SERVER(server))
                return;

	rec = g_new0(MODULE_SERVER_REC, 1);
	MODULE_DATA_SET(server, rec);

	rec->floodlist = g_hash_table_new((GHashFunc) i_istr_hash, (GCompareFunc) i_istr_equal);
}

static void flood_hash_destroy(const char *key, FLOOD_REC *flood)
{
	while (flood->items != NULL) {
		FLOOD_ITEM_REC *rec = flood->items->data;

		flood->items = g_slist_remove(flood->items, rec);

		g_slist_foreach(rec->msgtimes, (GFunc) g_free, NULL);
		g_slist_free(rec->msgtimes);
		g_free(rec->target);
		g_free(rec);
	}

	g_free(flood->nick);
	g_free(flood);
}

/* Deinitialize flood protection */
static void flood_deinit_server(IRC_SERVER_REC *server)
{
	MODULE_SERVER_REC *mserver;

	g_return_if_fail(server != NULL);

	if (!IS_IRC_SERVER(server))
                return;

	mserver = MODULE_DATA(server);
	if (mserver != NULL && mserver->floodlist != NULL) {
		flood_timecheck = 0;

		g_hash_table_foreach(mserver->floodlist,
				     (GHFunc) flood_hash_destroy, NULL);
		g_hash_table_destroy(mserver->floodlist);
	}
	g_free(mserver);
	MODULE_DATA_UNSET(server);
}

static FLOOD_ITEM_REC *flood_find(FLOOD_REC *flood, int level,
				  const char *target)
{
	GSList *tmp;

	for (tmp = flood->items; tmp != NULL; tmp = tmp->next) {
		FLOOD_ITEM_REC *rec = tmp->data;

		if (rec->level == level &&
		    g_ascii_strcasecmp(rec->target, target) == 0)
			return rec;
	}

	return NULL;
}

/* All messages should go through here.. */
static void flood_newmsg(IRC_SERVER_REC *server, int level, const char *nick,
			 const char *host, const char *target)
{
	MODULE_SERVER_REC *mserver;
	FLOOD_REC *flood;
	FLOOD_ITEM_REC *rec;
	time_t now, *ttime;
	GSList *times, *tnext;

	g_return_if_fail(server != NULL);
	g_return_if_fail(nick != NULL);

	mserver = MODULE_DATA(server);
	flood = g_hash_table_lookup(mserver->floodlist, nick);

	rec = flood == NULL ? NULL : flood_find(flood, level, target);
	if (rec != NULL) {
		now = time(NULL);
		for (times = rec->msgtimes; times != NULL; times = tnext) {
			time_t *data = times->data;
			tnext = times->next;

			if (now - *data >= flood_timecheck) {
				rec->msgtimes = g_slist_remove(rec->msgtimes, data);
				g_free(data);
			} else
				break;
		}
		ttime = g_new(time_t, 1);
		*ttime = now;
		rec->msgtimes = g_slist_append(rec->msgtimes, ttime);
		if (g_slist_length(rec->msgtimes) > flood_max_msgs) {
			/* flooding! */
			signal_emit("flood", 5, server, nick, host,
				    GINT_TO_POINTER(rec->level), target);
		}
		return;
	}

	if (flood == NULL) {
		flood = g_new0(FLOOD_REC, 1);
		flood->nick = g_strdup(nick);
		g_hash_table_insert(mserver->floodlist, flood->nick, flood);
	}

	rec = g_new0(FLOOD_ITEM_REC, 1);
	rec->level = level;
	rec->msgtimes = NULL;
	ttime = g_new(time_t, 1);
	*ttime = time(NULL);
	rec->msgtimes = g_slist_append(rec->msgtimes, ttime);
	rec->target = g_strdup(target);

	flood->items = g_slist_append(flood->items, rec);
}

static void flood_privmsg(IRC_SERVER_REC *server, const char *data,
			  const char *nick, const char *addr)
{
	char *params, *target, *text;
	int level;

	g_return_if_fail(data != NULL);
	g_return_if_fail(server != NULL);

	if (addr == NULL || g_ascii_strcasecmp(nick, server->nick) == 0)
		return;

	params = event_get_params(data, 2, &target, &text);

	level = server_ischannel(SERVER(server), target) ? MSGLEVEL_PUBLIC : MSGLEVEL_MSGS;
	if (addr != NULL && !ignore_check(SERVER(server), nick, addr, target, text, level))
		flood_newmsg(server, level, nick, addr, target);

	g_free(params);
}

static void flood_notice(IRC_SERVER_REC *server, const char *data,
			 const char *nick, const char *addr)
{
	char *params, *target, *text;

	g_return_if_fail(data != NULL);
	g_return_if_fail(server != NULL);

	if (addr == NULL || g_ascii_strcasecmp(nick, server->nick) == 0)
		return;

	params = event_get_params(data, 2, &target, &text);
	if (!ignore_check(SERVER(server), nick, addr, target, text, MSGLEVEL_NOTICES))
		flood_newmsg(server, MSGLEVEL_NOTICES, nick, addr, target);

	g_free(params);
}

static void flood_ctcp(IRC_SERVER_REC *server, const char *data,
		       const char *nick, const char *addr, const char *target)
{
	int level;

	g_return_if_fail(data != NULL);
	g_return_if_fail(server != NULL);

	if (addr == NULL || g_ascii_strcasecmp(nick, server->nick) == 0)
		return;

	level = g_ascii_strncasecmp(data, "ACTION ", 7) != 0 ? MSGLEVEL_CTCPS :
		(server_ischannel(SERVER(server), target) ? MSGLEVEL_PUBLIC : MSGLEVEL_MSGS);
	if (!ignore_check(SERVER(server), nick, addr, target, data, level))
		flood_newmsg(server, level, nick, addr, target);
}

static void read_settings(void)
{
	flood_timecheck = settings_get_int("flood_timecheck");
	flood_max_msgs = settings_get_int("flood_max_msgs");

	if (flood_timecheck > 0 && flood_max_msgs > 0) {
		if (flood_tag == -1) {
			flood_tag = g_timeout_add(5000, (GSourceFunc) flood_timeout, NULL);

			signal_add("event privmsg", (SIGNAL_FUNC) flood_privmsg);
			signal_add("event notice", (SIGNAL_FUNC) flood_notice);
			signal_add("ctcp msg", (SIGNAL_FUNC) flood_ctcp);
		}
	} else if (flood_tag != -1) {
		g_source_remove(flood_tag);
		flood_tag = -1;

		signal_remove("event privmsg", (SIGNAL_FUNC) flood_privmsg);
		signal_remove("event notice", (SIGNAL_FUNC) flood_notice);
		signal_remove("ctcp msg", (SIGNAL_FUNC) flood_ctcp);
	}
}

void irc_flood_init(void)
{
	settings_add_int("flood", "flood_timecheck", 8);
	settings_add_int("flood", "flood_max_msgs", 4);

	flood_tag = -1;
	read_settings();
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
	signal_add_first("server connected", (SIGNAL_FUNC) flood_init_server);
	signal_add("server destroyed", (SIGNAL_FUNC) flood_deinit_server);

	autoignore_init();
	settings_check();
	module_register("flood", "irc");
}

void irc_flood_deinit(void)
{
	autoignore_deinit();

	if (flood_tag != -1) {
		g_source_remove(flood_tag);
		signal_remove("event privmsg", (SIGNAL_FUNC) flood_privmsg);
		signal_remove("event notice", (SIGNAL_FUNC) flood_notice);
		signal_remove("ctcp msg", (SIGNAL_FUNC) flood_ctcp);
	}

	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
	signal_remove("server connected", (SIGNAL_FUNC) flood_init_server);
	signal_remove("server destroyed", (SIGNAL_FUNC) flood_deinit_server);
}

MODULE_ABICHECK(irc_flood)
