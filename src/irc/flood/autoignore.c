/*
 autoignore.c : irssi

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
#include "modules.h"
#include "signals.h"
#include "commands.h"
#include "levels.h"
#include "misc.h"
#include "settings.h"
#include "common-setup.h"

#include "irc-server.h"
#include "ignore.h"

#include "autoignore.h"

static int ignore_tag;

GSList *server_autoignores(IRC_SERVER_REC *server)
{
	MODULE_SERVER_REC *rec;

	g_return_val_if_fail(server != NULL, NULL);

	rec = MODULE_DATA(server);
	return rec->ignorelist;
}

static void autoignore_remove_rec(IRC_SERVER_REC *server, AUTOIGNORE_REC *rec)
{
	MODULE_SERVER_REC *mserver;

	g_return_if_fail(server != NULL);
	g_return_if_fail(rec != NULL);

	signal_emit("autoignore remove", 2, server, rec);

	g_free(rec->nick);
	g_free(rec);

	mserver = MODULE_DATA(server);
	mserver->ignorelist = g_slist_remove(mserver->ignorelist, rec);
}

static AUTOIGNORE_REC *autoignore_find(IRC_SERVER_REC *server, const char *mask)
{
	MODULE_SERVER_REC *mserver;
	GSList *tmp;

	g_return_val_if_fail(server != NULL, NULL);
	g_return_val_if_fail(mask != NULL, NULL);

	mserver = MODULE_DATA(server);
	for (tmp = mserver->ignorelist; tmp != NULL; tmp = tmp->next) {
		AUTOIGNORE_REC *rec = tmp->data;

		if (g_strcasecmp(rec->nick, mask) == 0)
			return rec;
	}

	return NULL;
}

/* timeout function: unignore old ignores.. */
static void autoignore_timeout_server(IRC_SERVER_REC *server)
{
	MODULE_SERVER_REC *mserver;
	GSList *tmp, *next;
	time_t t;

	g_return_if_fail(server != NULL);

	mserver = MODULE_DATA(server);
	t = time(NULL);
	t -= mserver->ignore_lastcheck;

	for (tmp = mserver->ignorelist; tmp != NULL; tmp = next) {
		AUTOIGNORE_REC *rec = tmp->data;

		next = tmp->next;
		if (rec->timeleft > t)
			rec->timeleft -= t;
		else
			autoignore_remove_rec(server, rec);
	}

	mserver->ignore_lastcheck = time(NULL);
}

static int autoignore_timeout(void)
{
	g_slist_foreach(servers, (GFunc) autoignore_timeout_server, NULL);
	return 1;
}

static void autoignore_init_server(IRC_SERVER_REC *server)
{
	MODULE_SERVER_REC *mserver;

	g_return_if_fail(server != NULL);

	mserver = MODULE_DATA(server);
	mserver->ignorelist = NULL;
	mserver->ignore_lastcheck = time(NULL)-AUTOIGNORE_TIMECHECK;
}

static void autoignore_deinit_server(IRC_SERVER_REC *server)
{
	MODULE_SERVER_REC *mserver;

	g_return_if_fail(server != NULL);

	mserver = MODULE_DATA(server);
	while (mserver->ignorelist != NULL)
		autoignore_remove_rec(server, (AUTOIGNORE_REC *) mserver->ignorelist->data);
}

IGNORE_REC *ignore_find_server(IRC_SERVER_REC *server, const char *mask)
{
	GSList *tmp;

	for (tmp = ignores; tmp != NULL; tmp = tmp->next) {
		IGNORE_REC *rec = tmp->data;

		if (rec->servertag != NULL &&
		    g_strcasecmp(rec->mask, mask) == 0 &&
		    g_strcasecmp(rec->servertag, server->tag) == 0)
			return rec;
	}

	return NULL;
}

void autoignore_add(IRC_SERVER_REC *server, const char *nick, int level)
{
	MODULE_SERVER_REC *mserver;
	AUTOIGNORE_REC *rec;
	IGNORE_REC *irec;
	int igtime;

	g_return_if_fail(server != NULL);
	g_return_if_fail(nick != NULL);
	if (level == 0) return;

	igtime = settings_get_int("autoignore_time");
	if (igtime <= 0) return;

	irec = ignore_find_server(server, nick);
	if (irec == NULL) {
		irec = g_new0(IGNORE_REC, 1);
		irec->servertag = g_strdup(server->tag);
		irec->mask = g_strdup(nick);
		irec->level = level;
		ignore_add_rec(irec);
	} else {
		irec->level |= level;
		ignore_update_rec(irec);
	}

	rec = autoignore_find(server, nick);
	if (rec != NULL) {
		/* already being ignored */
		rec->timeleft = igtime;
		return;
	}

	rec = g_new(AUTOIGNORE_REC, 1);
	rec->nick = g_strdup(nick);
	rec->timeleft = igtime;
	rec->level = level;

	mserver = MODULE_DATA(server);
	mserver->ignorelist = g_slist_append(mserver->ignorelist, rec);

	signal_emit("autoignore new", 2, server, rec);
}

int autoignore_remove(IRC_SERVER_REC *server, const char *mask, int level)
{
	AUTOIGNORE_REC *rec;
	IGNORE_REC *irec;

	g_return_val_if_fail(server != NULL, FALSE);
	g_return_val_if_fail(mask != NULL, FALSE);

	irec = ignore_find_server(server, mask);
	if (irec != NULL) {
		irec->level &= ~level;
		ignore_update_rec(irec);
	}

	rec = autoignore_find(server, mask);
	if (rec != NULL && (level & rec->level)) {
		rec->level &= ~level;
		if (rec->level == 0) autoignore_remove_rec(server, rec);
		return TRUE;
	}

	return FALSE;
}

static void sig_flood(IRC_SERVER_REC *server, const char *nick, const char *host, gpointer levelp)
{
	int level, check_level;

	level = GPOINTER_TO_INT(levelp);
	check_level = level2bits(settings_get_str("autoignore_levels"));

	if (level & check_level)
		autoignore_add(server, nick, level);
}

void autoignore_init(void)
{
	settings_add_int("flood", "autoignore_time", 300);
	settings_add_str("flood", "autoignore_levels", "ctcps");

	ignore_tag = g_timeout_add(AUTOIGNORE_TIMECHECK, (GSourceFunc) autoignore_timeout, NULL);

	signal_add("server connected", (SIGNAL_FUNC) autoignore_init_server);
	signal_add("server disconnected", (SIGNAL_FUNC) autoignore_deinit_server);
	signal_add("flood", (SIGNAL_FUNC) sig_flood);
}

void autoignore_deinit(void)
{
	g_source_remove(ignore_tag);

	signal_remove("server connected", (SIGNAL_FUNC) autoignore_init_server);
	signal_remove("server disconnected", (SIGNAL_FUNC) autoignore_deinit_server);
	signal_remove("flood", (SIGNAL_FUNC) sig_flood);
}
