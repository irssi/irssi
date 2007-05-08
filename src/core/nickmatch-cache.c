/*
 nickmatch-cache.c : irssi

    Copyright (C) 2001 Timo Sirainen

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

#include "channels.h"
#include "nicklist.h"

#include "nickmatch-cache.h"

static GSList *lists;

NICKMATCH_REC *nickmatch_init(NICKMATCH_REBUILD_FUNC func)
{
	NICKMATCH_REC *rec;

	rec = g_new0(NICKMATCH_REC, 1);
	rec->func = func;

	lists = g_slist_append(lists, rec);
        return rec;
}

void nickmatch_deinit(NICKMATCH_REC *rec)
{
	lists = g_slist_remove(lists, rec);

        g_hash_table_destroy(rec->nicks);
        g_free(rec);
}

static void nickmatch_check_channel(CHANNEL_REC *channel, NICKMATCH_REC *rec)
{
	GSList *nicks, *tmp;

	nicks = nicklist_getnicks(channel);
	for (tmp = nicks; tmp != NULL; tmp = tmp->next) {
		NICK_REC *nick = tmp->data;

		rec->func(rec->nicks, channel, nick);
	}
        g_slist_free(nicks);
}

void nickmatch_rebuild(NICKMATCH_REC *rec)
{
	if (rec->nicks != NULL)
		g_hash_table_destroy(rec->nicks);

	rec->nicks = g_hash_table_new((GHashFunc) g_direct_hash,
				      (GCompareFunc) g_direct_equal);

	g_slist_foreach(channels, (GFunc) nickmatch_check_channel, rec);
}

static void sig_nick_new(CHANNEL_REC *channel, NICK_REC *nick)
{
	GSList *tmp;

        g_return_if_fail(channel != NULL);
	g_return_if_fail(nick != NULL);

	for (tmp = lists; tmp != NULL; tmp = tmp->next) {
		NICKMATCH_REC *rec = tmp->data;

		rec->func(rec->nicks, channel, nick);
	}
}

static void sig_nick_remove(CHANNEL_REC *channel, NICK_REC *nick)
{
	GSList *tmp;

        g_return_if_fail(channel != NULL);
	g_return_if_fail(nick != NULL);

	for (tmp = lists; tmp != NULL; tmp = tmp->next) {
		NICKMATCH_REC *rec = tmp->data;

                g_hash_table_remove(rec->nicks, nick);
	}
}

void nickmatch_cache_init(void)
{
	lists = NULL;
        signal_add("nicklist new", (SIGNAL_FUNC) sig_nick_new);
        signal_add("nicklist changed", (SIGNAL_FUNC) sig_nick_new);
        signal_add("nicklist host changed", (SIGNAL_FUNC) sig_nick_new);
        signal_add("nicklist remove", (SIGNAL_FUNC) sig_nick_remove);
}

void nickmatch_cache_deinit(void)
{
	g_slist_foreach(lists, (GFunc) nickmatch_deinit, NULL);
        g_slist_free(lists);

	signal_remove("nicklist new", (SIGNAL_FUNC) sig_nick_new);
        signal_remove("nicklist changed", (SIGNAL_FUNC) sig_nick_new);
        signal_remove("nicklist host changed", (SIGNAL_FUNC) sig_nick_new);
        signal_remove("nicklist remove", (SIGNAL_FUNC) sig_nick_remove);
}
