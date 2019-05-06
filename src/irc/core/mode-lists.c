/*
 mode-lists.c : irssi

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
#include <irssi/src/core/misc.h>
#include <irssi/src/core/signals.h>

#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/irc/core/irc-channels.h>
#include <irssi/src/irc/core/mode-lists.h>

static void ban_free(GSList **list, BAN_REC *rec)
{
	g_return_if_fail(list != NULL);
	g_return_if_fail(rec != NULL);

	*list = g_slist_remove(*list, rec);

	g_free(rec->ban);
	g_free_not_null(rec->setby);
	g_free(rec);
}

void banlist_free(GSList *banlist)
{
	while (banlist != NULL)
		ban_free(&banlist, banlist->data);
}

BAN_REC *banlist_find(GSList *list, const char *ban)
{
	GSList *tmp;

	g_return_val_if_fail(ban != NULL, NULL);

	for (tmp = list; tmp != NULL; tmp = tmp->next) {
		BAN_REC *rec = tmp->data;

		if (g_ascii_strcasecmp(rec->ban, ban) == 0)
			return rec;
	}

	return NULL;
}

BAN_REC *banlist_add(IRC_CHANNEL_REC *channel, const char *ban,
		     const char *nick, time_t time)
{
	BAN_REC *rec;

	g_return_val_if_fail(channel != NULL, NULL);
	g_return_val_if_fail(ban != NULL, NULL);

	rec = banlist_find(channel->banlist, ban);
	if (rec != NULL) {
		/* duplicate - ignore. some servers send duplicates
		   for non-ops because they just replace the hostname with
		   eg. "localhost"... */
		return NULL;
	}

	rec = g_new(BAN_REC, 1);
	rec->ban = g_strdup(ban);
	rec->setby = nick == NULL || *nick == '\0' ? NULL :
		g_strdup(nick);
	rec->time = time;

	channel->banlist = g_slist_append(channel->banlist, rec);

	signal_emit("ban new", 2, channel, rec);
	return rec;
}

void banlist_remove(IRC_CHANNEL_REC *channel, const char *ban, const char *nick)
{
	BAN_REC *rec;

	g_return_if_fail(channel != NULL);
	g_return_if_fail(ban != NULL);

	rec = banlist_find(channel->banlist, ban);
	if (rec != NULL) {
		signal_emit("ban remove", 3, channel, rec, nick);
		ban_free(&channel->banlist, rec);
	}
}

static void channel_destroyed(IRC_CHANNEL_REC *channel)
{
	if (!IS_IRC_CHANNEL(channel))
                return;

	banlist_free(channel->banlist);
}

static void event_banlist(IRC_SERVER_REC *server, const char *data)
{
	IRC_CHANNEL_REC *chanrec;
	char *params, *channel, *ban, *setby, *tims;
	time_t tim;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 5, NULL, &channel, &ban, &setby, &tims);
	chanrec = irc_channel_find(server, channel);
	if (chanrec != NULL) {
		tim = (time_t) atol(tims);
		banlist_add(chanrec, ban, setby, tim);
	}
	g_free(params);
}

void mode_lists_init(void)
{
	signal_add("channel destroyed", (SIGNAL_FUNC) channel_destroyed);

	signal_add("chanquery ban", (SIGNAL_FUNC) event_banlist);
}

void mode_lists_deinit(void)
{
	signal_remove("channel destroyed", (SIGNAL_FUNC) channel_destroyed);

	signal_remove("chanquery ban", (SIGNAL_FUNC) event_banlist);
}
