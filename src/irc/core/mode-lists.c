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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "misc.h"
#include "signals.h"

#include "irc.h"
#include "mode-lists.h"

static void ban_free(GSList **list, BAN_REC *rec)
{
	g_return_if_fail(list != NULL);
	g_return_if_fail(rec != NULL);

	g_free(rec->ban);
	g_free_not_null(rec->setby);
	g_free(rec);

	*list = g_slist_remove(*list, rec);
}

void banlist_free(GSList *banlist)
{
	while (banlist != NULL)
		ban_free(&banlist, banlist->data);
}

BAN_REC *banlist_add(CHANNEL_REC *channel, const char *ban,
		     const char *nick, time_t time)
{
	BAN_REC *rec;

	g_return_val_if_fail(channel != NULL, NULL);
	g_return_val_if_fail(ban != NULL, NULL);

	rec = g_new(BAN_REC, 1);
	rec->ban = g_strdup(ban);
	rec->setby = nick == NULL || *nick == '\0' ? NULL :
		g_strdup(nick);
	rec->time = time;

	channel->banlist = g_slist_append(channel->banlist, rec);

	signal_emit("ban new", 1, rec);
	return rec;
}

static BAN_REC *banlist_find(GSList *list, const char *ban)
{
	GSList *tmp;

	g_return_val_if_fail(ban != NULL, NULL);

	for (tmp = list; tmp != NULL; tmp = tmp->next) {
		BAN_REC *rec = tmp->data;

		if (g_strcasecmp(rec->ban, ban) == 0)
			return rec;
	}

	return NULL;
}

void banlist_remove(CHANNEL_REC *channel, const char *ban)
{
	BAN_REC *rec;

	g_return_if_fail(channel != NULL);
	g_return_if_fail(ban != NULL);

	rec = banlist_find(channel->banlist, ban);
	if (rec != NULL) {
		signal_emit("ban remove", 1, rec);
		ban_free(&channel->banlist, rec);
	}
}

BAN_REC *banlist_exception_add(CHANNEL_REC *channel, const char *ban,
			       const char *nick, time_t time)
{
	BAN_REC *rec;

	g_return_val_if_fail(channel != NULL, NULL);
	g_return_val_if_fail(ban != NULL, NULL);

	rec = g_new(BAN_REC, 1);
	rec->ban = g_strdup(ban);
	rec->setby = nick == NULL || *nick == '\0' ? NULL :
		g_strdup(nick);
	rec->time = time;

	channel->ebanlist = g_slist_append(channel->ebanlist, rec);

	signal_emit("ban exception new", 1, rec);
	return rec;
}

void banlist_exception_remove(CHANNEL_REC *channel, const char *ban)
{
	BAN_REC *rec;

	g_return_if_fail(channel != NULL);
	g_return_if_fail(ban != NULL);

	rec = banlist_find(channel->ebanlist, ban);
	if (rec != NULL) {
		signal_emit("ban exception remove", 1, rec);
		ban_free(&channel->ebanlist, rec);
	}
}

static void invitelist_free(CHANNEL_REC *channel)
{
	g_return_if_fail(channel != NULL);

	g_slist_foreach(channel->invitelist, (GFunc) g_free, NULL);
	g_slist_free(channel->invitelist);
}

void invitelist_add(CHANNEL_REC *channel, const char *mask)
{
	g_return_if_fail(channel != NULL);
	g_return_if_fail(mask != NULL);

	channel->invitelist = g_slist_append(channel->invitelist, g_strdup(mask));

	signal_emit("invitelist new", 2, channel, mask);
}

void invitelist_remove(CHANNEL_REC *channel, const char *mask)
{
	GSList *tmp;

	g_return_if_fail(channel != NULL);
	g_return_if_fail(mask != NULL);

	tmp = gslist_find_icase_string(channel->invitelist, mask);
	if (tmp == NULL) return;

	signal_emit("invitelist remove", 2, channel, tmp->data);
	g_free(tmp->data);
	channel->invitelist = g_slist_remove(channel->invitelist, tmp->data);
}

static void channel_destroyed(CHANNEL_REC *channel)
{
	g_return_if_fail(channel != NULL);

	banlist_free(channel->banlist);
	banlist_free(channel->ebanlist);
	invitelist_free(channel);
}

static void event_banlist(const char *data, IRC_SERVER_REC *server)
{
	CHANNEL_REC *chanrec;
	char *params, *channel, *ban, *setby, *tims;
	time_t tim;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 5, NULL, &channel, &ban, &setby, &tims);
	chanrec = channel_find(server, channel);
	if (chanrec != NULL) {
		tim = (time_t) atol(tims);
		banlist_add(chanrec, ban, setby, tim);
	}
	g_free(params);
}

static void event_ebanlist(const char *data, IRC_SERVER_REC *server)
{
	CHANNEL_REC *chanrec;
	char *params, *channel, *ban, *setby, *tims;
	time_t tim;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 5, NULL, &channel, &ban, &setby, &tims);
	chanrec = channel_find(server, channel);
	if (chanrec != NULL) {
		tim = (time_t) atol(tims);
		banlist_exception_add(chanrec, ban, setby, tim);
	}
	g_free(params);
}

static void event_invite_list(const char *data, IRC_SERVER_REC *server)
{
	CHANNEL_REC *chanrec;
	char *params, *channel, *invite;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &channel, &invite);
	chanrec = channel_find(server, channel);

	if (chanrec != NULL)
		invitelist_add(chanrec, invite);

	g_free(params);
}

void mode_lists_init(void)
{
	signal_add("channel destroyed", (SIGNAL_FUNC) channel_destroyed);

	signal_add("chanquery ban", (SIGNAL_FUNC) event_banlist);
	signal_add("chanquery eban", (SIGNAL_FUNC) event_ebanlist);
	signal_add("chanquery ilist", (SIGNAL_FUNC) event_invite_list);
}

void mode_lists_deinit(void)
{
	signal_remove("channel destroyed", (SIGNAL_FUNC) channel_destroyed);

	signal_remove("chanquery ban", (SIGNAL_FUNC) event_banlist);
	signal_remove("chanquery eban", (SIGNAL_FUNC) event_ebanlist);
	signal_remove("chanquery ilist", (SIGNAL_FUNC) event_invite_list);
}
