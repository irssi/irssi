/*
 massjoin.c : irssi

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
#include "settings.h"

#include "irc-servers.h"
#include "irc-channels.h"
#include "irc-nicklist.h"

static int massjoin_tag;
static int massjoin_max_joins;

/* Massjoin support - really useful when trying to do things (like op/deop)
   to people after netjoins. It sends
   "massjoin #channel nick!user@host nick2!user@host ..." signals */
static void event_join(IRC_SERVER_REC *server, const char *data,
		       const char *nick, const char *address)
{
	char *params, *channel, *ptr;
	IRC_CHANNEL_REC *chanrec;
	NICK_REC *nickrec;
	GSList *nicks, *tmp;

	g_return_if_fail(data != NULL);

	if (g_strcasecmp(nick, server->nick) == 0) {
		/* You joined, no need to do anything here */
		return;
	}

	params = event_get_params(data, 1, &channel);
	ptr = strchr(channel, 7); /* ^G does something weird.. */
	if (ptr != NULL) *ptr = '\0';

	/* find channel */
	chanrec = irc_channel_find(server, channel);
	g_free(params);
	if (chanrec == NULL) return;

	/* check that the nick isn't already in nicklist. seems to happen
	   sometimes (server desyncs or something?) */
	nickrec = nicklist_find(CHANNEL(chanrec), nick);
	if (nickrec != NULL) {
		/* destroy the old record */
		nicklist_remove(CHANNEL(chanrec), nickrec);
	}

	/* add user to nicklist */
	nickrec = irc_nicklist_insert(chanrec, nick, FALSE, FALSE, FALSE, TRUE, NULL);
        nicklist_set_host(CHANNEL(chanrec), nickrec, address);

	if (chanrec->massjoins == 0) {
		/* no nicks waiting in massjoin queue */
		chanrec->massjoin_start = time(NULL);
		chanrec->last_massjoins = 0;
	}

	if (nickrec->realname == NULL) {
		/* Check if user is already in some other channel,
		   get the realname and other stuff from there */
		nicks = nicklist_get_same(SERVER(server), nick);
		for (tmp = nicks; tmp != NULL; tmp = tmp->next->next) {
			NICK_REC *rec = tmp->next->data;

			if (rec->realname != NULL) {
				nickrec->last_check = rec->last_check;
				nickrec->realname = g_strdup(rec->realname);
				nickrec->gone = rec->gone;
				nickrec->serverop = rec->serverop;
				break;
			}
		}
		g_slist_free(nicks);
	}

	chanrec->massjoins++;
}

static void event_part(IRC_SERVER_REC *server, const char *data,
		       const char *nick, const char *addr)
{
	char *params, *channel, *reason;
	IRC_CHANNEL_REC *chanrec;
	NICK_REC *nickrec;

	g_return_if_fail(data != NULL);

	if (g_strcasecmp(nick, server->nick) == 0) {
		/* you left channel, no need to do anything here */
		return;
	}

	params = event_get_params(data, 2, &channel, &reason);

	/* find channel */
	chanrec = irc_channel_find(server, channel);
	if (chanrec == NULL) {
		g_free(params);
		return;
	}

	/* remove user from nicklist */
	nickrec = nicklist_find(CHANNEL(chanrec), nick);
	if (nickrec != NULL) {
		if (nickrec->send_massjoin) {
			/* quick join/part after which it's useless to send
			   nick in massjoin */
			chanrec->massjoins--;
		}
		nicklist_remove(CHANNEL(chanrec), nickrec);
	}
	g_free(params);
}

static void event_quit(IRC_SERVER_REC *server, const char *data,
		       const char *nick)
{
        IRC_CHANNEL_REC *channel;
	NICK_REC *nickrec;
	GSList *nicks, *tmp;

	g_return_if_fail(data != NULL);

	if (g_strcasecmp(nick, server->nick) == 0) {
		/* you quit, don't do anything here */
		return;
	}

	/* Remove nick from all channels */
	nicks = nicklist_get_same(SERVER(server), nick);
	for (tmp = nicks; tmp != NULL; tmp = tmp->next->next) {
                channel = tmp->data;
		nickrec = tmp->next->data;

		if (nickrec->send_massjoin) {
			/* quick join/quit after which it's useless to
			   send nick in massjoin */
			channel->massjoins--;
		}
		nicklist_remove(CHANNEL(channel), nickrec);
	}
	g_slist_free(nicks);
}

static void event_kick(IRC_SERVER_REC *server, const char *data)
{
	char *params, *channel, *nick, *reason;
	IRC_CHANNEL_REC *chanrec;
	NICK_REC *nickrec;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, &channel, &nick, &reason);

	if (g_strcasecmp(nick, server->nick) == 0) {
		/* you were kicked, no need to do anything */
		g_free(params);
		return;
	}

	/* Remove user from nicklist */
	chanrec = irc_channel_find(server, channel);
	nickrec = chanrec == NULL ? NULL :
		nicklist_find(CHANNEL(chanrec), nick);

	if (chanrec != NULL && nickrec != NULL) {
		if (nickrec->send_massjoin) {
			/* quick join/kick after which it's useless to
			   send nick in massjoin */
			chanrec->massjoins--;
		}
		nicklist_remove(CHANNEL(chanrec), nickrec);
	}

	g_free(params);
}

static void massjoin_send_hash(gpointer key, NICK_REC *nick, GSList **list)
{
	if (nick->send_massjoin) {
		nick->send_massjoin = FALSE;
		*list = g_slist_append(*list, nick);
	}
}

/* Send channel's massjoin list signal */
static void massjoin_send(IRC_CHANNEL_REC *channel)
{
	GSList *list;

	list = NULL;
	g_hash_table_foreach(channel->nicks, (GHFunc) massjoin_send_hash, &list);

	channel->massjoins = 0;
	signal_emit("massjoin", 2, channel, list);
	g_slist_free(list);
}

static void server_check_massjoins(IRC_SERVER_REC *server, time_t max)
{
	GSList *tmp;

	/*
	   1) First time always save massjoin count to last_massjoins
	   2) Next time check if there's been less than massjoin_max_joins
	      (yes, the name is misleading..) joins since previous check.
	        yes) send a massjoin signal and reset last_massjoin count
	        no) unless we've waited for massjoin_max_wait seconds already,
		    goto 2.

	   So, with single joins the massjoin signal is sent 1-2 seconds after
	   the join.
	*/

	/* Scan all channels through for massjoins */
	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		IRC_CHANNEL_REC *rec = tmp->data;

		if (!IS_IRC_CHANNEL(rec) || rec->massjoins <= 0)
			continue;

		if (rec->massjoin_start < max || /* We've waited long enough */
		    (rec->last_massjoins > 0 &&
		     rec->massjoins-massjoin_max_joins < rec->last_massjoins)) { /* Less than x joins since last check */
			/* send them */
			massjoin_send(rec);
		} else {
			/* Wait for some more.. */
			rec->last_massjoins = rec->massjoins;
		}
	}

}

static int sig_massjoin_timeout(void)
{
	GSList *tmp;
	time_t max;

	max = time(NULL)-settings_get_int("massjoin_max_wait");
	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		IRC_SERVER_REC *server = tmp->data;

                if (IS_IRC_SERVER(server))
			server_check_massjoins(server, max);
	}

	return 1;
}

static void read_settings(void)
{
	massjoin_max_joins = settings_get_int("massjoin_max_joins");
}

void massjoin_init(void)
{
        settings_add_int("misc", "massjoin_max_wait", 5000);
        settings_add_int("misc", "massjoin_max_joins", 3);
	massjoin_tag = g_timeout_add(1000, (GSourceFunc) sig_massjoin_timeout, NULL);

	read_settings();
	signal_add_first("event join", (SIGNAL_FUNC) event_join);
	signal_add("event part", (SIGNAL_FUNC) event_part);
	signal_add("event kick", (SIGNAL_FUNC) event_kick);
	signal_add("event quit", (SIGNAL_FUNC) event_quit);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
}

void massjoin_deinit(void)
{
	g_source_remove(massjoin_tag);

	signal_remove("event join", (SIGNAL_FUNC) event_join);
	signal_remove("event part", (SIGNAL_FUNC) event_part);
	signal_remove("event kick", (SIGNAL_FUNC) event_kick);
	signal_remove("event quit", (SIGNAL_FUNC) event_quit);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
}
