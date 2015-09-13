/*
 channels-query.c : irssi

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

/*

 How the thing works:

 - After channel is joined and NAMES list is got, send "channel joined" signal
 - "channel joined" : add channel to server->queries lists

loop:
 - Wait for NAMES list from all channels before doing anything else..
 - After got the last NAMES list, start sending the queries ..
 - find the query to send, check where server->queries list isn't NULL
   (mode, who, banlist, ban exceptions, invite list)
 - if not found anything -> all channels are synced
 - send "command #chan1,#chan2,#chan3,.." command to server
 - wait for reply from server, then check if it was last query to be sent to
   channel. If it was, send "channel sync" signal
 - check if the reply was for last channel in the command list. If so,
   goto loop
*/

#include "module.h"
#include "misc.h"
#include "signals.h"
#include "settings.h"

#include "modes.h"
#include "mode-lists.h"
#include "nicklist.h"
#include "irc-servers.h"
#include "irc-channels.h"
#include "servers-redirect.h"

enum {
	CHANNEL_QUERY_MODE,
	CHANNEL_QUERY_WHO,
	CHANNEL_QUERY_BMODE,

	CHANNEL_QUERIES
};

#define CHANNEL_IS_MODE_QUERY(a) ((a) != CHANNEL_QUERY_WHO)

typedef struct {
	int current_query_type; /* query type that is currently being asked */
        GSList *current_queries; /* All channels that are currently being queried */

	GSList *queries[CHANNEL_QUERIES]; /* All queries that need to be asked from server */
} SERVER_QUERY_REC;

static void sig_connected(IRC_SERVER_REC *server)
{
	SERVER_QUERY_REC *rec;

	g_return_if_fail(server != NULL);
	if (!IS_IRC_SERVER(server))
		return;

	rec = g_new0(SERVER_QUERY_REC, 1);
        server->chanqueries = rec;
}

static void sig_disconnected(IRC_SERVER_REC *server)
{
	SERVER_QUERY_REC *rec;
	int n;

	g_return_if_fail(server != NULL);
	if (!IS_IRC_SERVER(server))
		return;

	rec = server->chanqueries;
	g_return_if_fail(rec != NULL);

	for (n = 0; n < CHANNEL_QUERIES; n++)
		g_slist_free(rec->queries[n]);
        g_slist_free(rec->current_queries);
	g_free(rec);

        server->chanqueries = NULL;
}

/* Add channel to query list */
static void query_add_channel(IRC_CHANNEL_REC *channel, int query_type)
{
	SERVER_QUERY_REC *rec;

	g_return_if_fail(channel != NULL);

	rec = channel->server->chanqueries;
	rec->queries[query_type] =
		g_slist_append(rec->queries[query_type], channel);
}

static void query_check(IRC_SERVER_REC *server);

static void query_remove_all(IRC_CHANNEL_REC *channel)
{
	SERVER_QUERY_REC *rec;
	int n;

	rec = channel->server->chanqueries;

	/* remove channel from query lists */
	for (n = 0; n < CHANNEL_QUERIES; n++)
		rec->queries[n] = g_slist_remove(rec->queries[n], channel);
	rec->current_queries = g_slist_remove(rec->current_queries, channel);

	query_check(channel->server);
}

static void sig_channel_destroyed(IRC_CHANNEL_REC *channel)
{
	g_return_if_fail(channel != NULL);

	if (IS_IRC_CHANNEL(channel) && !channel->server->disconnected &&
	    !channel->synced)
		query_remove_all(channel);
}

static int channels_have_all_names(IRC_SERVER_REC *server)
{
	GSList *tmp;

	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		IRC_CHANNEL_REC *rec = tmp->data;

		if (IS_IRC_CHANNEL(rec) && !rec->names_got)
			return 0;
	}

	return 1;
}

static int query_find_next(SERVER_QUERY_REC *server)
{
	int n;

	for (n = 0; n < CHANNEL_QUERIES; n++) {
		if (server->queries[n] != NULL)
			return n;
	}

	return -1;
}

static void query_send(IRC_SERVER_REC *server, int query)
{
	SERVER_QUERY_REC *rec;
	IRC_CHANNEL_REC *chanrec;
	GSList *chans;
	char *cmd, *chanstr_commas, *chanstr;
	int onlyone, count;

	rec = server->chanqueries;

        /* get the list of channels to query */
	onlyone = (server->no_multi_who && query == CHANNEL_QUERY_WHO) ||
		(server->no_multi_mode && CHANNEL_IS_MODE_QUERY(query));

	if (onlyone) {
                chans = rec->queries[query];
		rec->queries[query] =
			g_slist_remove_link(rec->queries[query], chans);

		chanrec = chans->data;
		chanstr_commas = g_strdup(chanrec->name);
		chanstr = g_strdup(chanrec->name);
                count = 1;
	} else {
		char *chanstr_spaces;

		chans = rec->queries[query];
                count = g_slist_length(chans);

		if (count > server->max_query_chans) {
			GSList *lastchan;

			lastchan = g_slist_nth(rec->queries[query],
					       server->max_query_chans-1);
                        count = server->max_query_chans;
			rec->queries[query] = lastchan->next;
			lastchan->next = NULL;
		} else {
                        rec->queries[query] = NULL;
		}

		chanstr_commas = gslistptr_to_string(chans, G_STRUCT_OFFSET(IRC_CHANNEL_REC, name), ",");
		chanstr_spaces = gslistptr_to_string(chans, G_STRUCT_OFFSET(IRC_CHANNEL_REC, name), " ");

		chanstr = g_strconcat(chanstr_commas, " ", chanstr_spaces, NULL);
		g_free(chanstr_spaces);
	}

	rec->current_query_type = query;
        rec->current_queries = chans;

	switch (query) {
	case CHANNEL_QUERY_MODE:
		cmd = g_strdup_printf("MODE %s", chanstr_commas);

		/* the stop-event is received once for each channel,
		   and we want to print 329 event (channel created). */
		server_redirect_event(server, "mode channel", count,
				      chanstr, -1, "chanquery abort",
				      "event 324", "chanquery mode",
                                      "event 329", "event 329",
				      "", "chanquery abort", NULL);
		break;

	case CHANNEL_QUERY_WHO:
		cmd = g_strdup_printf("WHO %s", chanstr_commas);

		server_redirect_event(server, "who",
				      server->one_endofwho ? 1 : count,
				      chanstr, -1,
				      "chanquery abort",
				      "event 315", "chanquery who end",
				      "event 352", "silent event who",
				      "", "chanquery abort", NULL);
		break;

	case CHANNEL_QUERY_BMODE:
		cmd = g_strdup_printf("MODE %s b", chanstr_commas);
		/* check all the multichannel problems with all
		   mode requests - if channels are joined manually
		   irssi could ask modes separately but afterwards
		   join the two b/e/I modes together */
		server_redirect_event(server, "mode b", count, chanstr, -1,
				      "chanquery abort",
				      "event 367", "chanquery ban",
				      "event 368", "chanquery ban end",
				      "", "chanquery abort", NULL);
		break;

	default:
                cmd = NULL;
	}

	irc_send_cmd(server, cmd);

	g_free(chanstr);
	g_free(chanstr_commas);
	g_free(cmd);
}

static void query_check(IRC_SERVER_REC *server)
{
	SERVER_QUERY_REC *rec;
        int query;

	g_return_if_fail(server != NULL);

	rec = server->chanqueries;
	if (rec->current_queries != NULL)
                return; /* old queries haven't been answered yet */

	if (server->max_query_chans > 1 && !server->no_multi_who && !server->no_multi_mode && !channels_have_all_names(server)) {
		/* all channels haven't sent /NAMES list yet */
		/* only do this if there would be a benefit in combining
		 * queries -- jilles */
		return;
	}

	query = query_find_next(rec);
	if (query == -1) {
		/* no queries left */
		return;
	}

        query_send(server, query);
}

/* if there's no more queries in queries in buffer, send the sync signal */
static void channel_checksync(IRC_CHANNEL_REC *channel)
{
	SERVER_QUERY_REC *rec;
	int n;

	g_return_if_fail(channel != NULL);

	if (channel->synced)
		return; /* already synced */

	rec = channel->server->chanqueries;
	for (n = 0; n < CHANNEL_QUERIES; n++) {
		if (g_slist_find(rec->queries[n], channel))
			return;
	}

	channel->synced = TRUE;
	signal_emit("channel sync", 1, channel);
}

/* Error occurred when trying to execute query - abort and try again. */
static void query_current_error(IRC_SERVER_REC *server)
{
	SERVER_QUERY_REC *rec;
	GSList *tmp;
        int query, abort_query;

	rec = server->chanqueries;

	/* fix the thing that went wrong - or if it was already fixed,
	   then all we can do is abort. */
        abort_query = FALSE;

	query = rec->current_query_type;
	if (query == CHANNEL_QUERY_WHO) {
		if (server->no_multi_who)
			abort_query = TRUE;
		else
			server->no_multi_who = TRUE;
	} else {
		if (server->no_multi_mode)
                        abort_query = TRUE;
                else
			server->no_multi_mode = TRUE;
	}

	if (!abort_query) {
		/* move all currently queried channels to main query lists */
		for (tmp = rec->current_queries; tmp != NULL; tmp = tmp->next) {
			rec->queries[query] =
				g_slist_append(rec->queries[query], tmp->data);
		}
	} else {
		/* check if failed channels are synced after this error */
		g_slist_foreach(rec->current_queries,
				(GFunc) channel_checksync, NULL);
	}

	g_slist_free(rec->current_queries);
	rec->current_queries = NULL;

        query_check(server);
}

static void sig_channel_joined(IRC_CHANNEL_REC *channel)
{
	if (!IS_IRC_CHANNEL(channel))
		return;

	if (!settings_get_bool("channel_sync"))
		return;

	/* Add channel to query lists */
	if (!channel->no_modes)
		query_add_channel(channel, CHANNEL_QUERY_MODE);
	if (g_hash_table_size(channel->nicks) <
	    settings_get_int("channel_max_who_sync"))
		query_add_channel(channel, CHANNEL_QUERY_WHO);
	if (!channel->no_modes)
		query_add_channel(channel, CHANNEL_QUERY_BMODE);

	query_check(channel->server);
}

static void channel_got_query(IRC_CHANNEL_REC *chanrec, int query_type)
{
	SERVER_QUERY_REC *rec;

	g_return_if_fail(chanrec != NULL);

	rec = chanrec->server->chanqueries;
	if (query_type != rec->current_query_type)
                return; /* shouldn't happen */

        /* got the query for channel.. */
	rec->current_queries =
		g_slist_remove(rec->current_queries, chanrec);
	channel_checksync(chanrec);

	/* check if we need to send another query.. */
	query_check(chanrec->server);
}

static void event_channel_mode(IRC_SERVER_REC *server, const char *data,
			       const char *nick)
{
	IRC_CHANNEL_REC *chanrec;
	char *channel, *mode;

	g_return_if_fail(data != NULL);

	event_get_params(data, 3 | PARAM_FLAG_GETREST,
				  NULL, &channel, &mode);
	chanrec = irc_channel_find(server, channel);
	if (chanrec != NULL) {
		if (chanrec->key != NULL && strchr(mode, 'k') == NULL) {
			/* we joined the channel with a key,
			   but it didn't have +k mode.. */
                        parse_channel_modes(chanrec, NULL, "-k", TRUE);
		}
		parse_channel_modes(chanrec, nick, mode, FALSE);
		channel_got_query(chanrec, CHANNEL_QUERY_MODE);
	}
}

static void event_end_of_who(IRC_SERVER_REC *server, const char *data)
{
        SERVER_QUERY_REC *rec;
        GSList *tmp, *next;
	char *channel, **channels;
        int failed, multiple;

	g_return_if_fail(data != NULL);

	event_get_params(data, 2, NULL, &channel);
	multiple = strchr(channel, ',') != NULL;
	channels = g_strsplit(channel, ",", -1);

        failed = FALSE;
	rec = server->chanqueries;
	for (tmp = rec->current_queries; tmp != NULL; tmp = next) {
		IRC_CHANNEL_REC *chanrec = tmp->data;

                next = tmp->next;
		if (strarray_find(channels, chanrec->name) == -1)
			continue;

		if (chanrec->ownnick->host == NULL && multiple &&
		    !server->one_endofwho) {
			/* we should receive our own host for each channel.
			   However, some servers really are stupid enough
			   not to reply anything to /WHO requests.. */
			failed = TRUE;
		} else {
			chanrec->wholist = TRUE;
			signal_emit("channel wholist", 1, chanrec);
			channel_got_query(chanrec, CHANNEL_QUERY_WHO);
		}
	}

	g_strfreev(channels);
	if (multiple)
		server->one_endofwho = TRUE;

	if (failed) {
		/* server didn't understand multiple WHO replies,
		   send them again separately */
                query_current_error(server);
	}
}

static void event_end_of_banlist(IRC_SERVER_REC *server, const char *data)
{
	IRC_CHANNEL_REC *chanrec;
	char *channel;

	g_return_if_fail(data != NULL);

	event_get_params(data, 2, NULL, &channel);
	chanrec = irc_channel_find(server, channel);

	if (chanrec != NULL)
		channel_got_query(chanrec, CHANNEL_QUERY_BMODE);
}

void channels_query_init(void)
{
	settings_add_bool("misc", "channel_sync", TRUE);
	settings_add_int("misc", "channel_max_who_sync", 1000);

	signal_add("server connected", (SIGNAL_FUNC) sig_connected);
	signal_add("server disconnected", (SIGNAL_FUNC) sig_disconnected);
	signal_add("channel joined", (SIGNAL_FUNC) sig_channel_joined);
	signal_add("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);

	signal_add("chanquery mode", (SIGNAL_FUNC) event_channel_mode);
	signal_add("chanquery who end", (SIGNAL_FUNC) event_end_of_who);

	signal_add("chanquery ban end", (SIGNAL_FUNC) event_end_of_banlist);
	signal_add("chanquery abort", (SIGNAL_FUNC) query_current_error);
}

void channels_query_deinit(void)
{
	signal_remove("server connected", (SIGNAL_FUNC) sig_connected);
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_disconnected);
	signal_remove("channel joined", (SIGNAL_FUNC) sig_channel_joined);
	signal_remove("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);

	signal_remove("chanquery mode", (SIGNAL_FUNC) event_channel_mode);
	signal_remove("chanquery who end", (SIGNAL_FUNC) event_end_of_who);

	signal_remove("chanquery ban end", (SIGNAL_FUNC) event_end_of_banlist);
	signal_remove("chanquery abort", (SIGNAL_FUNC) query_current_error);
}
