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
#include <irssi/src/core/misc.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/settings.h>

#include <irssi/src/irc/core/modes.h>
#include <irssi/src/irc/core/mode-lists.h>
#include <irssi/src/core/nicklist.h>
#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/irc/core/irc-channels.h>
#include <irssi/src/irc/core/servers-redirect.h>

/* here are the WHOX commands we send. the full spec can be found on [1].

   (1) WHOX_CHANNEL_FULL_CMD for getting the user list when we join a channel. we request the fields
       c (channel), u (user), h (host), n (nick), f (flags), d (hops), a (account), and r (the real
       name goes last because it is the only that can contain spaces.) we request all those fields
       as they are also included in the "regular" WHO reply we would get without WHOX.

   (2) WHOX_USERACCOUNT_CMD for getting the account names of people that joined. this code is
       obviously only used when we don't have extended-joins. we request n (nick) and a (account)
       only, and we only send WHO nick with this command.

   [1] https://github.com/UndernetIRC/ircu2/blob/u2_10_12_branch/doc/readme.who
  */
#define WHOX_CHANNEL_FULL_CMD "WHO %s %%tcuhnfdar," WHOX_CHANNEL_FULL_ID
#define WHOX_USERACCOUNT_CMD "WHO %s %%tna," WHOX_USERACCOUNT_ID

static void sig_connected(IRC_SERVER_REC *server)
{
	SERVER_QUERY_REC *rec;

	g_return_if_fail(server != NULL);
	if (!IS_IRC_SERVER(server))
		return;

	rec = g_new0(SERVER_QUERY_REC, 1);
	rec->accountqueries = g_hash_table_new_full(
	    (GHashFunc) i_istr_hash, (GCompareFunc) i_istr_equal, (GDestroyNotify) g_free, NULL);
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
	if (rec == NULL)
		return;
	g_return_if_fail(rec != NULL);

	g_hash_table_destroy(rec->accountqueries);
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
	if (rec == NULL) return;

	/* remove channel from query lists */
	for (n = 0; n < CHANNEL_QUERIES; n++)
		rec->queries[n] = g_slist_remove(rec->queries[n], channel);
	rec->current_queries = g_slist_remove(rec->current_queries, channel);

	if (!channel->server->disconnected)
		query_check(channel->server);
}

static void sig_channel_destroyed(IRC_CHANNEL_REC *channel)
{
	g_return_if_fail(channel != NULL);

	if (IS_IRC_CHANNEL(channel))
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
		if (server->isupport != NULL &&
		    g_hash_table_lookup(server->isupport, "whox") != NULL) {
			cmd = g_strdup_printf(WHOX_CHANNEL_FULL_CMD, chanstr_commas);
		} else {
			cmd = g_strdup_printf("WHO %s", chanstr_commas);
		}

		server_redirect_event(server, "who", server->one_endofwho ? 1 : count, chanstr, -1,
		                      "chanquery abort",                /* failure signal */
		                      "event 315", "chanquery who end", /* */
		                      "event 352", "silent event who",  /* */
		                      "event 354", "silent event whox", /* */
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

	irc_send_cmd_later(server, cmd);

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

void irc_channels_query_purge_accountquery(IRC_SERVER_REC *server, const char *nick)
{
	GSList *tmp, *next, *prev;
	REDIRECT_REC *redirect;
	char *cmd, *target_cmd;
	gboolean was_removed;

	/* remove the marker */
	was_removed = g_hash_table_remove(server->chanqueries->accountqueries, nick);

	/* if it was removed we may have an outstanding query */
	if (was_removed) {
		target_cmd = g_strdup_printf(WHOX_USERACCOUNT_CMD "\r\n", nick);

		/* remove queued WHO command */
		prev = NULL;
		for (tmp = server->cmdqueue; tmp != NULL; tmp = next) {
			next = tmp->next->next;
			cmd = tmp->data;
			redirect = tmp->next->data;

			if (g_strcmp0(cmd, target_cmd) == 0) {
				if (prev != NULL)
					prev->next = next;
				else
					server->cmdqueue = next;

				/* remove the redirection */
				g_slist_free_1(tmp->next);
				if (redirect != NULL)
					server_redirect_destroy(redirect);

				/* remove the command */
				g_slist_free_1(tmp);
				g_free(cmd);

				server->cmdcount--;
				server->cmdlater--;
			} else {
				prev = tmp->next;
			}
		}

		g_free(target_cmd);
	}
}

static void query_useraccount_error(IRC_SERVER_REC *server, const char *cmd, const char *arg)
{
	/* query failed, ignore it but remove the marker */
	g_hash_table_remove(server->chanqueries->accountqueries, arg);
}

static void sig_event_join(IRC_SERVER_REC *server, const char *data, const char *nick,
                           const char *address)
{
	char *params, *channel, *ptr, *account;
	GSList *nicks, *tmp;
	IRC_CHANNEL_REC *chanrec;
	NICK_REC *nickrec;

	g_return_if_fail(data != NULL);

	if (i_slist_find_string(server->cap_active, CAP_EXTENDED_JOIN)) {
		/* no need to chase accounts */
		return;
	}

	if (g_ascii_strcasecmp(nick, server->nick) == 0) {
		/* You joined, do nothing */
		return;
	}

	params = event_get_params(data, 3, &channel, NULL, NULL);

	ptr = strchr(channel, 7); /* ^G does something weird.. */
	if (ptr != NULL)
		*ptr = '\0';

	/* find channel */
	chanrec = irc_channel_find(server, channel);
	if (chanrec == NULL) {
		g_free(params);
		return;
	}

	g_free(params);

	if (!chanrec->wholist) {
		return;
	}

	/* find nick */
	nickrec = nicklist_find(CHANNEL(chanrec), nick);
	if (nickrec == NULL) {
		return;
	}

	if (nickrec->account != NULL) {
		return;
	}

	if (g_hash_table_contains(server->chanqueries->accountqueries, nick)) {
		/* query already sent */
		return;
	}
	account = NULL;

	/* Check if user is already in some other channel, get the account from there */
	nicks = nicklist_get_same(SERVER(server), nick);
	for (tmp = nicks; tmp != NULL; tmp = tmp->next->next) {
		NICK_REC *rec = tmp->next->data;

		if (rec->account != NULL) {
			account = rec->account;
			break;
		}
	}
	g_slist_free(nicks);

	if (account != NULL) {
		nicklist_set_account(CHANNEL(chanrec), nickrec, account);
		return;
	}

	if (g_hash_table_size(chanrec->nicks) < settings_get_int("channel_max_who_sync") &&
	    server->isupport != NULL && g_hash_table_lookup(server->isupport, "whox") != NULL &&
	    server->split_servers == NULL &&
	    g_hash_table_size(server->chanqueries->accountqueries) <
	        settings_get_int("account_max_chase")) {
		char *cmd;
		server_redirect_event(server, "who user", 1, nick, -1,
		                      "chanquery useraccount abort", /* failure signal */
		                      "event 354", "silent event whox useraccount", /* */
		                      "", "event empty",                            /* */
		                      NULL);
		cmd = g_strdup_printf(WHOX_USERACCOUNT_CMD, nick);
		g_hash_table_add(server->chanqueries->accountqueries, g_strdup(nick));
		/* queue the command */
		irc_send_cmd_later(server, cmd);
		g_free(cmd);
	}
}

static void event_channel_mode(IRC_SERVER_REC *server, const char *data,
			       const char *nick)
{
	IRC_CHANNEL_REC *chanrec;
	char *params, *channel, *mode;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3 | PARAM_FLAG_GETREST,
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

	g_free(params);
}

static void event_end_of_who(IRC_SERVER_REC *server, const char *data)
{
        SERVER_QUERY_REC *rec;
        GSList *tmp, *next;
	char *params, *channel, **channels;
        int failed, multiple;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);
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

        g_free(params);
}

static void event_end_of_banlist(IRC_SERVER_REC *server, const char *data)
{
	IRC_CHANNEL_REC *chanrec;
	char *params, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);
	chanrec = irc_channel_find(server, channel);

	if (chanrec != NULL)
		channel_got_query(chanrec, CHANNEL_QUERY_BMODE);

	g_free(params);
}

void channels_query_init(void)
{
	settings_add_bool("misc", "channel_sync", TRUE);
	settings_add_int("misc", "channel_max_who_sync", 1000);
	settings_add_int("misc", "account_max_chase", 10);

	signal_add("server connected", (SIGNAL_FUNC) sig_connected);
	signal_add("server disconnected", (SIGNAL_FUNC) sig_disconnected);
	signal_add("channel joined", (SIGNAL_FUNC) sig_channel_joined);
	signal_add("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);

	signal_add("event join", (SIGNAL_FUNC) sig_event_join);

	signal_add("chanquery mode", (SIGNAL_FUNC) event_channel_mode);
	signal_add("chanquery who end", (SIGNAL_FUNC) event_end_of_who);

	signal_add("chanquery ban end", (SIGNAL_FUNC) event_end_of_banlist);
	signal_add("chanquery abort", (SIGNAL_FUNC) query_current_error);
	signal_add("chanquery useraccount abort", (SIGNAL_FUNC) query_useraccount_error);
}

void channels_query_deinit(void)
{
	signal_remove("server connected", (SIGNAL_FUNC) sig_connected);
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_disconnected);
	signal_remove("channel joined", (SIGNAL_FUNC) sig_channel_joined);
	signal_remove("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);

	signal_remove("event join", (SIGNAL_FUNC) sig_event_join);

	signal_remove("chanquery mode", (SIGNAL_FUNC) event_channel_mode);
	signal_remove("chanquery who end", (SIGNAL_FUNC) event_end_of_who);

	signal_remove("chanquery ban end", (SIGNAL_FUNC) event_end_of_banlist);
	signal_remove("chanquery abort", (SIGNAL_FUNC) query_current_error);
	signal_remove("chanquery useraccount abort", (SIGNAL_FUNC) query_useraccount_error);
}
