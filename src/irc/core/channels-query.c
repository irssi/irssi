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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
   server. If it was, send "channel sync" signal
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
	CHANNEL_QUERY_EMODE,
	CHANNEL_QUERY_IMODE,

	CHANNEL_QUERIES
};

#define CHANNEL_IS_MODE_QUERY(a) ((a) != CHANNEL_QUERY_WHO)

typedef struct {
	int last_query;
	char *last_query_chan;
        GSList *queries[CHANNEL_QUERIES];
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
	g_free_not_null(rec->last_query_chan);
	g_free(rec);
}

/* Add channel to query list */
static void channel_query_add(IRC_CHANNEL_REC *channel, int query)
{
	SERVER_QUERY_REC *rec;

	g_return_if_fail(channel != NULL);

	rec = channel->server->chanqueries;
	g_return_if_fail(rec != NULL);

	rec->queries[query] = g_slist_append(rec->queries[query], channel);
}

static void channels_query_check(IRC_SERVER_REC *server);

static void channel_query_remove_all(IRC_CHANNEL_REC *channel)
{
	SERVER_QUERY_REC *rec;
	int n;

	rec = channel->server->chanqueries;
	g_return_if_fail(rec != NULL);

	/* remove channel from query lists */
	for (n = 0; n < CHANNEL_QUERIES; n++)
		rec->queries[n] = g_slist_remove(rec->queries[n], channel);

	channels_query_check(channel->server);}


static void sig_channel_destroyed(IRC_CHANNEL_REC *channel)
{
	g_return_if_fail(channel != NULL);

	if (IS_IRC_CHANNEL(channel) && channel->server != NULL &&
	    !channel->synced)
		channel_query_remove_all(channel);
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

static int find_next_query(SERVER_QUERY_REC *server)
{
	int n;

	for (n = 0; n < CHANNEL_QUERIES; n++) {
		if (server->queries[n] != NULL)
			return n;
	}

	return -1;
}

static void channel_send_query(IRC_SERVER_REC *server, int query)
{
	SERVER_QUERY_REC *rec;
	IRC_CHANNEL_REC *chanrec;
	GSList *chans, *newchans;
	char *cmd, *chanstr_commas, *chanstr;
	int onlyone, count;

	rec = server->chanqueries;
	g_return_if_fail(rec != NULL);

	onlyone = (server->no_multi_who && query == CHANNEL_QUERY_WHO) ||
		(server->no_multi_mode && CHANNEL_IS_MODE_QUERY(query));

        newchans = NULL;
	if (onlyone) {
		chanrec = rec->queries[query]->data;
		chans = g_slist_append(NULL, chanrec);
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
			newchans = lastchan->next;
                        lastchan->next = NULL;
		}

		chanstr_commas = gslistptr_to_string(rec->queries[query], G_STRUCT_OFFSET(IRC_CHANNEL_REC, name), ",");
		chanstr_spaces = gslistptr_to_string(rec->queries[query], G_STRUCT_OFFSET(IRC_CHANNEL_REC, name), " ");

		chanstr = g_strconcat(chanstr_commas, " ", chanstr_spaces, NULL);
		g_free(chanstr_spaces);
	}

	switch (query) {
	case CHANNEL_QUERY_MODE:
		cmd = g_strdup_printf("MODE %s", chanstr_commas);

		/* the stop-event is received once for each channel */
		server_redirect_event(server, "mode channel", count,
				      chanstr, -1, "chanquery mode abort",
				      "event 324", "chanquery mode",
				      "", "chanquery mode abort", NULL);
		break;

	case CHANNEL_QUERY_WHO:
		cmd = g_strdup_printf("WHO %s", chanstr_commas);

		server_redirect_event(server, "who",
				      server->one_endofwho ? 1 : count,
				      chanstr, -1,
				      "chanquery who abort",
				      "event 315", "chanquery who end",
				      "event 352", "silent event who",
				      "", "chanquery who abort", NULL);
		break;

	case CHANNEL_QUERY_BMODE:
		cmd = g_strdup_printf("MODE %s b", chanstr_commas);
		/* check all the multichannel problems with all
		   mode requests - if channels are joined manually
		   irssi could ask modes separately but afterwards
		   join the two b/e/I modes together */
		server_redirect_event(server, "mode b", count, chanstr, -1,
				      "chanquery mode abort",
				      "event 367", "chanquery ban",
				      "event 368", "chanquery ban end",
				      "", "chanquery mode abort", NULL);
		break;

	case CHANNEL_QUERY_EMODE:
		cmd = g_strdup_printf("MODE %s e", chanstr_commas);
		server_redirect_event(server, "mode e", count, chanstr, -1,
				      "chanquery mode abort",
				      "event 348", "chanquery eban",
				      "event 349", "chanquery eban end",
				      "", "chanquery mode abort", NULL);
		break;

	case CHANNEL_QUERY_IMODE:
		cmd = g_strdup_printf("MODE %s I", chanstr_commas);
		server_redirect_event(server, "mode I", count, chanstr, -1,
				      "chanquery mode abort",
				      "event 346", "chanquery ilist",
				      "event 347", "chanquery ilist end",
				      "", "chanquery mode abort", NULL);
		break;

	default:
                cmd = NULL;
	}

	g_free(chanstr);
	g_free(chanstr_commas);

	/* Get the channel of last query */
	chanrec = g_slist_last(chans)->data;
	rec->last_query_chan = g_strdup(chanrec->name);
	rec->last_query = query;

	if (!onlyone) {
		/* all channels queried, set to newchans which contains
		   the rest of the channels for the same query (usually NULL
		   unless query count exceeded max_query_chans) */
		g_slist_free(rec->queries[query]);
		rec->queries[query] = newchans;
	} else {
		/* remove the first channel from list */
		rec->queries[query] =
			g_slist_remove(rec->queries[query], chans->data);
	}

	/* send the command */
	irc_send_cmd(server, cmd);
	g_free(cmd);
}

static void channels_query_check(IRC_SERVER_REC *server)
{
	SERVER_QUERY_REC *rec;
        int query;

	g_return_if_fail(server != NULL);

	rec = server->chanqueries;
	g_return_if_fail(rec != NULL);

	g_free_and_null(rec->last_query_chan);
	if (!channels_have_all_names(server)) {
		/* all channels haven't sent /NAMES list yet */
		return;
	}

	query = find_next_query(rec);
	if (query == -1) {
		/* no queries left */
		return;
	}

        channel_send_query(server, query);
}

static void sig_channel_joined(IRC_CHANNEL_REC *channel)
{
	SERVER_QUERY_REC *rec;

	if (!IS_IRC_CHANNEL(channel))
		return;

	if (!settings_get_bool("channel_sync"))
		return;

	/* Add channel to query lists */
	if (!channel->no_modes)
		channel_query_add(channel, CHANNEL_QUERY_MODE);
	channel_query_add(channel, CHANNEL_QUERY_WHO);
	if (!channel->no_modes) {
		channel_query_add(channel, CHANNEL_QUERY_BMODE);
		if (channel->server->emode_known) {
			channel_query_add(channel, CHANNEL_QUERY_EMODE);
			channel_query_add(channel, CHANNEL_QUERY_IMODE);
		}
	}

	rec = channel->server->chanqueries;
	if (rec->last_query_chan == NULL)
		channels_query_check(channel->server);
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
	g_return_if_fail(rec != NULL);

	for (n = 0; n < CHANNEL_QUERIES; n++) {
		if (g_slist_find(rec->queries[n], channel))
			return;
	}

	channel->synced = TRUE;
	signal_emit("channel sync", 1, channel);
}

static void channel_got_query(IRC_SERVER_REC *server, IRC_CHANNEL_REC *chanrec,
			      const char *channel)
{
	SERVER_QUERY_REC *rec;

	g_return_if_fail(server != NULL);
	g_return_if_fail(channel != NULL);

	rec = server->chanqueries;
	g_return_if_fail(rec != NULL);

	/* check if channel is synced */
	if (chanrec != NULL) channel_checksync(chanrec);

	/* check if we need to get another query.. */
	if (rec->last_query_chan != NULL &&
	    g_strcasecmp(rec->last_query_chan, channel) == 0)
		channels_query_check(server);
}

static void event_channel_mode(IRC_SERVER_REC *server, const char *data,
			       const char *nick)
{
	IRC_CHANNEL_REC *chanrec;
	char *params, *channel, *mode;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3 | PARAM_FLAG_GETREST, NULL, &channel, &mode);
	chanrec = irc_channel_find(server, channel);
	if (chanrec != NULL) {
		if (chanrec->key != NULL && strchr(mode, 'k') == NULL) {
			/* we joined the channel with a key,
			   but it didn't have +k mode.. */
                        parse_channel_modes(chanrec, NULL, "-k");
		}
		parse_channel_modes(chanrec, nick, mode);
	}
	channel_got_query(server, chanrec, channel);

	g_free(params);
}

static void event_end_of_who(IRC_SERVER_REC *server, const char *data)
{
	IRC_CHANNEL_REC *chanrec;
	char *params, *channel, **chans;
	int n, onewho;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);

	chans = g_strsplit(channel, ",", -1);
        onewho = strchr(channel, ',') != NULL;
	if (onewho) {
		/* instead of multiple End of WHO replies we get
		   only this one... */
		server->one_endofwho = TRUE;

		/* check that the WHO actually did return something
		   (that it understood #chan1,#chan2,..) */
		chanrec = irc_channel_find(server, chans[0]);
		if (chanrec->ownnick->host == NULL)
			server->no_multi_who = TRUE;
	}

	for (n = 0; chans[n] != NULL; n++) {
		chanrec = irc_channel_find(server, chans[n]);
		if (chanrec == NULL)
			continue;

		if (onewho && server->no_multi_who) {
			channel_query_add(chanrec, CHANNEL_QUERY_WHO);
			continue;
		}

		chanrec->wholist = TRUE;
		signal_emit("channel wholist", 1, chanrec);

		/* check if we need can send another query */
		channel_got_query(server, chanrec, chans[n]);
	}

	g_strfreev(chans);
	g_free(params);

	if (onewho && server->no_multi_who) {
		/* server didn't understand multiple WHO replies,
		   send them again separately */
		channels_query_check(server);
	}
}

static void event_end_of_banlist(IRC_SERVER_REC *server, const char *data)
{
	IRC_CHANNEL_REC *chanrec;
	char *params, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);
	chanrec = irc_channel_find(server, channel);

	channel_got_query(server, chanrec, channel);

	g_free(params);
}

static void event_end_of_ebanlist(IRC_SERVER_REC *server, const char *data)
{
	IRC_CHANNEL_REC *chanrec;
	char *params, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);
	chanrec = irc_channel_find(server, channel);

	channel_got_query(server, chanrec, channel);

	g_free(params);
}

static void event_end_of_invitelist(IRC_SERVER_REC *server, const char *data)
{
	IRC_CHANNEL_REC *chanrec;
	char *params, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);
	chanrec = irc_channel_find(server, channel);

	channel_got_query(server, chanrec, channel);

	g_free(params);
}

static void channel_lost(IRC_SERVER_REC *server, const char *channel)
{
	IRC_CHANNEL_REC *chanrec;

	chanrec = irc_channel_find(server, channel);
	if (chanrec != NULL) {
		/* channel not found - probably created a new channel
		   and left it immediately. */
		channel_query_remove_all(chanrec);
	}

	channel_got_query(server, chanrec, channel);
}

static void multi_command_error(IRC_SERVER_REC *server, const char *data,
				int query, const char *event)
{
	IRC_CHANNEL_REC *chanrec;
	char *params, *channel, **chans;
	int n;

	params = event_get_params(data, 2, NULL, &channel);

	chans = g_strsplit(channel, ",", -1);
	for (n = 0; chans[n] != NULL; n++)
	{
		chanrec = irc_channel_find(server, chans[n]);
		if (chanrec != NULL)
			channel_query_add(chanrec, query);
	}
	g_strfreev(chans);
	g_free(params);

	channels_query_check(server);
}

static void event_mode_abort(IRC_SERVER_REC *server, const char *data)
{
	char *params, *channel;

	g_return_if_fail(data != NULL);
	params = event_get_params(data, 2, NULL, &channel);

	if (strchr(channel, ',') == NULL) {
		channel_lost(server, channel);
	} else {
		SERVER_QUERY_REC *rec = server->chanqueries;

		server->no_multi_mode = TRUE;
		multi_command_error(server, data, rec->last_query, "event 324");
	}

	g_free(params);
}

static void event_who_abort(IRC_SERVER_REC *server, const char *data)
{
	char *params, *channel;

	g_return_if_fail(data != NULL);
	params = event_get_params(data, 2, NULL, &channel);

	if (strchr(channel, ',') == NULL) {
		channel_lost(server, channel);
	} else {
		server->no_multi_who = TRUE;
		multi_command_error(server, data, CHANNEL_QUERY_WHO, "event 315");
	}

	g_free(params);
}

void channels_query_init(void)
{
	settings_add_bool("misc", "channel_sync", TRUE);

	signal_add("server connected", (SIGNAL_FUNC) sig_connected);
	signal_add("server disconnected", (SIGNAL_FUNC) sig_disconnected);
	signal_add("channel joined", (SIGNAL_FUNC) sig_channel_joined);
	signal_add("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);

	signal_add("chanquery mode", (SIGNAL_FUNC) event_channel_mode);
	signal_add("chanquery who end", (SIGNAL_FUNC) event_end_of_who);

	signal_add("chanquery eban end", (SIGNAL_FUNC) event_end_of_ebanlist);
	signal_add("chanquery ban end", (SIGNAL_FUNC) event_end_of_banlist);
	signal_add("chanquery ilist end", (SIGNAL_FUNC) event_end_of_invitelist);
	signal_add("chanquery mode abort", (SIGNAL_FUNC) event_mode_abort);
	signal_add("chanquery who abort", (SIGNAL_FUNC) event_who_abort);
}

void channels_query_deinit(void)
{
	signal_remove("server connected", (SIGNAL_FUNC) sig_connected);
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_disconnected);
	signal_remove("channel joined", (SIGNAL_FUNC) sig_channel_joined);
	signal_remove("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);

	signal_remove("chanquery mode", (SIGNAL_FUNC) event_channel_mode);
	signal_remove("chanquery who end", (SIGNAL_FUNC) event_end_of_who);

	signal_remove("chanquery eban end", (SIGNAL_FUNC) event_end_of_ebanlist);
	signal_remove("chanquery ban end", (SIGNAL_FUNC) event_end_of_banlist);
	signal_remove("chanquery ilist end", (SIGNAL_FUNC) event_end_of_invitelist);
	signal_remove("chanquery mode abort", (SIGNAL_FUNC) event_mode_abort);
	signal_remove("chanquery who abort", (SIGNAL_FUNC) event_who_abort);
}
