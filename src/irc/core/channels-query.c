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

 - After channel is joined and NAMES list is got, send "channel query" signal
 - "channel query" : add channel to server->quries lists

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
#include "modules.h"
#include "misc.h"
#include "signals.h"

#include "channels.h"
#include "irc.h"
#include "modes.h"
#include "mode-lists.h"
#include "nicklist.h"
#include "irc-server.h"
#include "server-redirect.h"

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
	char *last_query_chan;
        GSList *queries[CHANNEL_QUERIES];
} SERVER_QUERY_REC;

static void sig_connected(IRC_SERVER_REC *server)
{
	SERVER_QUERY_REC *rec;

	g_return_if_fail(server != NULL);
	if (!irc_server_check(server)) return;

	rec = g_new0(SERVER_QUERY_REC, 1);
        server->chanqueries = rec;
}

static void sig_disconnected(IRC_SERVER_REC *server)
{
	SERVER_QUERY_REC *rec;
	int n;

	g_return_if_fail(server != NULL);
	if (!irc_server_check(server)) return;

	rec = server->chanqueries;
	g_return_if_fail(rec != NULL);

	for (n = 0; n < CHANNEL_QUERIES; n++)
		g_slist_free(rec->queries[n]);
	g_free_not_null(rec->last_query_chan);
	g_free(rec);
}

/* Add channel to query list */
static void channel_query_add(CHANNEL_REC *channel, int query)
{
	SERVER_QUERY_REC *rec;

	g_return_if_fail(channel != NULL);

	rec = channel->server->chanqueries;
	g_return_if_fail(rec != NULL);

	rec->queries[query] = g_slist_append(rec->queries[query], channel);
}

static void channel_query_remove_all(CHANNEL_REC *channel)
{
	SERVER_QUERY_REC *rec;
	int n;

	rec = channel->server->chanqueries;
	g_return_if_fail(rec != NULL);

	/* remove channel from query lists */
	for (n = 0; n < CHANNEL_QUERIES; n++)
		rec->queries[n] = g_slist_remove(rec->queries[n], channel);
}


static void sig_channel_destroyed(CHANNEL_REC *channel)
{
	g_return_if_fail(channel != NULL);

	if (channel->server != NULL && !channel->synced)
		channel_query_remove_all(channel);
}

static int channels_have_all_names(IRC_SERVER_REC *server)
{
	GSList *tmp;

	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *rec = tmp->data;

		if (!rec->names_got)
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
	CHANNEL_REC *chanrec;
	GSList *tmp, *chans;
	char *cmd, *chanstr_commas, *chanstr;
	int onlyone;

	rec = server->chanqueries;
	g_return_if_fail(rec != NULL);

	onlyone = (server->no_multi_who && query == CHANNEL_QUERY_WHO) ||
		(server->no_multi_mode && CHANNEL_IS_MODE_QUERY(query));

	if (onlyone) {
		chanrec = rec->queries[query]->data;
		chans = g_slist_append(NULL, chanrec);
		chanstr_commas = g_strdup(chanrec->name);
		chanstr = g_strdup(chanrec->name);
	} else {
		char *chanstr_spaces;

		chans = rec->queries[query];

		chanstr_commas = gslist_to_string(rec->queries[query], G_STRUCT_OFFSET(CHANNEL_REC, name), ",");
		chanstr_spaces = gslist_to_string(rec->queries[query], G_STRUCT_OFFSET(CHANNEL_REC, name), " ");

		chanstr = g_strconcat(chanstr_commas, " ", chanstr_spaces, NULL);
		g_free(chanstr_spaces);
	}

	switch (query) {
	case CHANNEL_QUERY_MODE:
		cmd = g_strdup_printf("MODE %s", chanstr_commas);
		for (tmp = chans; tmp != NULL; tmp = tmp->next) {
			chanrec = tmp->data;

			server_redirect_event((SERVER_REC *) server, chanstr, 3,
					      "event 403", "chanquery mode abort", 1,
					      "event 442", "chanquery mode abort", 1, /* "you're not on that channel" */
					      "event 324", "chanquery mode", 1, NULL);
		}
		break;

	case CHANNEL_QUERY_WHO:
		cmd = g_strdup_printf("WHO %s", chanstr_commas);

		for (tmp = chans; tmp != NULL; tmp = tmp->next) {
			chanrec = tmp->data;

			server_redirect_event((SERVER_REC *) server, chanstr, 2,
					      "event 401", "chanquery who abort", 1,
					      "event 315", "chanquery who end", 1,
					      "event 352", "silent event who", 1, NULL);
		}
		break;

	case CHANNEL_QUERY_BMODE:
		cmd = g_strdup_printf("MODE %s b", chanstr_commas);
		for (tmp = chans; tmp != NULL; tmp = tmp->next) {
			chanrec = tmp->data;

			server_redirect_event((SERVER_REC *) server, chanrec->name, 2,
					      "event 403", "chanquery mode abort", 1,
					      "event 368", "chanquery ban end", 1,
					      "event 367", "chanquery ban", 1, NULL);
		}
		break;

	case CHANNEL_QUERY_EMODE:
		cmd = g_strdup_printf("MODE %s e", chanstr_commas);
		for (tmp = chans; tmp != NULL; tmp = tmp->next) {
			chanrec = tmp->data;

			server_redirect_event((SERVER_REC *) server, chanrec->name, 4,
					      "event 403", "chanquery mode abort", 1,
					      "event 349", "chanquery eban end", 1,
					      "event 348", "chanquery eban", 1, NULL);
		}
		break;

	case CHANNEL_QUERY_IMODE:
		cmd = g_strdup_printf("MODE %s I", chanstr_commas);
		for (tmp = chans; tmp != NULL; tmp = tmp->next) {
			chanrec = tmp->data;

			server_redirect_event((SERVER_REC *) server, chanrec->name, 4,
					      "event 403", "chanquery mode abort", 1,
					      "event 347", "chanquery ilist end", 1,
					      "event 346", "chanquery ilist", 1, NULL);
		}
		break;

	default:
                cmd = NULL;
	}

	g_free(chanstr);
	g_free(chanstr_commas);

	/* Get the channel of last query */
	chanrec = g_slist_last(chans)->data;
	rec->last_query_chan = g_strdup(chanrec->name);

	if (!onlyone) {
		/* all channels queried, set to NULL */
		g_slist_free(rec->queries[query]);
		rec->queries[query] = NULL;
	} else {
		/* remove the first channel from list */
		rec->queries[query] = g_slist_remove(rec->queries[query], chans->data);
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

static void sig_channel_query(CHANNEL_REC *channel)
{
	SERVER_QUERY_REC *rec;

	g_return_if_fail(channel != NULL);

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
static void channel_checksync(CHANNEL_REC *channel)
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

static void channel_got_query(IRC_SERVER_REC *server, CHANNEL_REC *chanrec, const char *channel)
{
	SERVER_QUERY_REC *rec;

	g_return_if_fail(server != NULL);
	g_return_if_fail(channel != NULL);

	rec = server->chanqueries;
	g_return_if_fail(rec != NULL);
	g_return_if_fail(rec->last_query_chan != NULL);

	/* check if we need to get another query.. */
	if (g_strcasecmp(rec->last_query_chan, channel) == 0)
		channels_query_check(server);

	/* check if channel is synced */
	if (chanrec != NULL) channel_checksync(chanrec);
}

static void event_channel_mode(char *data, IRC_SERVER_REC *server, const char *nick)
{
	CHANNEL_REC *chanrec;
	char *params, *channel, *mode;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3 | PARAM_FLAG_GETREST, NULL, &channel, &mode);
	chanrec = channel_find(server, channel);
	if (chanrec != NULL)
		parse_channel_modes(chanrec, nick, mode);
	channel_got_query(server, chanrec, channel);

	g_free(params);
}

static void multi_query_remove(IRC_SERVER_REC *server, const char *event, const char *data)
{
	GSList *queue;

	while ((queue = server_redirect_getqueue((SERVER_REC *) server, event, data)) != NULL)
		server_redirect_remove_next((SERVER_REC *) server, event, queue);
}

static void event_end_of_who(const char *data, IRC_SERVER_REC *server)
{
	CHANNEL_REC *chanrec;
	NICK_REC *nick;
	char *params, *channel, **chans;
	int n, onewho;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);

        onewho = strchr(channel, ',') != NULL;
	if (onewho) {
		/* instead of multiple End of WHO replies we get
		   only this one... */
		server->one_endofwho = TRUE;
		multi_query_remove(server, "event 315", data);

		/* check that the WHO actually did return something
		   (that it understood #chan1,#chan2,..) */
		chanrec = channel_find(server, channel);
		nick = nicklist_find(chanrec, server->nick);
		if (nick->host == NULL)
			server->no_multi_who = TRUE;
	}

	chans = g_strsplit(channel, ",", -1);
	for (n = 0; chans[n] != NULL; n++) {
		chanrec = channel_find(server, chans[n]);
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

static void event_end_of_banlist(const char *data, IRC_SERVER_REC *server)
{
	CHANNEL_REC *chanrec;
	char *params, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);
	chanrec = channel_find(server, channel);

	channel_got_query(server, chanrec, channel);

	g_free(params);
}

static void event_end_of_ebanlist(const char *data, IRC_SERVER_REC *server)
{
	CHANNEL_REC *chanrec;
	char *params, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);
	chanrec = channel_find(server, channel);

	channel_got_query(server, chanrec, channel);

	g_free(params);
}

static void event_end_of_invitelist(const char *data, IRC_SERVER_REC *server)
{
	CHANNEL_REC *chanrec;
	char *params, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);
	chanrec = channel_find(server, channel);

	channel_got_query(server, chanrec, channel);

	g_free(params);
}

static void channel_lost(IRC_SERVER_REC *server, const char *channel)
{
	CHANNEL_REC *chanrec;

	chanrec = channel_find(server, channel);
	if (chanrec != NULL) {
		/* channel not found - probably created a new channel
		   and left it immediately. */
		channel_query_remove_all(chanrec);
	}

	channel_got_query(server, chanrec, channel);
}

static void multi_command_error(IRC_SERVER_REC *server, const char *data, int query, const char *event)
{
	CHANNEL_REC *chanrec;
	char *params, *channel, **chans;
	int n;

	multi_query_remove(server, event, data);

	params = event_get_params(data, 2, NULL, &channel);

	chans = g_strsplit(channel, ",", -1);
	for (n = 0; chans[n] != NULL; n++)
	{
		chanrec = channel_find(server, chans[n]);
		if (chanrec != NULL)
			channel_query_add(chanrec, query);
	}
	g_strfreev(chans);
	g_free(params);

	channels_query_check(server);
}

static void event_mode_abort(const char *data, IRC_SERVER_REC *server)
{
	char *params, *channel;

	g_return_if_fail(data != NULL);
	params = event_get_params(data, 2, NULL, &channel);

	if (strchr(channel, ',') == NULL) {
		channel_lost(server, channel);
	} else {
		server->no_multi_mode = TRUE;
		multi_command_error(server, data, CHANNEL_QUERY_MODE, "event 324");
	}

	g_free(params);
}

static void event_who_abort(const char *data, IRC_SERVER_REC *server)
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
	signal_add("server connected", (SIGNAL_FUNC) sig_connected);
	signal_add("server disconnected", (SIGNAL_FUNC) sig_disconnected);
	signal_add("channel query", (SIGNAL_FUNC) sig_channel_query);
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
	signal_remove("channel query", (SIGNAL_FUNC) sig_channel_query);
	signal_remove("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);

	signal_remove("chanquery mode", (SIGNAL_FUNC) event_channel_mode);
	signal_remove("chanquery who end", (SIGNAL_FUNC) event_end_of_who);

	signal_remove("chanquery eban end", (SIGNAL_FUNC) event_end_of_ebanlist);
	signal_remove("chanquery ban end", (SIGNAL_FUNC) event_end_of_banlist);
	signal_remove("chanquery ilist end", (SIGNAL_FUNC) event_end_of_invitelist);
	signal_remove("chanquery mode abort", (SIGNAL_FUNC) event_mode_abort);
	signal_remove("chanquery who abort", (SIGNAL_FUNC) event_who_abort);
}
