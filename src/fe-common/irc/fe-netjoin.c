/*
 fe-netjoin.c : irssi

    Copyright (C) 2000 Timo Sirainen

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
#include <irssi/src/fe-common/irc/module-formats.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/settings.h>

#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/irc/core/modes.h>
#include <irssi/src/core/ignore.h>
#include <irssi/src/irc/core/netsplit.h>

#include <irssi/src/fe-common/core/printtext.h>

#define NETJOIN_WAIT_TIME 5 /* how many seconds to wait for the netsplitted JOIN messages to stop */
#define NETJOIN_MAX_WAIT 30 /* how many seconds to wait for nick to join to the rest of the channels she was before the netsplit */

typedef struct {
	char *nick;
	GSList *old_channels;
	GSList *now_channels;
} NETJOIN_REC;

typedef struct {
	IRC_SERVER_REC *server;
	time_t last_netjoin;

	GSList *netjoins;
} NETJOIN_SERVER_REC;

typedef struct {
	int count;
        GString *nicks;
} TEMP_PRINT_REC;

static int join_tag;
static int netjoin_max_nicks, hide_netsplit_quits;
static int printing_joins;
static GSList *joinservers;

static NETJOIN_SERVER_REC *netjoin_find_server(IRC_SERVER_REC *server)
{
	GSList *tmp;

	g_return_val_if_fail(server != NULL, NULL);

	for (tmp = joinservers; tmp != NULL; tmp = tmp->next) {
		NETJOIN_SERVER_REC *rec = tmp->data;

		if (rec->server == server)
                        return rec;
	}

	return NULL;
}

static NETJOIN_REC *netjoin_add(IRC_SERVER_REC *server, const char *nick,
				GSList *channels)
{
	NETJOIN_REC *rec;
	NETJOIN_SERVER_REC *srec;

	g_return_val_if_fail(server != NULL, NULL);
	g_return_val_if_fail(nick != NULL, NULL);

	rec = g_new0(NETJOIN_REC, 1);
	rec->nick = g_strdup(nick);
	while (channels != NULL) {
		NETSPLIT_CHAN_REC *channel = channels->data;

		rec->old_channels = g_slist_append(rec->old_channels,
						   g_strdup(channel->name));
		channels = channels->next;
	}

	srec = netjoin_find_server(server);
	if (srec == NULL) {
		srec = g_new0(NETJOIN_SERVER_REC, 1);
		srec->server = server;
                joinservers = g_slist_append(joinservers, srec);
	}

	srec->last_netjoin = time(NULL);
	srec->netjoins = g_slist_append(srec->netjoins, rec);
	return rec;
}

static NETJOIN_REC *netjoin_find(IRC_SERVER_REC *server, const char *nick)
{
	NETJOIN_SERVER_REC *srec;
	GSList *tmp;

	g_return_val_if_fail(server != NULL, NULL);
	g_return_val_if_fail(nick != NULL, NULL);

	srec = netjoin_find_server(server);
        if (srec == NULL) return NULL;

	for (tmp = srec->netjoins; tmp != NULL; tmp = tmp->next) {
		NETJOIN_REC *rec = tmp->data;

		if (g_ascii_strcasecmp(rec->nick, nick) == 0)
			return rec;
	}

	return NULL;
}

static void netjoin_remove(NETJOIN_SERVER_REC *server, NETJOIN_REC *rec)
{
	server->netjoins = g_slist_remove(server->netjoins, rec);

        g_slist_foreach(rec->old_channels, (GFunc) g_free, NULL);
	g_slist_foreach(rec->now_channels, (GFunc) g_free, NULL);
	g_slist_free(rec->old_channels);
	g_slist_free(rec->now_channels);

	g_free(rec->nick);
	g_free(rec);
}

static void netjoin_server_remove(NETJOIN_SERVER_REC *server)
{
	joinservers = g_slist_remove(joinservers, server);

	while (server->netjoins != NULL)
		netjoin_remove(server, server->netjoins->data);
        g_free(server);
}

static void print_channel_netjoins(char *channel, TEMP_PRINT_REC *rec,
				   NETJOIN_SERVER_REC *server)
{
	if (rec->nicks->len > 0)
		g_string_truncate(rec->nicks, rec->nicks->len-2);

	printformat(server->server, channel, MSGLEVEL_JOINS,
		    rec->count > netjoin_max_nicks ?
		    IRCTXT_NETSPLIT_JOIN_MORE : IRCTXT_NETSPLIT_JOIN,
		    rec->nicks->str, rec->count-netjoin_max_nicks);

	g_string_free(rec->nicks, TRUE);
	g_free(rec);
	g_free(channel);
}

static void print_netjoins(NETJOIN_SERVER_REC *server, const char *filter_channel)
{
	TEMP_PRINT_REC *temp;
	GHashTable *channels;
	GSList *tmp, *tmp2, *next, *next2, *old;

	g_return_if_fail(server != NULL);

	printing_joins = TRUE;

	/* save nicks to string, clear now_channels and remove the same
	   channels from old_channels list */
	channels = g_hash_table_new((GHashFunc) i_istr_hash, (GCompareFunc) i_istr_equal);
	for (tmp = server->netjoins; tmp != NULL; tmp = next) {
		NETJOIN_REC *rec = tmp->data;

		next = g_slist_next(tmp);

		for (tmp2 = rec->now_channels; tmp2 != NULL; tmp2 = next2) {
			char *channel = tmp2->data;
			char *realchannel = channel + 1;

			next2 = g_slist_next(tmp2);

			/* Filter the results by channel if asked to do so */
			if (filter_channel != NULL &&
			    strcasecmp(realchannel, filter_channel) != 0)
				continue;

			temp = g_hash_table_lookup(channels, realchannel);
			if (temp == NULL) {
				temp = g_new0(TEMP_PRINT_REC, 1);
				temp->nicks = g_string_new(NULL);
				g_hash_table_insert(channels,
						    g_strdup(realchannel),
						    temp);
			}

			temp->count++;
			if (temp->count <= netjoin_max_nicks) {
				if (*channel != ' ')
					g_string_append_c(temp->nicks,
							  *channel);
				g_string_append_printf(temp->nicks, "%s, ",
						  rec->nick);
			}

			/* remove the channel from old_channels too */
			old = i_slist_find_icase_string(rec->old_channels, realchannel);
			if (old != NULL) {
				void *data = old->data;
				rec->old_channels =
					g_slist_remove(rec->old_channels, data);
				g_free(data);
			}

			/* drop tmp2 from the list */
			rec->now_channels = g_slist_delete_link(rec->now_channels, tmp2);
			g_free(channel);
		}

		if (rec->old_channels == NULL)
                        netjoin_remove(server, rec);
	}

	g_hash_table_foreach(channels, (GHFunc) print_channel_netjoins,
			     server);
	g_hash_table_destroy(channels);

	if (server->netjoins == NULL)
		netjoin_server_remove(server);

	printing_joins = FALSE;
}

/* something is going to be printed to screen, print our current netsplit
   message before it. */
static void sig_print_starting(TEXT_DEST_REC *dest)
{
	NETJOIN_SERVER_REC *rec;

	if (printing_joins)
		return;

	if (!IS_IRC_SERVER(dest->server))
		return;

	rec = netjoin_find_server(IRC_SERVER(dest->server));
	if (rec != NULL && rec->netjoins != NULL) {
		/* if netjoins exists, the server rec should be
		   still valid. otherwise, calling server->ischannel
		   may not be safe. */
		if (dest->target != NULL &&
		    !server_ischannel((SERVER_REC *) rec->server, dest->target))
			return;

		print_netjoins(rec, NULL);
	}
}

static int sig_check_netjoins(void)
{
	GSList *tmp, *next;
	int diff;
	time_t now;

	now = time(NULL);
	/* first print all netjoins which haven't had any new joins
	 * for NETJOIN_WAIT_TIME; this may cause them to be removed
	 * (all users who rejoined, rejoined all channels) */
	for (tmp = joinservers; tmp != NULL; tmp = next) {
		NETJOIN_SERVER_REC *server = tmp->data;

		next = tmp->next;
		diff = now-server->last_netjoin;
		if (diff <= NETJOIN_WAIT_TIME) {
			/* wait for more JOINs */
			continue;
		}

                if (server->netjoins != NULL)
			print_netjoins(server, NULL);
	}

	/* now remove all netjoins which haven't had any new joins
	 * for NETJOIN_MAX_WAIT (user rejoined some but not all channels
	 * after split) */
	for (tmp = joinservers; tmp != NULL; tmp = next) {
		NETJOIN_SERVER_REC *server = tmp->data;

		next = tmp->next;
		diff = now-server->last_netjoin;
		if (diff >= NETJOIN_MAX_WAIT) {
			/* waited long enough, forget about the rest */
                        netjoin_server_remove(server);
		}
	}

	if (joinservers == NULL) {
		g_source_remove(join_tag);
		signal_remove("print starting", (SIGNAL_FUNC) sig_print_starting);
                join_tag = -1;
	}
	return 1;
}

static void msg_quit(IRC_SERVER_REC *server, const char *nick,
		     const char *address, const char *reason)
{
	if (IS_IRC_SERVER(server) && quitmsg_is_split(reason))
		signal_stop();
}

static void msg_join(IRC_SERVER_REC *server, const char *channel,
		     const char *nick, const char *address)
{
	NETSPLIT_REC *split;
	NETJOIN_REC *netjoin;
	GSList *channels;
	int rejoin = 1;

	if (!IS_IRC_SERVER(server))
		return;

	if (ignore_check(SERVER(server), nick, address,
			 channel, NULL, MSGLEVEL_JOINS))
		return;

	split = netsplit_find(server, nick, address);
	netjoin = netjoin_find(server, nick);
	if (split == NULL && netjoin == NULL)
                return;

	/* if this was not a channel they split from, treat it normally */
	if (netjoin != NULL) {
		if (!i_slist_find_icase_string(netjoin->old_channels, channel))
			return;
	} else {
		channels = split->channels;
		while (channels != NULL) {
			NETSPLIT_CHAN_REC *schannel = channels->data;

			if (!strcasecmp(schannel->name, channel))
				break;
			channels = channels->next;
		}
		/* we still need to create a NETJOIN_REC now as the
		 * NETSPLIT_REC will be destroyed */
		if (channels == NULL)
			rejoin = 0;
	}

	if (join_tag == -1) {
		join_tag = g_timeout_add(1000, (GSourceFunc)
					 sig_check_netjoins, NULL);
		signal_add("print starting", (SIGNAL_FUNC) sig_print_starting);
	}

	if (netjoin == NULL)
		netjoin = netjoin_add(server, nick, split->channels);

	if (rejoin)
	{
		netjoin->now_channels = g_slist_append(netjoin->now_channels,
						       g_strconcat(" ", channel, NULL));
		signal_stop();
	}
}

static int netjoin_set_nickmode(IRC_SERVER_REC *server, NETJOIN_REC *rec,
				const char *channel, char prefix)
{
	GSList *pos;
	const char *flags;
	char *found_chan = NULL;

	for (pos = rec->now_channels; pos != NULL; pos = pos->next) {
		char *chan = pos->data;
		if (strcasecmp(chan+1, channel) == 0) {
			found_chan = chan;
			break;
		}
	}

	if (found_chan == NULL)
		return FALSE;

	flags = server->get_nick_flags(SERVER(server));
	while (*flags != '\0') {
		if (found_chan[0] == *flags)
			break;
		if (prefix == *flags) {
			found_chan[0] = prefix;
			break;
		}
		flags++;
	}
	return TRUE;
}

static void msg_mode(IRC_SERVER_REC *server, const char *channel,
		     const char *sender, const char *addr, const char *data)
{
	NETJOIN_REC *rec;
	char *params, *mode, *nicks;
	char **nicklist, **nick, type, prefix;
	int show;

	g_return_if_fail(data != NULL);
	if (!server_ischannel(SERVER(server), channel) || addr != NULL)
		return;

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST,
				  &mode, &nicks);

	/* parse server mode changes - hide operator status changes and
	   show them in the netjoin message instead as @ before the nick */
	nick = nicklist = g_strsplit(nicks, " ", -1);

	type = '+'; show = FALSE;
	for (; *mode != '\0'; mode++) {
		if (*mode == '+' || *mode == '-') {
			type = *mode;
			continue;
		}

		if (*nick != NULL && GET_MODE_PREFIX(server, *mode)) {
                        /* give/remove ops */
			rec = netjoin_find(server, *nick);
			prefix = GET_MODE_PREFIX(server, *mode);
			if (rec == NULL || type != '+' || prefix == '\0' ||
			    !netjoin_set_nickmode(server, rec, channel, prefix))
				show = TRUE;
                        nick++;
		} else {
			if (HAS_MODE_ARG(server, type, *mode) && *nick != NULL)
				nick++;
			show = TRUE;
		}
	}

	if (!show) signal_stop();

	g_strfreev(nicklist);
	g_free(params);
}

static void read_settings(void)
{
	int old_hide;

        old_hide = hide_netsplit_quits;
	hide_netsplit_quits = settings_get_bool("hide_netsplit_quits");
	netjoin_max_nicks = settings_get_int("netjoin_max_nicks");

	if (old_hide && !hide_netsplit_quits) {
		signal_remove("message quit", (SIGNAL_FUNC) msg_quit);
		signal_remove("message join", (SIGNAL_FUNC) msg_join);
		signal_remove("message irc mode", (SIGNAL_FUNC) msg_mode);
	} else if (!old_hide && hide_netsplit_quits) {
		signal_add("message quit", (SIGNAL_FUNC) msg_quit);
		signal_add("message join", (SIGNAL_FUNC) msg_join);
		signal_add("message irc mode", (SIGNAL_FUNC) msg_mode);
	}
}

static void sig_server_disconnected(IRC_SERVER_REC *server)
{
	NETJOIN_SERVER_REC *netjoin_server;

	g_return_if_fail(server != NULL);

	if (!IS_IRC_SERVER(server))
		return;

	if ((netjoin_server = netjoin_find_server(server))) {
		netjoin_server_remove(netjoin_server);
	}
}

void fe_netjoin_init(void)
{
	settings_add_bool("misc", "hide_netsplit_quits", TRUE);
	settings_add_int("misc", "netjoin_max_nicks", 10);

	join_tag = -1;
	printing_joins = FALSE;

	read_settings();
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
	signal_add("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);
}

void fe_netjoin_deinit(void)
{
	while (joinservers != NULL)
		netjoin_server_remove(joinservers->data);
	if (join_tag != -1) {
		g_source_remove(join_tag);
		signal_remove("print starting", (SIGNAL_FUNC) sig_print_starting);
	}

	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);

	signal_remove("message quit", (SIGNAL_FUNC) msg_quit);
	signal_remove("message join", (SIGNAL_FUNC) msg_join);
	signal_remove("message irc mode", (SIGNAL_FUNC) msg_mode);
}
