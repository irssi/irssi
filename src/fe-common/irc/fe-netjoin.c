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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "module-formats.h"
#include "signals.h"
#include "levels.h"
#include "misc.h"
#include "settings.h"

#include "irc.h"
#include "irc-server.h"
#include "modes.h"
#include "ignore.h"
#include "netsplit.h"

#define NETJOIN_WAIT_TIME 2 /* how many seconds to wait for the netsplitted JOIN messages to stop */
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

static int join_tag, output_hidden;
static int netjoin_max_nicks, hide_netsplit_quits;
static GSList *joinservers;

static void sig_stop(void)
{
	signal_stop();
}

static void remove_hide_output(void)
{
	if (output_hidden) {
		output_hidden = FALSE;
		signal_remove("print text stripped", (SIGNAL_FUNC) sig_stop);
		signal_remove("print text", (SIGNAL_FUNC) sig_stop);
	}
}

static void hide_output(void)
{
	if (!output_hidden) {
		output_hidden = TRUE;
		signal_add_first("print text stripped", (SIGNAL_FUNC) sig_stop);
		signal_add_first("print text", (SIGNAL_FUNC) sig_stop);
	}
}

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

static NETJOIN_REC *netjoin_add(IRC_SERVER_REC *server, const char *nick, GSList *channels)
{
	NETJOIN_REC *rec;
	NETJOIN_SERVER_REC *srec;

	g_return_val_if_fail(server != NULL, NULL);
	g_return_val_if_fail(nick != NULL, NULL);
	g_return_val_if_fail(channels != NULL, NULL);

	rec = g_new0(NETJOIN_REC, 1);
	rec->nick = g_strdup(nick);
	while (channels != NULL) {
		NETSPLIT_CHAN_REC *channel = channels->data;

		rec->old_channels = g_slist_append(rec->old_channels, g_strdup(channel->name));
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

		if (g_strcasecmp(rec->nick, nick) == 0)
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

static void print_channel_netjoins(char *channel, TEMP_PRINT_REC *rec, NETJOIN_SERVER_REC *server)
{
	if (rec->nicks->len > 0)
		g_string_truncate(rec->nicks, rec->nicks->len-2);

	printformat(server->server, channel, MSGLEVEL_JOINS,
		    rec->count > netjoin_max_nicks ? IRCTXT_NETSPLIT_JOIN_MORE : IRCTXT_NETSPLIT_JOIN,
		    rec->nicks->str, rec->count-netjoin_max_nicks);

	g_string_free(rec->nicks, TRUE);
	g_free(rec);
	g_free(channel);
}

static void print_netjoins(NETJOIN_SERVER_REC *server)
{
	TEMP_PRINT_REC *temp;
	GHashTable *channels;
	GSList *tmp, *next, *old;

	g_return_if_fail(server != NULL);

	/* save nicks to string, clear now_channels and remove the same
	   channels from old_channels list */
	channels = g_hash_table_new((GHashFunc) g_istr_hash, (GCompareFunc) g_istr_equal);
	for (tmp = server->netjoins; tmp != NULL; tmp = next) {
		NETJOIN_REC *rec = tmp->data;

		next = tmp->next;
		while (rec->now_channels != NULL) {
			char *channel = rec->now_channels->data;
			char *realchannel = channel + (*channel == '@');

			temp = g_hash_table_lookup(channels, realchannel);
			if (temp == NULL) {
				temp = g_new0(TEMP_PRINT_REC, 1);
				temp->nicks = g_string_new(NULL);
				g_hash_table_insert(channels, g_strdup(realchannel), temp);
			}

			temp->count++;
			if (temp->count <= netjoin_max_nicks) {
				if (*channel == '@')
					g_string_append_c(temp->nicks, '@');
				g_string_sprintfa(temp->nicks, "%s, ", rec->nick);
			}

			/* remove the channel from old_channels too */
			old = gslist_find_icase_string(rec->old_channels, realchannel);
			if (old != NULL) {
				g_free(old->data);
				rec->old_channels = g_slist_remove(rec->old_channels, old->data);
			}

			g_free(channel);
                        rec->now_channels = g_slist_remove(rec->now_channels, channel);
		}

		if (rec->old_channels == NULL)
                        netjoin_remove(server, rec);
	}

        g_hash_table_foreach(channels, (GHFunc) print_channel_netjoins, server);
	g_hash_table_destroy(channels);

	if (server->netjoins == NULL)
                netjoin_server_remove(server);
}

static int sig_check_netjoins(void)
{
	GSList *tmp, *next;
	int diff;

	/* just to make sure that text hiding wasn't left on accidentally */
	remove_hide_output();

	for (tmp = joinservers; tmp != NULL; tmp = next) {
		NETJOIN_SERVER_REC *server = tmp->data;

		next = tmp->next;
		diff = time(NULL)-server->last_netjoin;
		if (diff <= NETJOIN_WAIT_TIME) {
			/* wait for more JOINs */
			continue;
		}

                if (server->netjoins != NULL)
			print_netjoins(server);
		else if (diff >= NETJOIN_MAX_WAIT) {
			/* waited long enough, remove the netjoin */
                        netjoin_server_remove(server);
		}
	}

	if (joinservers == NULL) {
		g_source_remove(join_tag);
                join_tag = -1;
	}
	return 1;
}

static void event_quit(const char *data)
{
	if (quitmsg_is_split(data))
		hide_output();
}

static void event_join(const char *data, IRC_SERVER_REC *server,
		       const char *nick, const char *address)
{
	NETSPLIT_REC *split;
	NETJOIN_REC *netjoin;
	char *params, *channel, *tmp;

	g_return_if_fail(data != NULL);

	/* just to make sure that text hiding wasn't left on accidentally */
	remove_hide_output();

	split = netsplit_find(server, nick, address);
	netjoin = netjoin_find(server, nick);
	if (split == NULL && netjoin == NULL)
                return;

	params = event_get_params(data, 1, &channel);
	tmp = strchr(channel, 7); /* ^G does something weird.. */
	if (tmp != NULL) *tmp = '\0';

	if (!ignore_check(server, nick, address, channel, NULL, MSGLEVEL_JOINS)) {
                if (join_tag == -1)
			join_tag = g_timeout_add(1000, (GSourceFunc) sig_check_netjoins, NULL);

		if (netjoin == NULL)
			netjoin = netjoin_add(server, nick, split->channels);

		netjoin->now_channels = g_slist_append(netjoin->now_channels, g_strdup(channel));
		hide_output();
	}
	g_free(params);
}

static int netjoin_set_operator(NETJOIN_REC *rec, const char *channel, int on)
{
	GSList *pos;

	pos = gslist_find_icase_string(rec->now_channels, channel);
	if (pos == NULL)
		return FALSE;

	g_free(pos->data);
	pos->data = !on ? g_strdup(channel) :
		g_strconcat("@", channel, NULL);
	return TRUE;
}

static void event_mode(const char *data, IRC_SERVER_REC *server, const char *addr)
{
	NETJOIN_REC *rec;
	char *params, *channel, *mode, *nicks;
	char **nicklist, **nick, type;
	int show;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3 | PARAM_FLAG_GETREST, &channel, &mode, &nicks);

	if (!ischannel(*channel) || addr != NULL) {
		g_free(params);
		return;
	}

	/* parse server mode changes - hide operator status changes and
	   show them in the netjoin message instead as @ before the nick */
	nick = nicklist = g_strsplit(nicks, " ", -1);

	type = '+'; show = FALSE;
	for (; *mode != '\0'; mode++) {
		if (*mode == '+' || *mode == '-') {
			type = *mode;
			continue;
		}

		if (*mode == 'o' && *nick != NULL) {
                        /* give/remove ops */
			rec = netjoin_find(server, *nick);
			if (rec != NULL && !netjoin_set_operator(rec, channel, type == '+'))
				show = TRUE;
                        nick++;
		} else {
			if (HAS_MODE_ARG(*mode) && *nick != NULL)
				nick++;
			show = TRUE;
		}
	}

	if (!show) hide_output();

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
		signal_remove("event quit", (SIGNAL_FUNC) event_quit);
		signal_remove("event join", (SIGNAL_FUNC) event_join);
		signal_remove("event mode", (SIGNAL_FUNC) event_mode);
		signal_remove("event quit", (SIGNAL_FUNC) remove_hide_output);
		signal_remove("event join", (SIGNAL_FUNC) remove_hide_output);
		signal_remove("event mode", (SIGNAL_FUNC) remove_hide_output);
	} else if (!old_hide && hide_netsplit_quits) {
		signal_add("event quit", (SIGNAL_FUNC) event_quit);
		signal_add("event join", (SIGNAL_FUNC) event_join);
		signal_add("event mode", (SIGNAL_FUNC) event_mode);
		signal_add_last("event quit", (SIGNAL_FUNC) remove_hide_output);
		signal_add_last("event join", (SIGNAL_FUNC) remove_hide_output);
		signal_add_last("event mode", (SIGNAL_FUNC) remove_hide_output);
	}
}

void fe_netjoin_init(void)
{
	settings_add_bool("misc", "hide_netsplit_quits", TRUE);
	settings_add_int("misc", "netjoin_max_nicks", 10);

	join_tag = -1;
	output_hidden = FALSE;

	read_settings();
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
}

void fe_netjoin_deinit(void)
{
	while (joinservers != NULL)
		netjoin_server_remove(joinservers->data);
	if (join_tag != -1) g_source_remove(join_tag);

	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
}
