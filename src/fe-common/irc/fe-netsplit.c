/*
 fe-netsplit.c : irssi

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
#include "commands.h"
#include "levels.h"
#include "settings.h"

#include "irc.h"
#include "irc-server.h"
#include "ignore.h"
#include "netsplit.h"

#define SPLIT_WAIT_TIME 2 /* how many seconds to wait for the QUIT split messages to stop */

static int split_tag;
static int netsplit_max_nicks;

static int get_last_split(IRC_SERVER_REC *server)
{
	GSList *tmp;
	time_t last;

        last = 0;
	for (tmp = server->split_servers; tmp != NULL; tmp = tmp->next) {
		NETSPLIT_SERVER_REC *rec = tmp->data;

		if (rec->last > last) last = rec->last;
	}

	return last;
}

typedef struct {
	char *name;
	int nick_count;
	GString *nicks;
} TEMP_SPLIT_CHAN_REC;

typedef struct {
        IRC_SERVER_REC *server_rec;
	GSList *servers; /* if many servers splitted from the same one */
	GSList *channels;
} TEMP_SPLIT_REC;

static TEMP_SPLIT_CHAN_REC *find_split_chan(TEMP_SPLIT_REC *rec, const char *name)
{
	GSList *tmp;

	for (tmp = rec->channels; tmp != NULL; tmp = tmp->next) {
		TEMP_SPLIT_CHAN_REC *chanrec = tmp->data;

		if (g_strcasecmp(chanrec->name, name) == 0)
			return chanrec;
	}

	return NULL;
}

static void get_server_splits(void *key, NETSPLIT_REC *split, TEMP_SPLIT_REC *rec)
{
	TEMP_SPLIT_CHAN_REC *chanrec;
	GSList *tmp;

	if (split->printed || g_slist_find(rec->servers, split->server) == NULL)
		return;

	split->printed = TRUE;
	for (tmp = split->channels; tmp != NULL; tmp = tmp->next) {
		NETSPLIT_CHAN_REC *splitchan = tmp->data;

		if (ignore_check(rec->server_rec, split->nick, split->address,
				 splitchan->name, "", MSGLEVEL_QUITS))
			continue;

		chanrec = find_split_chan(rec, splitchan->name);
		if (chanrec == NULL) {
			chanrec = g_new0(TEMP_SPLIT_CHAN_REC, 1);
			chanrec->name = splitchan->name;
			chanrec->nicks = g_string_new(NULL);

			rec->channels = g_slist_append(rec->channels, chanrec);
		}

		split->server->prints++;
		chanrec->nick_count++;
		if (netsplit_max_nicks <= 0 ||
		    chanrec->nick_count < netsplit_max_nicks) {
			if (splitchan->nick.op) g_string_append_c(chanrec->nicks, '@');
			g_string_sprintfa(chanrec->nicks, "%s ", split->nick);
		}
	}
}

static void print_splits(IRC_SERVER_REC *server, TEMP_SPLIT_REC *rec)
{
	GString *destservers;
	char *sourceserver;
	GSList *tmp;

	destservers = g_string_new(NULL);
	for (tmp = rec->servers; tmp != NULL; tmp = tmp->next) {
		NETSPLIT_SERVER_REC *rec = tmp->data;

		if (rec->prints > 0)
			g_string_sprintfa(destservers, "%s, ", rec->destserver);
	}
	if (destservers->len == 0) {
                /* no nicks to print in this server */
		g_string_free(destservers, TRUE);
		return;
	}
	g_string_truncate(destservers, destservers->len-2);

	sourceserver = ((NETSPLIT_SERVER_REC *) (rec->servers->data))->server;
	for (tmp = rec->channels; tmp != NULL; tmp = tmp->next) {
		TEMP_SPLIT_CHAN_REC *chan = tmp->data;

		g_string_truncate(chan->nicks, chan->nicks->len-1);

		if (netsplit_max_nicks > 0 && chan->nick_count > netsplit_max_nicks) {
			printformat(server, chan->name, MSGLEVEL_QUITS, IRCTXT_NETSPLIT_MORE,
				    sourceserver, destservers->str, chan->nicks->str,
				    chan->nick_count - netsplit_max_nicks);
		} else {
			printformat(server, chan->name, MSGLEVEL_QUITS, IRCTXT_NETSPLIT,
				    sourceserver, destservers->str, chan->nicks->str);
		}
	}

	g_string_free(destservers, TRUE);
}

static void temp_split_chan_free(TEMP_SPLIT_CHAN_REC *rec)
{
	g_string_free(rec->nicks, TRUE);
	g_free(rec);
}

static int check_server_splits(IRC_SERVER_REC *server)
{
	TEMP_SPLIT_REC temp;
	GSList *tmp, *next, *servers;
	time_t last;

	last = get_last_split(server);
	if (time(NULL)-last < SPLIT_WAIT_TIME)
		return FALSE;

	servers = g_slist_copy(server->split_servers);
	while (servers != NULL) {
		NETSPLIT_SERVER_REC *sserver = servers->data;

		/* get all the splitted servers that have the same
		   source server */
                temp.servers = NULL;
		for (tmp = servers; tmp != NULL; tmp = next) {
			NETSPLIT_SERVER_REC *rec = tmp->data;

			next = tmp->next;
			if (g_strcasecmp(rec->server, sserver->server) == 0) {
                                rec->prints = 0;
				temp.servers = g_slist_append(temp.servers, rec);
				servers = g_slist_remove(servers, rec);
			}
		}

                temp.server_rec = server;
		temp.channels = NULL;

		g_hash_table_foreach(server->splits, (GHFunc) get_server_splits, &temp);
		print_splits(server, &temp);

		g_slist_foreach(temp.channels, (GFunc) temp_split_chan_free, NULL);
		g_slist_free(temp.servers);
		g_slist_free(temp.channels);
	}

        return TRUE;
}

static int sig_check_splits(void)
{
	GSList *tmp;
	int stop;

	stop = TRUE;
	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		IRC_SERVER_REC *rec = tmp->data;

		if (rec->split_servers != NULL) {
			if (!check_server_splits(rec))
				stop = FALSE;
		}
	}

	if (stop) {
		g_source_remove(split_tag);
                split_tag = -1;
	}
	return 1;
}

static void sig_netsplit_servers(IRC_SERVER_REC *server, NETSPLIT_SERVER_REC *rec)
{
	if (!settings_get_bool("hide_netsplit_quits"))
		return;

	if (split_tag == -1)
		split_tag = g_timeout_add(1000, (GSourceFunc) sig_check_splits, NULL);
}

static void split_print(const char *nick, NETSPLIT_REC *rec)
{
	NETSPLIT_CHAN_REC *chan;

	chan = rec->channels->data;
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_NETSPLITS_LINE,
		    rec->nick, chan == NULL ? "" : chan->name,
		    rec->server->server, rec->server->destserver);
}

static void cmd_netsplit(const char *data, IRC_SERVER_REC *server)
{
	if (server == NULL || !server->connected)
		cmd_return_error(CMDERR_NOT_CONNECTED);

	if (server->split_servers == NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_NO_NETSPLITS);
		return;
	}

	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_NETSPLITS_HEADER);
        g_hash_table_foreach(server->splits, (GHFunc) split_print, NULL);
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_NETSPLITS_FOOTER);
}

static void read_settings(void)
{
        netsplit_max_nicks = settings_get_int("netsplit_max_nicks");
}

void fe_netsplit_init(void)
{
	settings_add_int("misc", "netsplit_max_nicks", 10);
	split_tag = -1;

	read_settings();
	signal_add("netsplit new server", (SIGNAL_FUNC) sig_netsplit_servers);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
	command_bind("netsplit", NULL, (SIGNAL_FUNC) cmd_netsplit);
}

void fe_netsplit_deinit(void)
{
	if (split_tag != -1) g_source_remove(split_tag);

	signal_remove("netsplit new server", (SIGNAL_FUNC) sig_netsplit_servers);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
	command_unbind("netsplit", (SIGNAL_FUNC) cmd_netsplit);
}
