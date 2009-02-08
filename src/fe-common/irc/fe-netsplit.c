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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include "module-formats.h"
#include "signals.h"
#include "levels.h"
#include "settings.h"

#include "irc-servers.h"
#include "irc-commands.h"
#include "ignore.h"
#include "netsplit.h"

#include "printtext.h"

#define SPLIT_WAIT_TIME 5 /* how many seconds to wait for the QUIT split messages to stop */

static int split_tag;
static int netsplit_max_nicks, netsplit_nicks_hide_threshold;
static int printing_splits;

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
	int nick_count, maxnickpos;
	GString *nicks;
} TEMP_SPLIT_CHAN_REC;

typedef struct {
        IRC_SERVER_REC *server_rec;
	GSList *servers; /* if many servers splitted from the same one */
	GSList *channels;
} TEMP_SPLIT_REC;

static GSList *get_source_servers(const char *server, GSList **servers)
{
	GSList *list, *next, *tmp;

	list = NULL;
	for (tmp = *servers; tmp != NULL; tmp = next) {
		NETSPLIT_SERVER_REC *rec = tmp->data;
		next = tmp->next;

		if (g_strcasecmp(rec->server, server) == 0) {
			rec->prints = 0;
			list = g_slist_append(list, rec);
			*servers = g_slist_remove(*servers, rec);
		}
	}

	return list;
}

static TEMP_SPLIT_CHAN_REC *find_split_chan(TEMP_SPLIT_REC *rec,
					    const char *name)
{
	GSList *tmp;

	for (tmp = rec->channels; tmp != NULL; tmp = tmp->next) {
		TEMP_SPLIT_CHAN_REC *chanrec = tmp->data;

		if (g_strcasecmp(chanrec->name, name) == 0)
			return chanrec;
	}

	return NULL;
}

static void get_server_splits(void *key, NETSPLIT_REC *split,
			      TEMP_SPLIT_REC *rec)
{
	TEMP_SPLIT_CHAN_REC *chanrec;
	GSList *tmp;

	if (split->printed ||
	    g_slist_find(rec->servers, split->server) == NULL)
		return;

	split->printed = TRUE;
	for (tmp = split->channels; tmp != NULL; tmp = tmp->next) {
		NETSPLIT_CHAN_REC *splitchan = tmp->data;

		if (ignore_check(SERVER(rec->server_rec), split->nick,
				 split->address, splitchan->name, "",
				 MSGLEVEL_QUITS))
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
		if (netsplit_nicks_hide_threshold <= 0 ||
		    chanrec->nick_count <= netsplit_nicks_hide_threshold) {
			if (splitchan->op)
				g_string_append_c(chanrec->nicks, '@');
			else if (splitchan->voice)
				g_string_append_c(chanrec->nicks, '+');
			g_string_append_printf(chanrec->nicks, "%s, ", split->nick);

			if (chanrec->nick_count == netsplit_max_nicks)
                                chanrec->maxnickpos = chanrec->nicks->len;
		}
	}
}

static void print_server_splits(IRC_SERVER_REC *server, TEMP_SPLIT_REC *rec)
{
	GString *destservers;
	char *sourceserver;
	GSList *tmp;

	destservers = g_string_new(NULL);
	for (tmp = rec->servers; tmp != NULL; tmp = tmp->next) {
		NETSPLIT_SERVER_REC *rec = tmp->data;

		if (rec->prints > 0) {
			g_string_append_printf(destservers, "%s, ",
					  rec->destserver);
		}
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

		g_string_truncate(chan->nicks, chan->nicks->len-2);

		if (netsplit_max_nicks > 0 &&
		    chan->nick_count > netsplit_max_nicks) {
			g_string_truncate(chan->nicks, chan->maxnickpos);
			printformat(server, chan->name, MSGLEVEL_QUITS,
				    IRCTXT_NETSPLIT_MORE, sourceserver,
				    destservers->str, chan->nicks->str,
				    chan->nick_count - netsplit_max_nicks);
		} else {
			printformat(server, chan->name, MSGLEVEL_QUITS,
				    IRCTXT_NETSPLIT, sourceserver,
				    destservers->str, chan->nicks->str);
		}
	}

	g_string_free(destservers, TRUE);
}

static void temp_split_chan_free(TEMP_SPLIT_CHAN_REC *rec)
{
	g_string_free(rec->nicks, TRUE);
	g_free(rec);
}

static void print_splits(IRC_SERVER_REC *server)
{
	TEMP_SPLIT_REC temp;
	GSList *servers;

	printing_splits = TRUE;

	servers = g_slist_copy(server->split_servers);
	while (servers != NULL) {
		NETSPLIT_SERVER_REC *sserver = servers->data;

		/* get all the splitted servers that have the same
		   source server */
                temp.servers = get_source_servers(sserver->server, &servers);
                temp.server_rec = server;
		temp.channels = NULL;

		g_hash_table_foreach(server->splits,
				     (GHFunc) get_server_splits, &temp);
		print_server_splits(server, &temp);

		g_slist_foreach(temp.channels,
				(GFunc) temp_split_chan_free, NULL);
		g_slist_free(temp.servers);
		g_slist_free(temp.channels);
	}

	printing_splits = FALSE;
}

static int check_server_splits(IRC_SERVER_REC *server)
{
	time_t last;

	g_return_val_if_fail(IS_IRC_SERVER(server), FALSE);

	last = get_last_split(server);
	if (time(NULL)-last < SPLIT_WAIT_TIME)
		return FALSE;

	print_splits(server);
        return TRUE;
}

/* something is going to be printed to screen, print our current netsplit
   message before it. */
static void sig_print_starting(void)
{
	GSList *tmp;

	if (printing_splits)
		return;

	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		IRC_SERVER_REC *rec = tmp->data;

		if (IS_IRC_SERVER(rec) && rec->split_servers != NULL)
			print_splits(rec);
	}
}

static int sig_check_splits(void)
{
	GSList *tmp;
	int stop;

	stop = TRUE;
	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		IRC_SERVER_REC *rec = tmp->data;

		if (!IS_IRC_SERVER(rec))
			continue;

		if (rec->split_servers != NULL) {
			if (!check_server_splits(rec))
				stop = FALSE;
		}
	}

	if (stop) {
		g_source_remove(split_tag);
		signal_remove("print starting", (SIGNAL_FUNC) sig_print_starting);
                split_tag = -1;
	}
	return 1;
}

static void sig_netsplit_servers(void)
{
	if (settings_get_bool("hide_netsplit_quits") && split_tag == -1) {
		split_tag = g_timeout_add(1000,
					  (GSourceFunc) sig_check_splits,
					  NULL);
		signal_add("print starting", (SIGNAL_FUNC) sig_print_starting);
	}
}

static int split_equal(NETSPLIT_REC *n1, NETSPLIT_REC *n2)
{
        return g_strcasecmp(n1->nick, n2->nick);
}

static void split_get(void *key, NETSPLIT_REC *rec, GSList **list)
{
	*list = g_slist_insert_sorted(*list, rec,
				      (GCompareFunc) split_equal);
}

static void split_print(NETSPLIT_REC *rec, SERVER_REC *server)
{
	NETSPLIT_CHAN_REC *chan;
        char *chanstr;

	chan = rec->channels->data;
	chanstr = chan == NULL ? "" :
		g_strconcat(chan->op ? "@" :
			    (chan->voice ? "+" : ""), chan->name, NULL);

	printformat(server, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_NETSPLITS_LINE,
		    rec->nick, chanstr, rec->server->server,
		    rec->server->destserver);

	g_free(chanstr);
}

/* SYNTAX: NETSPLIT */
static void cmd_netsplit(const char *data, IRC_SERVER_REC *server)
{
	GSList *list;

        CMD_IRC_SERVER(server);

	if (server->split_servers == NULL) {
		printformat(server, NULL, MSGLEVEL_CLIENTNOTICE,
			    IRCTXT_NO_NETSPLITS);
		return;
	}

	printformat(server, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_NETSPLITS_HEADER);

        list = NULL;
	g_hash_table_foreach(server->splits, (GHFunc) split_get, &list);
	g_slist_foreach(list, (GFunc) split_print, server);
        g_slist_free(list);

	printformat(server, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_NETSPLITS_FOOTER);
}

static void read_settings(void)
{
        netsplit_max_nicks = settings_get_int("netsplit_max_nicks");
	netsplit_nicks_hide_threshold =
		settings_get_int("netsplit_nicks_hide_threshold");
	if (netsplit_nicks_hide_threshold < netsplit_max_nicks)
		netsplit_max_nicks = netsplit_nicks_hide_threshold;
}

void fe_netsplit_init(void)
{
	settings_add_int("misc", "netsplit_max_nicks", 10);
	settings_add_int("misc", "netsplit_nicks_hide_threshold", 15);
	split_tag = -1;
	printing_splits = FALSE;

	read_settings();
	signal_add("netsplit new", (SIGNAL_FUNC) sig_netsplit_servers);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
	command_bind_irc("netsplit", NULL, (SIGNAL_FUNC) cmd_netsplit);
}

void fe_netsplit_deinit(void)
{
	if (split_tag != -1) {
		g_source_remove(split_tag);
		signal_remove("print starting", (SIGNAL_FUNC) sig_print_starting);
	}

	signal_remove("netsplit new", (SIGNAL_FUNC) sig_netsplit_servers);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
	command_unbind("netsplit", (SIGNAL_FUNC) cmd_netsplit);
}
