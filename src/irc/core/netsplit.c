/*
 netsplit.c : irssi

    Copyright (C) 1999 Timo Sirainen

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
#include "signals.h"
#include "commands.h"
#include "misc.h"

#include "irc-servers.h"
#include "irc-channels.h"
#include "netsplit.h"

/* How long to keep netsplits in memory (seconds) */
#define NETSPLIT_MAX_REMEMBER (60*60)

static int split_tag;

static NETSPLIT_SERVER_REC *netsplit_server_find(IRC_SERVER_REC *server,
						 const char *servername,
						 const char *destserver)
{
	GSList *tmp;

	g_return_val_if_fail(IS_IRC_SERVER(server), NULL);

	for (tmp = server->split_servers; tmp != NULL; tmp = tmp->next) {
		NETSPLIT_SERVER_REC *rec = tmp->data;

		if (g_strcasecmp(rec->server, servername) == 0 &&
		    g_strcasecmp(rec->destserver, destserver) == 0)
			return rec;
	}

	return NULL;
}

static NETSPLIT_SERVER_REC *netsplit_server_create(IRC_SERVER_REC *server,
						   const char *servername,
						   const char *destserver)
{
	NETSPLIT_SERVER_REC *rec;

	g_return_val_if_fail(IS_IRC_SERVER(server), NULL);

	rec = netsplit_server_find(server, servername, destserver);
	if (rec != NULL) {
		rec->last = time(NULL);
		return rec;
	}

	rec = g_new0(NETSPLIT_SERVER_REC, 1);
	rec->last = time(NULL);
	rec->server = g_strdup(servername);
	rec->destserver = g_strdup(destserver);

	server->split_servers = g_slist_append(server->split_servers, rec);
	signal_emit("netsplit server new", 2, server, rec);

	return rec;
}

static void netsplit_server_destroy(IRC_SERVER_REC *server,
				    NETSPLIT_SERVER_REC *rec)
{
	g_return_if_fail(IS_IRC_SERVER(server));

	server->split_servers = g_slist_remove(server->split_servers, rec);

	signal_emit("netsplit server remove", 2, server, rec);

        g_free(rec->server);
	g_free(rec->destserver);
	g_free(rec);
}

static NETSPLIT_REC *netsplit_add(IRC_SERVER_REC *server, const char *nick,
				  const char *address, const char *servers)
{
	NETSPLIT_REC *rec;
	NETSPLIT_CHAN_REC *splitchan;
	NICK_REC *nickrec;
	GSList *tmp;
	char *p, *dupservers;

	g_return_val_if_fail(IS_IRC_SERVER(server), NULL);
	g_return_val_if_fail(nick != NULL, NULL);
	g_return_val_if_fail(address != NULL, NULL);

	/* get splitted servers */
	dupservers = g_strdup(servers);
	p = strchr(dupservers, ' ');
	if (p == NULL) {
		g_free(dupservers);
		g_warning("netsplit_add() : only one server found");
		return NULL;
	}
	*p++ = '\0';

	rec = g_new0(NETSPLIT_REC, 1);
	rec->nick = g_strdup(nick);
	rec->address = g_strdup(address);
	rec->destroy = time(NULL)+NETSPLIT_MAX_REMEMBER;

	rec->server = netsplit_server_create(server, dupservers, p);
	rec->server->count++;
	g_free(dupservers);

	/* copy the channel nick records.. */
	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *channel = tmp->data;

		nickrec = nicklist_find(channel, nick);
		if (nickrec == NULL)
			continue;

		splitchan = g_new0(NETSPLIT_CHAN_REC, 1);
		splitchan->name = g_strdup(channel->name);
		memcpy(&splitchan->nick, nickrec, sizeof(NICK_REC));

		rec->channels = g_slist_append(rec->channels, splitchan);
	}

	if (rec->channels == NULL)
		g_warning("netsplit_add(): nick '%s' not in any channels", nick);

	g_hash_table_insert(server->splits, rec->nick, rec);

	signal_emit("netsplit new", 1, rec);
	return rec;
}

static void netsplit_destroy(IRC_SERVER_REC *server, NETSPLIT_REC *rec)
{
	GSList *tmp;

	g_return_if_fail(IS_IRC_SERVER(server));
	g_return_if_fail(rec != NULL);

	signal_emit("netsplit remove", 1, rec);
	for (tmp = rec->channels; tmp != NULL; tmp = tmp->next) {
		NETSPLIT_CHAN_REC *rec = tmp->data;

		g_free(rec->name);
		g_free(rec);
	}

	if (--rec->server->count == 0)
		netsplit_server_destroy(server, rec->server);

	g_free(rec->nick);
	g_free(rec->address);
	g_free(rec);
}

static void netsplit_destroy_hash(void *key, NETSPLIT_REC *rec,
				  IRC_SERVER_REC *server)
{
	netsplit_destroy(server, rec);
}

NETSPLIT_REC *netsplit_find(IRC_SERVER_REC *server, const char *nick,
			    const char *address)
{
	NETSPLIT_REC *rec;

	g_return_val_if_fail(IS_IRC_SERVER(server), NULL);
	g_return_val_if_fail(nick != NULL, NULL);

	rec = g_hash_table_lookup(server->splits, nick);
	if (rec == NULL) return NULL;

	return (address == NULL ||
		g_strcasecmp(rec->address, address) == 0) ? rec : NULL;
}

NICK_REC *netsplit_find_channel(IRC_SERVER_REC *server, const char *nick,
				const char *address, const char *channel)
{
	NETSPLIT_REC *rec;
	GSList *tmp;

	g_return_val_if_fail(IS_IRC_SERVER(server), NULL);
	g_return_val_if_fail(nick != NULL, NULL);
	g_return_val_if_fail(channel != NULL, NULL);

	rec = netsplit_find(server, nick, address);
	if (rec == NULL) return NULL;

	for (tmp = rec->channels; tmp != NULL; tmp = tmp->next) {
		NETSPLIT_CHAN_REC *rec = tmp->data;

		if (g_strcasecmp(rec->name, channel) == 0)
			return &rec->nick;
	}

	return NULL;
}

/* check if quit message is a netsplit message - there's some paranoia
   checks which are probably a bit useless since nowadays IRC servers
   add space after quit message if it looks like a netsplit message. */
int quitmsg_is_split(const char *msg)
{
	char *host1, *host2, *p;
	int ok;

	g_return_val_if_fail(msg != NULL, FALSE);

	/* must have only two words */
	p = strchr(msg, ' ');
	if (p == NULL || p == msg || strchr(p+1, ' ') != NULL)
		return FALSE;

	/* check that it looks ok.. */
	if (!match_wildcards("*.* *.*", msg) ||
	    strstr(msg, "..") != NULL || strstr(msg, "))") != NULL)
		return FALSE;

	/* get the two hosts */
	host1 = g_strndup(msg, (int) (p-msg));
	host2 = p;

	ok = FALSE;
	if (g_strcasecmp(host1, host2) != 0) { /* hosts can't be same.. */
		/* check that domain length is 2 or 3 */
		p = strrchr(host1, '.');
		if (p != NULL && (strlen(p+1) == 2 || strlen(p+1) == 3)) {
			p = strrchr(host2, '.');
			if (p != NULL && (strlen(p+1) == 2 ||
					  strlen(p+1) == 3)) {
				/* it looks just like a netsplit to me. */
				ok = TRUE;
			}
		}
	}
	g_free(host1);

	return ok;
}

static void split_set_timeout(void *key, NETSPLIT_REC *rec, NETSPLIT_REC *orig)
{
	/* same servers -> split over -> destroy old records sooner.. */
	if (rec->server == orig->server)
		rec->destroy = time(NULL)+60;
}

static void event_join(IRC_SERVER_REC *server, const char *data,
		       const char *nick, const char *address)
{
	NETSPLIT_REC *rec;

	/* check if split is over */
	rec = g_hash_table_lookup(server->splits, nick);

	if (rec != NULL && g_strcasecmp(rec->address, address) == 0) {
		/* yep, looks like it is. for same people that had the same
		   splitted servers set the timeout to one minute.

		   .. if the user just changed server, she can't use the
		   same nick (unless the server is broken) so don't bother
		   checking that the nick's server matches the split. */
		g_hash_table_foreach(server->splits,
				     (GHFunc) split_set_timeout, rec);
	}
}

/* remove the nick from netsplit, but do it last so that other "event join"
   signal handlers can check if the join was a netjoin */
static void event_join_last(IRC_SERVER_REC *server, const char *data,
			    const char *nick, const char *address)
{
	NETSPLIT_REC *rec;

	rec = g_hash_table_lookup(server->splits, nick);
	if (rec != NULL) {
		g_hash_table_remove(server->splits, rec->nick);
		netsplit_destroy(server, rec);
	}
}

static void event_quit(IRC_SERVER_REC *server, const char *data,
		       const char *nick, const char *address)
{
	g_return_if_fail(data != NULL);

	if (*data == ':') data++;
	if (g_strcasecmp(nick, server->nick) != 0 && quitmsg_is_split(data)) {
		/* netsplit! */
		netsplit_add(server, nick, address, data);
	}
}

static void sig_disconnected(IRC_SERVER_REC *server)
{
	g_return_if_fail(server != NULL);

	if (!IS_IRC_SERVER(server))
		return;

	g_hash_table_foreach(server->splits,
			     (GHFunc) netsplit_destroy_hash, server);
	g_hash_table_destroy(server->splits);
}

static int split_server_check(void *key, NETSPLIT_REC *rec,
			      IRC_SERVER_REC *server)
{
	/* Check if this split record is too old.. */
	if (rec->destroy > time(NULL))
		return FALSE;

	netsplit_destroy(server, rec);
	return TRUE;
}

static int split_check_old(void)
{
	GSList *tmp;

	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		IRC_SERVER_REC *server = tmp->data;

		if (!IS_IRC_SERVER(server))
			continue;

		g_hash_table_foreach_remove(server->splits,
					    (GHRFunc) split_server_check,
					    server);
	}

	return 1;
}

void netsplit_init(void)
{
	split_tag = g_timeout_add(1000, (GSourceFunc) split_check_old, NULL);
	signal_add_first("event join", (SIGNAL_FUNC) event_join);
	signal_add_last("event join", (SIGNAL_FUNC) event_join_last);
	signal_add_first("event quit", (SIGNAL_FUNC) event_quit);
	signal_add("server disconnected", (SIGNAL_FUNC) sig_disconnected);
}

void netsplit_deinit(void)
{
	GSList *tmp;

	for (tmp = servers; tmp != NULL; tmp = tmp->next)
		sig_disconnected(tmp->data);

	g_source_remove(split_tag);
	signal_remove("event join", (SIGNAL_FUNC) event_join);
	signal_remove("event join", (SIGNAL_FUNC) event_join_last);
	signal_remove("event quit", (SIGNAL_FUNC) event_quit);
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_disconnected);
}
