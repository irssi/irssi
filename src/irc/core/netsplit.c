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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include <irssi/src/core/signals.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/core/misc.h>

#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/irc/core/irc-channels.h>
#include <irssi/src/irc/core/netsplit.h>

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

		if (g_ascii_strcasecmp(rec->server, servername) == 0 &&
		    g_ascii_strcasecmp(rec->destserver, destserver) == 0)
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
		splitchan->name = g_strdup(channel->visible_name);
		splitchan->op = nickrec->op;
		splitchan->halfop = nickrec->halfop;
		splitchan->voice = nickrec->voice;
		memcpy(splitchan->prefixes, nickrec->prefixes, sizeof(splitchan->prefixes));

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
	g_slist_free(rec->channels);

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
		g_ascii_strcasecmp(rec->address, address) == 0) ? rec : NULL;
}

NETSPLIT_CHAN_REC *netsplit_find_channel(IRC_SERVER_REC *server,
					 const char *nick, const char *address,
					 const char *channel)
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

		if (g_ascii_strcasecmp(rec->name, channel) == 0)
			return rec;
	}

	return NULL;
}

/* check if quit message is a netsplit message */
int quitmsg_is_split(const char *msg)
{
	const char *host2, *p;
	int prev, host1_dot, host2_dot;

	g_return_val_if_fail(msg != NULL, FALSE);

	/* NOTE: there used to be some paranoia checks (some older IRC
	   clients have even more), but they're pretty useless nowadays,
	   since IRC server prefixes the quit message with a space if it
	   looks like a netsplit message.

	   So, the check is currently just:
             - host1.domain1 host2.domain2
             - top-level domains have to be 2+ characters long,
	       containing only alphabets
	     - only 1 space
	     - no double-dots (".." - probably useless check)
	     - hosts/domains can't start or end with a dot
             - the two hosts can't be identical (probably useless check)
	     - can't contain ':' or '/' chars (some servers allow URLs)
	   */
	host2 = NULL;
	prev = '\0';
	host1_dot = host2_dot = 0;
	while (*msg != '\0') {
		if (*msg == ' ') {
			if (prev == '.' || prev == '\0') {
				/* domains can't end with '.', space can't
				   be the first character in msg. */
				return FALSE;
			}
			if (host2 != NULL)
				return FALSE; /* only one space allowed */
			if (!host1_dot)
                                return FALSE; /* host1 didn't have domain */
			host2 = msg + 1;
		} else if (*msg == '.') {
			if (prev == '\0' || prev == ' ' || prev == '.') {
				/* domains can't start with '.'
				   and can't have ".." */
				return FALSE;
			}

			if (host2 != NULL)
				host2_dot = TRUE;
			else
                                host1_dot = TRUE;
		} else if (*msg == ':' || *msg == '/')
			return FALSE;

		prev = *msg;
		msg++;
	}

	if (!host2_dot || prev == '.')
                return FALSE;

        /* top-domain1 must be 2+ chars long and contain only alphabets */
	p = host2-1;
	while (p[-1] != '.') {
		if (!i_isalpha(p[-1]))
                        return FALSE;
		p--;
	}
	if (host2-p-1 < 2) return FALSE;

        /* top-domain2 must be 2+ chars long and contain only alphabets */
	p = host2+strlen(host2);
	while (p[-1] != '.') {
		if (!i_isalpha(p[-1]))
                        return FALSE;
		p--;
	}
	if (strlen(p) < 2) return FALSE;

        return TRUE;
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

	if (nick == NULL)
		return;

	/* check if split is over */
	rec = g_hash_table_lookup(server->splits, nick);

	if (rec != NULL && g_ascii_strcasecmp(rec->address, address) == 0) {
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

	if (nick == NULL)
		return;

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
	if (g_ascii_strcasecmp(nick, server->nick) != 0 && quitmsg_is_split(data)) {
		/* netsplit! */
		netsplit_add(server, nick, address, data);
	}
}

static void event_nick(IRC_SERVER_REC *server, const char *data)
{
	NETSPLIT_REC *rec;
	char *params, *nick;

	params = event_get_params(data, 1, &nick);

	/* remove nick from split list when somebody changed
	   nick to this one during split */
        rec = g_hash_table_lookup(server->splits, nick);
	if (rec != NULL) {
	        g_hash_table_remove(server->splits, rec->nick);
		netsplit_destroy(server, rec);
	}

        g_free(params);
}

static void sig_disconnected(IRC_SERVER_REC *server)
{
	g_return_if_fail(server != NULL);

	if (!IS_IRC_SERVER(server))
		return;

	if (server->splits == NULL)
		return;

	g_hash_table_foreach(server->splits,
			     (GHFunc) netsplit_destroy_hash, server);
	g_hash_table_destroy(server->splits);
        server->splits = NULL;
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
	signal_add("event nick", (SIGNAL_FUNC) event_nick);
	signal_add("server disconnected", (SIGNAL_FUNC) sig_disconnected);
}

void netsplit_deinit(void)
{
	g_source_remove(split_tag);
	signal_remove("event join", (SIGNAL_FUNC) event_join);
	signal_remove("event join", (SIGNAL_FUNC) event_join_last);
	signal_remove("event quit", (SIGNAL_FUNC) event_quit);
	signal_remove("event nick", (SIGNAL_FUNC) event_nick);
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_disconnected);
}
