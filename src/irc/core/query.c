/*
 query.c : irssi

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

#include "misc.h"
#include "signals.h"
#include "modules.h"

#include "irc.h"
#include "query.h"

GSList *queries;

QUERY_REC *query_create(IRC_SERVER_REC *server, const char *nick, int automatic)
{
	QUERY_REC *rec;

	g_return_val_if_fail(nick != NULL, NULL);

	rec = g_new0(QUERY_REC, 1);
	queries = g_slist_append(queries, rec);
	if (server != NULL) server->queries = g_slist_append(server->queries, rec);

        MODULE_DATA_INIT(rec);
	rec->type = module_get_uniq_id("IRC", WI_IRC_QUERY);
	rec->nick = g_strdup(nick);
	if (server != NULL) {
		rec->server_tag = g_strdup(server->tag);
		rec->server = server;
	}

	signal_emit("query created", 2, rec, GINT_TO_POINTER(automatic));
	return rec;
}

void query_destroy(QUERY_REC *query)
{
	g_return_if_fail(query != NULL);

        if (query->destroying) return;
	query->destroying = TRUE;

	queries = g_slist_remove(queries, query);
	if (query->server != NULL)
		query->server->queries = g_slist_remove(query->server->queries, query);
	signal_emit("query destroyed", 1, query);

        MODULE_DATA_DEINIT(query);
        g_free_not_null(query->address);
	g_free(query->nick);
        g_free(query->server_tag);
	g_free(query);
}


static QUERY_REC *query_find_server(IRC_SERVER_REC *server, const char *nick)
{
	GSList *tmp;

	for (tmp = server->queries; tmp != NULL; tmp = tmp->next) {
		QUERY_REC *rec = tmp->data;

		if (g_strcasecmp(nick, rec->nick) == 0)
			return rec;
	}

	return NULL;
}

QUERY_REC *query_find(IRC_SERVER_REC *server, const char *nick)
{
	g_return_val_if_fail(nick != NULL, NULL);

	if (server != NULL)
		return query_find_server(server, nick);

	/* find from any server */
	return gslist_foreach_find(servers, (FOREACH_FIND_FUNC) query_find_server, (void *) nick);
}

void query_change_server(QUERY_REC *query, IRC_SERVER_REC *server)
{
	g_return_if_fail(query != NULL);

	query->server = server;
	signal_emit("query server changed", 2, query, server);
}

static void event_privmsg(const char *data, IRC_SERVER_REC *server, const char *nick, const char *addr)
{
	char *params, *target, *msg;
	QUERY_REC *query;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST, &target, &msg);

	if (addr != NULL && *msg != 1 && !ischannel(*target)) {
		/* save nick's address to query */
		query = query_find(server, nick);
		if (query != NULL && (query->address == NULL || strcmp(query->address, addr) != 0)) {
			g_free_not_null(query->address);
			query->address = g_strdup(addr);

			signal_emit("query address changed", 1, query);
		}
	}

	g_free(params);
}

static void event_nick(const char *data, IRC_SERVER_REC *server, const char *orignick)
{
	char *params, *nick;
	GSList *tmp;

	params = event_get_params(data, 1, &nick);

	for (tmp = server->queries; tmp != NULL; tmp = tmp->next) {
		QUERY_REC *rec = tmp->data;

		if (g_strcasecmp(rec->nick, orignick) == 0) {
			g_free(rec->nick);
			rec->nick = g_strdup(nick);
			signal_emit("query nick changed", 1, rec);
		}
	}

	g_free(params);
}

void query_init(void)
{
	signal_add_last("event privmsg", (SIGNAL_FUNC) event_privmsg);
	signal_add("event nick", (SIGNAL_FUNC) event_nick);
}

void query_deinit(void)
{
	signal_remove("event privmsg", (SIGNAL_FUNC) event_privmsg);
	signal_remove("event nick", (SIGNAL_FUNC) event_nick);
}
