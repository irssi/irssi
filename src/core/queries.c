/*
 queries.c : irssi

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

#include "module.h"
#include "signals.h"
#include "misc.h"

#include "servers.h"
#include "queries.h"

GSList *queries;

void query_init(QUERY_REC *query, int automatic)
{
	g_return_if_fail(query != NULL);
	g_return_if_fail(query->name != NULL);

	queries = g_slist_append(queries, query);

        MODULE_DATA_INIT(query);
	query->type = module_get_uniq_id_str("WINDOW ITEM TYPE", "QUERY");
	if (query->server_tag != NULL) {
		query->server = server_find_tag(query->server_tag);
		if (query->server != NULL) {
			query->server->queries =
				g_slist_append(query->server->queries, query);
		}
	}

	signal_emit("query created", 2, query, GINT_TO_POINTER(automatic));
}

void query_destroy(QUERY_REC *query)
{
	g_return_if_fail(IS_QUERY(query));

        if (query->destroying) return;
	query->destroying = TRUE;

	queries = g_slist_remove(queries, query);
	if (query->server != NULL) {
		query->server->queries =
			g_slist_remove(query->server->queries, query);
	}
	signal_emit("query destroyed", 1, query);

        MODULE_DATA_DEINIT(query);
	g_free_not_null(query->hilight_color);
        g_free_not_null(query->server_tag);
        g_free_not_null(query->address);
	g_free(query->name);
	g_free(query);
}

static QUERY_REC *query_find_server(SERVER_REC *server, const char *nick)
{
	GSList *tmp;

	g_return_val_if_fail(IS_SERVER(server), NULL);

	if (server->query_find_func != NULL) {
		/* use the server specific query find function */
		return server->query_find_func(server, nick);
	}

	for (tmp = server->queries; tmp != NULL; tmp = tmp->next) {
		QUERY_REC *rec = tmp->data;

		if (g_strcasecmp(rec->name, nick) == 0)
			return rec;
	}

	return NULL;
}

QUERY_REC *query_find(SERVER_REC *server, const char *nick)
{
	GSList *tmp;

	g_return_val_if_fail(server == NULL || IS_SERVER(server), NULL);
	g_return_val_if_fail(nick != NULL, NULL);

	if (server != NULL)
		return query_find_server(server, nick);

	for (tmp = queries; tmp != NULL; tmp = tmp->next) {
		QUERY_REC *rec = tmp->data;

		if (g_strcasecmp(rec->name, nick) == 0)
			return rec;
	}

        return NULL;
}

void query_change_nick(QUERY_REC *query, const char *nick)
{
	char *oldnick;

	g_return_if_fail(IS_QUERY(query));

        oldnick = query->name;
	query->name = g_strdup(nick);
	signal_emit("query nick changed", 2, query, oldnick);
        g_free(oldnick);
}

void query_change_address(QUERY_REC *query, const char *address)
{
	g_return_if_fail(IS_QUERY(query));

        g_free_not_null(query->address);
	query->address = g_strdup(address);
	signal_emit("query address changed", 1, query);
}

void query_change_server(QUERY_REC *query, SERVER_REC *server)
{
	g_return_if_fail(IS_QUERY(query));

	if (query->server != NULL) {
		query->server->queries =
                        g_slist_remove(query->server->queries, query);
	}
	if (server != NULL)
                server->queries = g_slist_append(server->queries, query);

	query->server = server;
	signal_emit("query server changed", 1, query);
}

void queries_init(void)
{
}

void queries_deinit(void)
{
	module_uniq_destroy("QUERY");
}
