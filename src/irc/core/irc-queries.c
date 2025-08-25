/*
 irc-queries.c : irssi

    Copyright (C) 1999-2000 Timo Sirainen

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
#include <irssi/src/core/misc.h>

#include <irssi/src/irc/core/irc-nicklist.h>
#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/irc/core/irc-queries.h>

QUERY_REC *irc_query_create(const char *server_tag,
			    const char *nick, int automatic)
{
	QUERY_REC *rec;

	g_return_val_if_fail(nick != NULL, NULL);

	rec = g_new0(QUERY_REC, 1);
	rec->chat_type = IRC_PROTOCOL;
	rec->name = g_strdup(nick);
        rec->server_tag = g_strdup(server_tag);
	query_init(rec, automatic);
	return rec;
}

QUERY_REC *irc_query_find(IRC_SERVER_REC *server, const char *nick)
{
	GSList *tmp;

	g_return_val_if_fail(nick != NULL, NULL);

	for (tmp = server->queries; tmp != NULL; tmp = tmp->next) {
		QUERY_REC *rec = tmp->data;

		if (server->nick_comp_func(rec->name, nick) == 0)
			return rec;
	}

	return NULL;
}

static void check_query_changes(IRC_SERVER_REC *server, const char *nick,
				const char *address, const char *target)
{
	QUERY_REC *query;

	if (server_ischannel(SERVER(server), target))
		return;

	query = irc_query_find(server, nick);
	if (query == NULL)
		return;

	if (g_strcmp0(query->name, nick) != 0) {
		/* upper/lowercase chars in nick changed */
		query_change_nick(query, nick);
	}

	if (address != NULL && (query->address == NULL ||
				g_strcmp0(query->address, address) != 0)) {
                /* host changed */
		query_change_address(query, address);
	}
}

static void ctcp_action(IRC_SERVER_REC *server, const char *msg,
			const char *nick, const char *address,
			const char *target)
{
        check_query_changes(server, nick, address, target);
}

static void event_nick(SERVER_REC *server, const char *data,
		       const char *orignick)
{
        QUERY_REC *query;
	char *params, *nick;

	query = query_find(server, orignick);
	if (query != NULL) {
		params = event_get_params(data, 1, &nick);
		if (g_strcmp0(query->name, nick) != 0)
			query_change_nick(query, nick);
		g_free(params);
	}
}

void irc_queries_init(void)
{
	signal_add_last("ctcp action", (SIGNAL_FUNC) ctcp_action);
	signal_add("event nick", (SIGNAL_FUNC) event_nick);
}

void irc_queries_deinit(void)
{
	signal_remove("ctcp action", (SIGNAL_FUNC) ctcp_action);
	signal_remove("event nick", (SIGNAL_FUNC) event_nick);
}
