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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "signals.h"
#include "misc.h"

#include "irc.h"
#include "irc-queries.h"

QUERY_REC *irc_query_create(IRC_SERVER_REC *server,
			    const char *nick, int automatic)
{
	QUERY_REC *rec;

	g_return_val_if_fail(server == NULL || IS_IRC_SERVER(server), NULL);
	g_return_val_if_fail(nick != NULL, NULL);

	rec = g_new0(QUERY_REC, 1);
	rec->chat_type = IRC_PROTOCOL;
	rec->name = g_strdup(nick);
	rec->server = (SERVER_REC *) server;
	query_init(rec, automatic);
	return rec;
}

static void sig_query_create(QUERY_REC **query,
			     void *chat_type, IRC_SERVER_REC *server,
			     const char *nick, void *automatic)
{
	if (chat_protocol_lookup("IRC") != GPOINTER_TO_INT(chat_type))
		return;

	g_return_if_fail(server == NULL || IS_IRC_SERVER(server));
	g_return_if_fail(query != NULL);
	g_return_if_fail(nick != NULL);

	*query = irc_query_create(server, nick, GPOINTER_TO_INT(automatic));
	signal_stop();
}

static void event_privmsg(const char *data, IRC_SERVER_REC *server, const char *nick, const char *addr)
{
	char *params, *target, *msg;
	QUERY_REC *query;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST, &target, &msg);

	if (addr != NULL && !ischannel(*target)) {
		/* save nick's address to query */
		query = irc_query_find(server, nick);
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

		if (g_strcasecmp(rec->name, orignick) == 0) {
			g_free(rec->name);
			rec->name = g_strdup(nick);
			signal_emit("query nick changed", 1, rec);
		}
	}

	g_free(params);
}

void irc_queries_init(void)
{
	signal_add("query create", (SIGNAL_FUNC) sig_query_create);
	signal_add_last("event privmsg", (SIGNAL_FUNC) event_privmsg);
	signal_add("event nick", (SIGNAL_FUNC) event_nick);
}

void irc_queries_deinit(void)
{
	signal_remove("query create", (SIGNAL_FUNC) sig_query_create);
	signal_remove("event privmsg", (SIGNAL_FUNC) event_privmsg);
	signal_remove("event nick", (SIGNAL_FUNC) event_nick);
}
