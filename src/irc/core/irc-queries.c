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

#include "irc-servers.h"
#include "irc-queries.h"

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

static void event_privmsg(IRC_SERVER_REC *server, const char *data,
			  const char *nick, const char *address)
{
	QUERY_REC *query;
	char *params, *target, *msg;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST, &target, &msg);

	if (address != NULL && !ischannel(*target)) {
		/* save nick's address to query */
		query = irc_query_find(server, nick);
		if (query != NULL && (query->address == NULL ||
				      strcmp(query->address, address) != 0))
                        query_change_address(query, address);
	}

	g_free(params);
}

static void event_nick(SERVER_REC *server, const char *data,
		       const char *orignick)
{
        QUERY_REC *query;
	char *params, *nick;

	query = query_find(server, orignick);
	if (query != NULL) {
		params = event_get_params(data, 1, &nick);
		query_change_nick(query, nick);
		g_free(params);
	}
}

void irc_queries_init(void)
{
	signal_add_last("event privmsg", (SIGNAL_FUNC) event_privmsg);
	signal_add("event nick", (SIGNAL_FUNC) event_nick);
}

void irc_queries_deinit(void)
{
	signal_remove("event privmsg", (SIGNAL_FUNC) event_privmsg);
	signal_remove("event nick", (SIGNAL_FUNC) event_nick);
}
