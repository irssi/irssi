/*
 fe-query.c : irssi

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
#include "module-formats.h"
#include "modules.h"
#include "signals.h"
#include "commands.h"
#include "settings.h"

#include "irc.h"
#include "levels.h"
#include "query.h"

#include "windows.h"
#include "window-items.h"

static int queryclose_tag, query_auto_close;

static void signal_query_created(QUERY_REC *query, gpointer automatic)
{
	window_item_create((WI_ITEM_REC *) query, GPOINTER_TO_INT(automatic));
        printformat(query->server, query->nick, MSGLEVEL_CLIENTNOTICE, IRCTXT_QUERY_STARTED, query->nick);
}

static void signal_query_created_curwin(QUERY_REC *query)
{
	g_return_if_fail(query != NULL);

	window_add_item(active_win, (WI_ITEM_REC *) query, FALSE);
	signal_stop();
}

static void signal_query_destroyed(QUERY_REC *query)
{
	WINDOW_REC *window;

	g_return_if_fail(query != NULL);

	window = window_item_window((WI_ITEM_REC *) query);
	if (window != NULL) window_remove_item(window, (WI_ITEM_REC *) query);
}

static void signal_window_item_removed(WINDOW_REC *window, WI_ITEM_REC *item)
{
	QUERY_REC *query;

	g_return_if_fail(window != NULL);

	query = irc_item_query(item);
        if (query != NULL) query_destroy(query);
}

static void sig_server_connected(IRC_SERVER_REC *server)
{
	GSList *tmp;

	if (!irc_server_check(server))
		return;

	/* check if there's any queries without server */
	for (tmp = queries; tmp != NULL; tmp = tmp->next) {
		QUERY_REC *rec = tmp->data;

		if (rec->server == NULL &&
		    g_strcasecmp(rec->server_tag, server->tag) == 0) {
			window_item_change_server((WI_ITEM_REC *) rec, server);
			server->queries = g_slist_append(server->queries, rec);
		}
	}
}

static void cmd_window_server(const char *data)
{
	SERVER_REC *server;

	g_return_if_fail(data != NULL);

	server = server_find_tag(data);
	if (irc_server_check(server) && irc_item_query(active_win->active)) {
                /* /WINDOW SERVER used in a query window */
		query_change_server((QUERY_REC *) active_win->active,
				    (IRC_SERVER_REC *) server);
		window_change_server(active_win, server);

		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_QUERY_SERVER_CHANGED, server->tag, server->connrec->address,
			    server->connrec->ircnet == NULL ? "" : server->connrec->ircnet);

		signal_stop();
	}
}

static void cmd_wquery(const char *data, void *server, WI_ITEM_REC *item)
{
	signal_add("query created", (SIGNAL_FUNC) signal_query_created_curwin);
	signal_emit("command query", 3, data, server, item);
	signal_remove("query created", (SIGNAL_FUNC) signal_query_created_curwin);
}

static void sig_window_changed(WINDOW_REC *window)
{
	GSList *tmp;

	if (query_auto_close <= 0)
		return;

	for (tmp = window->items; tmp != NULL; tmp = tmp->next) {
		if (irc_item_query(tmp->data))
			break;
	}
	if (tmp == NULL) return; /* no queries in window */

	/* reset the window's last_line timestamp so that query doesn't get
	   closed immediately after switched to the window. */
        window->last_line = time(NULL);
}

static int sig_query_autoclose(void)
{
	WINDOW_REC *window;
	GSList *tmp, *next;
	time_t now;

	now = time(NULL);
	for (tmp = queries; tmp != NULL; tmp = next) {
		QUERY_REC *rec = tmp->data;

		next = tmp->next;
		window = window_item_window((WI_ITEM_REC *) rec);
		if (window != active_win && rec->new_data == 0 &&
		    now-window->last_line > query_auto_close)
                        query_destroy(rec);
	}
        return 1;
}

static void read_settings(void)
{
	query_auto_close = settings_get_int("query_auto_close");
	if (query_auto_close > 0 && queryclose_tag == -1)
		queryclose_tag = g_timeout_add(5000, (GSourceFunc) sig_query_autoclose, NULL);
	else if (query_auto_close <= 0 && queryclose_tag != -1) {
		g_source_remove(queryclose_tag);
		queryclose_tag = -1;
	}
}

void fe_query_init(void)
{
	settings_add_int("lookandfeel", "query_auto_close", 0);

	queryclose_tag = -1;
	read_settings();

	signal_add("query created", (SIGNAL_FUNC) signal_query_created);
	signal_add("query destroyed", (SIGNAL_FUNC) signal_query_destroyed);
	signal_add("window item remove", (SIGNAL_FUNC) signal_window_item_removed);
	signal_add("server connected", (SIGNAL_FUNC) sig_server_connected);
	signal_add("window changed", (SIGNAL_FUNC) sig_window_changed);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);

	command_bind("wquery", NULL, (SIGNAL_FUNC) cmd_wquery);
	command_bind("window server", NULL, (SIGNAL_FUNC) cmd_window_server);
}

void fe_query_deinit(void)
{
	if (queryclose_tag != -1) g_source_remove(queryclose_tag);

	signal_remove("query created", (SIGNAL_FUNC) signal_query_created);
	signal_remove("query destroyed", (SIGNAL_FUNC) signal_query_destroyed);
	signal_remove("window item remove", (SIGNAL_FUNC) signal_window_item_removed);
	signal_remove("server connected", (SIGNAL_FUNC) sig_server_connected);
	signal_remove("window changed", (SIGNAL_FUNC) sig_window_changed);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);

	command_unbind("wquery", (SIGNAL_FUNC) cmd_wquery);
	command_unbind("window server", (SIGNAL_FUNC) cmd_window_server);
}
