/*
 windows.c : irssi

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
#include "server.h"
#include "settings.h"

#include "levels.h"

#include "printtext.h"
#include "windows.h"
#include "window-items.h"

GSList *windows;
WINDOW_REC *active_win;

static int window_get_new_refnum(void)
{
	WINDOW_REC *win;
	GSList *tmp;
	int refnum;

	refnum = 1;
	tmp = windows;
	while (tmp != NULL) {
		win = tmp->data;

		if (refnum != win->refnum) {
			tmp = tmp->next;
			continue;
		}

		refnum++;
		tmp = windows;
	}

	return refnum;
}

WINDOW_REC *window_create(WI_ITEM_REC *item, int automatic)
{
	WINDOW_REC *rec;

	rec = g_new0(WINDOW_REC, 1);
	rec->refnum = window_get_new_refnum();

	windows = g_slist_append(windows, rec);
	signal_emit("window created", 2, rec, GINT_TO_POINTER(automatic));

	if (item != NULL) window_add_item(rec, item, automatic);
	if (windows->next == NULL || !automatic || settings_get_bool("window_auto_change")) {
		if (automatic && windows->next != NULL)
			signal_emit("window changed automatic", 1, rec);
		window_set_active(rec);
	}
	return rec;
}

void window_destroy(WINDOW_REC *window)
{
	g_return_if_fail(window != NULL);

	if (window->destroying) return;
	window->destroying = TRUE;

	while (window->items != NULL)
		window_remove_item(window, window->items->data);

	windows = g_slist_remove(windows, window);
	signal_emit("window destroyed", 1, window);

	g_slist_foreach(window->waiting_channels, (GFunc) g_free, NULL);
	g_slist_free(window->waiting_channels);

	g_free_not_null(window->name);
	g_free(window);
}

void window_set_active_num(int number)
{
	GSList *win;

	win = g_slist_nth(windows, number);
	if (win == NULL) return;

	active_win = win->data;
	signal_emit("window changed", 1, active_win);
}

void window_set_active(WINDOW_REC *window)
{
	int number;

	number = g_slist_index(windows, window);
	if (number == -1) return;

	active_win = window;
	signal_emit("window changed", 1, active_win);
}

void window_change_server(WINDOW_REC *window, void *server)
{
	window->active_server = server;
	signal_emit("window server changed", 2, window, server);
}

void window_set_name(WINDOW_REC *window, const char *name)
{
	g_free_not_null(window->name);
	window->name = g_strdup(name);

	signal_emit("window name changed", 1, window);
}

void window_set_level(WINDOW_REC *window, int level)
{
	g_return_if_fail(window != NULL);

	window->level = level;
        signal_emit("window level changed", 1, window);
}

WINDOW_REC *window_find_level(void *server, int level)
{
	WINDOW_REC *match;
	GSList *tmp;

	match = NULL;
	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		if ((server == NULL || rec->active_server == server) &&
		    (rec->level & level)) {
			if (server == NULL || rec->active_server == server)
				return rec;
			match = rec;
		}
	}

	return match;
}

WINDOW_REC *window_find_closest(void *server, const char *name, int level)
{
	WINDOW_REC *window;
	WI_ITEM_REC *item;

	/* match by name */
	item = name == NULL ? NULL :
		window_item_find(server, name);
	if (item != NULL)
                return window_item_window(item);

	/* match by level */
	if (level != MSGLEVEL_HILIGHT)
		level &= ~(MSGLEVEL_HILIGHT | MSGLEVEL_NOHILIGHT);
	window = window_find_level(server, level);
	if (window != NULL) return window;

	/* fallback to active */
	return active_win;
}

static void cmd_window(const char *data, void *server, WI_ITEM_REC *item)
{
	command_runsub("window", data, server, item);
}

static void cmd_window_new(const char *data, void *server, WI_ITEM_REC *item)
{
	WINDOW_REC *window;
	int type;

	g_return_if_fail(data != NULL);

	type = (g_strcasecmp(data, "hide") == 0 || g_strcasecmp(data, "tab") == 0) ? 1 :
		(g_strcasecmp(data, "split") == 0 ? 2 : 0);
	signal_emit("gui window create override", 1, GINT_TO_POINTER(type));

	window = window_create(NULL, FALSE);
	window_change_server(window, server);
}

static void cmd_window_close(const char *data)
{
	/* destroy window unless it's the last one */
	if (windows->next != NULL)
		window_destroy(active_win);
}

/* return the first window number with the highest activity */
static int window_highest_activity(WINDOW_REC *window)
{
	WINDOW_REC *rec;
	GSList *tmp;
	int max_num, max_act, through;

	max_num = 0; max_act = 0; through = FALSE;

	tmp = g_slist_find(windows, window);
	for (;; tmp = tmp->next) {
		if (tmp == NULL) {
			tmp = windows;
			through = TRUE;
		}

		if (through && tmp->data == window)
			break;

		rec = tmp->data;

		if (rec->new_data && max_act < rec->new_data) {
			max_act = rec->new_data;
			max_num = g_slist_index(windows, rec)+1;
		}
	}

	return max_num;
}

/* channel name - first try channel from same server */
static int window_find_name(WINDOW_REC *window, const char *name)
{
	WI_ITEM_REC *item;
	int num;

	item = window_item_find(window->active_server, name);
	if (item == NULL && window->active_server != NULL) {
		/* not found from the active server - any server? */
		item = window_item_find(NULL, name);
	}

	if (item == NULL) {
		char *chan;

		/* still nothing? maybe user just left the # in front of
		   channel, try again with it.. */
		chan = g_strdup_printf("#%s", name);
		item = window_item_find(window->active_server, chan);
		if (item == NULL) item = window_item_find(NULL, chan);
		g_free(chan);
	}

	if (item == NULL)
		return 0;

	/* get the window number */
	window = MODULE_DATA(item);
	if (window == NULL) return 0;

	num = g_slist_index(windows, window);
	return num < 0 ? 0 : num+1;
}

static void cmd_window_goto(const char *data)
{
	int num;

	g_return_if_fail(data != NULL);

	num = 0;
	if (g_strcasecmp(data, "active") == 0)
                num = window_highest_activity(active_win);
	else if (isdigit(*data))
		num = atol(data);
	else
                num = window_find_name(active_win, data);

	if (num > 0)
		window_set_active_num(num-1);
}

static void cmd_window_next(const char *data)
{
	int num;

	num = g_slist_index(windows, active_win)+1;
	if (num >= g_slist_length(windows)) num = 0;
	window_set_active_num(num);
}

static void cmd_window_prev(const char *data)
{
	int num;

	num = g_slist_index(windows, active_win)-1;
	if (num < 0) num = g_slist_length(windows)-1;
	window_set_active_num(num);
}

static void cmd_window_level(const char *data)
{
	g_return_if_fail(data != NULL);

	window_set_level(active_win, combine_level(active_win->level, data));
	printtext(NULL, NULL, MSGLEVEL_CLIENTNOTICE, "Window level is now %s",
		  bits2level(active_win->level));
}

static void cmd_window_server(const char *data)
{
	SERVER_REC *server;

	g_return_if_fail(data != NULL);

	server = server_find_tag(data);
	if (server == NULL)
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_UNKNOWN_SERVER_TAG, data);
	else if (active_win->active == NULL) {
		window_change_server(active_win, server);
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_SERVER_CHANGED, server->tag, server->connrec->address,
			    server->connrec->ircnet == NULL ? "" : server->connrec->ircnet);
	}
}

static void cmd_window_item_prev(const char *data, void *server, WI_ITEM_REC *item)
{
	WINDOW_REC *window;
	WI_ITEM_REC *last;
	GSList *tmp;

	window = item == NULL ? NULL : MODULE_DATA(item);
	if (window == NULL) return;

	last = NULL;
	for (tmp = window->items; tmp != NULL; tmp = tmp->next) {
		WI_ITEM_REC *rec = tmp->data;

		if (rec != item)
			last = rec;
		else {
			/* current channel. did we find anything?
			   if not, go to the last channel */
			if (last != NULL) break;
		}
	}

	if (last != NULL)
                window_item_set_active(window, last);
}

static void cmd_window_item_next(const char *data, void *server, WI_ITEM_REC *item)
{
	WINDOW_REC *window;
	WI_ITEM_REC *next;
	GSList *tmp;
	int gone;

	window = item == NULL ? NULL : MODULE_DATA(item);
	if (window == NULL) return;

	next = NULL; gone = FALSE;
	for (tmp = window->items; tmp != NULL; tmp = tmp->next) {
		WI_ITEM_REC *rec = tmp->data;

		if (rec == item)
			gone = TRUE;
		else {
			if (gone) {
				/* found the next channel */
				next = rec;
				break;
			}

			if (next == NULL)
				next = rec; /* fallback to first channel */
		}
	}

	if (next != NULL)
                window_item_set_active(window, next);
}

static void cmd_window_name(const char *data)
{
        window_set_name(active_win, data);
}

static void sig_server_looking(void *server)
{
	GSList *tmp;

	g_return_if_fail(server != NULL);

	/* try to keep some server assigned to windows.. */
	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		if (rec->active_server == NULL)
			window_change_server(rec, server);
	}
}

static void sig_server_disconnected(void *server)
{
	GSList *tmp;

	g_return_if_fail(server != NULL);

	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		if (rec->active_server == server)
			window_change_server(rec, NULL);
	}
}

void windows_init(void)
{
	active_win = NULL;
	settings_add_bool("lookandfeel", "window_auto_change", FALSE);

	command_bind("window", NULL, (SIGNAL_FUNC) cmd_window);
	command_bind("window new", NULL, (SIGNAL_FUNC) cmd_window_new);
	command_bind("window close", NULL, (SIGNAL_FUNC) cmd_window_close);
	command_bind("window server", NULL, (SIGNAL_FUNC) cmd_window_server);
	command_bind("window goto", NULL, (SIGNAL_FUNC) cmd_window_goto);
	command_bind("window prev", NULL, (SIGNAL_FUNC) cmd_window_prev);
	command_bind("window next", NULL, (SIGNAL_FUNC) cmd_window_next);
	command_bind("window level", NULL, (SIGNAL_FUNC) cmd_window_level);
	command_bind("window item prev", NULL, (SIGNAL_FUNC) cmd_window_item_prev);
	command_bind("window item next", NULL, (SIGNAL_FUNC) cmd_window_item_next);
	command_bind("window name", NULL, (SIGNAL_FUNC) cmd_window_name);
	signal_add("server looking", (SIGNAL_FUNC) sig_server_looking);
	signal_add("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);
	signal_add("server connect failed", (SIGNAL_FUNC) sig_server_disconnected);
}

void windows_deinit(void)
{
	command_unbind("window", (SIGNAL_FUNC) cmd_window);
	command_unbind("window new", (SIGNAL_FUNC) cmd_window_new);
	command_unbind("window close", (SIGNAL_FUNC) cmd_window_close);
	command_unbind("window server", (SIGNAL_FUNC) cmd_window_server);
	command_unbind("window goto", (SIGNAL_FUNC) cmd_window_goto);
	command_unbind("window prev", (SIGNAL_FUNC) cmd_window_prev);
	command_unbind("window next", (SIGNAL_FUNC) cmd_window_next);
	command_unbind("window level", (SIGNAL_FUNC) cmd_window_level);
	command_unbind("window item prev", (SIGNAL_FUNC) cmd_window_item_prev);
	command_unbind("window item next", (SIGNAL_FUNC) cmd_window_item_next);
	command_unbind("window name", (SIGNAL_FUNC) cmd_window_name);
	signal_remove("server looking", (SIGNAL_FUNC) sig_server_looking);
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);
	signal_remove("server connect failed", (SIGNAL_FUNC) sig_server_disconnected);
}
