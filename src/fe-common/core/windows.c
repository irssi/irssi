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
#include "misc.h"
#include "settings.h"

#include "levels.h"

#include "printtext.h"
#include "windows.h"
#include "window-items.h"

GSList *windows; /* first in the list is the active window,
                    next is the last active, etc. */
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

	windows = g_slist_prepend(windows, rec);
	signal_emit("window created", 2, rec, GINT_TO_POINTER(automatic));

	if (item != NULL) window_add_item(rec, item, automatic);
	if (windows->next == NULL || !automatic || settings_get_bool("window_auto_change")) {
		if (automatic && windows->next != NULL)
			signal_emit("window changed automatic", 1, rec);
		window_set_active(rec);
	}
	return rec;
}

/* removed_refnum was removed from the windows list, pack the windows so
   there won't be any holes. If there is any holes after removed_refnum,
   leave the windows behind it alone. */
static void windows_pack(int removed_refnum)
{
	WINDOW_REC *window;
	int refnum;

	for (refnum = removed_refnum+1;; refnum++) {
		window = window_find_refnum(refnum);
		if (window == NULL) break;

		window_set_refnum(window, refnum-1);
	}
}

void window_destroy(WINDOW_REC *window)
{
	int refnum;

	g_return_if_fail(window != NULL);

	if (window->destroying) return;
	window->destroying = TRUE;

	while (window->items != NULL)
		window_remove_item(window, window->items->data);

	windows = g_slist_remove(windows, window);
	signal_emit("window destroyed", 1, window);

	g_slist_foreach(window->waiting_channels, (GFunc) g_free, NULL);
	g_slist_free(window->waiting_channels);

	refnum = window->refnum;
	g_free_not_null(window->name);
	g_free(window);

	if (active_win == window && windows != NULL)
		window_set_active(windows->data);

	windows_pack(refnum);
}

void window_set_active(WINDOW_REC *window)
{
	if (window == active_win)
		return;

	active_win = window;
        windows = g_slist_remove(windows, active_win);
	windows = g_slist_prepend(windows, active_win);

	signal_emit("window changed", 1, active_win);
}

void window_change_server(WINDOW_REC *window, void *server)
{
	window->active_server = server;
	signal_emit("window server changed", 2, window, server);
}

void window_set_refnum(WINDOW_REC *window, int refnum)
{
	GSList *tmp;
	int old_refnum;

	g_return_if_fail(window != NULL);
	g_return_if_fail(refnum >= 1);
	if (window->refnum == refnum) return;

	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		if (rec->refnum == refnum) {
			rec->refnum = window->refnum;
                        signal_emit("window refnum changed", 2, rec, GINT_TO_POINTER(refnum));
			break;
		}
	}

	old_refnum = window->refnum;
	window->refnum = refnum;
	signal_emit("window refnum changed", 2, window, GINT_TO_POINTER(old_refnum));
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

/* return active item's name, or if none is active, window's name */
char *window_get_active_name(WINDOW_REC *window)
{
	g_return_val_if_fail(window != NULL, NULL);

	if (window->active != NULL)
		return window->active->name;

	return window->name;
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

WINDOW_REC *window_find_refnum(int refnum)
{
	GSList *tmp;

	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		if (rec->refnum == refnum)
			return rec;
	}

	return NULL;
}

static int windows_refnum_last(void)
{
	GSList *tmp;
	int max;

	max = -1;
	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		if (rec->refnum > max)
			max = rec->refnum;
	}

	return max;
}

static int window_refnum_prev(int refnum)
{
	GSList *tmp;
	int prev, max;

	max = prev = -1;
	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		if (rec->refnum < refnum && (max == -1 || rec->refnum > max))
			prev = rec->refnum;
		if (max == -1 || rec->refnum > max)
			max = rec->refnum;
	}

	return prev != -1 ? prev : max;
}

static int window_refnum_next(int refnum)
{
	GSList *tmp;
	int min, next;

	min = next = -1;
	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		if (rec->refnum > refnum && (next == -1 || rec->refnum < next))
			next = rec->refnum;
		if (min == -1 || rec->refnum < min)
			min = rec->refnum;
	}

	return next != -1 ? next : min;
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

	type = (g_strncasecmp(data, "hid", 3) == 0 || g_strcasecmp(data, "tab") == 0) ? 1 :
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
static WINDOW_REC *window_highest_activity(WINDOW_REC *window)
{
	WINDOW_REC *rec, *max_win;
	GSList *tmp;
	int max_act, through;

	g_return_val_if_fail(window != NULL, NULL);

	max_win = NULL; max_act = 0; through = FALSE;

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
			max_win = rec;
		}
	}

	return max_win;
}

WINDOW_REC *window_find_name(const char *name)
{
	GSList *tmp;

	g_return_val_if_fail(name != NULL, NULL);

	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		if (rec->name != NULL && g_strcasecmp(rec->name, name) == 0)
			return rec;
	}

	return NULL;
}

WINDOW_REC *window_find_item(WINDOW_REC *window, const char *name)
{
	WINDOW_REC *rec;
	WI_ITEM_REC *item;

	g_return_val_if_fail(name != NULL, NULL);

	rec = window_find_name(name);
	if (rec != NULL) return rec;

	item = window == NULL ? NULL :
		window_item_find(window->active_server, name);
	if (item == NULL && window->active_server != NULL) {
		/* not found from the active server - any server? */
		item = window_item_find(NULL, name);
	}

	if (item == NULL) {
		char *chan;

		/* still nothing? maybe user just left the # in front of
		   channel, try again with it.. */
		chan = g_strdup_printf("#%s", name);
		item = window == NULL ? NULL :
			window_item_find(window->active_server, chan);
		if (item == NULL) item = window_item_find(NULL, chan);
		g_free(chan);
	}

	if (item == NULL)
		return 0;

	return MODULE_DATA(item);
}

static void cmd_window_refnum(const char *data)
{
	WINDOW_REC *window;

	if (!is_numeric(data, 0))
		return;

	window = window_find_refnum(atoi(data));
        if (window != NULL)
		window_set_active(window);
}

static void cmd_window_goto(const char *data)
{
	WINDOW_REC *window;

	g_return_if_fail(data != NULL);

	if (is_numeric(data, 0)) {
		cmd_window_refnum(data);
		return;
	}

	if (g_strcasecmp(data, "active") == 0)
                window = window_highest_activity(active_win);
	else
                window = window_find_item(active_win, data);

	if (window != NULL)
		window_set_active(window);
}

static void cmd_window_next(void)
{
	int num;

	num = window_refnum_next(active_win->refnum);
	if (num < 1) num = windows_refnum_last();

	window_set_active(window_find_refnum(num));
}

static void cmd_window_prev(void)
{
	int num;

	num = window_refnum_prev(active_win->refnum);
	if (num < 1) num = window_refnum_next(0);

	window_set_active(window_find_refnum(num));
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

static void cmd_window_number(const char *data)
{
	int num;

	num = atoi(data);
	if (num < 1)
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_REFNUM_TOO_LOW);
	else
		window_set_refnum(active_win, num);
}

static void cmd_window_name(const char *data)
{
        window_set_name(active_win, data);
}

/* we're moving the first window to last - move the first contiguous block
   of refnums to left. Like if there's windows 1..5 and 7..10, move 1 to
   11, 2..5 to 1..4 and leave 7..10 alone  */
static void windows_move_left(WINDOW_REC *move_window)
{
	WINDOW_REC *window;
	int refnum;

	window_set_refnum(move_window, windows_refnum_last()+1);
	for (refnum = 2;; refnum++) {
		window = window_find_refnum(refnum);
		if (window == NULL) break;

		window_set_refnum(window, refnum-1);
	}
}

/* we're moving the last window to first - make some space so we can use the
   refnum 1 */
static void windows_move_right(WINDOW_REC *move_window)
{
	WINDOW_REC *window;
	int refnum;

	/* find the first unused refnum, like if there's windows
	   1..5 and 7..10, we only need to move 1..5 to 2..6 */
	refnum = 1;
	while (window_find_refnum(refnum) != NULL) refnum++;

	refnum--;
	while (refnum > 0) {
		window = window_find_refnum(refnum);
		g_return_if_fail(window != NULL);
		window_set_refnum(window, window == move_window ? 1 : refnum+1);

		refnum--;
	}
}

static void cmd_window_move_left(void)
{
	int refnum;

	refnum = window_refnum_prev(active_win->refnum);
	if (refnum != -1) {
		window_set_refnum(active_win, active_win->refnum-1);
		return;
	}

	windows_move_left(active_win);
}

static void cmd_window_move_right(void)
{
	int refnum;

	refnum = window_refnum_next(active_win->refnum);
	if (refnum != -1) {
		window_set_refnum(active_win, active_win->refnum+1);
		return;
	}

        windows_move_right(active_win);
}

static void cmd_window_move(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	int new_refnum, refnum;

	if (!is_numeric(data, 0)) {
		command_runsub("window move", data, server, item);
                return;
	}

	new_refnum = atoi(data);
	if (new_refnum > active_win->refnum) {
		for (;;) {
			refnum = window_refnum_next(active_win->refnum);
			if (refnum == -1 || refnum > new_refnum)
				break;

			window_set_refnum(active_win, refnum);
		}
	} else {
		for (;;) {
			refnum = window_refnum_prev(active_win->refnum);
			if (refnum == -1 || refnum < new_refnum)
				break;

			window_set_refnum(active_win, refnum);
		}
	}
}

static int windows_compare(WINDOW_REC *w1, WINDOW_REC *w2)
{
	return w1->refnum < w2->refnum ? -1 : 1;
}

GSList *windows_get_sorted(void)
{
	GSList *tmp, *list;

	list = NULL;
	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		list = g_slist_insert_sorted(list, tmp->data, (GCompareFunc) windows_compare);
	}

	return list;
}

static void cmd_window_list(void)
{
	GSList *tmp, *sorted;
	char *levelstr;

	sorted = windows_get_sorted();
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_WINDOWLIST_HEADER);
	for (tmp = sorted; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		levelstr = bits2level(rec->level);
		printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_WINDOWLIST_LINE,
			    rec->refnum, rec->name == NULL ? "" : rec->name,
			    rec->active == NULL ? "" : rec->active->name,
			    rec->active_server == NULL ? "" : ((SERVER_REC *) rec->active_server)->tag,
			    levelstr);
		g_free(levelstr);
	}
	g_slist_free(sorted);
        printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_WINDOWLIST_FOOTER);
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
	command_bind("window kill", NULL, (SIGNAL_FUNC) cmd_window_close);
	command_bind("window server", NULL, (SIGNAL_FUNC) cmd_window_server);
	command_bind("window refnum", NULL, (SIGNAL_FUNC) cmd_window_refnum);
	command_bind("window goto", NULL, (SIGNAL_FUNC) cmd_window_goto);
	command_bind("window prev", NULL, (SIGNAL_FUNC) cmd_window_prev);
	command_bind("window next", NULL, (SIGNAL_FUNC) cmd_window_next);
	command_bind("window level", NULL, (SIGNAL_FUNC) cmd_window_level);
	command_bind("window item prev", NULL, (SIGNAL_FUNC) cmd_window_item_prev);
	command_bind("window item next", NULL, (SIGNAL_FUNC) cmd_window_item_next);
	command_bind("window number", NULL, (SIGNAL_FUNC) cmd_window_number);
	command_bind("window name", NULL, (SIGNAL_FUNC) cmd_window_name);
	command_bind("window move", NULL, (SIGNAL_FUNC) cmd_window_move);
	command_bind("window move left", NULL, (SIGNAL_FUNC) cmd_window_move_left);
	command_bind("window move right", NULL, (SIGNAL_FUNC) cmd_window_move_right);
	command_bind("window list", NULL, (SIGNAL_FUNC) cmd_window_list);
	signal_add("server looking", (SIGNAL_FUNC) sig_server_looking);
	signal_add("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);
	signal_add("server connect failed", (SIGNAL_FUNC) sig_server_disconnected);
}

void windows_deinit(void)
{
	command_unbind("window", (SIGNAL_FUNC) cmd_window);
	command_unbind("window new", (SIGNAL_FUNC) cmd_window_new);
	command_unbind("window close", (SIGNAL_FUNC) cmd_window_close);
	command_unbind("window kill", (SIGNAL_FUNC) cmd_window_close);
	command_unbind("window server", (SIGNAL_FUNC) cmd_window_server);
	command_unbind("window refnum", (SIGNAL_FUNC) cmd_window_refnum);
	command_unbind("window goto", (SIGNAL_FUNC) cmd_window_goto);
	command_unbind("window prev", (SIGNAL_FUNC) cmd_window_prev);
	command_unbind("window next", (SIGNAL_FUNC) cmd_window_next);
	command_unbind("window level", (SIGNAL_FUNC) cmd_window_level);
	command_unbind("window item prev", (SIGNAL_FUNC) cmd_window_item_prev);
	command_unbind("window item next", (SIGNAL_FUNC) cmd_window_item_next);
	command_unbind("window number", (SIGNAL_FUNC) cmd_window_number);
	command_unbind("window name", (SIGNAL_FUNC) cmd_window_name);
	command_unbind("window move", (SIGNAL_FUNC) cmd_window_move);
	command_unbind("window move left", (SIGNAL_FUNC) cmd_window_move_left);
	command_unbind("window move right", (SIGNAL_FUNC) cmd_window_move_right);
	command_unbind("window list", (SIGNAL_FUNC) cmd_window_list);
	signal_remove("server looking", (SIGNAL_FUNC) sig_server_looking);
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);
	signal_remove("server connect failed", (SIGNAL_FUNC) sig_server_disconnected);
}
