/*
 window-commands.c : irssi

    Copyright (C) 2000 Timo Sirainen

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
#include "signals.h"
#include "commands.h"
#include "misc.h"
#include "servers.h"

#include "levels.h"

#include "themes.h"
#include "fe-windows.h"
#include "window-items.h"
#include "window-save.h"
#include "printtext.h"

static void cmd_window(const char *data, void *server, WI_ITEM_REC *item)
{
	if (is_numeric(data, 0)) {
                signal_emit("command window refnum", 3, data, server, item);
		return;
	}

	command_runsub("window", data, server, item);
}

/* SYNTAX: WINDOW NEW [hide] */
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

/* SYNTAX: WINDOW CLOSE */
static void cmd_window_close(const char *data)
{
	/* destroy window unless it's the last one */
	if (windows->next != NULL)
		window_destroy(active_win);
}

/* SYNTAX: WINDOW REFNUM <number> */
static void cmd_window_refnum(const char *data)
{
	WINDOW_REC *window;

	if (!is_numeric(data, 0))
		return;

	window = window_find_refnum(atoi(data));
	if (window != NULL)
		window_set_active(window);
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

/* SYNTAX: WINDOW GOTO active|<number>|<name> */
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

/* SYNTAX: WINDOW NEXT */
static void cmd_window_next(void)
{
	int num;

	num = window_refnum_next(active_win->refnum, TRUE);
	if (num < 1) num = windows_refnum_last();

	window_set_active(window_find_refnum(num));
}

/* SYNTAX: WINDOW LAST */
static void cmd_window_last(void)
{
	if (windows->next != NULL)
		window_set_active(windows->next->data);
}

/* SYNTAX: WINDOW PREV */
static void cmd_window_prev(void)
{
	int num;

	num = window_refnum_prev(active_win->refnum, TRUE);
	if (num < 1) num = window_refnum_next(0, TRUE);

	window_set_active(window_find_refnum(num));
}

/* SYNTAX: WINDOW LEVEL [<level>] */
static void cmd_window_level(const char *data)
{
	char *level;

	g_return_if_fail(data != NULL);

	window_set_level(active_win, combine_level(active_win->level, data));

	level = active_win->level == 0 ? g_strdup("NONE") :
		bits2level(active_win->level);
	printtext(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
		  "Window level is now %s", level);
	g_free(level);
}

/* SYNTAX: WINDOW SERVER <tag> */
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
			    server->connrec->chatnet == NULL ? "" : server->connrec->chatnet);
	}
}

static void cmd_window_item(const char *data, void *server, WI_ITEM_REC *item)
{
	command_runsub("window item", data, server, item);
}

/* SYNTAX: WINDOW ITEM PREV */
static void cmd_window_item_prev(void)
{
	window_item_prev(active_win);
}

/* SYNTAX: WINDOW ITEM NEXT */
static void cmd_window_item_next(void)
{
	window_item_next(active_win);
}

/* SYNTAX: WINDOW NUMBER <number> */
static void cmd_window_number(const char *data)
{
	int num;

	num = atoi(data);
	if (num < 1)
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_REFNUM_TOO_LOW);
	else
		window_set_refnum(active_win, num);
}

/* SYNTAX: WINDOW NAME <name> */
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

	refnum = window_refnum_prev(active_win->refnum, TRUE);
	if (refnum != -1) {
		window_set_refnum(active_win, refnum);
		return;
	}

	windows_move_left(active_win);
}

static void cmd_window_move_right(void)
{
	int refnum;

	refnum = window_refnum_next(active_win->refnum, TRUE);
	if (refnum != -1) {
		window_set_refnum(active_win, refnum);
		return;
	}

        windows_move_right(active_win);
}

/* SYNTAX: WINDOW MOVE <number>|left|right */
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
			refnum = window_refnum_next(active_win->refnum, FALSE);
			if (refnum == -1 || refnum > new_refnum)
				break;

			window_set_refnum(active_win, refnum);
		}
	} else {
		for (;;) {
			refnum = window_refnum_prev(active_win->refnum, FALSE);
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

static GSList *windows_get_sorted(void)
{
	GSList *tmp, *list;

	list = NULL;
	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		list = g_slist_insert_sorted(list, tmp->data, (GCompareFunc) windows_compare);
	}

	return list;
}

/* SYNTAX: WINDOW LIST */
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

/* SYNTAX: WINDOW THEME <name> */
static void cmd_window_theme(const char *data)
{
	g_free_not_null(active_win->theme_name);
	active_win->theme_name = g_strdup(data);

	active_win->theme = theme_load(data);
	if (active_win->theme != NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
			    IRCTXT_WINDOW_THEME_CHANGED, data);
	} else {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
			    IRCTXT_THEME_NOT_FOUND, data);
	}
}

/* SYNTAX: SAVEWINDOWS */
static void cmd_savewindows(void)
{
	windows_save();
}

void window_commands_init(void)
{
	command_bind("window", NULL, (SIGNAL_FUNC) cmd_window);
	command_bind("window new", NULL, (SIGNAL_FUNC) cmd_window_new);
	command_bind("window close", NULL, (SIGNAL_FUNC) cmd_window_close);
	command_bind("window kill", NULL, (SIGNAL_FUNC) cmd_window_close);
	command_bind("window server", NULL, (SIGNAL_FUNC) cmd_window_server);
	command_bind("window refnum", NULL, (SIGNAL_FUNC) cmd_window_refnum);
	command_bind("window goto", NULL, (SIGNAL_FUNC) cmd_window_goto);
	command_bind("window prev", NULL, (SIGNAL_FUNC) cmd_window_prev);
	command_bind("window next", NULL, (SIGNAL_FUNC) cmd_window_next);
	command_bind("window last", NULL, (SIGNAL_FUNC) cmd_window_last);
	command_bind("window level", NULL, (SIGNAL_FUNC) cmd_window_level);
	command_bind("window item", NULL, (SIGNAL_FUNC) cmd_window_item);
	command_bind("window item prev", NULL, (SIGNAL_FUNC) cmd_window_item_prev);
	command_bind("window item next", NULL, (SIGNAL_FUNC) cmd_window_item_next);
	command_bind("window number", NULL, (SIGNAL_FUNC) cmd_window_number);
	command_bind("window name", NULL, (SIGNAL_FUNC) cmd_window_name);
	command_bind("window move", NULL, (SIGNAL_FUNC) cmd_window_move);
	command_bind("window move left", NULL, (SIGNAL_FUNC) cmd_window_move_left);
	command_bind("window move right", NULL, (SIGNAL_FUNC) cmd_window_move_right);
	command_bind("window list", NULL, (SIGNAL_FUNC) cmd_window_list);
	command_bind("window theme", NULL, (SIGNAL_FUNC) cmd_window_theme);
	command_bind("savewindows", NULL, (SIGNAL_FUNC) cmd_savewindows);
}

void window_commands_deinit(void)
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
	command_unbind("window last", (SIGNAL_FUNC) cmd_window_last);
	command_unbind("window level", (SIGNAL_FUNC) cmd_window_level);
	command_unbind("window item", (SIGNAL_FUNC) cmd_window_item);
	command_unbind("window item prev", (SIGNAL_FUNC) cmd_window_item_prev);
	command_unbind("window item next", (SIGNAL_FUNC) cmd_window_item_next);
	command_unbind("window number", (SIGNAL_FUNC) cmd_window_number);
	command_unbind("window name", (SIGNAL_FUNC) cmd_window_name);
	command_unbind("window move", (SIGNAL_FUNC) cmd_window_move);
	command_unbind("window move left", (SIGNAL_FUNC) cmd_window_move_left);
	command_unbind("window move right", (SIGNAL_FUNC) cmd_window_move_right);
	command_unbind("window list", (SIGNAL_FUNC) cmd_window_list);
	command_unbind("window theme", (SIGNAL_FUNC) cmd_window_theme);
	command_unbind("savewindows", (SIGNAL_FUNC) cmd_savewindows);
}
