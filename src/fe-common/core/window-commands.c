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
#include "windows-layout.h"
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

/* SYNTAX: WINDOW CLOSE [<first> [<last>] */
static void cmd_window_close(const char *data)
{
        GSList *tmp, *destroys;
	char *first, *last;
        int first_num, last_num;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 2, &first, &last))
		return;

	if ((*first != '\0' && !is_numeric(first, '\0')) ||
	    ((*last != '\0') && !is_numeric(last, '\0'))) {
		cmd_params_free(free_arg);
                return;
	}

	first_num = *first == '\0' ? active_win->refnum : atoi(first);
	last_num = *last == '\0' ? active_win->refnum : atoi(last);

        /* get list of windows to destroy */
        destroys = NULL;
	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		if (rec->refnum >= first_num && rec->refnum <= last_num)
			destroys = g_slist_append(destroys, rec);
	}

        /* really destroy the windows */
	while (destroys != NULL) {
		WINDOW_REC *rec = destroys->data;

		if (windows->next != NULL)
			window_destroy(rec);

                destroys = g_slist_remove(destroys, rec);
	}

	cmd_params_free(free_arg);
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

		if (rec->data_level > 0 && max_act < rec->data_level) {
			max_act = rec->data_level;
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
                window = window_find_item(active_win->active_server, data);

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

/* SYNTAX: WINDOW PREVIOUS */
static void cmd_window_previous(void)
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
	printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
			   TXT_WINDOW_LEVEL, level);
	g_free(level);
}

/* SYNTAX: WINDOW SERVER [-sticky | -unsticky] <tag> */
static void cmd_window_server(const char *data)
{
	GHashTable *optlist;
	SERVER_REC *server;
        char *tag;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS,
			    "window server", &optlist, &tag))
		return;

	if (*tag == '\0' &&
	    (g_hash_table_lookup(optlist, "sticky") != NULL ||
	     g_hash_table_lookup(optlist, "unsticky") != NULL)) {
		tag = active_win->active_server->tag;
	}

	if (*tag == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
	server = server_find_tag(tag);

	if (g_hash_table_lookup(optlist, "unsticky") != NULL &&
	    active_win->servertag != NULL) {
		g_free_and_null(active_win->servertag);
		printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
				   TXT_UNSET_SERVER_STICKY, server->tag);
	}

	if (active_win->servertag != NULL &&
	    g_hash_table_lookup(optlist, "sticky") == NULL) {
		printformat_window(active_win, MSGLEVEL_CLIENTERROR,
				   TXT_ERROR_SERVER_STICKY);
	} else if (server == NULL) {
		printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
				   TXT_UNKNOWN_SERVER_TAG, tag);
	} else if (active_win->active == NULL) {
		window_change_server(active_win, server);
		if (g_hash_table_lookup(optlist, "sticky") != NULL) {
                        g_free_not_null(active_win->servertag);
			active_win->servertag = g_strdup(server->tag);
			printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
					   TXT_SET_SERVER_STICKY, server->tag);
		}
		printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
				   TXT_SERVER_CHANGED,
				   server->tag, server->connrec->address,
				   server->connrec->chatnet == NULL ? "" :
				   server->connrec->chatnet);
	}

	cmd_params_free(free_arg);
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

/* SYNTAX: WINDOW ITEM GOTO <name> */
static void cmd_window_item_goto(const char *data, SERVER_REC *server)
{
        WI_ITEM_REC *item;

        item = window_item_find_window(active_win, server, data);
        if (item != NULL)
                window_item_set_active(active_win, item);
}

/* SYNTAX: WINDOW ITEM MOVE <number>|<name> */
static void cmd_window_item_move(const char *data, SERVER_REC *server,
                                 WI_ITEM_REC *item)
{
        WINDOW_REC *window;

        if (is_numeric(data, '\0')) {
                /* move current window item to specified window */
                window = window_find_refnum(atoi(data));
        } else {
                /* move specified window item to current window */
                item = window_item_find(server, data);
                window = active_win;
        }
        if (window != NULL && item != NULL)
                window_item_set_active(window, item);
}

/* SYNTAX: WINDOW NUMBER [-sticky] <number> */
static void cmd_window_number(const char *data)
{
	GHashTable *optlist;
        char *refnum;
	void *free_arg;
        int num;

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS,
			    "window number", &optlist, &refnum))
		return;

	if (*refnum == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	num = atoi(refnum);
	if (num < 1) {
		printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
				   TXT_REFNUM_TOO_LOW);
	} else {
		window_set_refnum(active_win, num);
		active_win->sticky_refnum =
			g_hash_table_lookup(optlist, "sticky") != NULL;
	}

        cmd_params_free(free_arg);
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

/* SYNTAX: WINDOW LIST */
static void cmd_window_list(void)
{
	GSList *tmp, *sorted;
	char *levelstr;

	sorted = windows_get_sorted();
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_WINDOWLIST_HEADER);
	for (tmp = sorted; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		levelstr = bits2level(rec->level);
		printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_WINDOWLIST_LINE,
			    rec->refnum, rec->name == NULL ? "" : rec->name,
			    rec->active == NULL ? "" : rec->active->name,
			    rec->active_server == NULL ? "" : ((SERVER_REC *) rec->active_server)->tag,
			    levelstr);
		g_free(levelstr);
	}
	g_slist_free(sorted);
        printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_WINDOWLIST_FOOTER);
}

/* SYNTAX: WINDOW THEME <name> */
static void cmd_window_theme(const char *data)
{
	THEME_REC *theme;

	g_free_not_null(active_win->theme_name);
	active_win->theme_name = g_strdup(data);

	active_win->theme = theme = theme_load(data);
	if (theme != NULL) {
		printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
				   TXT_WINDOW_THEME_CHANGED,
				   theme->name, theme->path);
	} else {
		printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
				   TXT_THEME_NOT_FOUND, data);
	}
}

static void cmd_layout(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	command_runsub("layout", data, server, item);
}

/* SYNTAX: FOREACH WINDOW <command> */
static void cmd_foreach_window(const char *data)
{
        WINDOW_REC *old;
	GSList *tmp;

        old = active_win;
	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

                active_win = rec;
		signal_emit("send command", 3, data, rec->active_server,
			    rec->active);
	}
        active_win = old;
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
	command_bind("window previous", NULL, (SIGNAL_FUNC) cmd_window_previous);
	command_bind("window next", NULL, (SIGNAL_FUNC) cmd_window_next);
	command_bind("window last", NULL, (SIGNAL_FUNC) cmd_window_last);
	command_bind("window level", NULL, (SIGNAL_FUNC) cmd_window_level);
	command_bind("window item", NULL, (SIGNAL_FUNC) cmd_window_item);
	command_bind("window item prev", NULL, (SIGNAL_FUNC) cmd_window_item_prev);
	command_bind("window item next", NULL, (SIGNAL_FUNC) cmd_window_item_next);
	command_bind("window item goto", NULL, (SIGNAL_FUNC) cmd_window_item_goto);
	command_bind("window item move", NULL, (SIGNAL_FUNC) cmd_window_item_move);
	command_bind("window number", NULL, (SIGNAL_FUNC) cmd_window_number);
	command_bind("window name", NULL, (SIGNAL_FUNC) cmd_window_name);
	command_bind("window move", NULL, (SIGNAL_FUNC) cmd_window_move);
	command_bind("window move left", NULL, (SIGNAL_FUNC) cmd_window_move_left);
	command_bind("window move right", NULL, (SIGNAL_FUNC) cmd_window_move_right);
	command_bind("window list", NULL, (SIGNAL_FUNC) cmd_window_list);
	command_bind("window theme", NULL, (SIGNAL_FUNC) cmd_window_theme);
	command_bind("layout", NULL, (SIGNAL_FUNC) cmd_layout);
	/* SYNTAX: LAYOUT SAVE */
	command_bind("layout save", NULL, (SIGNAL_FUNC) windows_layout_save);
	/* SYNTAX: LAYOUT RESET */
	command_bind("layout reset", NULL, (SIGNAL_FUNC) windows_layout_reset);
	command_bind("foreach window", NULL, (SIGNAL_FUNC) cmd_foreach_window);

	command_set_options("window number", "sticky");
	command_set_options("window server", "sticky unsticky");
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
	command_unbind("window previous", (SIGNAL_FUNC) cmd_window_previous);
	command_unbind("window next", (SIGNAL_FUNC) cmd_window_next);
	command_unbind("window last", (SIGNAL_FUNC) cmd_window_last);
	command_unbind("window level", (SIGNAL_FUNC) cmd_window_level);
	command_unbind("window item", (SIGNAL_FUNC) cmd_window_item);
	command_unbind("window item prev", (SIGNAL_FUNC) cmd_window_item_prev);
	command_unbind("window item next", (SIGNAL_FUNC) cmd_window_item_next);
	command_unbind("window item goto", (SIGNAL_FUNC) cmd_window_item_goto);
	command_unbind("window item move", (SIGNAL_FUNC) cmd_window_item_move);
	command_unbind("window number", (SIGNAL_FUNC) cmd_window_number);
	command_unbind("window name", (SIGNAL_FUNC) cmd_window_name);
	command_unbind("window move", (SIGNAL_FUNC) cmd_window_move);
	command_unbind("window move left", (SIGNAL_FUNC) cmd_window_move_left);
	command_unbind("window move right", (SIGNAL_FUNC) cmd_window_move_right);
	command_unbind("window list", (SIGNAL_FUNC) cmd_window_list);
	command_unbind("window theme", (SIGNAL_FUNC) cmd_window_theme);
	command_unbind("layout", (SIGNAL_FUNC) cmd_layout);
	command_unbind("layout save", (SIGNAL_FUNC) windows_layout_save);
	command_unbind("layout reset", (SIGNAL_FUNC) windows_layout_reset);
	command_unbind("foreach window", (SIGNAL_FUNC) cmd_foreach_window);
}
