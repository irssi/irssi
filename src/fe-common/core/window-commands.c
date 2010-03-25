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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include "module-formats.h"
#include "signals.h"
#include "commands.h"
#include "misc.h"
#include "servers.h"
#include "settings.h"

#include "levels.h"

#include "themes.h"
#include "fe-windows.h"
#include "window-items.h"
#include "windows-layout.h"
#include "printtext.h"

static void window_print_binds(WINDOW_REC *win)
{
	GSList *tmp;

	printformat_window(win, MSGLEVEL_CLIENTCRAP,
			   TXT_WINDOW_INFO_BOUND_ITEMS_HEADER);
	for (tmp = win->bound_items; tmp != NULL; tmp = tmp->next) {
		WINDOW_BIND_REC *bind = tmp->data;

		printformat_window(win, MSGLEVEL_CLIENTCRAP,
				   TXT_WINDOW_INFO_BOUND_ITEM,
				   bind->name, bind->servertag,
				   bind->sticky ? "sticky" : "");
	}
	printformat_window(win, MSGLEVEL_CLIENTCRAP,
			   TXT_WINDOW_INFO_BOUND_ITEMS_FOOTER);
}

static void window_print_items(WINDOW_REC *win)
{
	GSList *tmp;
        const char *type;

	printformat_window(win, MSGLEVEL_CLIENTCRAP,
			   TXT_WINDOW_INFO_ITEMS_HEADER);
	for (tmp = win->items; tmp != NULL; tmp = tmp->next) {
		WI_ITEM_REC *item = tmp->data;

		type = module_find_id_str("WINDOW ITEM TYPE", item->type);
		printformat_window(win, MSGLEVEL_CLIENTCRAP,
				   TXT_WINDOW_INFO_ITEM,
				   type == NULL ? "??" : type,
				   item->visible_name,
				   item->server == NULL ? "" :
				   item->server->tag);
	}
	printformat_window(win, MSGLEVEL_CLIENTCRAP,
			   TXT_WINDOW_INFO_ITEMS_FOOTER);
}

static void cmd_window_info(WINDOW_REC *win)
{
        char *levelstr;

	printformat_window(win, MSGLEVEL_CLIENTCRAP,
			   TXT_WINDOW_INFO_HEADER);

        /* Window reference number + sticky status */
	if (!win->sticky_refnum) {
		printformat_window(win, MSGLEVEL_CLIENTCRAP,
				   TXT_WINDOW_INFO_REFNUM, win->refnum);
	} else {
		printformat_window(win, MSGLEVEL_CLIENTCRAP,
				   TXT_WINDOW_INFO_REFNUM_STICKY, win->refnum);
	}

        /* Window name */
	if (win->name != NULL) {
		printformat_window(win, MSGLEVEL_CLIENTCRAP,
				   TXT_WINDOW_INFO_NAME, win->name);
	}

        /* Window width / height */
	printformat_window(win, MSGLEVEL_CLIENTCRAP, TXT_WINDOW_INFO_SIZE,
			   win->width, win->height);

	/* Window immortality */
	if (win->immortal) {
		printformat_window(win, MSGLEVEL_CLIENTCRAP,
				   TXT_WINDOW_INFO_IMMORTAL);
	}

	/* Window history name */
	if (win->history_name != NULL) {
		printformat_window(win, MSGLEVEL_CLIENTCRAP,
				   TXT_WINDOW_INFO_HISTORY, win->history_name);
	}

        /* Window level */
	levelstr = win->level == 0 ?
		g_strdup("NONE") : bits2level(win->level);
	printformat_window(win, MSGLEVEL_CLIENTCRAP, TXT_WINDOW_INFO_LEVEL,
			   levelstr);
	g_free(levelstr);

        /* Active window server + sticky status */
	if (win->servertag == NULL) {
		printformat_window(win, MSGLEVEL_CLIENTCRAP,
				   TXT_WINDOW_INFO_SERVER,
				   win->active_server != NULL ?
				   win->active_server->tag : "NONE");
	} else {
		if (win->active_server != NULL &&
		    strcmp(win->active_server->tag, win->servertag) != 0)
                        g_warning("Active server isn't the sticky server!");

		printformat_window(win, MSGLEVEL_CLIENTCRAP,
				   TXT_WINDOW_INFO_SERVER_STICKY,
				   win->servertag);
	}

        /* Window theme + error status */
	if (win->theme_name != NULL) {
		printformat_window(win, MSGLEVEL_CLIENTCRAP,
				   TXT_WINDOW_INFO_THEME, win->theme_name,
				   win->theme != NULL ? "" : "(not loaded)");
	}

        /* Bound items in window */
	if (win->bound_items != NULL)
                window_print_binds(win);

        /* Item */
	if (win->items != NULL)
                window_print_items(win);

        signal_emit("window print info", 1, win);

	printformat_window(win, MSGLEVEL_CLIENTCRAP,
			   TXT_WINDOW_INFO_FOOTER);
}

static void cmd_window(const char *data, void *server, WI_ITEM_REC *item)
{
        while (*data == ' ') data++;

	if (*data == '\0')
                cmd_window_info(active_win);
	else if (is_numeric(data, 0))
                signal_emit("command window refnum", 3, data, server, item);
        else
		command_runsub("window", data, server, item);
}

/* SYNTAX: WINDOW NEW [HIDDEN|SPLIT] */
static void cmd_window_new(const char *data, void *server, WI_ITEM_REC *item)
{
	WINDOW_REC *window;
	int type;

	g_return_if_fail(data != NULL);

	type = (g_ascii_strncasecmp(data, "hid", 3) == 0 || g_ascii_strcasecmp(data, "tab") == 0) ? 1 :
		(g_ascii_strcasecmp(data, "split") == 0 ? 2 : 0);
	signal_emit("gui window create override", 1, GINT_TO_POINTER(type));

	window = window_create(NULL, FALSE);
	window_change_server(window, server);
}

/* SYNTAX: WINDOW CLOSE [<first> [<last>]] */
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
	last_num = *last == '\0' ? first_num : atoi(last);

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

		if (windows->next != NULL) {
			if (!rec->immortal)
				window_destroy(rec);
			else {
				printformat_window(rec, MSGLEVEL_CLIENTERROR,
						   TXT_WINDOW_IMMORTAL_ERROR);
			}
		}

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

/**
 * return the window with the highest activity
 *
 * If ignore_refnum is true, the most recently active window with the highest
 * activity will be returned. If ignore_refnum is false, the refnum will be used
 * to break ties between windows with equally high activity.
 */
static WINDOW_REC *window_highest_activity(WINDOW_REC *window,
                                           int ignore_refnum)
{
	WINDOW_REC *rec, *max_win;
	GSList *tmp;
	int max_act, max_ref, through;

	g_return_val_if_fail(window != NULL, NULL);

	max_win = NULL; max_act = 0; max_ref = 0; through = FALSE;

	tmp = g_slist_find(windows, window);
	for (;; tmp = tmp->next) {
		if (tmp == NULL) {
			tmp = windows;
			through = TRUE;
		}

		if (through && tmp->data == window)
			break;

		rec = tmp->data;

		/* ignore refnum */
		if (ignore_refnum &&
		    rec->data_level > 0 && max_act < rec->data_level) {
			max_act = rec->data_level;
			max_win = rec;
		}

		/* windows with lower refnums break ties */
		else if (!ignore_refnum &&
		         rec->data_level > 0 &&
		         (rec->data_level > max_act ||
		          (rec->data_level == max_act && rec->refnum < max_ref))) {
			max_act = rec->data_level;
			max_win = rec;
			max_ref = rec->refnum;
		}
	}

	return max_win;
}

static inline int is_nearer(int r1, int r2)
{
	int a = r2 < active_win->refnum;
	int b = r1 < r2;

	if (r1 > active_win->refnum)
		return a || b;
	else
		return a && b;
}

static WINDOW_REC *window_find_item_cycle(SERVER_REC *server, const char *name)
{
	WINDOW_REC *rec, *win;
	GSList *tmp;

	win = NULL;

	tmp = g_slist_find(windows, active_win);
	tmp = tmp->next;
	for (;; tmp = tmp->next) {
		if (tmp == NULL)
			tmp = windows;

		if (tmp->data == active_win)
			break;

		rec = tmp->data;

		if (window_item_find_window(rec, server, name) != NULL &&
		    (win == NULL || is_nearer(rec->refnum, win->refnum))) {
			win = rec;
			if (server != NULL) break;
		}
	}

	return win;
}

/* SYNTAX: WINDOW GOTO active|<number>|<name> */
static void cmd_window_goto(const char *data)
{
	WINDOW_REC *window;
	char *target;
	void *free_arg;

	g_return_if_fail(data != NULL);

	if (is_numeric(data, 0)) {
		cmd_window_refnum(data);
		return;
	}

	if (!cmd_get_params(data, &free_arg, 1, &target))
		return;

	if (g_ascii_strcasecmp(target, "active") == 0)
		window = window_highest_activity(active_win,
			settings_get_bool("active_window_ignore_refnum"));
	else {
		window = window_find_name(target);
		if (window == NULL && active_win->active_server != NULL)
			window = window_find_item_cycle(active_win->active_server, target);
		if (window == NULL)
			window = window_find_item_cycle(NULL, target);
	}

	if (window != NULL)
		window_set_active(window);

	cmd_params_free(free_arg);
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

/* SYNTAX: WINDOW IMMORTAL on|off|toggle */
static void cmd_window_immortal(const char *data)
{
	int set;

	if (*data == '\0')
		set = active_win->immortal;
	else if (g_ascii_strcasecmp(data, "ON") == 0)
                set = TRUE;
	else if (g_ascii_strcasecmp(data, "OFF") == 0)
                set = FALSE;
	else if (g_ascii_strcasecmp(data, "TOGGLE") == 0)
                set = !active_win->immortal;
	else {
		printformat_window(active_win, MSGLEVEL_CLIENTERROR,
				   TXT_NOT_TOGGLE);
		return;
	}

	if (set) {
                window_set_immortal(active_win, TRUE);
		printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
				   TXT_WINDOW_SET_IMMORTAL);
	} else {
                window_set_immortal(active_win, FALSE);
		printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
				   TXT_WINDOW_UNSET_IMMORTAL);
	}
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

	if (*tag == '\0' && active_win->active_server != NULL &&
	    (g_hash_table_lookup(optlist, "sticky") != NULL ||
	     g_hash_table_lookup(optlist, "unsticky") != NULL)) {
		tag = active_win->active_server->tag;
	}

	if (*tag == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
	server = server_find_tag(tag);
	if (server == NULL)
		server = server_find_lookup_tag(tag);

	if (g_hash_table_lookup(optlist, "unsticky") != NULL &&
	    active_win->servertag != NULL) {
		g_free_and_null(active_win->servertag);
		printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
				   TXT_UNSET_SERVER_STICKY);
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
        while (*data == ' ') data++;

	if (is_numeric(data, '\0'))
		signal_emit("command window item goto", 3, data, server, item);
	else
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

/* SYNTAX: WINDOW ITEM GOTO <number>|<name> */
static void cmd_window_item_goto(const char *data, SERVER_REC *server)
{
	WI_ITEM_REC *item;
	GSList *tmp;
	void *free_arg;
	char *target;
	
	if (!cmd_get_params(data, &free_arg, 1, &target))
		return;

	if (is_numeric(target, '\0')) {
		/* change to specified number */
		tmp = g_slist_nth(active_win->items, atoi(target)-1);
		item = tmp == NULL ? NULL : tmp->data;
	} else {
		item = window_item_find_window(active_win, server, target);
	}

        if (item != NULL)
                window_item_set_active(active_win, item);

	cmd_params_free(free_arg);
}

/* SYNTAX: WINDOW ITEM MOVE <number>|<name> */
static void cmd_window_item_move(const char *data, SERVER_REC *server,
                                 WI_ITEM_REC *item)
{
	WINDOW_REC *window;
	void *free_arg;
	char *target;

	if (!cmd_get_params(data, &free_arg, 1, &target))
		return;

        if (is_numeric(target, '\0')) {
                /* move current window item to specified window */
                window = window_find_refnum(atoi(target));
        } else {
                /* move specified window item to current window */
                item = window_item_find(server, target);
                window = active_win;
        }
        if (window != NULL && item != NULL)
		window_item_set_active(window, item);

	cmd_params_free(free_arg);
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
	WINDOW_REC *win;

	win = window_find_name(data);
	if (win == NULL || win == active_win)
		window_set_name(active_win, data);
	else if (active_win->name == NULL ||
		 strcmp(active_win->name, data) != 0) {
		printformat_window(active_win, MSGLEVEL_CLIENTERROR,
				   TXT_WINDOW_NAME_NOT_UNIQUE, data);
	}
}

/* SYNTAX: WINDOW HISTORY <name> */
void cmd_window_history(const char *data)
{
	window_set_history(active_win, data);
}

/* we're moving the first window to last - move the first contiguous block
   of refnums to left. Like if there's windows 1..5 and 7..10, move 1 to
   11, 2..5 to 1..4 and leave 7..10 alone */
static void window_refnums_move_left(WINDOW_REC *move_window)
{
	WINDOW_REC *window;
	int refnum, new_refnum;

        new_refnum = windows_refnum_last();
	for (refnum = move_window->refnum+1; refnum <= new_refnum; refnum++) {
		window = window_find_refnum(refnum);
		if (window == NULL) {
                        new_refnum++;
			break;
		}

		window_set_refnum(window, refnum-1);
	}

	window_set_refnum(move_window, new_refnum);
}

/* we're moving the last window to first - make some space so we can use the
   refnum 1 */
static void window_refnums_move_right(WINDOW_REC *move_window)
{
	WINDOW_REC *window;
	int refnum, new_refnum;

        new_refnum = 1;
	if (window_find_refnum(new_refnum) == NULL) {
		window_set_refnum(move_window, new_refnum);
                return;
	}

	/* find the first unused refnum, like if there's windows
	   1..5 and 7..10, we only need to move 1..5 to 2..6 */
	refnum = new_refnum;
	while (move_window->refnum == refnum ||
	       window_find_refnum(refnum) != NULL) refnum++;
	refnum--;

	while (refnum >= new_refnum) {
		window = window_find_refnum(refnum);
		window_set_refnum(window, refnum+1);

		refnum--;
	}

	window_set_refnum(move_window, new_refnum);
}

/* SYNTAX: WINDOW MOVE PREV */
static void cmd_window_move_prev(void)
{
	int refnum;

	refnum = window_refnum_prev(active_win->refnum, FALSE);
	if (refnum != -1) {
		window_set_refnum(active_win, refnum);
		return;
	}

	window_refnums_move_left(active_win);
}

/* SYNTAX: WINDOW MOVE NEXT */
static void cmd_window_move_next(void)
{
	int refnum;

	refnum = window_refnum_next(active_win->refnum, FALSE);
	if (refnum != -1) {
		window_set_refnum(active_win, refnum);
		return;
	}

        window_refnums_move_right(active_win);
}

static void active_window_move_to(int new_refnum)
{
	int refnum;

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

/* SYNTAX: WINDOW MOVE FIRST */
static void cmd_window_move_first(void)
{
	active_window_move_to(1);
}

/* SYNTAX: WINDOW MOVE LAST */
static void cmd_window_move_last(void)
{
	active_window_move_to(windows_refnum_last());
}

/* SYNTAX: WINDOW MOVE <number>|<direction> */
static void cmd_window_move(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	if (!is_numeric(data, 0)) {
		command_runsub("window move", data, server, item);
                return;
	}

	active_window_move_to(atoi(data));
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
			    rec->active == NULL ? "" : rec->active->visible_name,
			    rec->active_server == NULL ? "" : ((SERVER_REC *) rec->active_server)->tag,
			    levelstr);
		g_free(levelstr);
	}
	g_slist_free(sorted);
        printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_WINDOWLIST_FOOTER);
}

/* SYNTAX: WINDOW THEME [-delete] [<name>] */
static void cmd_window_theme(const char *data)
{
	THEME_REC *theme;
	GHashTable *optlist;
        char *name;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS,
			    "window theme", &optlist, &name))
		return;

	if (g_hash_table_lookup(optlist, "delete") != NULL) {
		g_free_and_null(active_win->theme_name);

		printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
				   TXT_WINDOW_THEME_REMOVED);
	} else if (*name == '\0') {
		if (active_win->theme == NULL) {
			printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
					   TXT_WINDOW_THEME_DEFAULT);
		} else {
                        theme = active_win->theme;
			printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
					   TXT_WINDOW_THEME,
					   theme->name, theme->path);
		}
	} else {
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

	cmd_params_free(free_arg);
}

static void cmd_layout(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	command_runsub("layout", data, server, item);
}

/* SYNTAX: FOREACH WINDOW <command> */
static void cmd_foreach_window(const char *data)
{
        WINDOW_REC *old;
        GSList *list;

        old = active_win;

	list = g_slist_copy(windows);
	while (list != NULL) {
		WINDOW_REC *rec = list->data;

		active_win = rec;
		signal_emit("send command", 3, data, rec->active_server,
			    rec->active);
                list = g_slist_remove(list, list->data);
	}

	if (g_slist_find(windows, old) != NULL)
		active_win = old;
}

void window_commands_init(void)
{
	settings_add_bool("lookandfeel", "active_window_ignore_refnum", TRUE);

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
	command_bind("window immortal", NULL, (SIGNAL_FUNC) cmd_window_immortal);
	command_bind("window item", NULL, (SIGNAL_FUNC) cmd_window_item);
	command_bind("window item prev", NULL, (SIGNAL_FUNC) cmd_window_item_prev);
	command_bind("window item next", NULL, (SIGNAL_FUNC) cmd_window_item_next);
	command_bind("window item goto", NULL, (SIGNAL_FUNC) cmd_window_item_goto);
	command_bind("window item move", NULL, (SIGNAL_FUNC) cmd_window_item_move);
	command_bind("window number", NULL, (SIGNAL_FUNC) cmd_window_number);
	command_bind("window name", NULL, (SIGNAL_FUNC) cmd_window_name);
	command_bind("window history", NULL, (SIGNAL_FUNC) cmd_window_history);
	command_bind("window move", NULL, (SIGNAL_FUNC) cmd_window_move);
	command_bind("window move prev", NULL, (SIGNAL_FUNC) cmd_window_move_prev);
	command_bind("window move next", NULL, (SIGNAL_FUNC) cmd_window_move_next);
	command_bind("window move first", NULL, (SIGNAL_FUNC) cmd_window_move_first);
	command_bind("window move last", NULL, (SIGNAL_FUNC) cmd_window_move_last);
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
	command_set_options("window theme", "delete");
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
	command_unbind("window immortal", (SIGNAL_FUNC) cmd_window_immortal);
	command_unbind("window item", (SIGNAL_FUNC) cmd_window_item);
	command_unbind("window item prev", (SIGNAL_FUNC) cmd_window_item_prev);
	command_unbind("window item next", (SIGNAL_FUNC) cmd_window_item_next);
	command_unbind("window item goto", (SIGNAL_FUNC) cmd_window_item_goto);
	command_unbind("window item move", (SIGNAL_FUNC) cmd_window_item_move);
	command_unbind("window number", (SIGNAL_FUNC) cmd_window_number);
	command_unbind("window name", (SIGNAL_FUNC) cmd_window_name);
	command_unbind("window history", (SIGNAL_FUNC) cmd_window_history);
	command_unbind("window move", (SIGNAL_FUNC) cmd_window_move);
	command_unbind("window move prev", (SIGNAL_FUNC) cmd_window_move_prev);
	command_unbind("window move next", (SIGNAL_FUNC) cmd_window_move_next);
	command_unbind("window move first", (SIGNAL_FUNC) cmd_window_move_first);
	command_unbind("window move last", (SIGNAL_FUNC) cmd_window_move_last);
	command_unbind("window list", (SIGNAL_FUNC) cmd_window_list);
	command_unbind("window theme", (SIGNAL_FUNC) cmd_window_theme);
	command_unbind("layout", (SIGNAL_FUNC) cmd_layout);
	command_unbind("layout save", (SIGNAL_FUNC) windows_layout_save);
	command_unbind("layout reset", (SIGNAL_FUNC) windows_layout_reset);
	command_unbind("foreach window", (SIGNAL_FUNC) cmd_foreach_window);
}
