/*
 mainwindows.c : irssi

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
#include "signals.h"
#include "commands.h"
#include "levels.h"
#include "misc.h"
#include "printtext.h"

#include "screen.h"
#include "statusbar.h"
#include "gui-windows.h"

#define WINDOW_MIN_SIZE 2
#define NEW_WINDOW_SIZE (WINDOW_MIN_SIZE + 1)

GSList *mainwindows;
MAIN_WINDOW_REC *active_mainwin;

static int reserved_up, reserved_down;

static MAIN_WINDOW_REC *find_window_with_room(void)
{
	MAIN_WINDOW_REC *biggest_rec;
	GSList *tmp;
	int space, biggest;

	biggest = 0; biggest_rec = NULL;
	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		space = rec->lines;
		if (space >= WINDOW_MIN_SIZE+NEW_WINDOW_SIZE && space > biggest) {
			biggest = space;
			biggest_rec = rec;
		}
	}

	return biggest_rec;
}

#ifdef USE_CURSES_WINDOWS
static void create_curses_window(MAIN_WINDOW_REC *window)
{
	window->curses_win = newwin(window->lines, COLS, window->first_line, 0);
        idlok(window->curses_win, 1);
}
#endif

static void mainwindow_resize(MAIN_WINDOW_REC *window, int ychange, int xchange)
{
	GSList *tmp;

	if (ychange == 0 && !xchange) return;

	window->lines = window->last_line-window->first_line+1;
#ifdef USE_CURSES_WINDOWS
#ifdef HAVE_CURSES_WRESIZE
	wresize(window->curses_win, window->lines, COLS);
	mvwin(window->curses_win, window->first_line, 0);
#else
	delwin(window->curses_win);
	create_curses_window(window);
#endif
#endif

	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		if (rec->gui_data != NULL &&
		    WINDOW_GUI(rec)->parent == window)
			gui_window_resize(rec, ychange, xchange);
	}

	gui_window_redraw(window->active);
	signal_emit("mainwindow resized", 1, window);
}

void mainwindows_recreate(void)
{
	GSList *tmp;

	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

#ifdef USE_CURSES_WINDOWS
		create_curses_window(rec);
#endif
		gui_window_redraw(rec->active);
	}
}

MAIN_WINDOW_REC *mainwindow_create(void)
{
	MAIN_WINDOW_REC *rec, *parent;
	int space;

	rec = g_new0(MAIN_WINDOW_REC, 1);
	rec->statusbar_lines = 1;

	if (mainwindows == NULL) {
		active_mainwin = rec;

		rec->first_line = reserved_up;
		rec->last_line = LINES-1-reserved_down-rec->statusbar_lines;
		rec->lines = rec->last_line-rec->first_line+1;
	} else {
		parent = WINDOW_GUI(active_win)->parent;
		if (parent->lines < WINDOW_MIN_SIZE+NEW_WINDOW_SIZE)
			parent = find_window_with_room();
		if (parent == NULL)
			return NULL; /* not enough space */

		space = (parent->lines-parent->statusbar_lines)/2;
		rec->first_line = parent->first_line;
		rec->last_line = rec->first_line + space-rec->statusbar_lines;
		rec->lines = rec->last_line-rec->first_line+1;
		parent->first_line = rec->last_line+1+rec->statusbar_lines;
		parent->lines = parent->last_line-parent->first_line+1;

		mainwindow_resize(parent, -space-1, FALSE);
	}

#ifdef USE_CURSES_WINDOWS
	rec->curses_win = newwin(rec->lines, COLS, rec->first_line, 0);
	refresh();
#endif

	mainwindows = g_slist_append(mainwindows, rec);
	signal_emit("mainwindow created", 1, rec);
	return rec;
}

static MAIN_WINDOW_REC *mainwindows_find_lower(int line)
{
	MAIN_WINDOW_REC *best;
	GSList *tmp;

	best = NULL;
	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		if (rec->first_line > line &&
		    (best == NULL || rec->first_line < best->first_line))
			best = rec;
	}

	return best;
}

static MAIN_WINDOW_REC *mainwindows_find_upper(int line)
{
	MAIN_WINDOW_REC *best;
	GSList *tmp;

	best = NULL;
	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		if (rec->last_line < line &&
		    (best == NULL || rec->last_line > best->last_line))
			best = rec;
	}

	return best;
}

static void mainwindows_add_space(int first_line, int last_line)
{
	MAIN_WINDOW_REC *rec;
	int size;

	if (last_line < first_line)
		return;

	size = last_line-first_line+1;

	rec = mainwindows_find_lower(last_line);
	if (rec != NULL) {
		rec->first_line = first_line;
		mainwindow_resize(rec, size, FALSE);
		return;
	}

	rec = mainwindows_find_upper(first_line);
	if (rec != NULL) {
		rec->last_line = last_line-rec->statusbar_lines;
		mainwindow_resize(rec, size, FALSE);
	}
}

static void gui_windows_remove_parent(MAIN_WINDOW_REC *window)
{
        MAIN_WINDOW_REC *new_parent;
	GSList *tmp;

        new_parent = mainwindows->data;
	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		if (rec->gui_data != NULL && WINDOW_GUI(rec)->parent == window)
                        gui_window_reparent(rec, new_parent);
	}
}

void mainwindow_destroy(MAIN_WINDOW_REC *window)
{
	g_return_if_fail(window != NULL);

#ifdef USE_CURSES_WINDOWS
	delwin(window->curses_win);
#endif

	mainwindows = g_slist_remove(mainwindows, window);
	signal_emit("mainwindow destroyed", 1, window);

	if (!quitting && mainwindows != NULL) {
		gui_windows_remove_parent(window);
		mainwindows_add_space(window->first_line, window->last_line+window->statusbar_lines);

		mainwindows_redraw();
		statusbar_redraw(NULL);
	}
	g_free(window);

	if (active_mainwin == window) active_mainwin = NULL;
}

void mainwindows_redraw(void)
{
        GSList *tmp;

	screen_refresh_freeze();
	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

                gui_window_redraw(rec->active);
	}
	screen_refresh_thaw();
}

static int mainwindows_compare(MAIN_WINDOW_REC *w1, MAIN_WINDOW_REC *w2)
{
	return w1->first_line < w2->first_line ? -1 : 1;
}

static int mainwindows_compare_reverse(MAIN_WINDOW_REC *w1, MAIN_WINDOW_REC *w2)
{
	return w1->first_line < w2->first_line ? 1 : -1;
}

static GSList *mainwindows_get_sorted(int reverse)
{
	GSList *tmp, *list;

	list = NULL;
	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		list = g_slist_insert_sorted(list, tmp->data, (GCompareFunc)
					     (reverse ? mainwindows_compare_reverse : mainwindows_compare));
	}

	return list;
}

static void mainwindows_resize_too_small(int ychange, int xchange)
{
	GSList *sorted, *tmp;
        int space, moved;

	/* terminal is too small - just take the space whereever possible */
	sorted = mainwindows_get_sorted(FALSE);
	moved = 0;
	for (tmp = sorted; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		space = rec->lines;
		if (ychange == 0 || space <= 0) {
			if (moved > 0) {
				rec->first_line -= moved;
				rec->last_line -= moved;
				signal_emit("mainwindow moved", 1, rec);
			}
			continue;
		}

		if (space > -ychange) space = -ychange;
		ychange += space;
		rec->first_line -= moved;
		moved += space;
		rec->last_line -= space;
		mainwindow_resize(rec, -space, xchange);
	}
	g_slist_free(sorted);
}

static void mainwindows_resize_smaller(int ychange, int xchange)
{
	GSList *sorted, *tmp;
        int space;

        space = 0;
	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		space += rec->lines-WINDOW_MIN_SIZE;
	}

	if (space < -ychange) {
		/* not enough space, use different algorithm */
		mainwindows_resize_too_small(ychange, xchange);
		return;
	}

	/* resize windows that have space */
	sorted = mainwindows_get_sorted(TRUE);
	for (tmp = sorted; tmp != NULL && ychange < 0; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		space = rec->lines-WINDOW_MIN_SIZE;
		if (space <= 0) {
			rec->first_line += ychange;
			rec->last_line += ychange;
			signal_emit("mainwindow moved", 1, rec);
			continue;
		}

		if (space <= 0) space = 1;
		if (space > -ychange) space = -ychange;
		rec->last_line += ychange;
		ychange += space;
		rec->first_line += ychange;

		mainwindow_resize(rec, -space, xchange);
	}
	g_slist_free(sorted);
}

static void mainwindows_resize_bigger(int ychange, int xchange)
{
	GSList *sorted, *tmp;
        int moved, space;

	sorted = mainwindows_get_sorted(FALSE);
	moved = 0;
	for (tmp = sorted; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		space = rec->lines-WINDOW_MIN_SIZE;
		if (ychange == 0 || (space >= 0 && tmp->next != NULL)) {
			if (moved > 0) {
				rec->first_line += moved;
				rec->last_line += moved;
				signal_emit("mainwindow moved", 1, rec);
			}
			continue;
		}

		if (space < 0 && tmp->next != NULL) {
                        /* space below minimum */
			space = -space;
			if (space > ychange) space = ychange;
		} else {
			/* lowest window - give all the extra space for it */
			space = ychange;
		}
		ychange -= space;
		rec->first_line += moved;
                moved += space;
		rec->last_line += moved;

		mainwindow_resize(rec, space, xchange);
	}
	g_slist_free(sorted);
}

void mainwindows_resize_horiz(int xchange)
{
	GSList *tmp;

	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		mainwindow_resize(rec, 0, xchange);
	}
}

void mainwindows_resize(int ychange, int xchange)
{
	screen_refresh_freeze();
	if (ychange < 0)
		mainwindows_resize_smaller(ychange, xchange);
	else if (ychange > 0)
		mainwindows_resize_bigger(ychange, xchange);
	else if (xchange != 0)
		mainwindows_resize_horiz(xchange);

	irssi_redraw();
	screen_refresh_thaw();
}

int mainwindows_reserve_lines(int count, int up)
{
	MAIN_WINDOW_REC *window;
	int ret;

	if (up) {
		g_return_val_if_fail(count > 0 || reserved_up > count, -1);

		ret = reserved_up;
		reserved_up += count;

		window = mainwindows_find_lower(-1);
		if (window != NULL) window->first_line += count;
	} else {
		g_return_val_if_fail(count > 0 || reserved_down > count, -1);

		ret = reserved_down;
		reserved_down += count;

		window = mainwindows_find_upper(LINES);
		if (window != NULL) window->last_line -= count;
	}

	if (window != NULL)
		mainwindow_resize(window, -count, FALSE);

	return ret;
}

static void mainwindows_resize_two(MAIN_WINDOW_REC *grow_win,
				   MAIN_WINDOW_REC *shrink_win, int count)
{
	mainwindow_resize(grow_win, count, FALSE);
	mainwindow_resize(shrink_win, -count, FALSE);
	gui_window_redraw(grow_win->active);
	gui_window_redraw(shrink_win->active);
	statusbar_redraw(grow_win->statusbar);
	statusbar_redraw(shrink_win->statusbar);
}

/* SYNTAX: WINDOW GROW [<lines>] */
static void cmd_window_grow(const char *data)
{
	MAIN_WINDOW_REC *window, *shrink_win;
	int count;

	count = *data == '\0' ? 1 : atoi(data);
	window = WINDOW_GUI(active_win)->parent;

	/* shrink lower window */
	shrink_win = mainwindows_find_lower(window->last_line);
	if (shrink_win != NULL && shrink_win->lines-count >= WINDOW_MIN_SIZE) {
                window->last_line += count;
		shrink_win->first_line += count;
	} else {
		/* shrink upper window */
		shrink_win = mainwindows_find_upper(window->first_line);
		if (shrink_win != NULL && shrink_win->lines-count >= WINDOW_MIN_SIZE) {
			window->first_line -= count;
			shrink_win->last_line -= count;
		} else {
			printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_WINDOW_TOO_SMALL);
			return;
		}
	}

	mainwindows_resize_two(window, shrink_win, count);
}

/* SYNTAX: WINDOW SHRINK [<lines>] */
static void cmd_window_shrink(const char *data)
{
	MAIN_WINDOW_REC *window, *grow_win;
	int count;

	count = *data == '\0' ? 1 : atoi(data);

	window = WINDOW_GUI(active_win)->parent;
	if (window->lines-count < WINDOW_MIN_SIZE) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_WINDOW_TOO_SMALL);
                return;
	}

	grow_win = mainwindows_find_lower(window->last_line);
	if (grow_win != NULL) {
                window->last_line -= count;
		grow_win->first_line -= count;
	} else {
		grow_win = mainwindows_find_upper(window->first_line);
		if (grow_win == NULL) return;

		window->first_line += count;
		grow_win->last_line += count;
	}

	mainwindows_resize_two(grow_win, window, count);
}

/* SYNTAX: WINDOW SIZE <lines> */
static void cmd_window_size(const char *data)
{
        char sizestr[MAX_INT_STRLEN];
	int size;

	if (!is_numeric(data, 0)) return;
	size = atoi(data);

	size -= WINDOW_GUI(active_win)->parent->lines;
	if (size == 0) return;

	ltoa(sizestr, size < 0 ? -size : size);
	if (size < 0)
		cmd_window_shrink(sizestr);
	else
		cmd_window_grow(sizestr);
}

/* SYNTAX: WINDOW BALANCE */
static void cmd_window_balance(void)
{
	GSList *sorted, *tmp;
	int avail_size, unit_size, bigger_units;
	int windows, last_line, old_size;

	windows = g_slist_length(mainwindows);
	if (windows == 1) return;

	avail_size = LINES-reserved_up-reserved_down;
	unit_size = avail_size/windows;
	bigger_units = avail_size%windows;

	sorted = mainwindows_get_sorted(FALSE);
        last_line = 0;
	for (tmp = sorted; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		old_size = rec->lines;
		rec->first_line = last_line+1;
		rec->last_line = rec->first_line-1 + unit_size -
			rec->statusbar_lines;
		rec->lines = rec->last_line-rec->first_line+1;

		if (bigger_units > 0) {
			rec->last_line++;
                        bigger_units--;
		}
		last_line = rec->last_line + rec->statusbar_lines;

		mainwindow_resize(rec, rec->lines-old_size, FALSE);
	}
	g_slist_free(sorted);

	mainwindows_redraw();
	statusbar_redraw(NULL);
}

/* SYNTAX: WINDOW HIDE [<number>|<name>] */
static void cmd_window_hide(const char *data)
{
	WINDOW_REC *window;

	if (mainwindows->next == NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_CANT_HIDE_LAST);
		return;
	}

	if (*data == '\0')
		window = active_win;
	else if (is_numeric(data, 0))
		window = window_find_refnum(atoi(data));
	else
		window = window_find_item(active_win->active_server, data);

	if (window == NULL) return;
	if (!is_window_visible(window)) return;

	mainwindow_destroy(WINDOW_GUI(window)->parent);

	if (active_mainwin == NULL) {
		active_mainwin = WINDOW_GUI(active_win)->parent;
                window_set_active(active_mainwin->active);
	}
}

/* SYNTAX: WINDOW SHOW <number>|<name> */
static void cmd_window_show(const char *data)
{
	WINDOW_REC *window;

	if (*data == '\0') cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

	window = is_numeric(data, 0) ?
		window_find_refnum(atoi(data)) :
		window_find_item(active_win->active_server, data);

	if (window == NULL) return;
	if (is_window_visible(window)) return;

	WINDOW_GUI(window)->parent = mainwindow_create();
	WINDOW_GUI(window)->parent->active = window;

	active_mainwin = NULL;
	window_set_active(window);
}

/* SYNTAX: WINDOW UP */
static void cmd_window_up(void)
{
	MAIN_WINDOW_REC *rec;

	rec = mainwindows_find_upper(active_mainwin->first_line);
	if (rec != NULL)
		window_set_active(rec->active);
}

/* SYNTAX: WINDOW DOWN */
static void cmd_window_down(void)
{
	MAIN_WINDOW_REC *rec;

	rec = mainwindows_find_lower(active_mainwin->last_line);
	if (rec != NULL)
		window_set_active(rec->active);
}

void mainwindows_init(void)
{
	mainwindows = NULL;
	active_mainwin = NULL;
	reserved_up = reserved_down = 0;

	/* for entry line */
	mainwindows_reserve_lines(1, FALSE);

	command_bind("window grow", NULL, (SIGNAL_FUNC) cmd_window_grow);
	command_bind("window shrink", NULL, (SIGNAL_FUNC) cmd_window_shrink);
	command_bind("window size", NULL, (SIGNAL_FUNC) cmd_window_size);
	command_bind("window balance", NULL, (SIGNAL_FUNC) cmd_window_balance);
	command_bind("window hide", NULL, (SIGNAL_FUNC) cmd_window_hide);
	command_bind("window show", NULL, (SIGNAL_FUNC) cmd_window_show);
	command_bind("window up", NULL, (SIGNAL_FUNC) cmd_window_up);
	command_bind("window down", NULL, (SIGNAL_FUNC) cmd_window_down);
}

void mainwindows_deinit(void)
{
	while (mainwindows != NULL)
		mainwindow_destroy(mainwindows->data);

	command_unbind("window grow", (SIGNAL_FUNC) cmd_window_grow);
	command_unbind("window shrink", (SIGNAL_FUNC) cmd_window_shrink);
	command_unbind("window size", (SIGNAL_FUNC) cmd_window_size);
	command_unbind("window balance", (SIGNAL_FUNC) cmd_window_balance);
	command_unbind("window hide", (SIGNAL_FUNC) cmd_window_hide);
	command_unbind("window show", (SIGNAL_FUNC) cmd_window_show);
	command_unbind("window up", (SIGNAL_FUNC) cmd_window_up);
	command_unbind("window down", (SIGNAL_FUNC) cmd_window_down);
}
