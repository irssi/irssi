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
#include "settings.h"
#include "printtext.h"

#include "screen.h"
#include "statusbar.h"
#include "gui-windows.h"

#define NEW_WINDOW_SIZE (WINDOW_MIN_SIZE + 1)

GSList *mainwindows;
MAIN_WINDOW_REC *active_mainwin;

static int reserved_up, reserved_down;
static int screen_width, screen_height;

static MAIN_WINDOW_REC *find_window_with_room(void)
{
	MAIN_WINDOW_REC *biggest_rec;
	GSList *tmp;
	int space, biggest;

	biggest = 0; biggest_rec = NULL;
	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		space = rec->height;
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
	window->curses_win = newwin(window->height, window->width,
				    window->first_line, 0);
        idlok(window->curses_win, 1);
}
#endif

static void mainwindow_resize(MAIN_WINDOW_REC *window, int xdiff, int ydiff)
{
	GSList *tmp;

	if (xdiff == 0 && ydiff == 0)
                return;

        window->width += xdiff;
	window->height = window->last_line-window->first_line+1;
#ifdef USE_CURSES_WINDOWS
#ifdef HAVE_CURSES_WRESIZE
	wresize(window->curses_win, window->height, window->width);
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
			gui_window_resize(rec, window->width, window->height);
	}

	textbuffer_view_set_window(WINDOW_GUI(window->active)->view,
				   window->curses_win);
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
		textbuffer_view_set_window(WINDOW_GUI(rec->active)->view,
					   rec->curses_win);
	}
}

MAIN_WINDOW_REC *mainwindow_create(void)
{
	MAIN_WINDOW_REC *rec, *parent;
	int space;

	rec = g_new0(MAIN_WINDOW_REC, 1);
	rec->width = screen_width;
	rec->statusbar_lines = 1;

	if (mainwindows == NULL) {
		active_mainwin = rec;

		rec->first_line = reserved_up;
		rec->last_line = screen_height-1 -
			reserved_down-rec->statusbar_lines;
		rec->height = rec->last_line-rec->first_line+1;
	} else {
		parent = WINDOW_GUI(active_win)->parent;
		if (parent->height < WINDOW_MIN_SIZE+NEW_WINDOW_SIZE)
			parent = find_window_with_room();
		if (parent == NULL)
			return NULL; /* not enough space */

		space = (parent->height-parent->statusbar_lines)/2;
		rec->first_line = parent->first_line;
		rec->last_line = rec->first_line + space-rec->statusbar_lines;
		rec->height = rec->last_line-rec->first_line+1;
		parent->first_line = rec->last_line+1+rec->statusbar_lines;
		parent->height = parent->last_line-parent->first_line+1;

		mainwindow_resize(parent, 0, -space-1);
	}

#ifdef USE_CURSES_WINDOWS
	rec->curses_win = newwin(rec->height, rec->width, rec->first_line, 0);
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
		mainwindow_resize(rec, 0, size);
		return;
	}

	rec = mainwindows_find_upper(first_line);
	if (rec != NULL) {
		rec->last_line = last_line-rec->statusbar_lines;
		mainwindow_resize(rec, 0, size);
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

GSList *mainwindows_get_sorted(int reverse)
{
	GSList *tmp, *list;

	list = NULL;
	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		list = g_slist_insert_sorted(list, tmp->data, (GCompareFunc)
					     (reverse ? mainwindows_compare_reverse : mainwindows_compare));
	}

	return list;
}

static void mainwindows_resize_too_small(int xdiff, int ydiff)
{
	GSList *sorted, *tmp;
        int space, moved;

	/* terminal is too small - just take the space whereever possible */
	sorted = mainwindows_get_sorted(FALSE);
	moved = 0;
	for (tmp = sorted; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		space = rec->height;
		if (ydiff == 0 || space <= 0) {
			if (moved > 0) {
				rec->first_line -= moved;
				rec->last_line -= moved;
				signal_emit("mainwindow moved", 1, rec);
			}
			continue;
		}

		if (space > -ydiff) space = -ydiff;
		ydiff += space;
		rec->first_line -= moved;
		moved += space;
		rec->last_line -= space;
		mainwindow_resize(rec, xdiff, -space);
	}
	g_slist_free(sorted);
}

static void mainwindows_resize_smaller(int xdiff, int ydiff)
{
	GSList *sorted, *tmp;
        int space;

        space = 0;
	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		space += rec->height-WINDOW_MIN_SIZE;
	}

	if (space < -ydiff) {
		/* not enough space, use different algorithm */
		mainwindows_resize_too_small(xdiff, ydiff);
		return;
	}

	/* resize windows that have space */
	sorted = mainwindows_get_sorted(TRUE);
	for (tmp = sorted; tmp != NULL && ydiff < 0; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		space = rec->height-WINDOW_MIN_SIZE;
		if (space <= 0) {
			rec->first_line += ydiff;
			rec->last_line += ydiff;
			signal_emit("mainwindow moved", 1, rec);
			continue;
		}

		if (space <= 0) space = 1;
		if (space > -ydiff) space = -ydiff;
		rec->last_line += ydiff;
		ydiff += space;
		rec->first_line += ydiff;

		mainwindow_resize(rec, xdiff, -space);
	}
	g_slist_free(sorted);
}

static void mainwindows_resize_bigger(int xdiff, int ydiff)
{
	GSList *sorted, *tmp;
        int moved, space;

	sorted = mainwindows_get_sorted(FALSE);
	moved = 0;
	for (tmp = sorted; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		space = rec->height-WINDOW_MIN_SIZE;
		if (ydiff == 0 || (space >= 0 && tmp->next != NULL)) {
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
			if (space > ydiff) space = ydiff;
		} else {
			/* lowest window - give all the extra space for it */
			space = ydiff;
		}
		ydiff -= space;
		rec->first_line += moved;
                moved += space;
		rec->last_line += moved;

		mainwindow_resize(rec, xdiff, space);
	}
	g_slist_free(sorted);
}

void mainwindows_resize_horiz(int xdiff)
{
	GSList *tmp;

	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		mainwindow_resize(rec, xdiff, 0);
	}
}

void mainwindows_resize(int width, int height)
{
	int xdiff, ydiff;

	xdiff = width-screen_width;
	ydiff = height-screen_height;
        screen_width = width;
        screen_height = height;

	screen_refresh_freeze();
	if (ydiff < 0)
		mainwindows_resize_smaller(xdiff, ydiff);
	else if (ydiff > 0)
		mainwindows_resize_bigger(xdiff, ydiff);
        else if (xdiff != 0)
		mainwindows_resize_horiz(xdiff);

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

		window = mainwindows_find_upper(screen_height);
		if (window != NULL) window->last_line -= count;
	}

	if (window != NULL)
		mainwindow_resize(window, 0, -count);

	return ret;
}

static void mainwindows_resize_two(MAIN_WINDOW_REC *grow_win,
				   MAIN_WINDOW_REC *shrink_win, int count)
{
	mainwindow_resize(grow_win, 0, count);
	mainwindow_resize(shrink_win, 0, -count);
	gui_window_redraw(grow_win->active);
	gui_window_redraw(shrink_win->active);
	statusbar_redraw(grow_win->statusbar);
	statusbar_redraw(shrink_win->statusbar);
}

static int mainwindow_grow(MAIN_WINDOW_REC *window, int count)
{
	MAIN_WINDOW_REC *shrink_win;

	/* shrink lower window */
	shrink_win = mainwindows_find_lower(window->last_line);
	if (shrink_win != NULL && shrink_win->height-count >= WINDOW_MIN_SIZE) {
                window->last_line += count;
		shrink_win->first_line += count;
	} else {
		/* shrink upper window */
		shrink_win = mainwindows_find_upper(window->first_line);
		if (shrink_win == NULL ||
		    shrink_win->height-count < WINDOW_MIN_SIZE)
			return FALSE;

		window->first_line -= count;
		shrink_win->last_line -= count;
	}

	mainwindows_resize_two(window, shrink_win, count);
        return TRUE;
}

static int mainwindow_shrink(MAIN_WINDOW_REC *window, int count)
{
	MAIN_WINDOW_REC *grow_win;

	if (window->height-count < WINDOW_MIN_SIZE)
                return FALSE;

	grow_win = mainwindows_find_lower(window->last_line);
	if (grow_win != NULL) {
                window->last_line -= count;
		grow_win->first_line -= count;
	} else {
		grow_win = mainwindows_find_upper(window->first_line);
		if (grow_win == NULL) return FALSE;

		window->first_line += count;
		grow_win->last_line += count;
	}

	mainwindows_resize_two(grow_win, window, count);
        return TRUE;
}

void mainwindow_set_size(MAIN_WINDOW_REC *window, int size)
{
        size -= window->height;
	if (size < 0)
		mainwindow_shrink(window, size);
	else
		mainwindow_grow(window, size);
}

/* SYNTAX: WINDOW GROW [<lines>] */
static void cmd_window_grow(const char *data)
{
	MAIN_WINDOW_REC *window;
	int count;

	count = *data == '\0' ? 1 : atoi(data);
	window = WINDOW_GUI(active_win)->parent;

	if (!mainwindow_grow(window, count)) {
		printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
				   TXT_WINDOW_TOO_SMALL);
	}
}

/* SYNTAX: WINDOW SHRINK [<lines>] */
static void cmd_window_shrink(const char *data)
{
	MAIN_WINDOW_REC *window;
	int count;

	count = *data == '\0' ? 1 : atoi(data);
	window = WINDOW_GUI(active_win)->parent;

	if (!mainwindow_shrink(window, count)) {
		printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
				   TXT_WINDOW_TOO_SMALL);
	}
}

/* SYNTAX: WINDOW SIZE <lines> */
static void cmd_window_size(const char *data)
{
        char sizestr[MAX_INT_STRLEN];
	int size;

	if (!is_numeric(data, 0)) return;
	size = atoi(data);

	size -= WINDOW_GUI(active_win)->parent->height;
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

	avail_size = screen_height - reserved_up-reserved_down;
	unit_size = avail_size/windows;
	bigger_units = avail_size%windows;

	sorted = mainwindows_get_sorted(FALSE);
        last_line = 0;
	for (tmp = sorted; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		old_size = rec->height;
		rec->first_line = last_line+1;
		rec->last_line = rec->first_line-1 + unit_size -
			rec->statusbar_lines;
		rec->height = rec->last_line-rec->first_line+1;

		if (bigger_units > 0) {
			rec->last_line++;
                        bigger_units--;
		}
		last_line = rec->last_line + rec->statusbar_lines;

		mainwindow_resize(rec, 0, rec->height-old_size);
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
		printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
				   TXT_CANT_HIDE_LAST);
		return;
	}

	if (*data == '\0')
		window = active_win;
	else if (is_numeric(data, 0)) {
		window = window_find_refnum(atoi(data));
		if (window == NULL) {
			printformat_window(active_win, MSGLEVEL_CLIENTERROR,
					   TXT_REFNUM_NOT_FOUND, data);
		}
	} else {
		window = window_find_item(active_win->active_server, data);
	}

	if (window == NULL || !is_window_visible(window))
		return;

	if (WINDOW_GUI(window)->parent->sticky_windows != NULL) {
		printformat_window(active_win, MSGLEVEL_CLIENTERROR,
				   TXT_CANT_HIDE_STICKY_WINDOWS);
                return;
	}

	mainwindow_destroy(WINDOW_GUI(window)->parent);

	if (active_mainwin == NULL) {
		active_mainwin = WINDOW_GUI(active_win)->parent;
                window_set_active(active_mainwin->active);
	}
}

/* SYNTAX: WINDOW SHOW <number>|<name> */
static void cmd_window_show(const char *data)
{
        MAIN_WINDOW_REC *parent;
	WINDOW_REC *window;

	if (*data == '\0') cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

	if (is_numeric(data, '\0')) {
                window = window_find_refnum(atoi(data));
		if (window == NULL) {
			printformat_window(active_win, MSGLEVEL_CLIENTERROR,
					   TXT_REFNUM_NOT_FOUND, data);
		}
	} else {
		window = window_find_item(active_win->active_server, data);
	}

	if (window == NULL || is_window_visible(window))
		return;

	if (WINDOW_GUI(window)->parent->sticky_windows != NULL) {
		printformat_window(active_win, MSGLEVEL_CLIENTERROR,
				   TXT_CANT_SHOW_STICKY_WINDOWS);
                return;
	}

	parent = mainwindow_create();
	if (settings_get_bool("autostick_split_windows")) {
		parent->sticky_windows =
			g_slist_append(parent->sticky_windows, window);
	}
        parent->active = window;
        gui_window_reparent(window, parent);

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

/* SYNTAX: WINDOW LEFT */
static void cmd_window_left(const char *data, SERVER_REC *server, void *item)
{
        MAIN_WINDOW_REC *parent;
        WINDOW_REC *window;
	int pos, num;

        window = NULL;
	if (active_mainwin->sticky_windows == NULL) {
		/* no sticky windows, go to previous non-sticky window */
                num = active_win->refnum;
		do {
			num = window_refnum_prev(num, TRUE);
			if (num < 0) {
                                window = NULL;
				break;
			}
                        window = window_find_refnum(num);
			parent = WINDOW_GUI(window)->parent;
		} while (g_slist_find(parent->sticky_windows, window) != NULL);
	} else {
		pos = g_slist_index(active_mainwin->sticky_windows,
				    active_win);
		if (pos > 0) {
			window = g_slist_nth_data(
					active_mainwin->sticky_windows, pos-1);
		} else {
			window = g_slist_last(
					active_mainwin->sticky_windows)->data;
		}
	}

        if (window != NULL)
		window_set_active(window);
}

/* SYNTAX: WINDOW RIGHT */
static void cmd_window_right(void)
{
        MAIN_WINDOW_REC *parent;
	WINDOW_REC *window;
        GSList *tmp;
	int num;

        window = NULL;
	if (active_mainwin->sticky_windows == NULL) {
		/* no sticky windows, go to next non-sticky window */
                num = active_win->refnum;
		do {
			num = window_refnum_next(num, TRUE);
			if (num < 0) {
                                window = NULL;
				break;
			}
                        window = window_find_refnum(num);
			parent = WINDOW_GUI(window)->parent;
		} while (g_slist_find(parent->sticky_windows, window) != NULL);
	} else {
		tmp = g_slist_find(active_mainwin->sticky_windows, active_win);
		if (tmp != NULL) {
			window = tmp->next != NULL ? tmp->next->data :
				active_mainwin->sticky_windows->data;
		}
	}

        if (window != NULL)
		window_set_active(window);
}

static void mainwindow_change_window(MAIN_WINDOW_REC *mainwin,
				     WINDOW_REC *window)
{
	MAIN_WINDOW_REC *parent;
	GSList *tmp;

	if (mainwin->sticky_windows != NULL) {
		/* sticky window */
		window_set_active(mainwin->sticky_windows->data);
                return;
	}

	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

                parent = WINDOW_GUI(rec)->parent;
		if (rec != window &&
		    g_slist_find(parent->sticky_windows, rec) == NULL) {
                        window_set_active(rec);
                        return;
		}
	}

        /* no more non-sticky windows, remove main window */
        mainwindow_destroy(mainwin);
}

/* SYNTAX: WINDOW STICK [ON|OFF|<ref#>] */
static void cmd_window_stick(const char *data)
{
	MAIN_WINDOW_REC *window = active_mainwin;

	if (is_numeric(data, '\0')) {
		WINDOW_REC *win = window_find_refnum(atoi(data));
		if (win == NULL) {
			printformat_window(active_win, MSGLEVEL_CLIENTERROR,
					   TXT_REFNUM_NOT_FOUND, data);
			return;
		}
                window = WINDOW_GUI(win)->parent;
	}

	if (g_strncasecmp(data, "OF", 2) == 0 || toupper(*data) == 'N') {
		/* unset sticky */
		if (g_slist_find(window->sticky_windows, active_win) == NULL) {
			printformat_window(active_win, MSGLEVEL_CLIENTERROR,
					   TXT_WINDOW_NOT_STICKY);
		} else {
			window->sticky_windows =
				g_slist_remove(window->sticky_windows,
					       active_win);
			printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
					   TXT_WINDOW_UNSET_STICKY);
		}
	} else {
                /* set sticky */
		active_mainwin->sticky_windows =
			g_slist_remove(active_mainwin->sticky_windows,
				       active_win);

		if (g_slist_find(window->sticky_windows, active_win) == NULL) {
			window->sticky_windows =
				g_slist_append(window->sticky_windows,
					       active_win);
		}
		if (window != active_mainwin) {
                        WINDOW_REC *movewin;

                        movewin = active_win;
			gui_window_reparent(movewin, window);
                        mainwindow_change_window(active_mainwin, movewin);

			active_mainwin = window;
                        window_set_active(movewin);
		}

		printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
				   TXT_WINDOW_SET_STICKY);
	}
}

void mainwindows_init(void)
{
	screen_width = COLS;
	screen_height = LINES;

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
	command_bind("window left", NULL, (SIGNAL_FUNC) cmd_window_left);
	command_bind("window right", NULL, (SIGNAL_FUNC) cmd_window_right);
	command_bind("window stick", NULL, (SIGNAL_FUNC) cmd_window_stick);
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
	command_unbind("window left", (SIGNAL_FUNC) cmd_window_left);
	command_unbind("window right", (SIGNAL_FUNC) cmd_window_right);
	command_unbind("window stick", (SIGNAL_FUNC) cmd_window_stick);
}
