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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include "module-formats.h"
#include "signals.h"
#include "commands.h"
#include "levels.h"
#include "misc.h"
#include "settings.h"
#include "printtext.h"

#include "term.h"
#include "gui-windows.h"

#define NEW_WINDOW_SIZE (WINDOW_MIN_SIZE + 1)

GSList *mainwindows;
MAIN_WINDOW_REC *active_mainwin;

int screen_reserved_top, screen_reserved_bottom;
static int old_screen_width, old_screen_height;

#define mainwindow_create_screen(window) \
	term_window_create(0, \
			   (window)->first_line + (window)->statusbar_lines_top, \
			   (window)->width, \
			   (window)->height - (window)->statusbar_lines)

#define mainwindow_set_screen_size(window) \
	term_window_move((window)->screen_win, 0, \
			 (window)->first_line + (window)->statusbar_lines_top, \
			 (window)->width, \
			 (window)->height - (window)->statusbar_lines);


static MAIN_WINDOW_REC *find_window_with_room(void)
{
	MAIN_WINDOW_REC *biggest_rec;
	GSList *tmp;
	int space, biggest;

	biggest = 0; biggest_rec = NULL;
	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		space = MAIN_WINDOW_TEXT_HEIGHT(rec);
		if (space >= WINDOW_MIN_SIZE+NEW_WINDOW_SIZE && space > biggest) {
			biggest = space;
			biggest_rec = rec;
		}
	}

	return biggest_rec;
}

#define window_size_equals(window, mainwin) \
	((window)->width == (mainwin)->width && \
	 (window)->height == MAIN_WINDOW_TEXT_HEIGHT(mainwin))

static void mainwindow_resize_windows(MAIN_WINDOW_REC *window)
{
	GSList *tmp;
        int resized;

	mainwindow_set_screen_size(window);

	resized = FALSE;
	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		if (rec->gui_data != NULL &&
		    WINDOW_GUI(rec)->parent == window &&
		    !window_size_equals(rec, window)) {
                        resized = TRUE;
			gui_window_resize(rec, window->width,
					  MAIN_WINDOW_TEXT_HEIGHT(window));
		}
	}

        if (resized)
		signal_emit("mainwindow resized", 1, window);
}

static void mainwindow_resize(MAIN_WINDOW_REC *window, int xdiff, int ydiff)
{
	if (quitting || (xdiff == 0 && ydiff == 0))
                return;

        window->width += xdiff;
	window->height = window->last_line-window->first_line+1;
        window->size_dirty = TRUE;
}

static GSList *get_sticky_windows_sorted(MAIN_WINDOW_REC *mainwin)
{
	GSList *tmp, *list;

        list = NULL;
	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		if (WINDOW_GUI(rec)->sticky && WINDOW_MAIN(rec) == mainwin) {
			list = g_slist_insert_sorted(list, rec, (GCompareFunc)
						     window_refnum_cmp);
		}
	}

        return list;
}

void mainwindow_change_active(MAIN_WINDOW_REC *mainwin,
			      WINDOW_REC *skip_window)
{
        WINDOW_REC *window, *other;
	GSList *tmp;

        mainwin->active = NULL;
	if (mainwin->sticky_windows) {
		/* sticky window */
                tmp = get_sticky_windows_sorted(mainwin);
                window = tmp->data;
		if (window == skip_window) {
			window = tmp->next == NULL ? NULL :
				tmp->next->data;
		}
                g_slist_free(tmp);

		if (window != NULL) {
			window_set_active(window);
			return;
		}
	}

        other = NULL;
	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		if (rec != skip_window) {
			other = rec;
			break;
		}
	}

	window_set_active(other);
	if (mainwindows->next != NULL)
		mainwindow_destroy(mainwin);
}

void mainwindows_recreate(void)
{
	GSList *tmp;

	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		rec->screen_win = mainwindow_create_screen(rec);
                rec->dirty = TRUE;
		textbuffer_view_set_window(WINDOW_GUI(rec->active)->view,
					   rec->screen_win);
	}
}

MAIN_WINDOW_REC *mainwindow_create(void)
{
	MAIN_WINDOW_REC *rec, *parent;
	int space;

	rec = g_new0(MAIN_WINDOW_REC, 1);
	rec->dirty = TRUE;
	rec->width = term_width;

	if (mainwindows == NULL) {
		active_mainwin = rec;

		rec->first_line = screen_reserved_top;
		rec->last_line = term_height-1 - screen_reserved_bottom;
		rec->height = rec->last_line-rec->first_line+1;
	} else {
		parent = WINDOW_MAIN(active_win);
		if (MAIN_WINDOW_TEXT_HEIGHT(parent) <
		    WINDOW_MIN_SIZE+NEW_WINDOW_SIZE)
			parent = find_window_with_room();
		if (parent == NULL)
			return NULL; /* not enough space */

		space = parent->height / 2;
		rec->first_line = parent->first_line;
		rec->last_line = rec->first_line + space;
		rec->height = rec->last_line-rec->first_line+1;

		parent->first_line += space+1;
		mainwindow_resize(parent, 0, -space-1);
	}

	rec->screen_win = mainwindow_create_screen(rec);
	term_refresh(NULL);

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
		rec->last_line = last_line;
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

		if (rec->gui_data != NULL && WINDOW_MAIN(rec) == window)
                        gui_window_reparent(rec, new_parent);
	}
}

void mainwindow_destroy(MAIN_WINDOW_REC *window)
{
	g_return_if_fail(window != NULL);

	mainwindows = g_slist_remove(mainwindows, window);
	signal_emit("mainwindow destroyed", 1, window);

        term_window_destroy(window->screen_win);

	if (mainwindows != NULL) {
		gui_windows_remove_parent(window);
		if (!quitting) {
			mainwindows_add_space(window->first_line,
					      window->last_line);
			mainwindows_redraw();
		}
	}

	g_free(window);

	if (active_mainwin == window) active_mainwin = NULL;
}

void mainwindows_redraw(void)
{
        GSList *tmp;

        irssi_set_dirty();
	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

                rec->dirty = TRUE;
	}
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

static void mainwindows_resize_smaller(int xdiff, int ydiff)
{
        MAIN_WINDOW_REC *rec;
	GSList *sorted, *tmp;
        int space;

	sorted = mainwindows_get_sorted(TRUE);
	if (sorted == NULL)
		return;

	for (;;) {
		space = 0;
		for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
			rec = tmp->data;
			space += MAIN_WINDOW_TEXT_HEIGHT(rec)-WINDOW_MIN_SIZE;
		}

		if (space >= -ydiff)
			break;

		rec = sorted->data;
		if (rec == active_mainwin && sorted->next != NULL)
			rec = sorted->next->data;
		sorted = g_slist_remove(sorted, rec);

		if (sorted != NULL) {
			/* terminal is too small - destroy the
			   uppest window and try again */
			mainwindow_destroy(rec);
		} else {
			/* only one window in screen.. just force the resize */
			rec->last_line += ydiff;
			mainwindow_resize(rec, xdiff, ydiff);
                        return;
		}
	}

	/* resize windows that have space */
	for (tmp = sorted; tmp != NULL && ydiff < 0; tmp = tmp->next) {
		rec = tmp->data;

		space = MAIN_WINDOW_TEXT_HEIGHT(rec)-WINDOW_MIN_SIZE;
		if (space == 0) {
			mainwindow_resize(rec, xdiff, 0);

			rec->first_line += ydiff;
			rec->last_line += ydiff;
			signal_emit("mainwindow moved", 1, rec);
			continue;
		}

		if (space > -ydiff) space = -ydiff;
		rec->last_line += ydiff;
		ydiff += space;
		rec->first_line += ydiff;

		mainwindow_resize(rec, xdiff, -space);
	}

	if (xdiff != 0) {
		while (tmp != NULL) {
			mainwindow_resize(tmp->data, xdiff, 0);
			tmp = tmp->next;
		}
	}

	g_slist_free(sorted);
}

static void mainwindows_resize_bigger(int xdiff, int ydiff)
{
	GSList *sorted, *tmp;

	sorted = mainwindows_get_sorted(FALSE);
	for (tmp = sorted; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		if (ydiff == 0 || tmp->next != NULL) {
			mainwindow_resize(rec, xdiff, 0);
			continue;
		}

		/* lowest window - give all the extra space for it */
		rec->last_line += ydiff;
		mainwindow_resize(rec, xdiff, ydiff);
	}
	g_slist_free(sorted);
}

static void mainwindows_resize_horiz(int xdiff)
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

	xdiff = width-old_screen_width;
	ydiff = height-old_screen_height;
        old_screen_width = width;
        old_screen_height = height;

	if (ydiff < 0)
		mainwindows_resize_smaller(xdiff, ydiff);
	else if (ydiff > 0)
		mainwindows_resize_bigger(xdiff, ydiff);
        else if (xdiff != 0)
		mainwindows_resize_horiz(xdiff);

        signal_emit("terminal resized", 0);

	irssi_redraw();
}

int mainwindows_reserve_lines(int top, int bottom)
{
	MAIN_WINDOW_REC *window;
	int ret;

        ret = -1;
	if (top != 0) {
		g_return_val_if_fail(top > 0 || screen_reserved_top > top, -1);

		ret = screen_reserved_top;
		screen_reserved_top += top;

		window = mainwindows_find_lower(-1);
		if (window != NULL) {
			window->first_line += top;
			mainwindow_resize(window, 0, -top);
		}
	}

	if (bottom != 0) {
		g_return_val_if_fail(bottom > 0 || screen_reserved_bottom > bottom, -1);

		ret = screen_reserved_bottom;
		screen_reserved_bottom += bottom;

		window = mainwindows_find_upper(term_height);
		if (window != NULL) {
			window->last_line -= bottom;
			mainwindow_resize(window, 0, -bottom);
		}
	}

	return ret;
}

int mainwindow_set_statusbar_lines(MAIN_WINDOW_REC *window,
				   int top, int bottom)
{
	int ret;

        ret = -1;
	if (top != 0) {
                ret = window->statusbar_lines_top;
		window->statusbar_lines_top += top;
                window->statusbar_lines += top;
	}

	if (bottom != 0) {
                ret = window->statusbar_lines_bottom;
                window->statusbar_lines_bottom += bottom;
                window->statusbar_lines += bottom;
	}

	if (top+bottom != 0)
                window->size_dirty = TRUE;

        return ret;
}

static void mainwindows_resize_two(MAIN_WINDOW_REC *grow_win,
				   MAIN_WINDOW_REC *shrink_win, int count)
{
        irssi_set_dirty();

	mainwindow_resize(grow_win, 0, count);
	mainwindow_resize(shrink_win, 0, -count);
	grow_win->dirty = TRUE;
	shrink_win->dirty = TRUE;
}

static int try_shrink_lower(MAIN_WINDOW_REC *window, int count)
{
	MAIN_WINDOW_REC *shrink_win;

	shrink_win = mainwindows_find_lower(window->last_line);
	if (shrink_win != NULL &&
	    MAIN_WINDOW_TEXT_HEIGHT(shrink_win)-count >= WINDOW_MIN_SIZE) {
                window->last_line += count;
		shrink_win->first_line += count;
		mainwindows_resize_two(window, shrink_win, count);
                return TRUE;
	}

        return FALSE;
}

static int try_shrink_upper(MAIN_WINDOW_REC *window, int count)
{
	MAIN_WINDOW_REC *shrink_win;

	shrink_win = mainwindows_find_upper(window->first_line);
	if (shrink_win != NULL &&
	    MAIN_WINDOW_TEXT_HEIGHT(shrink_win)-count >= WINDOW_MIN_SIZE) {
		window->first_line -= count;
		shrink_win->last_line -= count;
		mainwindows_resize_two(window, shrink_win, count);
                return TRUE;
	}

        return FALSE;
}

static int mainwindow_grow(MAIN_WINDOW_REC *window, int count,
			   int resize_lower)
{
	if (!resize_lower || !try_shrink_lower(window, count)) {
		if (!try_shrink_upper(window, count)) {
                        if (resize_lower || !try_shrink_lower(window, count))
				return FALSE;
		}
	}

        return TRUE;
}

static int try_grow_lower(MAIN_WINDOW_REC *window, int count)
{
	MAIN_WINDOW_REC *grow_win;

	grow_win = mainwindows_find_lower(window->last_line);
	if (grow_win != NULL) {
                window->last_line -= count;
		grow_win->first_line -= count;
		mainwindows_resize_two(grow_win, window, count);
	}

        return grow_win != NULL;
}

static int try_grow_upper(MAIN_WINDOW_REC *window, int count)
{
	MAIN_WINDOW_REC *grow_win;

	grow_win = mainwindows_find_upper(window->first_line);
	if (grow_win != NULL) {
		window->first_line += count;
		grow_win->last_line += count;
		mainwindows_resize_two(grow_win, window, count);
	}

        return grow_win != NULL;
}

static int mainwindow_shrink(MAIN_WINDOW_REC *window, int count, int resize_lower)
{
	if (MAIN_WINDOW_TEXT_HEIGHT(window)-count < WINDOW_MIN_SIZE)
                return FALSE;

	if (!resize_lower || !try_grow_lower(window, count)) {
		if (!try_grow_upper(window, count)) {
                        if (resize_lower || !try_grow_lower(window, count))
				return FALSE;
		}
	}

        return TRUE;
}

/* Change the window height - the height includes the lines needed for
   statusbars. If resize_lower is TRUE, the lower window is first tried
   to be resized instead of upper window. */
void mainwindow_set_size(MAIN_WINDOW_REC *window, int height, int resize_lower)
{
        height -= window->height;
	if (height < 0)
		mainwindow_shrink(window, -height, resize_lower);
	else
		mainwindow_grow(window, height, resize_lower);
}

void mainwindows_redraw_dirty(void)
{
	GSList *tmp;

	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		if (rec->size_dirty) {
                        rec->size_dirty = FALSE;
			mainwindow_resize_windows(rec);
		}
		if (rec->dirty) {
                        rec->dirty = FALSE;
			gui_window_redraw(rec->active);
		}
	}
}

/* SYNTAX: WINDOW GROW [<lines>] */
static void cmd_window_grow(const char *data)
{
	MAIN_WINDOW_REC *window;
	int count;

	count = *data == '\0' ? 1 : atoi(data);
	window = WINDOW_MAIN(active_win);

	if (!mainwindow_grow(window, count, FALSE)) {
		printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
				   TXT_WINDOW_TOO_SMALL);
	}
}

/* SYNTAX: WINDOW SHRINK [<lines>] */
static void cmd_window_shrink(const char *data)
{
	int count;

	count = *data == '\0' ? 1 : atoi(data);
	if (!mainwindow_shrink(WINDOW_MAIN(active_win), count, FALSE)) {
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

	size -= WINDOW_MAIN(active_win)->height -
		WINDOW_MAIN(active_win)->statusbar_lines;
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

	avail_size = term_height - screen_reserved_top-screen_reserved_bottom;
	unit_size = avail_size/windows;
	bigger_units = avail_size%windows;

	sorted = mainwindows_get_sorted(FALSE);
        last_line = screen_reserved_top;
	for (tmp = sorted; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		old_size = rec->height;
		rec->first_line = last_line;
		rec->last_line = rec->first_line + unit_size-1;

		if (bigger_units > 0) {
			rec->last_line++;
                        bigger_units--;
		}

		rec->height = rec->last_line-rec->first_line+1;
		last_line = rec->last_line+1;

		mainwindow_resize(rec, 0, rec->height-old_size);
	}
	g_slist_free(sorted);

	mainwindows_redraw();
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

	if (WINDOW_MAIN(window)->sticky_windows) {
		printformat_window(active_win, MSGLEVEL_CLIENTERROR,
				   TXT_CANT_HIDE_STICKY_WINDOWS);
                return;
	}

	mainwindow_destroy(WINDOW_MAIN(window));

	if (active_mainwin == NULL) {
		active_mainwin = WINDOW_MAIN(active_win);
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

	if (WINDOW_GUI(window)->sticky) {
		printformat_window(active_win, MSGLEVEL_CLIENTERROR,
				   TXT_CANT_SHOW_STICKY_WINDOWS);
                return;
	}

	parent = mainwindow_create();
	parent->active = window;
        gui_window_reparent(window, parent);

	if (settings_get_bool("autostick_split_windows"))
                gui_window_set_sticky(window);

	active_mainwin = NULL;
	window_set_active(window);
}

/* SYNTAX: WINDOW UP */
static void cmd_window_up(void)
{
	MAIN_WINDOW_REC *rec;

	rec = mainwindows_find_upper(active_mainwin->first_line);
	if (rec == NULL)
		rec = mainwindows_find_upper(term_height);
	if (rec != NULL)
		window_set_active(rec->active);
}

/* SYNTAX: WINDOW DOWN */
static void cmd_window_down(void)
{
	MAIN_WINDOW_REC *rec;

	rec = mainwindows_find_lower(active_mainwin->last_line);
	if (rec == NULL)
		rec = mainwindows_find_lower(-1);
	if (rec != NULL)
		window_set_active(rec->active);
}

#define WINDOW_STICKY_MATCH(window, sticky_parent) \
	((!WINDOW_GUI(window)->sticky && (sticky_parent) == NULL) || \
	 (WINDOW_GUI(window)->sticky && \
	  WINDOW_MAIN(window) == (sticky_parent)))

static int window_refnum_left(int refnum, int wrap)
{
        MAIN_WINDOW_REC *find_sticky;
	WINDOW_REC *window;

	window = window_find_refnum(refnum);
	g_return_val_if_fail(window != NULL, -1);

	find_sticky = WINDOW_MAIN(window)->sticky_windows ?
		WINDOW_MAIN(window) : NULL;

	do {
		refnum = window_refnum_prev(refnum, wrap);
		if (refnum < 0)
			break;

		window = window_find_refnum(refnum);
	} while (!WINDOW_STICKY_MATCH(window, find_sticky));

        return refnum;
}

static int window_refnum_right(int refnum, int wrap)
{
        MAIN_WINDOW_REC *find_sticky;
	WINDOW_REC *window;

	window = window_find_refnum(refnum);
	g_return_val_if_fail(window != NULL, -1);

	find_sticky = WINDOW_MAIN(window)->sticky_windows ?
		WINDOW_MAIN(window) : NULL;

	do {
		refnum = window_refnum_next(refnum, wrap);
		if (refnum < 0)
			break;

		window = window_find_refnum(refnum);
	} while (!WINDOW_STICKY_MATCH(window, find_sticky));

        return refnum;
}

/* SYNTAX: WINDOW LEFT */
static void cmd_window_left(const char *data, SERVER_REC *server, void *item)
{
	int refnum;

	refnum = window_refnum_left(active_win->refnum, TRUE);
	if (refnum != -1)
		window_set_active(window_find_refnum(refnum));
}

/* SYNTAX: WINDOW RIGHT */
static void cmd_window_right(void)
{
	int refnum;

	refnum = window_refnum_right(active_win->refnum, TRUE);
	if (refnum != -1)
		window_set_active(window_find_refnum(refnum));
}

static void window_reparent(WINDOW_REC *win, MAIN_WINDOW_REC *mainwin)
{
	MAIN_WINDOW_REC *old_mainwin;

	old_mainwin = WINDOW_MAIN(win);

	if (old_mainwin != mainwin) {
		gui_window_set_unsticky(win);

		if (old_mainwin->active == win) {
			mainwindow_change_active(old_mainwin, win);
			if (active_mainwin == NULL) {
				active_mainwin = mainwin;
				window_set_active(mainwin->active);
			}
		}

		gui_window_reparent(win, mainwin);
		window_set_active(win);
	}
}

/* SYNTAX: WINDOW STICK [<ref#>] [ON|OFF] */
static void cmd_window_stick(const char *data)
{
        MAIN_WINDOW_REC *mainwin;
        WINDOW_REC *win;

        mainwin = active_mainwin;
        win = active_mainwin->active;

	if (is_numeric(data, ' ')) {
		/* ref# specified */
		win = window_find_refnum(atoi(data));
		if (win == NULL) {
			printformat_window(active_win, MSGLEVEL_CLIENTERROR,
					   TXT_REFNUM_NOT_FOUND, data);
			return;
		}

		while (*data != ' ' && *data != '\0') data++;
		while (*data == ' ') data++;
	}

	if (g_ascii_strncasecmp(data, "OF", 2) == 0 || i_toupper(*data) == 'N') {
		/* unset sticky */
		if (!WINDOW_GUI(win)->sticky) {
			printformat_window(win, MSGLEVEL_CLIENTERROR,
					   TXT_WINDOW_NOT_STICKY);
		} else {
                        gui_window_set_unsticky(win);
			printformat_window(win, MSGLEVEL_CLIENTNOTICE,
					   TXT_WINDOW_UNSET_STICKY);
		}
	} else {
		/* set sticky */
		window_reparent(win, mainwin);
                gui_window_set_sticky(win);

		printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
				   TXT_WINDOW_SET_STICKY);
	}
}

/* SYNTAX: WINDOW MOVE LEFT */
static void cmd_window_move_left(void)
{
	int refnum;

	refnum = window_refnum_left(active_win->refnum, TRUE);
	if (refnum != -1)
		window_set_refnum(active_win, refnum);
}

/* SYNTAX: WINDOW MOVE RIGHT */
static void cmd_window_move_right(void)
{
	int refnum;

	refnum = window_refnum_right(active_win->refnum, TRUE);
	if (refnum != -1)
		window_set_refnum(active_win, refnum);
}

/* SYNTAX: WINDOW MOVE UP */
static void cmd_window_move_up(void)
{
	MAIN_WINDOW_REC *rec;

	rec = mainwindows_find_upper(active_mainwin->first_line);
        if (rec != NULL)
		window_reparent(active_win, rec);
}

/* SYNTAX: WINDOW MOVE DOWN */
static void cmd_window_move_down(void)
{
	MAIN_WINDOW_REC *rec;

	rec = mainwindows_find_lower(active_mainwin->last_line);
	if (rec != NULL)
		window_reparent(active_win, rec);
}

static void windows_print_sticky(WINDOW_REC *win)
{
        MAIN_WINDOW_REC *mainwin;
        GSList *tmp, *list;
	GString *str;

        mainwin = WINDOW_MAIN(win);

        /* convert to string */
	str = g_string_new(NULL);
	list = get_sticky_windows_sorted(mainwin);
	for (tmp = list; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		g_string_append_printf(str, "#%d, ", rec->refnum);
	}
        g_string_truncate(str, str->len-2);
        g_slist_free(list);

	printformat_window(win, MSGLEVEL_CLIENTCRAP,
			   TXT_WINDOW_INFO_STICKY, str->str);
        g_string_free(str, TRUE);
}

static void sig_window_print_info(WINDOW_REC *win)
{
	GUI_WINDOW_REC *gui;

	gui = WINDOW_GUI(win);
	if (gui->use_scroll) {
		printformat_window(win, MSGLEVEL_CLIENTCRAP,
				   TXT_WINDOW_INFO_SCROLL,
				   gui->scroll ? "yes" : "no");
	}

	if (WINDOW_MAIN(win)->sticky_windows)
                windows_print_sticky(win);
}

void mainwindows_init(void)
{
	old_screen_width = term_width;
	old_screen_height = term_height;

	mainwindows = NULL;
	active_mainwin = NULL;
	screen_reserved_top = screen_reserved_bottom = 0;

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
	command_bind("window move left", NULL, (SIGNAL_FUNC) cmd_window_move_left);
	command_bind("window move right", NULL, (SIGNAL_FUNC) cmd_window_move_right);
	command_bind("window move up", NULL, (SIGNAL_FUNC) cmd_window_move_up);
	command_bind("window move down", NULL, (SIGNAL_FUNC) cmd_window_move_down);
        signal_add("window print info", (SIGNAL_FUNC) sig_window_print_info);
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
	command_unbind("window move left", (SIGNAL_FUNC) cmd_window_move_left);
	command_unbind("window move right", (SIGNAL_FUNC) cmd_window_move_right);
	command_unbind("window move up", (SIGNAL_FUNC) cmd_window_move_up);
	command_unbind("window move down", (SIGNAL_FUNC) cmd_window_move_down);
        signal_remove("window print info", (SIGNAL_FUNC) sig_window_print_info);
}
