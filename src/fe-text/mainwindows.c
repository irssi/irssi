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
#include <irssi/src/fe-text/module-formats.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/fe-common/core/printtext.h>

#include <irssi/src/fe-text/term.h>
#include <irssi/src/fe-text/gui-windows.h>

#define NEW_WINDOW_SIZE (WINDOW_MIN_SIZE + 1)

GSList *mainwindows;
MAIN_WINDOW_REC *active_mainwin;
MAIN_WINDOW_BORDER_REC *clrtoeol_info;

int screen_reserved_top, screen_reserved_bottom;
int screen_reserved_left, screen_reserved_right;
static int screen_width, screen_height;
static int screen_collapsed = 0; /* see mainwindows_resize */

#define mainwindow_create_screen(window)                                                           \
	term_window_create((window)->first_column + (window)->statusbar_columns_left,              \
	                   (window)->first_line + (window)->statusbar_lines_top,                   \
	                   (window)->width - (window)->statusbar_columns,                          \
	                   (window)->height - (window)->statusbar_lines)

#define mainwindow_set_screen_size(window)                                                         \
	term_window_move((window)->screen_win,                                                     \
	                 (window)->first_column + (window)->statusbar_columns_left,                \
	                 (window)->first_line + (window)->statusbar_lines_top,                     \
	                 (window)->width - (window)->statusbar_columns,                            \
	                 (window)->height - (window)->statusbar_lines);

static MAIN_WINDOW_REC *find_window_with_room()
{
	MAIN_WINDOW_REC *biggest_rec;
	GSList *tmp;
	int space, biggest;

	biggest = 0;
	biggest_rec = NULL;
	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		space = MAIN_WINDOW_TEXT_HEIGHT(rec);
		if (space >= WINDOW_MIN_SIZE + NEW_WINDOW_SIZE && space > biggest) {
			biggest = space;
			biggest_rec = rec;
		}
	}

	return biggest_rec;
}

static MAIN_WINDOW_REC *find_window_with_room_right(void)
{
	MAIN_WINDOW_REC *biggest_rec;
	GSList *tmp;
	int space, biggest;

	biggest = 0;
	biggest_rec = NULL;
	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		space = MAIN_WINDOW_TEXT_WIDTH(rec);
		if (space >= 2 * NEW_WINDOW_WIDTH && space > biggest) {
			biggest = space;
			biggest_rec = rec;
		}
	}

	return biggest_rec;
}

#define window_size_equals(window, mainwin)                                                        \
	((window)->width == MAIN_WINDOW_TEXT_WIDTH(mainwin) &&                                     \
	 (window)->height == MAIN_WINDOW_TEXT_HEIGHT(mainwin))

static void mainwindow_resize_windows(MAIN_WINDOW_REC *window)
{
	GSList *tmp;
	int resized;

	/* Clamp screen window size to at least 1x1 to keep text views valid */
	{
		int sx = window->first_column + window->statusbar_columns_left;
		int sy = window->first_line + window->statusbar_lines_top;
		int sw = window->width - window->statusbar_columns;
		int sh = window->height - window->statusbar_lines;
		if (sw < 1)
			sw = 1;
		if (sh < 1)
			sh = 1;
		term_window_move(window->screen_win, sx, sy, sw, sh);
	}

	resized = FALSE;
	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		if (rec->gui_data != NULL && WINDOW_GUI(rec)->parent == window &&
		    !window_size_equals(rec, window)) {
			{
				int tw = MAIN_WINDOW_TEXT_WIDTH(window);
				int th = MAIN_WINDOW_TEXT_HEIGHT(window);
				if (tw < 1)
					tw = 1;
				if (th < 1)
					th = 1;
				resized = TRUE;
				gui_window_resize(rec, tw, th);
			}
		}
	}

	if (resized)
		signal_emit("mainwindow resized", 1, window);
}

static void mainwindow_resize(MAIN_WINDOW_REC *window, int xdiff, int ydiff)
{
	int height, width;
	if (quitting || (xdiff == 0 && ydiff == 0))
		return;

	height = window->height + ydiff;
	width = window->width + xdiff;
	window->width = window->last_column - window->first_column + 1;
	window->height = window->last_line - window->first_line + 1;
	if (height != window->height || width != window->width) {
		g_warning("Resizing window %p W:%d expected:%d H:%d expected:%d", window,
		          window->width, width, window->height, height);
	}
	window->size_dirty = TRUE;
}

static GSList *get_sticky_windows_sorted(MAIN_WINDOW_REC *mainwin)
{
	GSList *tmp, *list;

	list = NULL;
	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		if (WINDOW_GUI(rec)->sticky && WINDOW_MAIN(rec) == mainwin) {
			list = g_slist_insert_sorted(list, rec, (GCompareFunc) window_refnum_cmp);
		}
	}

	return list;
}

void mainwindow_change_active(MAIN_WINDOW_REC *mainwin, WINDOW_REC *skip_window)
{
	WINDOW_REC *window, *other;
	GSList *tmp;

	mainwin->active = NULL;
	if (mainwin->sticky_windows) {
		/* sticky window */
		tmp = get_sticky_windows_sorted(mainwin);
		window = tmp->data;
		if (window == skip_window) {
			window = tmp->next == NULL ? NULL : tmp->next->data;
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
		textbuffer_view_set_window(WINDOW_GUI(rec->active)->view, rec->screen_win);
	}
}

MAIN_WINDOW_REC *mainwindow_create(int right)
{
	MAIN_WINDOW_REC *rec, *parent;
	int space;

	rec = g_new0(MAIN_WINDOW_REC, 1);
	rec->dirty = TRUE;

	if (mainwindows == NULL) {
		active_mainwin = rec;

		rec->first_line = screen_reserved_top;
		rec->last_line = term_height - 1 - screen_reserved_bottom;
		rec->height = rec->last_line - rec->first_line + 1;
		rec->first_column = screen_reserved_left;
		rec->last_column = screen_width - 1 - screen_reserved_right;
		rec->width = rec->last_column - rec->first_column + 1;
	} else {
		parent = WINDOW_MAIN(active_win);

		if (!right) {
			GSList *tmp, *line;
			if (MAIN_WINDOW_TEXT_HEIGHT(parent) < WINDOW_MIN_SIZE + NEW_WINDOW_SIZE)
				parent = find_window_with_room();
			if (parent == NULL) {
				g_free(rec);
				return NULL; /* not enough space */
			}

			space = parent->height / 2;
			rec->first_line = parent->first_line;
			rec->last_line = rec->first_line + space;
			rec->height = rec->last_line - rec->first_line + 1;
			rec->first_column = screen_reserved_left;
			rec->last_column = screen_width - 1 - screen_reserved_right;
			rec->width = rec->last_column - rec->first_column + 1;

			line = mainwindows_get_line(parent);
			for (tmp = line; tmp != NULL; tmp = tmp->next) {
				MAIN_WINDOW_REC *rec = tmp->data;
				rec->first_line += space + 1;
				mainwindow_resize(rec, 0, -space - 1);
			}
			g_slist_free(line);
		} else {
			if (MAIN_WINDOW_TEXT_WIDTH(parent) < 2 * NEW_WINDOW_WIDTH) {
				parent = find_window_with_room_right();
			}
			if (parent == NULL) {
				g_free(rec);
				return NULL; /* not enough space */
			}

			space = parent->width / 2;
			rec->first_line = parent->first_line;
			rec->last_line = parent->last_line;
			rec->height = parent->height;
			rec->first_column = parent->last_column - space + 1;
			rec->last_column = parent->last_column;
			rec->width = rec->last_column - rec->first_column + 1;

			parent->last_column -= space + 1;
			mainwindow_resize(parent, -space - 1, 0);
		}
	}

	rec->screen_win = mainwindow_create_screen(rec);
	term_refresh(NULL);

	mainwindows = g_slist_append(mainwindows, rec);
	signal_emit("mainwindow created", 1, rec);
	return rec;
}

static MAIN_WINDOW_REC *mainwindows_find_lower(MAIN_WINDOW_REC *window)
{
	int last_line;
	MAIN_WINDOW_REC *best;
	GSList *tmp;

	/* unfortunate special case: if the window has been resized
	   and there is not enough room, the last_line could become
	   smaller than the first_line, sending us in an infinite
	   loop */
	if (window != NULL)
		last_line =
		    window->last_line > window->first_line ? window->last_line : window->first_line;
	else
		last_line = -1;

	best = NULL;
	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		if (rec->first_line > last_line &&
		    (best == NULL || rec->first_line < best->first_line))
			best = rec;
	}

	return best;
}

static MAIN_WINDOW_REC *mainwindows_find_right(MAIN_WINDOW_REC *window, int find_first)
{
	int first_line, last_line, last_column;
	MAIN_WINDOW_REC *best;
	GSList *tmp;

	if (window != NULL) {
		first_line = window->first_line;
		last_line = window->last_line;
		last_column = window->last_column;
	} else {
		first_line = last_line = last_column = -1;
	}

	if (find_first)
		last_column = -1;

	best = NULL;
	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		if (rec->first_line >= first_line && rec->last_line <= last_line &&
		    rec->first_column > last_column &&
		    (best == NULL || rec->first_column < best->first_column))
			best = rec;
	}

	return best;
}

static MAIN_WINDOW_REC *mainwindows_find_lower_right(MAIN_WINDOW_REC *window)
{
	MAIN_WINDOW_REC *best;

	best = mainwindows_find_right(window, FALSE);
	if (best == NULL)
		best = mainwindows_find_lower(window);

	return best;
}

static MAIN_WINDOW_REC *mainwindows_find_upper(MAIN_WINDOW_REC *window)
{
	int first_line;
	MAIN_WINDOW_REC *best;
	GSList *tmp;

	if (window != NULL)
		first_line = window->first_line;
	else
		first_line = screen_height;

	best = NULL;
	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		if (rec->last_line < first_line &&
		    (best == NULL || rec->last_line > best->last_line))
			best = rec;
	}

	return best;
}

static MAIN_WINDOW_REC *mainwindows_find_left(MAIN_WINDOW_REC *window, int find_last)
{
	int first_line, last_line, first_column;
	MAIN_WINDOW_REC *best;
	GSList *tmp;

	if (window != NULL) {
		first_line = window->first_line;
		last_line = window->last_line;
		first_column = window->first_column;
	} else {
		first_line = last_line = screen_height;
		first_column = screen_width;
	}

	if (find_last)
		first_column = screen_width;

	best = NULL;
	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		if (rec->first_line >= first_line && rec->last_line <= last_line &&
		    rec->last_column < first_column &&
		    (best == NULL || rec->last_column > best->last_column))
			best = rec;
	}

	return best;
}

static MAIN_WINDOW_REC *mainwindows_find_upper_left(MAIN_WINDOW_REC *window)
{
	MAIN_WINDOW_REC *best;

	best = mainwindows_find_left(window, FALSE);
	if (best == NULL)
		best = mainwindows_find_upper(window);

	return best;
}

static MAIN_WINDOW_REC *mainwindows_find_left_upper(MAIN_WINDOW_REC *window)
{
	MAIN_WINDOW_REC *best;

	best = mainwindows_find_left(window, FALSE);
	if (best == NULL)
		best = mainwindows_find_left(mainwindows_find_upper(window), TRUE);

	return best;
}

GSList *mainwindows_get_line(MAIN_WINDOW_REC *rec)
{
	MAIN_WINDOW_REC *win;
	GSList *list;

	list = NULL;

	for (win = mainwindows_find_left(rec, FALSE); win != NULL;
	     win = mainwindows_find_left(win, FALSE)) {
		list = g_slist_append(list, win);
	}

	if (rec != NULL)
		list = g_slist_append(list, rec);

	for (win = mainwindows_find_right(rec, FALSE); win != NULL;
	     win = mainwindows_find_right(win, FALSE)) {
		list = g_slist_append(list, win);
	}

	return list;
}

/* add back the space which was occupied by destroyed mainwindow first_line .. last_line */
static void mainwindows_add_space(MAIN_WINDOW_REC *destroy_win)
{
	MAIN_WINDOW_REC *rec;
	int size, rsize;

	if (destroy_win->last_line < destroy_win->first_line)
		return;

	if (destroy_win->last_column < destroy_win->first_column)
		return;

	rsize = destroy_win->last_column - destroy_win->first_column + 1;
	rec = mainwindows_find_left(destroy_win, FALSE);
	if (rec != NULL) {
		rec->last_column = destroy_win->last_column;
		mainwindow_resize(rec, rsize + 1, 0);
		return;
	}

	rec = mainwindows_find_right(destroy_win, FALSE);
	if (rec != NULL) {
		rec->first_column = destroy_win->first_column;
		mainwindow_resize(rec, rsize + 1, 0);
		return;
	}

	size = destroy_win->last_line - destroy_win->first_line + 1;

	rec = mainwindows_find_lower(destroy_win);
	if (rec != NULL) {
		GSList *tmp, *list;
		list = mainwindows_get_line(rec);

		for (tmp = list; tmp != NULL; tmp = tmp->next) {
			MAIN_WINDOW_REC *rec = tmp->data;
			rec->first_line = destroy_win->first_line;
			mainwindow_resize(rec, 0, size);
		}

		g_slist_free(list);
		return;
	}

	rec = mainwindows_find_upper(destroy_win);
	if (rec != NULL) {
		GSList *tmp, *list;
		list = mainwindows_get_line(rec);

		for (tmp = list; tmp != NULL; tmp = tmp->next) {
			MAIN_WINDOW_REC *rec = tmp->data;
			rec->last_line = destroy_win->last_line;
			mainwindow_resize(rec, 0, size);
		}

		g_slist_free(list);
		return;
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

static void mainwindow_destroy_full(MAIN_WINDOW_REC *window, int respace)
{
	g_return_if_fail(window != NULL);

	mainwindows = g_slist_remove(mainwindows, window);
	signal_emit("mainwindow destroyed", 1, window);

	term_window_destroy(window->screen_win);

	if (mainwindows != NULL) {
		gui_windows_remove_parent(window);
		if (respace) {
			mainwindows_add_space(window);
			mainwindows_redraw();
		}
	}

	g_free(window);

	if (active_mainwin == window)
		active_mainwin = NULL;
}

void mainwindow_destroy(MAIN_WINDOW_REC *window)
{
	mainwindow_destroy_full(window, !quitting);
}

void mainwindow_destroy_half(MAIN_WINDOW_REC *window)
{
	mainwindow_destroy_full(window, FALSE);
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
	return w1->first_line < w2->first_line     ? -1 :
	       w1->first_line > w2->first_line     ? 1 :
	       w1->first_column < w2->first_column ? -1 :
	       w1->first_column > w2->first_column ? 1 :
	                                             0;
}

static int mainwindows_compare_reverse(MAIN_WINDOW_REC *w1, MAIN_WINDOW_REC *w2)
{
	return w1->first_line < w2->first_line     ? 1 :
	       w1->first_line > w2->first_line     ? -1 :
	       w1->first_column < w2->first_column ? 1 :
	       w1->first_column > w2->first_column ? -1 :
	                                             0;
}

GSList *mainwindows_get_sorted(int reverse)
{
	GSList *tmp, *list;

	list = NULL;
	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		list = g_slist_insert_sorted(
		    list, tmp->data,
		    (GCompareFunc) (reverse ? mainwindows_compare_reverse : mainwindows_compare));
	}

	return list;
}

static void mainwindows_resize_smaller(int ydiff)
{
	MAIN_WINDOW_REC *rec;
	GSList *sorted, *tmp;
	int space;

	sorted = NULL;
	for (rec = mainwindows_find_lower(NULL); rec != NULL; rec = mainwindows_find_lower(rec)) {
		sorted = g_slist_prepend(sorted, rec);
	}
	if (sorted == NULL)
		return;

	for (;;) {
		int skip_active = FALSE;
		space = 0;
		/* for each line of windows, calculate the space that can be reduced still */
		for (tmp = sorted; tmp != NULL; tmp = tmp->next) {
			int min;
			GSList *line, *ltmp;
			rec = tmp->data;
			line = mainwindows_get_line(rec);
			min = screen_height - ydiff;
			for (ltmp = line; ltmp != NULL; ltmp = ltmp->next) {
				int lmin;
				MAIN_WINDOW_REC *win = ltmp->data;
				if (win == active_mainwin && tmp == sorted)
					skip_active = TRUE;

				lmin = MAIN_WINDOW_TEXT_HEIGHT(win) - WINDOW_MIN_SIZE;
				if (lmin < min)
					min = lmin;
			}
			g_slist_free(line);
			space += min;
		}

		if (space >= -ydiff)
			break;

		rec = sorted->data;
		if (skip_active && sorted->next != NULL)
			rec = sorted->next->data;
		sorted = g_slist_remove(sorted, rec);

		if (sorted != NULL) {
			/* terminal is too small - destroy the
			   uppest window and try again */
			GSList *line, *ltmp;
			line = mainwindows_get_line(rec);
			for (ltmp = line; ltmp != NULL; ltmp = ltmp->next) {
				MAIN_WINDOW_REC *win = ltmp->data;
				mainwindow_destroy(win);
			}
			g_slist_free(line);
		} else {
			/* only one line of window in screen.. just force the resize */
			GSList *line, *ltmp;
			line = mainwindows_get_line(rec);
			for (ltmp = line; ltmp != NULL; ltmp = ltmp->next) {
				MAIN_WINDOW_REC *win = ltmp->data;
				win->last_line += ydiff;
				mainwindow_resize(win, 0, ydiff);
			}
			g_slist_free(line);
			return;
		}
	}

	/* resize windows that have space */
	for (tmp = sorted; tmp != NULL && ydiff < 0; tmp = tmp->next) {
		int min;
		GSList *line, *ltmp;

		rec = tmp->data;
		line = mainwindows_get_line(rec);
		min = screen_height - ydiff;
		for (ltmp = line; ltmp != NULL; ltmp = ltmp->next) {
			int lmin;
			MAIN_WINDOW_REC *win = ltmp->data;
			lmin = MAIN_WINDOW_TEXT_HEIGHT(win) - WINDOW_MIN_SIZE;
			if (lmin < min)
				min = lmin;
		}
		space = min;

		if (space == 0) {
			/* move the line */
			for (ltmp = line; ltmp != NULL; ltmp = ltmp->next) {
				MAIN_WINDOW_REC *win = ltmp->data;
				mainwindow_resize(win, 0, 0);
				win->size_dirty = TRUE;
				win->first_line += ydiff;
				win->last_line += ydiff;
				signal_emit("mainwindow moved", 1, win);
			}
		} else {
			if (space > -ydiff)
				space = -ydiff;
			for (ltmp = line; ltmp != NULL; ltmp = ltmp->next) {
				MAIN_WINDOW_REC *win = ltmp->data;
				win->last_line += ydiff;
				win->first_line += ydiff + space;

				mainwindow_resize(win, 0, -space);
			}
			ydiff += space;
		}
		g_slist_free(line);
	}

	g_slist_free(sorted);
}

static void mainwindows_rresize_line(int xdiff, MAIN_WINDOW_REC *win)
{
	int windows, i, extra_width, next_column, shrunk;
	int *widths;
	GSList *line, *tmp;
	int new_avail, old_avail, width_mod;

	line = mainwindows_get_line(win);
	windows = g_slist_length(line);
	widths = g_new0(int, windows);

	/* Available text width on this line should respect globally reserved columns */
	new_avail = screen_width - screen_reserved_left - screen_reserved_right - windows + 1;
	old_avail =
	    (screen_width - xdiff) - screen_reserved_left - screen_reserved_right - windows + 1;
	extra_width = new_avail;
	for (tmp = line, i = 0; tmp != NULL; tmp = tmp->next, i++) {
		MAIN_WINDOW_REC *rec = tmp->data;
		/* Scale each window proportionally based on available text widths (excluding
		 * reserved columns) */
		widths[i] = old_avail > 0 ? (MAIN_WINDOW_TEXT_WIDTH(rec) * new_avail) / old_avail :
		                            MAIN_WINDOW_TEXT_WIDTH(rec);
		extra_width -= widths[i] + rec->statusbar_columns;
	}
	shrunk = FALSE;
	for (i = windows; extra_width < 0; i = i > 1 ? i - 1 : windows) {
		if (widths[i - 1] > NEW_WINDOW_WIDTH || (i == 1 && !shrunk)) {
			widths[i - 1]--;
			extra_width++;
			shrunk = i == 1;
		}
	}

	/* Start after reserved left columns */
	next_column = screen_reserved_left;

	/* Distribute any leftover width across windows; base modulo on available width */
	width_mod = new_avail % windows;
#define extra                                                                                      \
	((i >= width_mod && i < extra_width + width_mod) ||                                        \
	         i + windows < extra_width + width_mod ?                                           \
	     1 :                                                                                   \
	     0)

	for (tmp = line, i = 0; tmp != NULL; tmp = tmp->next, i++) {
		MAIN_WINDOW_REC *rec = tmp->data;
		gboolean is_last = (tmp->next == NULL);
		rec->first_column = next_column;
		if (is_last) {
			/* Anchor rightmost window to reserved-right boundary to avoid gap/lag */
			rec->last_column = screen_width - 1 - screen_reserved_right;
			mainwindow_resize(
			    rec, (rec->last_column - rec->first_column + 1) - rec->width, 0);
		} else {
			rec->last_column =
			    rec->first_column + widths[i] + rec->statusbar_columns + extra - 1;
			/* Ensure we never write past the globally reserved right columns */
			if (rec->last_column > screen_width - 1 - screen_reserved_right)
				rec->last_column = screen_width - 1 - screen_reserved_right;
			mainwindow_resize(
			    rec, widths[i] + rec->statusbar_columns + extra - rec->width, 0);
		}
		rec->size_dirty = TRUE;
		next_column = rec->last_column + 2;
	}
#undef extra

	g_free(widths);
	g_slist_free(line);
}

void mainwindows_resize(int width, int height)
{
	int xdiff, ydiff;

	xdiff = width - screen_width;
	ydiff = height - screen_height;
	screen_width = width;
	screen_height = height;

	/* Collapse mode: allow resize down to 1x1 and avoid destructive layout. */
	{
		int avail_w = screen_width - screen_reserved_left - screen_reserved_right;
		int avail_h = screen_height - screen_reserved_top - screen_reserved_bottom;
		if (avail_w <= 1 || avail_h <= 1) {
			GSList *tmp;
			if (!screen_collapsed)
				screen_collapsed = 1;
			for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
				MAIN_WINDOW_REC *rec = tmp->data;
				rec->first_column = screen_reserved_left;
				rec->last_column = screen_reserved_left;
				rec->width = 1;
				rec->first_line = screen_reserved_top;
				rec->last_line = screen_reserved_top;
				rec->height = 1;
				rec->size_dirty = TRUE;
				rec->dirty = TRUE;
			}
			signal_emit("terminal resized", 0);
			irssi_redraw();
			return;
		} else if (screen_collapsed) {
			/* Recover from collapsed state: reflow horizontally. */
			MAIN_WINDOW_REC *win;
			screen_collapsed = 0;
			for (win = mainwindows_find_lower(NULL); win != NULL;
			     win = mainwindows_find_lower(win)) {
				mainwindows_rresize_line(0, win);
			}
			irssi_set_dirty();
		}
	}

	if (ydiff > 0) {
		/* algorithm: enlarge bottom window */
		MAIN_WINDOW_REC *rec;
		GSList *line, *tmp;
		line = mainwindows_get_line(mainwindows_find_upper(NULL));
		for (tmp = line; tmp != NULL; tmp = tmp->next) {
			rec = tmp->data;
			rec->last_line += ydiff;
			mainwindow_resize(rec, 0, ydiff);
		}
		g_slist_free(line);
	}

	if (xdiff > 0) {
		/* algorithm: distribute new space on each line */
		MAIN_WINDOW_REC *win;

		for (win = mainwindows_find_lower(NULL); win != NULL;
		     win = mainwindows_find_lower(win)) {
			mainwindows_rresize_line(xdiff, win);
		}
	}

	if (xdiff < 0) {
		/* algorithm: shrink each window,
		   destroy windows on the right if no room */
		MAIN_WINDOW_REC *win;

		for (win = mainwindows_find_lower(NULL); win != NULL;
		     win = mainwindows_find_lower(win)) {
			int max_windows, i, last_column;
			GSList *line, *tmp;

			line = mainwindows_get_line(win);
			/* Respect globally reserved columns when computing capacity */
			max_windows =
			    (screen_width - screen_reserved_left - screen_reserved_right + 1) /
			    (NEW_WINDOW_WIDTH + 1);
			if (max_windows < 1)
				max_windows = 1;
			last_column = screen_width - 1 - screen_reserved_right;
			for (tmp = line, i = 0; tmp != NULL; tmp = tmp->next, i++) {
				MAIN_WINDOW_REC *rec = tmp->data;
				if (i >= max_windows)
					mainwindow_destroy_half(rec);
				else
					last_column = rec->last_column;
			}
			win = line->data;
			g_slist_free(line);

			mainwindows_rresize_line(
			    screen_width - screen_reserved_right - last_column + 1, win);
		}
	}

	if (ydiff < 0) {
		/* algorithm: shrink windows starting from bottom,
		   destroy windows starting from top if no room */
		mainwindows_resize_smaller(ydiff);
	}

	/* if we lost our active mainwin, get a new one */
	if (active_mainwin == NULL && active_win != NULL && !quitting) {
		active_mainwin = WINDOW_MAIN(active_win);
		window_set_active(active_mainwin->active);
	}

	signal_emit("terminal resized", 0);

	irssi_redraw();
}

int mainwindows_reserve_lines(int top, int bottom)
{
	MAIN_WINDOW_REC *window;
	int ret;

	ret = -1;
	if (top != 0) {
		GSList *list, *tmp;
		g_return_val_if_fail(top > 0 || screen_reserved_top > top, -1);

		ret = screen_reserved_top;
		screen_reserved_top += top;

		list = mainwindows_get_line(mainwindows_find_lower(NULL));
		for (tmp = list; tmp != NULL; tmp = tmp->next) {
			window = tmp->data;
			window->first_line += top;
			mainwindow_resize(window, 0, -top);
		}
		g_slist_free(list);
	}

	if (bottom != 0) {
		GSList *list, *tmp;
		g_return_val_if_fail(bottom > 0 || screen_reserved_bottom > bottom, -1);

		ret = screen_reserved_bottom;
		screen_reserved_bottom += bottom;

		list = mainwindows_get_line(mainwindows_find_upper(NULL));
		for (tmp = list; tmp != NULL; tmp = tmp->next) {
			window = tmp->data;
			window->last_line -= bottom;
			mainwindow_resize(window, 0, -bottom);
		}
		g_slist_free(list);
	}

	return ret;
}

int mainwindow_set_statusbar_lines(MAIN_WINDOW_REC *window, int top, int bottom)
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

	if (top + bottom != 0)
		window->size_dirty = TRUE;

	return ret;
}

static void mainwindows_resize_two(GSList *grow_list, GSList *shrink_list, int count)
{
	GSList *tmp;
	MAIN_WINDOW_REC *win;

	irssi_set_dirty();

	for (tmp = shrink_list; tmp != NULL; tmp = tmp->next) {
		win = tmp->data;
		mainwindow_resize(win, 0, -count);
		win->dirty = TRUE;
	}
	for (tmp = grow_list; tmp != NULL; tmp = tmp->next) {
		win = tmp->data;
		mainwindow_resize(win, 0, count);
		win->dirty = TRUE;
	}
}

static int try_shrink_lower(MAIN_WINDOW_REC *window, int count)
{
	MAIN_WINDOW_REC *shrink_win;

	g_return_val_if_fail(count >= 0, FALSE);

	shrink_win = mainwindows_find_lower(window);
	if (shrink_win != NULL) {
		int ok;
		GSList *shrink_list, *tmp;
		MAIN_WINDOW_REC *win;

		ok = TRUE;
		shrink_list = mainwindows_get_line(shrink_win);

		for (tmp = shrink_list; tmp != NULL; tmp = tmp->next) {
			win = tmp->data;
			if (MAIN_WINDOW_TEXT_HEIGHT(win) - count < WINDOW_MIN_SIZE) {
				ok = FALSE;
				break;
			}
		}
		if (ok) {
			GSList *grow_list;
			grow_list = mainwindows_get_line(window);

			for (tmp = shrink_list; tmp != NULL; tmp = tmp->next) {
				win = tmp->data;
				win->first_line += count;
			}
			for (tmp = grow_list; tmp != NULL; tmp = tmp->next) {
				win = tmp->data;
				win->last_line += count;
			}

			mainwindows_resize_two(grow_list, shrink_list, count);
			g_slist_free(grow_list);
		}

		g_slist_free(shrink_list);
		return ok;
	}

	return FALSE;
}

static int try_shrink_upper(MAIN_WINDOW_REC *window, int count)
{
	MAIN_WINDOW_REC *shrink_win;

	g_return_val_if_fail(count >= 0, FALSE);

	shrink_win = mainwindows_find_upper(window);
	if (shrink_win != NULL) {
		int ok;
		GSList *shrink_list, *tmp;
		MAIN_WINDOW_REC *win;

		ok = TRUE;
		shrink_list = mainwindows_get_line(shrink_win);

		for (tmp = shrink_list; tmp != NULL; tmp = tmp->next) {
			win = tmp->data;
			if (MAIN_WINDOW_TEXT_HEIGHT(win) - count < WINDOW_MIN_SIZE) {
				ok = FALSE;
				break;
			}
		}
		if (ok) {
			GSList *grow_list;
			grow_list = mainwindows_get_line(window);
			for (tmp = grow_list; tmp != NULL; tmp = tmp->next) {
				win = tmp->data;
				win->first_line -= count;
			}
			for (tmp = shrink_list; tmp != NULL; tmp = tmp->next) {
				win = tmp->data;
				win->last_line -= count;
			}
			mainwindows_resize_two(grow_list, shrink_list, count);
			g_slist_free(grow_list);
		}
		g_slist_free(shrink_list);
		return ok;
	}

	return FALSE;
}

static int mainwindow_grow(MAIN_WINDOW_REC *window, int count, int resize_lower)
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

	grow_win = mainwindows_find_lower(window);
	if (grow_win != NULL) {
		MAIN_WINDOW_REC *win;
		GSList *grow_list, *shrink_list, *tmp;
		grow_list = mainwindows_get_line(grow_win);
		shrink_list = mainwindows_get_line(window);
		for (tmp = grow_list; tmp != NULL; tmp = tmp->next) {
			win = tmp->data;
			win->first_line -= count;
		}
		for (tmp = shrink_list; tmp != NULL; tmp = tmp->next) {
			win = tmp->data;
			win->last_line -= count;
		}
		mainwindows_resize_two(grow_list, shrink_list, count);
		g_slist_free(shrink_list);
		g_slist_free(grow_list);
	}

	return grow_win != NULL;
}

static int try_grow_upper(MAIN_WINDOW_REC *window, int count)
{
	MAIN_WINDOW_REC *grow_win;

	grow_win = mainwindows_find_upper(window);
	if (grow_win != NULL) {
		MAIN_WINDOW_REC *win;
		GSList *grow_list, *shrink_list, *tmp;
		grow_list = mainwindows_get_line(grow_win);
		shrink_list = mainwindows_get_line(window);
		for (tmp = grow_list; tmp != NULL; tmp = tmp->next) {
			win = tmp->data;
			win->last_line += count;
		}
		for (tmp = shrink_list; tmp != NULL; tmp = tmp->next) {
			win = tmp->data;
			win->first_line += count;
		}
		mainwindows_resize_two(grow_list, shrink_list, count);
		g_slist_free(shrink_list);
		g_slist_free(grow_list);
	}

	return grow_win != NULL;
}

static int mainwindow_shrink(MAIN_WINDOW_REC *window, int count, int resize_lower)
{
	g_return_val_if_fail(count >= 0, FALSE);

	if (MAIN_WINDOW_TEXT_HEIGHT(window) - count < WINDOW_MIN_SIZE)
		return FALSE;

	if (!resize_lower || !try_grow_lower(window, count)) {
		if (!try_grow_upper(window, count)) {
			if (resize_lower || !try_grow_lower(window, count))
				return FALSE;
		}
	}

	return TRUE;
}

static void mainwindows_rresize_two(MAIN_WINDOW_REC *grow_win, MAIN_WINDOW_REC *shrink_win,
                                    int count)
{
	irssi_set_dirty();

	mainwindow_resize(grow_win, count, 0);
	mainwindow_resize(shrink_win, -count, 0);
	grow_win->dirty = TRUE;
	shrink_win->dirty = TRUE;
}

static int try_shrink_right(MAIN_WINDOW_REC *window, int count)
{
	MAIN_WINDOW_REC *shrink_win;

	g_return_val_if_fail(count >= 0, FALSE);

	shrink_win = mainwindows_find_right(window, FALSE);
	if (shrink_win != NULL) {
		if (MAIN_WINDOW_TEXT_WIDTH(shrink_win) - count < NEW_WINDOW_WIDTH) {
			return FALSE;
		}

		shrink_win->first_column += count;
		window->last_column += count;

		mainwindows_rresize_two(window, shrink_win, count);
		return TRUE;
	}

	return FALSE;
}

static int try_shrink_left(MAIN_WINDOW_REC *window, int count)
{
	MAIN_WINDOW_REC *shrink_win;

	g_return_val_if_fail(count >= 0, FALSE);

	shrink_win = mainwindows_find_left(window, FALSE);
	if (shrink_win != NULL) {
		if (MAIN_WINDOW_TEXT_WIDTH(shrink_win) - count < NEW_WINDOW_WIDTH) {
			return FALSE;
		}
		window->first_column -= count;
		shrink_win->last_column -= count;

		mainwindows_rresize_two(window, shrink_win, count);
		return TRUE;
	}

	return FALSE;
}

static int mainwindow_grow_right(MAIN_WINDOW_REC *window, int count)
{
	if (!try_shrink_right(window, count)) {
		if (!try_shrink_left(window, count))
			return FALSE;
	}

	return TRUE;
}

static int try_grow_right(MAIN_WINDOW_REC *window, int count)
{
	MAIN_WINDOW_REC *grow_win;

	grow_win = mainwindows_find_right(window, FALSE);
	if (grow_win != NULL) {
		grow_win->first_column -= count;
		window->last_column -= count;
		mainwindows_rresize_two(grow_win, window, count);
		return TRUE;
	}

	return FALSE;
}

static int try_grow_left(MAIN_WINDOW_REC *window, int count)
{
	MAIN_WINDOW_REC *grow_win;

	grow_win = mainwindows_find_left(window, FALSE);
	if (grow_win != NULL) {
		grow_win->last_column += count;
		window->first_column += count;
		mainwindows_rresize_two(grow_win, window, count);
		return TRUE;
	}

	return FALSE;
}

static int mainwindow_shrink_right(MAIN_WINDOW_REC *window, int count)
{
	g_return_val_if_fail(count >= 0, FALSE);

	if (MAIN_WINDOW_TEXT_WIDTH(window) - count < NEW_WINDOW_WIDTH)
		return FALSE;

	if (!try_grow_right(window, count)) {
		if (!try_grow_left(window, count))
			return FALSE;
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

void mainwindow_set_rsize(MAIN_WINDOW_REC *window, int width)
{
	width -= window->width;
	if (width < 0)
		mainwindow_shrink_right(window, -width);
	else
		mainwindow_grow_right(window, width);
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
		} else if (WINDOW_GUI(rec->active)->view->dirty) {
			gui_window_redraw(rec->active);
		}
	}
}

static void mainwindow_grow_int(int count)
{
	if (count == 0) {
		return;
	} else if (count < 0) {
		if (!mainwindow_shrink(WINDOW_MAIN(active_win), -count, FALSE)) {
			printformat_window(active_win, MSGLEVEL_CLIENTNOTICE, TXT_WINDOW_TOO_SMALL);
		}
	} else {
		if (!mainwindow_grow(WINDOW_MAIN(active_win), count, FALSE)) {
			printformat_window(active_win, MSGLEVEL_CLIENTNOTICE, TXT_WINDOW_TOO_SMALL);
		}
	}
}

static void window_balance_vertical(void)
{
	GSList *sorted, *stmp, *line, *ltmp;
	int avail_size, unit_size, bigger_units;
	int windows, last_line, old_size;
	MAIN_WINDOW_REC *win;

	windows = g_slist_length(mainwindows);
	if (windows == 1)
		return;

	sorted = NULL;
	windows = 0;
	for (win = mainwindows_find_lower(NULL); win != NULL; win = mainwindows_find_lower(win)) {
		windows++;
		sorted = g_slist_append(sorted, win);
	}

	avail_size = term_height - screen_reserved_top - screen_reserved_bottom;
	unit_size = avail_size / windows;
	bigger_units = avail_size % windows;

	last_line = screen_reserved_top;
	for (stmp = sorted; stmp != NULL; stmp = stmp->next) {
		win = stmp->data;
		line = mainwindows_get_line(win);

		for (ltmp = line; ltmp != NULL; ltmp = ltmp->next) {
			MAIN_WINDOW_REC *rec = ltmp->data;
			old_size = rec->height;
			rec->first_line = last_line;
			rec->last_line = rec->first_line + unit_size - 1;

			if (bigger_units > 0) {
				rec->last_line++;
			}

			mainwindow_resize(rec, 0, rec->last_line - rec->first_line + 1 - old_size);
		}
		if (line != NULL && bigger_units > 0) {
			bigger_units--;
		}
		last_line = win->last_line + 1;

		g_slist_free(line);
	}
	g_slist_free(sorted);

	mainwindows_redraw();
}

/* SYNTAX: WINDOW HIDE [<number>|<name>] */
static void cmd_window_hide(const char *data)
{
	WINDOW_REC *window;

	if (mainwindows->next == NULL) {
		printformat_window(active_win, MSGLEVEL_CLIENTNOTICE, TXT_CANT_HIDE_LAST);
		return;
	}

	if (*data == '\0')
		window = active_win;
	else if (is_numeric(data, 0)) {
		window = window_find_refnum(atoi(data));
		if (window == NULL) {
			printformat_window(active_win, MSGLEVEL_CLIENTERROR, TXT_REFNUM_NOT_FOUND,
			                   data);
		}
	} else {
		window = window_find_item(active_win->active_server, data);
	}

	if (window == NULL || !is_window_visible(window))
		return;

	if (WINDOW_MAIN(window)->sticky_windows) {
		if (!settings_get_bool("autounstick_windows")) {
			printformat_window(active_win, MSGLEVEL_CLIENTERROR,
			                   TXT_CANT_HIDE_STICKY_WINDOWS);
			return;
		}
	}

	mainwindow_destroy(WINDOW_MAIN(window));

	if (active_mainwin == NULL) {
		active_mainwin = WINDOW_MAIN(active_win);
		window_set_active(active_mainwin->active);
	}
}

/* SYNTAX: WINDOW SHOW [-right] <number>|<name> */
static void cmd_window_show(const char *data)
{
	GHashTable *optlist;
	MAIN_WINDOW_REC *parent;
	WINDOW_REC *window;
	char *args;
	void *free_arg;
	int right;

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_GETREST | PARAM_FLAG_OPTIONS,
	                    "window show", &optlist, &args))
		return;

	right = g_hash_table_lookup(optlist, "right") != NULL;

	if (*args == '\0') {
		cmd_params_free(free_arg);
		cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);
	}

	if (is_numeric(args, '\0')) {
		window = window_find_refnum(atoi(args));
		if (window == NULL) {
			printformat_window(active_win, MSGLEVEL_CLIENTERROR, TXT_REFNUM_NOT_FOUND,
			                   args);
		}
	} else {
		window = window_find_item(active_win->active_server, args);
	}

	cmd_params_free(free_arg);

	if (window == NULL || is_window_visible(window))
		return;

	if (WINDOW_GUI(window)->sticky) {
		if (!settings_get_bool("autounstick_windows")) {
			printformat_window(active_win, MSGLEVEL_CLIENTERROR,
			                   TXT_CANT_SHOW_STICKY_WINDOWS);
			return;
		}
	}

	parent = mainwindow_create(right);
	if (parent == NULL) {
		printformat_window(active_win, MSGLEVEL_CLIENTERROR, TXT_WINDOW_TOO_SMALL);
		return;
	}

	parent->active = window;
	gui_window_reparent(window, parent);

	if (settings_get_bool("autostick_split_windows"))
		gui_window_set_sticky(window);

	active_mainwin = NULL;
	window_set_active(window);
}

static void mainwindow_grow_right_int(int count)
{
	if (count == 0) {
		return;
	} else if (count < 0) {
		if (!mainwindow_shrink_right(WINDOW_MAIN(active_win), -count)) {
			printformat_window(active_win, MSGLEVEL_CLIENTNOTICE, TXT_WINDOW_TOO_SMALL);
		}
	} else {
		if (!mainwindow_grow_right(WINDOW_MAIN(active_win), count)) {
			printformat_window(active_win, MSGLEVEL_CLIENTNOTICE, TXT_WINDOW_TOO_SMALL);
		}
	}
}

/* SYNTAX: WINDOW GROW [-right] [<lines>|<columns>] */
static void cmd_window_grow(const char *data)
{
	GHashTable *optlist;
	char *args;
	void *free_arg;
	int count;

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_GETREST | PARAM_FLAG_OPTIONS,
	                    "window grow", &optlist, &args))
		return;

	count = *data == '\0' ? 1 : atoi(args);

	if (g_hash_table_lookup(optlist, "right") != NULL) {
		mainwindow_grow_right_int(count);
	} else {
		mainwindow_grow_int(count);
	}

	cmd_params_free(free_arg);
}

/* SYNTAX: WINDOW SHRINK [-right] [<lines>|<columns>] */
static void cmd_window_shrink(const char *data)
{
	GHashTable *optlist;
	char *args;
	void *free_arg;
	int count;

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_GETREST | PARAM_FLAG_OPTIONS,
	                    "window shrink", &optlist, &args))
		return;

	count = *data == '\0' ? 1 : atoi(args);
	if (count < -INT_MAX)
		count = -INT_MAX;

	if (g_hash_table_lookup(optlist, "right") != NULL) {
		mainwindow_grow_right_int(-count);
	} else {
		mainwindow_grow_int(-count);
	}

	cmd_params_free(free_arg);
}

/* SYNTAX: WINDOW SIZE [-right] <lines>|<columns> */
static void cmd_window_size(const char *data)
{
	GHashTable *optlist;
	char *args;
	void *free_arg;
	int size;

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_GETREST | PARAM_FLAG_OPTIONS,
	                    "window size", &optlist, &args))
		return;

	if (!is_numeric(args, 0)) {
		cmd_params_free(free_arg);
		return;
	}
	size = atoi(data);

	if (g_hash_table_lookup(optlist, "right") != NULL) {
		size -= MAIN_WINDOW_TEXT_WIDTH(WINDOW_MAIN(active_win));

		mainwindow_grow_right_int(size);
	} else {
		size -= WINDOW_MAIN(active_win)->height - WINDOW_MAIN(active_win)->statusbar_lines;
		if (size < -INT_MAX)
			size = -INT_MAX;

		mainwindow_grow_int(size);
	}

	cmd_params_free(free_arg);
}

static void window_balance_horizontal(void)
{
	GSList *line, *ltmp;
	int avail_width, unit_width, bigger_units;
	int windows, last_column, old_width;
	MAIN_WINDOW_REC *win;

	line = mainwindows_get_line(WINDOW_MAIN(active_win));
	windows = g_slist_length(line);
	if (windows == 1) {
		g_slist_free(line);
		return;
	}

	avail_width = term_width - screen_reserved_left - screen_reserved_right - windows + 1;
	unit_width = avail_width / windows;
	bigger_units = avail_width % windows;

	last_column = screen_reserved_left;
	for (ltmp = line; ltmp != NULL; ltmp = ltmp->next) {
		win = ltmp->data;
		old_width = win->width;
		win->first_column = last_column;
		win->last_column = win->first_column + unit_width - 1;

		if (bigger_units > 0) {
			win->last_column++;
			bigger_units--;
		}

		mainwindow_resize(win, win->last_column - win->first_column + 1 - old_width, 0);
		last_column = win->last_column + 2;
	}
	g_slist_free(line);

	mainwindows_redraw();
}

/* SYNTAX: WINDOW BALANCE [-right] */
static void cmd_window_balance(const char *data)
{
	GHashTable *optlist;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, PARAM_FLAG_GETREST | PARAM_FLAG_OPTIONS,
	                    "window balance", &optlist))
		return;

	if (g_hash_table_lookup(optlist, "right") != NULL) {
		window_balance_horizontal();
	} else {
		window_balance_vertical();
	}

	cmd_params_free(free_arg);
}

/* SYNTAX: WINDOW UP [-directional] */
static void cmd_window_up(const char *data)
{
	MAIN_WINDOW_REC *rec;
	GHashTable *optlist;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, PARAM_FLAG_GETREST | PARAM_FLAG_OPTIONS, "window up",
	                    &optlist))
		return;

	if (g_hash_table_lookup(optlist, "directional") != NULL) {
		rec = mainwindows_find_upper(active_mainwin);
		if (rec == NULL)
			rec = mainwindows_find_upper(NULL);
	} else {
		rec = mainwindows_find_left_upper(active_mainwin);
		if (rec == NULL)
			rec = mainwindows_find_left_upper(NULL);
	}
	if (rec != NULL)
		window_set_active(rec->active);

	cmd_params_free(free_arg);
}

/* SYNTAX: WINDOW DOWN [-directional] */
static void cmd_window_down(const char *data)
{
	MAIN_WINDOW_REC *rec;
	GHashTable *optlist;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, PARAM_FLAG_GETREST | PARAM_FLAG_OPTIONS, "window down",
	                    &optlist))
		return;

	if (g_hash_table_lookup(optlist, "directional") != NULL) {
		rec = mainwindows_find_lower(active_mainwin);
		if (rec == NULL)
			rec = mainwindows_find_lower(NULL);
	} else {
		rec = mainwindows_find_lower_right(active_mainwin);
		if (rec == NULL)
			rec = mainwindows_find_lower_right(NULL);
	}

	if (rec != NULL)
		window_set_active(rec->active);

	cmd_params_free(free_arg);
}

#define WINDOW_STICKY_MATCH(window, sticky_parent)                                                 \
	((!WINDOW_GUI(window)->sticky && (sticky_parent) == NULL) ||                               \
	 (WINDOW_GUI(window)->sticky && WINDOW_MAIN(window) == (sticky_parent)))

static int window_refnum_left(int refnum, int wrap)
{
	MAIN_WINDOW_REC *find_sticky;
	WINDOW_REC *window;
	int start_refnum = refnum;

	window = window_find_refnum(refnum);
	g_return_val_if_fail(window != NULL, -1);

	find_sticky = WINDOW_MAIN(window)->sticky_windows ? WINDOW_MAIN(window) : NULL;

	do {
		refnum = window_refnum_prev(refnum, wrap);
		if (refnum < 0 || refnum == start_refnum)
			break;

		window = window_find_refnum(refnum);
	} while (!WINDOW_STICKY_MATCH(window, find_sticky) || is_window_visible(window));

	return refnum;
}

static int window_refnum_right(int refnum, int wrap)
{
	MAIN_WINDOW_REC *find_sticky;
	WINDOW_REC *window;
	int start_refnum = refnum;

	window = window_find_refnum(refnum);
	g_return_val_if_fail(window != NULL, -1);

	find_sticky = WINDOW_MAIN(window)->sticky_windows ? WINDOW_MAIN(window) : NULL;

	do {
		refnum = window_refnum_next(refnum, wrap);
		if (refnum < 0 || refnum == start_refnum)
			break;

		window = window_find_refnum(refnum);
	} while (!WINDOW_STICKY_MATCH(window, find_sticky) || is_window_visible(window));

	return refnum;
}

/* SYNTAX: WINDOW LEFT [-directional] */
static void cmd_window_left(const char *data, SERVER_REC *server, void *item)
{
	GHashTable *optlist;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, PARAM_FLAG_GETREST | PARAM_FLAG_OPTIONS, "window left",
	                    &optlist))
		return;

	if (g_hash_table_lookup(optlist, "directional") != NULL) {
		MAIN_WINDOW_REC *rec;

		rec = mainwindows_find_left(active_mainwin, FALSE);
		if (rec == NULL)
			rec = mainwindows_find_left(active_mainwin, TRUE);
		if (rec != NULL)
			window_set_active(rec->active);
	} else {
		int refnum;

		refnum = window_refnum_left(active_win->refnum, TRUE);
		if (refnum != -1)
			window_set_active(window_find_refnum(refnum));
	}

	cmd_params_free(free_arg);
}

/* SYNTAX: WINDOW RIGHT [-directional] */
static void cmd_window_right(const char *data)
{
	GHashTable *optlist;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, PARAM_FLAG_GETREST | PARAM_FLAG_OPTIONS,
	                    "window right", &optlist))
		return;

	if (g_hash_table_lookup(optlist, "directional") != NULL) {
		MAIN_WINDOW_REC *rec;

		rec = mainwindows_find_right(active_mainwin, FALSE);
		if (rec == NULL)
			rec = mainwindows_find_right(active_mainwin, TRUE);
		if (rec != NULL)
			window_set_active(rec->active);
	} else {
		int refnum;

		refnum = window_refnum_right(active_win->refnum, TRUE);
		if (refnum != -1)
			window_set_active(window_find_refnum(refnum));
	}

	cmd_params_free(free_arg);
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
			printformat_window(active_win, MSGLEVEL_CLIENTERROR, TXT_REFNUM_NOT_FOUND,
			                   data);
			return;
		}

		while (*data != ' ' && *data != '\0')
			data++;
		while (*data == ' ')
			data++;
	}

	if (g_ascii_strncasecmp(data, "OF", 2) == 0 || i_toupper(*data) == 'N') {
		/* unset sticky */
		if (!WINDOW_GUI(win)->sticky) {
			printformat_window(win, MSGLEVEL_CLIENTERROR, TXT_WINDOW_NOT_STICKY);
		} else {
			gui_window_set_unsticky(win);
			printformat_window(win, MSGLEVEL_CLIENTNOTICE, TXT_WINDOW_UNSET_STICKY);
		}
	} else {
		/* set sticky */
		window_reparent(win, mainwin);
		gui_window_set_sticky(win);

		printformat_window(active_win, MSGLEVEL_CLIENTNOTICE, TXT_WINDOW_SET_STICKY);
	}
}

/* SYNTAX: WINDOW MOVE LEFT [-directional] */
static void cmd_window_move_left(const char *data)
{
	GHashTable *optlist;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, PARAM_FLAG_GETREST | PARAM_FLAG_OPTIONS,
	                    "window move left", &optlist))
		return;

	if (g_hash_table_lookup(optlist, "directional") != NULL) {
		MAIN_WINDOW_REC *rec;

		rec = mainwindows_find_left(active_mainwin, FALSE);
		if (rec == NULL)
			rec = mainwindows_find_left(active_mainwin, TRUE);
		if (rec != NULL)
			window_reparent(active_win, rec);
	} else {
		int refnum;

		refnum = window_refnum_left(active_win->refnum, TRUE);
		if (refnum != -1)
			window_set_refnum(active_win, refnum);
	}

	cmd_params_free(free_arg);
}

/* SYNTAX: WINDOW MOVE RIGHT [-directional] */
static void cmd_window_move_right(const char *data)
{
	GHashTable *optlist;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, PARAM_FLAG_GETREST | PARAM_FLAG_OPTIONS,
	                    "window move right", &optlist))
		return;

	if (g_hash_table_lookup(optlist, "directional") != NULL) {
		MAIN_WINDOW_REC *rec;

		rec = mainwindows_find_right(active_mainwin, FALSE);
		if (rec == NULL)
			rec = mainwindows_find_right(active_mainwin, TRUE);
		if (rec != NULL)
			window_reparent(active_win, rec);
	} else {
		int refnum;

		refnum = window_refnum_right(active_win->refnum, TRUE);
		if (refnum != -1)
			window_set_refnum(active_win, refnum);
	}

	cmd_params_free(free_arg);
}

/* SYNTAX: WINDOW MOVE UP [-directional] */
static void cmd_window_move_up(const char *data)
{
	MAIN_WINDOW_REC *rec;
	GHashTable *optlist;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, PARAM_FLAG_GETREST | PARAM_FLAG_OPTIONS,
	                    "window move up", &optlist))
		return;

	if (g_hash_table_lookup(optlist, "directional") != NULL) {
		rec = mainwindows_find_upper(active_mainwin);
	} else {
		rec = mainwindows_find_upper_left(active_mainwin);
	}

	if (rec != NULL)
		window_reparent(active_win, rec);

	cmd_params_free(free_arg);
}

/* SYNTAX: WINDOW MOVE DOWN [-directional] */
static void cmd_window_move_down(const char *data)
{
	MAIN_WINDOW_REC *rec;
	GHashTable *optlist;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, PARAM_FLAG_GETREST | PARAM_FLAG_OPTIONS,
	                    "window move down", &optlist))
		return;

	if (g_hash_table_lookup(optlist, "directional") != NULL) {
		rec = mainwindows_find_lower(active_mainwin);
	} else {
		rec = mainwindows_find_lower_right(active_mainwin);
	}

	if (rec != NULL)
		window_reparent(active_win, rec);

	cmd_params_free(free_arg);
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
	g_string_truncate(str, str->len - 2);
	g_slist_free(list);

	printformat_window(win, MSGLEVEL_CLIENTCRAP, TXT_WINDOW_INFO_STICKY, str->str);
	g_string_free(str, TRUE);
}

static void sig_window_print_info(WINDOW_REC *win)
{
	GUI_WINDOW_REC *gui;

	gui = WINDOW_GUI(win);
	if (gui->use_scroll) {
		printformat_window(win, MSGLEVEL_CLIENTCRAP, TXT_WINDOW_INFO_SCROLL,
		                   gui->scroll ? "yes" : "no");
	}

	if (WINDOW_MAIN(win)->sticky_windows)
		windows_print_sticky(win);
}

void mainwindows_init(void)
{
	screen_width = term_width;
	screen_height = term_height;

	mainwindows = NULL;
	active_mainwin = NULL;
	clrtoeol_info = g_new0(MAIN_WINDOW_BORDER_REC, 1);
	screen_reserved_top = screen_reserved_bottom = 0;
	screen_reserved_left = screen_reserved_right = 0;

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

	command_set_options("window show", "right");
	command_set_options("window grow", "right");
	command_set_options("window shrink", "right");
	command_set_options("window size", "right");
	command_set_options("window balance", "right");
	command_set_options("window up", "directional");
	command_set_options("window down", "directional");
	command_set_options("window left", "directional");
	command_set_options("window right", "directional");
	command_set_options("window move left", "directional");
	command_set_options("window move right", "directional");
	command_set_options("window move up", "directional");
	command_set_options("window move down", "directional");
}

void mainwindows_deinit(void)
{
	while (mainwindows != NULL)
		mainwindow_destroy(mainwindows->data);
	g_free(clrtoeol_info);

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

int mainwindows_reserve_columns(int left, int right)
{
	MAIN_WINDOW_REC *window;
	int ret = -1;
	if (left != 0) {
		GSList *list, *tmp;
		g_return_val_if_fail(left > 0 || screen_reserved_left > left, -1);
		ret = screen_reserved_left;
		screen_reserved_left += left;
		list = mainwindows_get_line(mainwindows_find_lower_right(NULL));
		for (tmp = list; tmp != NULL; tmp = tmp->next) {
			window = tmp->data;
			window->first_column += left;
			mainwindow_resize(window, -left, 0);
		}
		g_slist_free(list);
	}
	if (right != 0) {
		GSList *list, *tmp;
		g_return_val_if_fail(right > 0 || screen_reserved_right > right, -1);
		ret = screen_reserved_right;
		screen_reserved_right += right;
		list = mainwindows_get_line(mainwindows_find_left_upper(NULL));
		for (tmp = list; tmp != NULL; tmp = tmp->next) {
			window = tmp->data;
			window->last_column -= right;
			mainwindow_resize(window, -right, 0);
		}
		g_slist_free(list);
	}
	return ret;
}

int mainwindow_set_statusbar_columns(MAIN_WINDOW_REC *window, int left, int right)
{
	int ret = -1;
	if (left != 0) {
		ret = window->statusbar_columns_left;
		window->statusbar_columns_left += left;
		window->statusbar_columns += left;
	}
	if (right != 0) {
		ret = window->statusbar_columns_right;
		window->statusbar_columns_right += right;
		window->statusbar_columns += right;
	}
	if (left + right != 0)
		window->size_dirty = TRUE;
	return ret;
}
