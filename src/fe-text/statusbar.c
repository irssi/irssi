/*
 statusbar.c : irssi

    Copyright (C) 1999-2001 Timo Sirainen

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
#include "signals.h"

#include "themes.h"

#include "statusbar.h"
#include "gui-windows.h"

static int backs[] = { 0, 4, 2, 6, 1, 5, 3, 7 }; /* FIXME: should be in some more generic place.. */

void statusbar_items_init(void);
void statusbar_items_deinit(void);

static GSList *statusbars;
static int sbar_uppest, sbar_lowest, sbars_up, sbars_down;

static void statusbar_item_destroy(SBAR_ITEM_REC *rec)
{
	rec->bar->items = g_slist_remove(rec->bar->items, rec);
	g_free(rec);
}

static int sbar_item_cmp(SBAR_ITEM_REC *item1, SBAR_ITEM_REC *item2)
{
	return item1->priority == item2->priority ? 0 :
		item1->priority < item2->priority ? -1 : 1;
}

static int statusbar_shrink_to_min(GSList *items, int size, int max_width)
{
	GSList *tmp;

	for (tmp = items; tmp != NULL; tmp = tmp->next) {
		SBAR_ITEM_REC *rec = tmp->data;

		size -= (rec->max_size-rec->min_size);
		rec->size = rec->min_size;

		if (size <= max_width) {
			rec->size += max_width-size;
                        break;
		}

		if (rec->size == 0) {
			/* min_size was 0, item removed.
			   remove the marginal too */
                        size--;
		}
	}

        return size;
}

static void statusbar_shrink_forced(GSList *items, int size, int max_width)
{
	GSList *tmp;

	for (tmp = items; tmp != NULL; tmp = tmp->next) {
		SBAR_ITEM_REC *rec = tmp->data;

		if (size-rec->size > max_width) {
			/* remove the whole item */
                        size -= rec->size+1; /* +1 == the marginal */
			rec->size = 0;
		} else {
			/* shrink the item */
			rec->size -= size-max_width;
                        break;
		}
	}
}

static void statusbar_get_sizes(STATUSBAR_REC *bar, int max_width)
{
	GSList *tmp, *prior_sorted;
        int width;

        /* first give items their max. size */
	prior_sorted = NULL;
	width = -1; /* -1 because of the marginals */
	for (tmp = bar->items; tmp != NULL; tmp = tmp->next) {
		SBAR_ITEM_REC *rec = tmp->data;

		rec->func(rec, TRUE);
		rec->size = rec->max_size;

		if (rec->size > 0) {
                        /* +1 == marginal between items */
			width += rec->max_size+1;

			prior_sorted = g_slist_insert_sorted(prior_sorted, rec,
							     (GCompareFunc)
							     sbar_item_cmp);
		}
	}

	if (width > max_width) {
		/* too big, start shrinking from items with lowest priority
		   and shrink until everything fits or until we've shrinked
		   all items. */
		width = statusbar_shrink_to_min(prior_sorted, width,
						max_width);
		if (width > max_width) {
			/* still need to shrink, remove the items with lowest
			   priority until everything fits to screen */
			statusbar_shrink_forced(prior_sorted, width,
						max_width);
		}
	}

	g_slist_free(prior_sorted);
}

static void statusbar_redraw_line(STATUSBAR_REC *bar)
{
        WINDOW_REC *old_active_win;
	GSList *tmp;
	int xpos, rxpos;

	old_active_win = active_win;
        if (bar->window != NULL)
		active_win = bar->window->active;

	statusbar_get_sizes(bar, COLS-2);

	xpos = 1;
	for (tmp = bar->items; tmp != NULL; tmp = tmp->next) {
		SBAR_ITEM_REC *rec = tmp->data;

		if (!rec->right_justify && rec->size > 0) {
			rec->xpos = xpos;
                        xpos += rec->size+1;
                        rec->func(rec, FALSE);
		}
	}

	rxpos = COLS-1;
	for (tmp = bar->items; tmp != NULL; tmp = tmp->next) {
		SBAR_ITEM_REC *rec = tmp->data;

		if (rec->right_justify && rec->size > 0) {
                        rxpos -= rec->size+1;
			rec->xpos = rxpos+1;
			rec->func(rec, FALSE);
		}
	}

	active_win = old_active_win;
}

static void statusbar_redraw_all(void)
{
	screen_refresh_freeze();
	g_slist_foreach(statusbars, (GFunc) statusbar_redraw, NULL);
	screen_refresh_thaw();
}

STATUSBAR_REC *statusbar_find(int pos, int line)
{
	GSList *tmp;

	for (tmp = statusbars; tmp != NULL; tmp = tmp->next) {
		STATUSBAR_REC *rec = tmp->data;

		if (rec->pos == pos && rec->line == line)
			return rec;
	}

	return NULL;
}

void statusbar_redraw(STATUSBAR_REC *bar)
{
	if (bar == NULL) {
		statusbar_redraw_all();
		return;
	}

	set_bg(stdscr, backs[bar->color] << 4);
	move(bar->ypos, 0); clrtoeol();
	set_bg(stdscr, 0);

	statusbar_redraw_line(bar);

        screen_refresh(NULL);
}

void statusbar_item_redraw(SBAR_ITEM_REC *item)
{
	g_return_if_fail(item != NULL);

	item->func(item, TRUE);
	if (item->max_size != item->size)
		statusbar_redraw(item->bar);
	else {
		item->func(item, FALSE);
                screen_refresh(NULL);
	}
}

static int get_last_bg(const char *str)
{
	int last = -1;

	while (*str != '\0') {
		if (*str == '%' && str[1] != '\0') {
                        str++;
			if (*str >= '0' && *str <= '7')
				last = *str-'0';
		}
                str++;
	}

        return last;
}

/* ypos is used only when pos == STATUSBAR_POS_MIDDLE */
STATUSBAR_REC *statusbar_create(int pos, int ypos)
{
	STATUSBAR_REC *rec;
        char *str;

	rec = g_new0(STATUSBAR_REC, 1);
	statusbars = g_slist_append(statusbars, rec);

	rec->pos = pos;
	rec->line = pos == STATUSBAR_POS_MIDDLE ? ypos :
		mainwindows_reserve_lines(1, pos == STATUSBAR_POS_UP);
	rec->ypos = pos == STATUSBAR_POS_MIDDLE ? ypos :
		pos == STATUSBAR_POS_UP ? rec->line : LINES-1-rec->line;

        /* get background color from sb_background abstract */
	str = theme_format_expand(current_theme, "{sb_background}");
	if (str == NULL) str = g_strdup("%n%8");
	rec->color_string = g_strconcat("%n", str, NULL);
        g_free(str);

	rec->color = get_last_bg(rec->color_string);
        if (rec->color < 0) rec->color = current_theme->default_real_color;

	if (pos == STATUSBAR_POS_UP) {
                if (sbars_up == 0) sbar_uppest = rec->line;
                sbars_up++;
		rec->line -= sbar_uppest;
	} else if (pos == STATUSBAR_POS_DOWN) {
		if (sbars_down == 0) sbar_lowest = rec->line;
		sbars_down++;
		rec->line -= sbar_lowest;
	}

	set_bg(stdscr, backs[rec->color] << 4);
	move(rec->ypos, 0); clrtoeol();
	set_bg(stdscr, 0);

	return rec;
}

static void statusbars_pack(int pos, int line)
{
	GSList *tmp;

	for (tmp = statusbars; tmp != NULL; tmp = tmp->next) {
		STATUSBAR_REC *rec = tmp->data;

		if (rec->pos == pos && rec->line > line) {
			rec->line--;
			rec->ypos += (pos == STATUSBAR_POS_UP ? -1 : 1);
		}
	}
}

void statusbar_destroy(STATUSBAR_REC *bar)
{
	g_return_if_fail(bar != NULL);

	if (bar->pos != STATUSBAR_POS_MIDDLE)
		mainwindows_reserve_lines(-1, bar->pos == STATUSBAR_POS_UP);

	if (bar->pos == STATUSBAR_POS_UP) sbars_up--;
	if (bar->pos == STATUSBAR_POS_DOWN) sbars_down--;
        statusbars = g_slist_remove(statusbars, bar);

	while (bar->items != NULL)
		statusbar_item_destroy(bar->items->data);

	if (bar->pos != STATUSBAR_POS_MIDDLE)
		statusbars_pack(bar->pos, bar->pos);
        g_free(bar->color_string);
	g_free(bar);

	if (!quitting) statusbar_redraw_all();
}

SBAR_ITEM_REC *statusbar_item_create(STATUSBAR_REC *bar,
				     int priority, int right_justify,
				     STATUSBAR_FUNC func)
{
	SBAR_ITEM_REC *rec;

	g_return_val_if_fail(bar != NULL, NULL);
	g_return_val_if_fail(func != NULL, NULL);

	rec = g_new0(SBAR_ITEM_REC, 1);
	rec->bar = bar;
	bar->items = g_slist_append(bar->items, rec);

        rec->priority = priority;
	rec->right_justify = right_justify;
	rec->func = func;

	return rec;
}

void statusbar_item_remove(SBAR_ITEM_REC *item)
{
	g_return_if_fail(item != NULL);

	statusbar_item_destroy(item);
	if (!quitting) statusbar_redraw_all();
}

static void sig_mainwindow_resized(MAIN_WINDOW_REC *window)
{
	STATUSBAR_REC *rec;

	rec = window->statusbar;
        rec->ypos = window->first_line+window->height;
}

void statusbar_init(void)
{
	statusbars = NULL;
	sbars_up = sbars_down = 0;

	statusbar_items_init();
	signal_add("mainwindow resized", (SIGNAL_FUNC) sig_mainwindow_resized);
	signal_add("mainwindow moved", (SIGNAL_FUNC) sig_mainwindow_resized);
}

void statusbar_deinit(void)
{
	statusbar_items_deinit();

	while (statusbars != NULL)
		statusbar_destroy(statusbars->data);

	signal_remove("mainwindow resized", (SIGNAL_FUNC) sig_mainwindow_resized);
	signal_remove("mainwindow moved", (SIGNAL_FUNC) sig_mainwindow_resized);
}
