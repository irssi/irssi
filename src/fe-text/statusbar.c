/*
 gui-statusbar.c : irssi

    Copyright (C) 1999 Timo Sirainen

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
#include "server.h"
#include "settings.h"

#include "windows.h"

#include "screen.h"
#include "statusbar.h"
#include "gui-windows.h"

void statusbar_items_init(void);
void statusbar_items_deinit(void);

static GSList *statusbars;
static int sbar_uppest, sbar_lowest, sbars_up, sbars_down;

static void statusbar_item_destroy(SBAR_ITEM_REC *rec)
{
	rec->bar->items = g_slist_remove(rec->bar->items, rec);
	g_free(rec);
}

static void statusbar_redraw_line(STATUSBAR_REC *bar)
{
	static int recurses = 0, resized = FALSE;
	STATUSBAR_FUNC func;
	GSList *tmp;
	int xpos, rxpos, old_resized;

	old_resized = resized;
	resized = FALSE;
	recurses++;

	xpos = 1;
	for (tmp = bar->items; tmp != NULL; tmp = tmp->next) {
		SBAR_ITEM_REC *rec = tmp->data;

		if (!rec->right_justify && xpos+rec->size < COLS) {
			rec->xpos = xpos;

			func = (STATUSBAR_FUNC) rec->func;
			func(rec, bar->ypos);

			if (resized) break;
			if (rec->size > 0) xpos += rec->size+1;
		}
	}

	rxpos = COLS-1;
	for (tmp = bar->items; tmp != NULL; tmp = tmp->next) {
		SBAR_ITEM_REC *rec = tmp->data;

		if (rec->right_justify && rxpos-rec->size > xpos) {
			rec->xpos = rxpos-rec->size;

			func = (STATUSBAR_FUNC) rec->func;
			func(rec, bar->ypos);

			if (resized) break;
			if (rec->size > 0) rxpos -= rec->size+1;
		}
	}

	resized = old_resized;
	if (--recurses > 0) resized = TRUE;
}

static void statusbar_redraw_all(void)
{
	GSList *tmp;

	screen_refresh_freeze();

	for (tmp = statusbars; tmp != NULL; tmp = tmp->next)
		statusbar_redraw(tmp->data);

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

	set_bg(stdscr, settings_get_int("statusbar_background") << 4);
	move(bar->ypos, 0); clrtoeol();
	set_bg(stdscr, 0);

	statusbar_redraw_line(bar);
}

void statusbar_item_redraw(SBAR_ITEM_REC *item)
{
	STATUSBAR_FUNC func;

	g_return_if_fail(item != NULL);

	func = (STATUSBAR_FUNC) item->func;
	func(item, item->bar->ypos);
}

/* ypos is used only when pos == STATUSBAR_POS_MIDDLE */
STATUSBAR_REC *statusbar_create(int pos, int ypos)
{
	STATUSBAR_REC *rec;

	rec = g_new0(STATUSBAR_REC, 1);
	statusbars = g_slist_append(statusbars, rec);

	rec->pos = pos;
	rec->line = pos == STATUSBAR_POS_MIDDLE ? ypos :
		mainwindows_reserve_lines(1, pos == STATUSBAR_POS_UP);
	rec->ypos = pos == STATUSBAR_POS_MIDDLE ? ypos :
		pos == STATUSBAR_POS_UP ? rec->line : LINES-1-rec->line;

	if (pos == STATUSBAR_POS_UP) {
                if (sbars_up == 0) sbar_uppest = rec->line;
                sbars_up++;
		rec->line -= sbar_uppest;
	} else if (pos == STATUSBAR_POS_DOWN) {
		if (sbars_down == 0) sbar_lowest = rec->line;
		sbars_down++;
		rec->line -= sbar_lowest;
	}

	set_bg(stdscr, settings_get_int("statusbar_background") << 4);
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
			rec->ypos += pos == STATUSBAR_POS_UP ? -1 : 1;
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
	g_free(bar);

	if (!quitting) statusbar_redraw_all();
}

SBAR_ITEM_REC *statusbar_item_create(STATUSBAR_REC *bar, int size, int right_justify, STATUSBAR_FUNC func)
{
	SBAR_ITEM_REC *rec;

	g_return_val_if_fail(bar != NULL, NULL);
	g_return_val_if_fail(func != NULL, NULL);

	rec = g_new0(SBAR_ITEM_REC, 1);
	rec->bar = bar;
	bar->items = g_slist_append(bar->items, rec);

	rec->xpos = -1;
	rec->size = size;
	rec->right_justify = right_justify;
	rec->func = (void *) func;

	return rec;
}

void statusbar_item_resize(SBAR_ITEM_REC *item, int size)
{
	g_return_if_fail(item != NULL);

	item->size = size;
	statusbar_redraw_all();
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
        rec->ypos = window->last_line+1;
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
