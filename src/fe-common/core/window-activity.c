/*
 window-activity.c : irssi

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
#include "signals.h"
#include "levels.h"
#include "server.h"

#include "windows.h"
#include "window-items.h"

static void sig_hilight_text(WINDOW_REC *window, SERVER_REC *server, const char *channel, gpointer levelptr, const char *msg)
{
	int level, oldlevel;

	level = GPOINTER_TO_INT(levelptr);
	if (window == active_win || (level & (MSGLEVEL_NEVER|MSGLEVEL_NO_ACT|MSGLEVEL_MSGS)))
		return;

	oldlevel = window->new_data;
	if (window->new_data < NEWDATA_TEXT) {
		window->new_data = NEWDATA_TEXT;
		signal_emit("window hilight", 1, window);
	}

	signal_emit("window activity", 2, window, GINT_TO_POINTER(oldlevel));
}

static void sig_dehilight(WINDOW_REC *window, WI_ITEM_REC *item)
{
	g_return_if_fail(window != NULL);

	if (item != NULL && item->new_data != 0) {
		item->new_data = 0;
		signal_emit("window item hilight", 1, item);
	}
}

static void sig_dehilight_window(WINDOW_REC *window)
{
        GSList *tmp;
	int oldlevel;

	g_return_if_fail(window != NULL);

	if (window->new_data == 0)
		return;

	if (window->new_data != 0) {
		oldlevel = window->new_data;
		window->new_data = 0;
		signal_emit("window hilight", 2, window, GINT_TO_POINTER(oldlevel));
	}
	signal_emit("window activity", 2, window, GINT_TO_POINTER(oldlevel));

	for (tmp = window->items; tmp != NULL; tmp = tmp->next)
		sig_dehilight(window, tmp->data);
}

static void sig_hilight_window_item(WI_ITEM_REC *item)
{
	WINDOW_REC *window;
	GSList *tmp;
	int level, oldlevel;

	window = window_item_window(item); level = 0;
	for (tmp = window->items; tmp != NULL; tmp = tmp->next) {
		item = tmp->data;

		if (item->new_data > level)
			level = item->new_data;
	}

	oldlevel = window->new_data;
	if (window->new_data < level || level == 0) {
		window->new_data = level;
		signal_emit("window hilight", 2, window, GINT_TO_POINTER(oldlevel));
	}
	signal_emit("window activity", 2, window, GINT_TO_POINTER(oldlevel));
}

void window_activity_init(void)
{
	signal_add("print text", (SIGNAL_FUNC) sig_hilight_text);
	signal_add("window item changed", (SIGNAL_FUNC) sig_dehilight);
	signal_add("window changed", (SIGNAL_FUNC) sig_dehilight_window);
	signal_add("window dehilight", (SIGNAL_FUNC) sig_dehilight_window);
	signal_add("window item hilight", (SIGNAL_FUNC) sig_hilight_window_item);
}

void window_activity_deinit(void)
{
	signal_remove("print text", (SIGNAL_FUNC) sig_hilight_text);
	signal_remove("window item changed", (SIGNAL_FUNC) sig_dehilight);
	signal_remove("window changed", (SIGNAL_FUNC) sig_dehilight_window);
	signal_remove("window dehilight", (SIGNAL_FUNC) sig_dehilight_window);
	signal_remove("window item hilight", (SIGNAL_FUNC) sig_hilight_window_item);
}
