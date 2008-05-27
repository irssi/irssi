/*
 mainwindow-activity.c : irssi

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
#include "signals.h"

#include "gui-windows.h"

/* Don't send window activity if window is already visible in
   another mainwindow */
static void sig_activity(WINDOW_REC *window)
{
	GSList *tmp;

	if (!is_window_visible(window) || window->data_level == 0)
		return;

	window->data_level = 0;
	g_free_and_null(window->hilight_color);

	for (tmp = window->items; tmp != NULL; tmp = tmp->next) {
		WI_ITEM_REC *item = tmp->data;

		item->data_level = 0;
		g_free_and_null(item->hilight_color);
	}
	signal_stop();
}

void mainwindow_activity_init(void)
{
	signal_add_first("window hilight", (SIGNAL_FUNC) sig_activity);
	signal_add_first("window activity", (SIGNAL_FUNC) sig_activity);
}

void mainwindow_activity_deinit(void)
{
	signal_remove("window hilight", (SIGNAL_FUNC) sig_activity);
	signal_remove("window activity", (SIGNAL_FUNC) sig_activity);
}
