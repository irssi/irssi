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
#include "servers.h"
#include "channels.h"
#include "misc.h"
#include "settings.h"

#include "fe-windows.h"
#include "window-items.h"
#include "nicklist.h"
#include "hilight-text.h"
#include "formats.h"

static char **noact_channels;
static int hilight_level, activity_level;

static void window_activity(WINDOW_REC *window,
			    int data_level, int hilight_color)
{
	int old_data_level;

	old_data_level = window->data_level;
	if (data_level == 0 || window->data_level < data_level) {
		window->data_level = data_level;
		window->hilight_color = hilight_color;
		signal_emit("window hilight", 1, window);
	}

	signal_emit("window activity", 2, window,
		    GINT_TO_POINTER(old_data_level));
}

static void window_item_activity(WI_ITEM_REC *item,
				 int data_level, int hilight_color)
{
	int old_data_level;

	old_data_level = item->data_level;
	if (data_level == 0 || item->data_level < data_level) {
		item->data_level = data_level;
		item->hilight_color = hilight_color;
		signal_emit("window item hilight", 1, item);
	}

	signal_emit("window item activity", 2, item,
		    GINT_TO_POINTER(old_data_level));
}

#define hide_target_activity(data_level, target) \
	((data_level) < DATA_LEVEL_HILIGHT && (target) != NULL && \
	(noact_channels) != NULL && \
	strarray_find((noact_channels), target) != -1)

static void sig_hilight_text(TEXT_DEST_REC *dest, const char *msg)
{
	WI_ITEM_REC *item;
	int data_level;

	if (dest->window == active_win ||
	    (dest->level & (MSGLEVEL_NEVER|MSGLEVEL_NO_ACT)))
		return;

	data_level = (dest->level & hilight_level) ?
		DATA_LEVEL_HILIGHT+dest->hilight_priority :
		((dest->level & activity_level) ?
		 DATA_LEVEL_MSG : DATA_LEVEL_TEXT);

	if (hide_target_activity(data_level, dest->target))
		return;

	if (dest->target != NULL) {
		item = window_item_find(dest->server, dest->target);
		if (item != NULL) {
			window_item_activity(item, data_level,
					     dest->hilight_color);
		}
	}
	window_activity(dest->window, data_level, dest->hilight_color);
}

static void sig_dehilight_window(WINDOW_REC *window)
{
        GSList *tmp;

	g_return_if_fail(window != NULL);

	if (window->data_level != 0) {
		window_activity(window, 0, 0);
		for (tmp = window->items; tmp != NULL; tmp = tmp->next)
			window_item_activity(tmp->data, 0, 0);
	}
}

static void read_settings(void)
{
	const char *channels;

	if (noact_channels != NULL)
		g_strfreev(noact_channels);

        channels = settings_get_str("noact_channels");
	noact_channels = *channels == '\0' ? NULL :
		g_strsplit(channels, " ", -1);

	activity_level = level2bits(settings_get_str("activity_levels"));
	hilight_level = MSGLEVEL_HILIGHT |
		level2bits(settings_get_str("hilight_levels"));
}

void window_activity_init(void)
{
	settings_add_str("lookandfeel", "noact_channels", "");
	settings_add_str("lookandfeel", "activity_levels", "PUBLIC");
	settings_add_str("lookandfeel", "hilight_levels", "MSGS DCCMSGS");

	read_settings();
	signal_add("print text", (SIGNAL_FUNC) sig_hilight_text);
	signal_add("window changed", (SIGNAL_FUNC) sig_dehilight_window);
	signal_add("window dehilight", (SIGNAL_FUNC) sig_dehilight_window);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
}

void window_activity_deinit(void)
{
	if (noact_channels != NULL)
		g_strfreev(noact_channels);

	signal_remove("print text", (SIGNAL_FUNC) sig_hilight_text);
	signal_remove("window changed", (SIGNAL_FUNC) sig_dehilight_window);
	signal_remove("window dehilight", (SIGNAL_FUNC) sig_dehilight_window);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
}
