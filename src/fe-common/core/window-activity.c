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
#include "misc.h"
#include "settings.h"

#include "windows.h"
#include "window-items.h"
#include "nicklist.h"
#include "hilight-text.h"

static const char *noact_channels;

static void sig_hilight_text(WINDOW_REC *window, SERVER_REC *server, const char *channel, gpointer levelptr, const char *msg)
{
	int level, oldlevel, new_data;

	level = GPOINTER_TO_INT(levelptr);
	if (window == active_win || (level & (MSGLEVEL_NEVER|MSGLEVEL_NO_ACT)))
		return;

	new_data = (level & (MSGLEVEL_HILIGHT|MSGLEVEL_MSGS)) ?
		NEWDATA_HILIGHT :
		((level & MSGLEVEL_PUBLIC) ? NEWDATA_MSG : NEWDATA_TEXT);

	if (new_data < NEWDATA_HILIGHT &&
	    channel != NULL && find_substr(noact_channels, channel))
		return;

	oldlevel = window->new_data;
	if (window->new_data < new_data) {
		window->new_data = new_data;
		window->last_color = 0;
		signal_emit("window hilight", 1, window);
	}

	signal_emit("window activity", 2, window, GINT_TO_POINTER(oldlevel));
}

static void sig_dehilight(WINDOW_REC *window, WI_ITEM_REC *item)
{
	g_return_if_fail(window != NULL);

	if (item != NULL && item->new_data != 0) {
		item->new_data = 0;
		item->last_color = 0;
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
		window->last_color = 0;
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
	int level, oldlevel, color;

	if (item->new_data < NEWDATA_HILIGHT &&
	    find_substr(noact_channels, item->name))
		return;

	window = window_item_window(item); level = 0; color = 0;
	for (tmp = window->items; tmp != NULL; tmp = tmp->next) {
		item = tmp->data;

		if (item->new_data > level) {
			level = item->new_data;
			color = item->last_color;
		}
	}

	oldlevel = window->new_data;
	if (level == NEWDATA_HILIGHT)
		window->last_color = color;
	if (window->new_data < level || level == 0) {
		window->new_data = level;
		signal_emit("window hilight", 2, window, GINT_TO_POINTER(oldlevel));
	}
	signal_emit("window activity", 2, window, GINT_TO_POINTER(oldlevel));
}

static void sig_message(SERVER_REC *server, const char *msg,
			const char *nick, const char *addr,
			const char *target, int level)
{
	WINDOW_REC *window;
	WI_ITEM_REC *item;

	/* get window and window item */
	item = window_item_find(server, target);
	window = item == NULL ?
		window_find_closest(server, target, level) :
		window_item_window(item);

	if (window == active_win)
		return;

	/* hilight */
	if (item != NULL) item->last_color = hilight_last_nick_color();
	level = (item != NULL && item->last_color > 0) ||
		(level & MSGLEVEL_MSGS) ||
		nick_match_msg(SERVER(server), msg, server->nick) ?
		NEWDATA_HILIGHT : NEWDATA_MSG;
	if (item != NULL && item->new_data < level) {
		item->new_data = level;
		signal_emit("window item hilight", 1, item);
	} else {
		int oldlevel = window->new_data;

		if (window->new_data < level) {
			window->new_data = level;
			window->last_color = hilight_last_nick_color();
			signal_emit("window hilight", 2, window,
				    GINT_TO_POINTER(oldlevel));
		}
		signal_emit("window activity", 2, window,
			    GINT_TO_POINTER(oldlevel));
	}
}

static void sig_message_public(SERVER_REC *server, const char *msg,
			       const char *nick, const char *addr,
			       const char *target)
{
	sig_message(server, msg, nick, addr, target, MSGLEVEL_PUBLIC);
}

static void sig_message_private(SERVER_REC *server, const char *msg,
				const char *nick, const char *addr)
{
	sig_message(server, msg, nick, addr, nick, MSGLEVEL_MSGS);
}

static void read_settings(void)
{
	noact_channels = settings_get_str("noact_channels");
}

void window_activity_init(void)
{
	settings_add_str("lookandfeel", "noact_channels", "");

	read_settings();
	signal_add("print text", (SIGNAL_FUNC) sig_hilight_text);
	signal_add("window item changed", (SIGNAL_FUNC) sig_dehilight);
	signal_add("window changed", (SIGNAL_FUNC) sig_dehilight_window);
	signal_add("window dehilight", (SIGNAL_FUNC) sig_dehilight_window);
	signal_add("window item hilight", (SIGNAL_FUNC) sig_hilight_window_item);
	signal_add("message public", (SIGNAL_FUNC) sig_message_public);
	signal_add("message private", (SIGNAL_FUNC) sig_message_private);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
}

void window_activity_deinit(void)
{
	signal_remove("print text", (SIGNAL_FUNC) sig_hilight_text);
	signal_remove("window item changed", (SIGNAL_FUNC) sig_dehilight);
	signal_remove("window changed", (SIGNAL_FUNC) sig_dehilight_window);
	signal_remove("window dehilight", (SIGNAL_FUNC) sig_dehilight_window);
	signal_remove("window item hilight", (SIGNAL_FUNC) sig_hilight_window_item);
	signal_remove("message public", (SIGNAL_FUNC) sig_message_public);
	signal_remove("message private", (SIGNAL_FUNC) sig_message_private);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
}
