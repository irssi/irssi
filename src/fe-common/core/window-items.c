/*
 window-items.c : irssi

    Copyright (C) 2000 Timo Sirainen

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
#include "modules.h"
#include "signals.h"
#include "servers.h"
#include "settings.h"

#include "levels.h"

#include "windows.h"
#include "window-items.h"

void window_add_item(WINDOW_REC *window, WI_ITEM_REC *item, int automatic)
{
	g_return_if_fail(window != NULL);
	g_return_if_fail(item != NULL);

	MODULE_DATA_SET(item, window);

	if (window->items == NULL) {
		window->active = item;
		window->active_server = item->server;
	}

	signal_emit("gui window item init", 1, item);

	if (!automatic || settings_get_bool("window_auto_change")) {
		if (automatic)
			signal_emit("window changed automatic", 1, window);
		window_set_active(window);
	}

	window->items = g_slist_append(window->items, item);
	signal_emit("window item new", 2, window, item);

	if (!automatic || g_slist_length(window->items) == 1) {
                window->active = NULL;
		window_item_set_active(window, item);
	}
}

void window_remove_item(WINDOW_REC *window, WI_ITEM_REC *item)
{
	g_return_if_fail(window != NULL);
	g_return_if_fail(item != NULL);

	if (g_slist_find(window->items, item) == NULL)
		return;

	MODULE_DATA_SET(item, NULL);
	window->items = g_slist_remove(window->items, item);

	if (window->active == item) {
		window_item_set_active(window, window->items == NULL ? NULL :
				       window->items->data);
	}

	signal_emit("window item remove", 2, window, item);
}

WINDOW_REC *window_item_window(WI_ITEM_REC *item)
{
	g_return_val_if_fail(item != NULL, NULL);

        return MODULE_DATA(item);
}

void window_item_change_server(WI_ITEM_REC *item, void *server)
{
	WINDOW_REC *window;

	g_return_if_fail(item != NULL);

	window = MODULE_DATA(item);
	item->server = server;

        signal_emit("window item server changed", 2, window, item);
	if (window->active == item) window_change_server(window, item->server);
}

void window_item_set_active(WINDOW_REC *window, WI_ITEM_REC *item)
{
	g_return_if_fail(window != NULL);

	if (window->active != item) {
		window->active = item;
		if (item != NULL) window_change_server(window, window->active_server);
		signal_emit("window item changed", 2, window, item);
	}
}

/* Return TRUE if `item' is the active window item in the window.
   `item' can be NULL. */
int window_item_is_active(WI_ITEM_REC *item)
{
	WINDOW_REC *window;

	if (item == NULL)
		return FALSE;

	window = window_item_window(item);
	if (window == NULL)
		return FALSE;

	return window->active == item;
}

void window_item_prev(WINDOW_REC *window)
{
	WI_ITEM_REC *last;
	GSList *tmp;

	g_return_if_fail(window != NULL);

	last = NULL;
	for (tmp = window->items; tmp != NULL; tmp = tmp->next) {
		WI_ITEM_REC *rec = tmp->data;

		if (rec != window->active)
			last = rec;
		else {
			/* current channel. did we find anything?
			   if not, go to the last channel */
			if (last != NULL) break;
		}
	}

	if (last != NULL)
                window_item_set_active(window, last);
}

void window_item_next(WINDOW_REC *window)
{
	WI_ITEM_REC *next;
	GSList *tmp;
	int gone;

	g_return_if_fail(window != NULL);

	next = NULL; gone = FALSE;
	for (tmp = window->items; tmp != NULL; tmp = tmp->next) {
		WI_ITEM_REC *rec = tmp->data;

		if (rec == window->active)
			gone = TRUE;
		else {
			if (gone) {
				/* found the next channel */
				next = rec;
				break;
			}

			if (next == NULL)
				next = rec; /* fallback to first channel */
		}
	}

	if (next != NULL)
                window_item_set_active(window, next);
}

static WI_ITEM_REC *window_item_find_window(WINDOW_REC *window, void *server, const char *name)
{
	GSList *tmp;

	for (tmp = window->items; tmp != NULL; tmp = tmp->next) {
		WI_ITEM_REC *rec = tmp->data;

		if ((server == NULL || rec->server == server) &&
		    g_strcasecmp(name, rec->name) == 0) return rec;
	}

	return NULL;
}

/* Find wanted window item by name. `server' can be NULL. */
WI_ITEM_REC *window_item_find(void *server, const char *name)
{
	WI_ITEM_REC *item;
	GSList *tmp;

	g_return_val_if_fail(name != NULL, NULL);

	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		item = window_item_find_window(rec, server, name);
		if (item != NULL) return item;
	}

	return NULL;
}

static int waiting_channels_get(WINDOW_REC *window, const char *tag)
{
	GSList *tmp;

	g_return_val_if_fail(window != NULL, FALSE);
	g_return_val_if_fail(tag != NULL, FALSE);

	for (tmp = window->waiting_channels; tmp != NULL; tmp = tmp->next) {
		if (g_strcasecmp(tmp->data, tag) == 0) {
			g_free(tmp->data);
			window->waiting_channels = g_slist_remove(window->waiting_channels, tmp->data);
			return TRUE;
		}
	}

	return FALSE;
}

void window_item_create(WI_ITEM_REC *item, int automatic)
{
	WINDOW_REC *window;
	GSList *tmp;
	char *str;
	int clear_waiting, reuse_unused_windows;

	g_return_if_fail(item != NULL);

	str = item->server == NULL ? NULL :
		g_strdup_printf("%s %s", ((SERVER_REC *) item->server)->tag, item->name);

	reuse_unused_windows =
		!settings_get_bool("autoclose_windows") ||
		settings_get_bool("reuse_unused_windows");

	clear_waiting = TRUE;
	window = NULL;
	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		if (reuse_unused_windows &&
		    rec->items == NULL && rec->level == 0 &&
		    (window == NULL || rec == active_win)) {
                        /* no items in this window, we should probably use it.. */
			window = rec;
		}

		if (rec->waiting_channels != NULL && str != NULL) {
			/* right name/server tag combination in
			   some waiting list? */
			if (waiting_channels_get(rec, str)) {
				window = rec;
				clear_waiting = FALSE;
				break;
			}
		}
	}
	g_free_not_null(str);

	if (window == NULL) {
		/* create new window to use */
		window = window_create(item, automatic);
	} else {
		/* use existing window */
		window_add_item(window, item, automatic);
	}

	if (clear_waiting) {
		/* clear window's waiting_channels list */
		g_slist_foreach(window->waiting_channels, (GFunc) g_free, NULL),
		g_slist_free(window->waiting_channels);
                window->waiting_channels = NULL;
	}
}

static void signal_window_item_changed(WINDOW_REC *window, WI_ITEM_REC *item)
{
	g_return_if_fail(window != NULL);

	if (g_slist_length(window->items) > 1) {
		/* default to printing "talking with ...",
		   you can override it it you wish */
		printformat(item->server, item->name, MSGLEVEL_CLIENTNOTICE,
			    IRCTXT_TALKING_WITH, item->name);
	}
}

void window_items_init(void)
{
	settings_add_bool("lookandfeel", "reuse_unused_windows", FALSE);

	signal_add_last("window item changed", (SIGNAL_FUNC) signal_window_item_changed);
}

void window_items_deinit(void)
{
	signal_remove("window item changed", (SIGNAL_FUNC) signal_window_item_changed);
}
