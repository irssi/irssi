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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include "module-formats.h"
#include "modules.h"
#include "signals.h"
#include "servers.h"
#include "channels.h"
#include "settings.h"

#include "levels.h"

#include "fe-windows.h"
#include "window-items.h"
#include "printtext.h"

static void window_item_add_signal(WINDOW_REC *window, WI_ITEM_REC *item, int automatic, int send_signal)
{
	g_return_if_fail(window != NULL);
	g_return_if_fail(item != NULL);
	g_return_if_fail(item->window == NULL);

        item->window = window;

	if (window->items == NULL) {
		window->active = item;
		window->active_server = item->server;
	}

	if (!automatic || settings_get_bool("window_auto_change")) {
		if (automatic)
			signal_emit("window changed automatic", 1, window);
		window_set_active(window);
	}

	window->items = g_slist_append(window->items, item);
	if (send_signal)
		signal_emit("window item new", 2, window, item);

	if (g_slist_length(window->items) == 1 ||
	    (!automatic && settings_get_bool("autofocus_new_items"))) {
                window->active = NULL;
		window_item_set_active(window, item);
	}
}

void window_item_add(WINDOW_REC *window, WI_ITEM_REC *item, int automatic)
{
	window_item_add_signal(window, item, automatic, TRUE);
}

static void window_item_remove_signal(WI_ITEM_REC *item, int emit_signal)
{
	WINDOW_REC *window;

	g_return_if_fail(item != NULL);

	window = window_item_window(item);

	if (window == NULL)
		return;

        item->window = NULL;
	window->items = g_slist_remove(window->items, item);

	if (window->active == item) {
		window_item_set_active(window, window->items == NULL ? NULL :
				       window->items->data);
	}

	if (emit_signal)
		signal_emit("window item remove", 2, window, item);
}

void window_item_remove(WI_ITEM_REC *item)
{
	window_item_remove_signal(item, TRUE);
}

void window_item_destroy(WI_ITEM_REC *item)
{
        window_item_remove(item);
        item->destroy(item);
}

void window_item_change_server(WI_ITEM_REC *item, void *server)
{
	WINDOW_REC *window;

	g_return_if_fail(item != NULL);

	window = window_item_window(item);
	item->server = server;

        signal_emit("window item server changed", 2, window, item);
	if (window->active == item) window_change_server(window, item->server);
}

void window_item_set_active(WINDOW_REC *window, WI_ITEM_REC *item)
{
		WINDOW_REC *old_window;

        g_return_if_fail(window != NULL);

        if (item != NULL) {
            old_window = window_item_window(item);
        	if (old_window != window) {
                /* move item to different window */
                window_item_remove_signal(item, FALSE);
                window_item_add_signal(window, item, FALSE, FALSE);
                signal_emit("window item moved", 3, window, item, old_window);
        	}
        }

	if (window->active != item) {
		window->active = item;
		if (item != NULL && window->active_server != item->server)
			window_change_server(window, item->server);
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

WI_ITEM_REC *window_item_find_window(WINDOW_REC *window,
                                     void *server, const char *name)
{
	CHANNEL_REC *channel;
	GSList *tmp;

	for (tmp = window->items; tmp != NULL; tmp = tmp->next) {
		WI_ITEM_REC *rec = tmp->data;

		if ((server == NULL || rec->server == server) &&
		    g_strcasecmp(name, rec->visible_name) == 0)
			return rec;
	}

	/* try with channel name too, it's not necessarily
	   same as visible_name (!channels) */
	channel = channel_find(server, name);
	if (channel != NULL && window_item_window(channel) == window)
		return (WI_ITEM_REC *) channel;

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

static int window_bind_has_sticky(WINDOW_REC *window)
{
	GSList *tmp;

	for (tmp = window->bound_items; tmp != NULL; tmp = tmp->next) {
		WINDOW_BIND_REC *rec = tmp->data;

		if (rec->sticky)
                        return TRUE;
	}

        return FALSE;
}

void window_item_create(WI_ITEM_REC *item, int automatic)
{
	WINDOW_REC *window;
        WINDOW_BIND_REC *bind;
	GSList *tmp, *sorted;
	int clear_waiting, reuse_unused_windows;

	g_return_if_fail(item != NULL);

	reuse_unused_windows = settings_get_bool("reuse_unused_windows");

	clear_waiting = TRUE;
	window = NULL;
        sorted = windows_get_sorted();
	for (tmp = sorted; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

                /* is item bound to this window? */
		if (item->server != NULL) {
			bind = window_bind_find(rec, item->server->tag,
						item->visible_name);
			if (bind != NULL) {
                                if (!bind->sticky)
					window_bind_destroy(rec, bind);
				window = rec;
				clear_waiting = FALSE;
				break;
			}
		}

		/* use this window IF:
		     - reuse_unused_windows is ON
		     - window has no existing items
		     - window has no name
		     - window has no sticky binds (/LAYOUT SAVEd)
		     - we already haven't found "good enough" window,
		       except if
                         - this is the active window
                         - old window had some temporary bounds and this
			   one doesn't
		     */
		if (reuse_unused_windows && rec->items == NULL &&
		    rec->name == NULL && !window_bind_has_sticky(rec) &&
		    (window == NULL || rec == active_win ||
		     window->bound_items != NULL))
			window = rec;
	}
        g_slist_free(sorted);

        if (window == NULL && !settings_get_bool("autocreate_windows")) {
                /* never create new windows automatically */
                window = active_win;
        }

	if (window == NULL) {
		/* create new window to use */
		if (settings_get_bool("autocreate_split_windows")) {
			signal_emit("gui window create override", 1,
				    GINT_TO_POINTER(0));
		}
		window = window_create(item, automatic);
	} else {
		/* use existing window */
		window_item_add(window, item, automatic);
	}

	if (clear_waiting)
                window_bind_remove_unsticky(window);
}

static void signal_window_item_changed(WINDOW_REC *window, WI_ITEM_REC *item)
{
	g_return_if_fail(window != NULL);

	if (g_slist_length(window->items) > 1) {
		/* default to printing "talking with ...",
		   you can override it it you wish */
		printformat(item->server, item->visible_name,
			    MSGLEVEL_CLIENTNOTICE,
			    TXT_TALKING_WITH, item->visible_name);
	}
}

void window_items_init(void)
{
	settings_add_bool("lookandfeel", "reuse_unused_windows", FALSE);
	settings_add_bool("lookandfeel", "autocreate_windows", TRUE);
	settings_add_bool("lookandfeel", "autocreate_split_windows", FALSE);
	settings_add_bool("lookandfeel", "autofocus_new_items", TRUE);

	signal_add_last("window item changed", (SIGNAL_FUNC) signal_window_item_changed);
}

void window_items_deinit(void)
{
	signal_remove("window item changed", (SIGNAL_FUNC) signal_window_item_changed);
}
