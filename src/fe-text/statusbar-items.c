/*
 statusbar-items.c : irssi

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
#include "settings.h"

#include "statusbar.h"
#include "gui-entry.h"

/* how often to redraw lagging time (seconds) */
#define LAG_REFRESH_TIME 10

/* If we haven't been able to check lag for this long, "(??)" is added after
   the lag */
#define MAX_LAG_UNKNOWN_TIME 30

/* activity */
static GSList *activity_items;
static GList *activity_list;

static GHashTable *input_entries;

static void item_window_active(SBAR_ITEM_REC *item, int get_size_only)
{
	WINDOW_REC *window;

        window = active_win;
	if (item->bar->parent_window != NULL)
		window = item->bar->parent_window->active;

	if (window != NULL && window->active != NULL) {
		statusbar_item_default_handler(item, get_size_only,
					       NULL, "", TRUE);
	} else if (get_size_only) {
                item->min_size = item->max_size = 0;
	}
}

static void item_window_empty(SBAR_ITEM_REC *item, int get_size_only)
{
	WINDOW_REC *window;

        window = active_win;
	if (item->bar->parent_window != NULL)
		window = item->bar->parent_window->active;

	if (window != NULL && window->active == NULL) {
		statusbar_item_default_handler(item, get_size_only,
					       NULL, "", TRUE);
	} else if (get_size_only) {
                item->min_size = item->max_size = 0;
	}
}

static void item_lag(SBAR_ITEM_REC *item, int get_size_only)
{
	SERVER_REC *server;
	GString *str;
	int lag_unknown, lag_min_show;
	time_t now;

	server = active_win == NULL ? NULL : active_win->active_server;
	if (server == NULL || server->lag_last_check == 0) {
                /* No lag information */
		if (get_size_only)
			item->min_size = item->max_size = 0;
		return;
	}

	now = time(NULL);
	str = g_string_new(NULL);

	/* FIXME: ugly ugly.. */
	if (server->lag_sent == 0 || now-server->lag_sent < 5) {
		lag_unknown = now-server->lag_last_check >
			MAX_LAG_UNKNOWN_TIME+settings_get_int("lag_check_time");
                lag_min_show = settings_get_int("lag_min_show");

		if (lag_min_show < 0 || (server->lag < lag_min_show && !lag_unknown)) {
                        /* small lag, don't display */
		} else {
			g_string_sprintfa(str, "%d.%02d", server->lag/1000,
					  (server->lag % 1000)/10);
			if (lag_unknown)
				g_string_append(str, " (?""?)");
		}
	} else {
		/* big lag, still waiting .. */
		g_string_sprintfa(str, "%ld (?""?)",
				  (long) (now-server->lag_sent));
	}

	if (str->len != 0) {
		statusbar_item_default_handler(item, get_size_only,
					       NULL, str->str, TRUE);
	} else {
		if (get_size_only)
			item->min_size = item->max_size = 0;
	}

	g_string_free(str, TRUE);
}

static char *get_activity_list(int normal, int hilight)
{
	GString *str;
	GList *tmp;
        char *ret;
        int is_det;

	str = g_string_new(NULL);

	for (tmp = activity_list; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *window = tmp->data;

		is_det = window->data_level >= DATA_LEVEL_HILIGHT;
		if ((!is_det && !normal) || (is_det && !hilight))
                        continue;

		g_string_append(str, "%c");
                if (str->len > 2)
			g_string_append_c(str, ',');

		switch (window->data_level) {
		case DATA_LEVEL_NONE:
		case DATA_LEVEL_TEXT:
			break;
		case DATA_LEVEL_MSG:
                        g_string_append(str, "%W");
			break;
		default:
			g_string_append(str, window->hilight_color == NULL ?
					"%M" : window->hilight_color);
			break;
		}
		g_string_sprintfa(str, "%d", window->refnum);

                /* make sure the background is returned to default */
		g_string_append(str, "%n");
	}

	ret = str->len == 0 ? NULL : str->str;
        g_string_free(str, ret == NULL);
        return ret;
}

/* redraw activity, FIXME: if we didn't get enough size, this gets buggy.
   At least "Det:" isn't printed properly. also we should rearrange the
   act list so that the highest priority items comes first. */
static void item_act(SBAR_ITEM_REC *item, int get_size_only)
{
	char *actlist;

	actlist = get_activity_list(TRUE, TRUE);
	if (actlist == NULL) {
		if (get_size_only)
			item->min_size = item->max_size = 0;
		return;
	}

	statusbar_item_default_handler(item, get_size_only,
				       NULL, actlist, FALSE);

	g_free_not_null(actlist);
}

static void sig_statusbar_activity_hilight(WINDOW_REC *window, gpointer oldlevel)
{
	GList *tmp;
	int inspos;

	g_return_if_fail(window != NULL);

	if (settings_get_bool("actlist_moves")) {
		/* Move the window to the first in the activity list */
		if (g_list_find(activity_list, window) != NULL)
			activity_list = g_list_remove(activity_list, window);
		if (window->data_level != 0)
			activity_list = g_list_prepend(activity_list, window);
		statusbar_items_redraw(activity_items);
		return;
	}

	if (g_list_find(activity_list, window) != NULL) {
		/* already in activity list */
		if (window->data_level == 0) {
			/* remove from activity list */
			activity_list = g_list_remove(activity_list, window);
			statusbar_items_redraw(activity_items);
		} else if (window->data_level != GPOINTER_TO_INT(oldlevel) ||
			 window->hilight_color != 0) {
			/* different level as last time (or maybe different
			   hilight color?), just redraw it. */
			statusbar_items_redraw(activity_items);
		}
		return;
	}

	if (window->data_level == 0)
		return;

	/* add window to activity list .. */
	inspos = 0;
	for (tmp = activity_list; tmp != NULL; tmp = tmp->next, inspos++) {
		WINDOW_REC *rec = tmp->data;

		if (window->refnum < rec->refnum) {
			activity_list =
				g_list_insert(activity_list, window, inspos);
			break;
		}
	}
	if (tmp == NULL)
		activity_list = g_list_append(activity_list, window);

	statusbar_items_redraw(activity_items);
}

static void sig_statusbar_activity_window_destroyed(WINDOW_REC *window)
{
	g_return_if_fail(window != NULL);

	if (g_list_find(activity_list, window) != NULL)
		activity_list = g_list_remove(activity_list, window);
	statusbar_items_redraw(activity_items);
}

static void sig_statusbar_activity_updated(void)
{
	statusbar_items_redraw(activity_items);
}

static void item_more(SBAR_ITEM_REC *item, int get_size_only)
{
}

static void item_input(SBAR_ITEM_REC *item, int get_size_only)
{
	GUI_ENTRY_REC *rec;

	if (get_size_only) {
		item->min_size = 2+screen_width/10;
                item->max_size = screen_width;
                return;
	}

	rec = g_hash_table_lookup(input_entries, item);
	if (rec == NULL) {
		rec = gui_entry_create(item->xpos, item->bar->real_ypos,
				       item->size);
                if (active_entry == NULL)
			gui_entry_set_active(rec);
		g_hash_table_insert(input_entries, item, rec);
	} else {
		gui_entry_move(rec, item->xpos, item->bar->real_ypos,
			       item->size);
		gui_entry_redraw(rec); /* FIXME: this is only necessary with ^L.. */
	}
}

static void sig_statusbar_item_created(SBAR_ITEM_REC *item)
{
	if (item->func == item_act)
		activity_items = g_slist_prepend(activity_items, item);
}

static void sig_statusbar_item_destroyed(SBAR_ITEM_REC *item)
{
	if (item->func == item_act)
		activity_items = g_slist_remove(activity_items, item);
	else {
		GUI_ENTRY_REC *rec;

		rec = g_hash_table_lookup(input_entries, item);
		if (rec != NULL) {
			gui_entry_destroy(rec);
                        g_hash_table_remove(input_entries, item);
		}
	}
}

void statusbar_items_init(void)
{
	settings_add_int("misc", "lag_min_show", 100);
	settings_add_bool("lookandfeel", "actlist_moves", FALSE);

	statusbar_item_register("window", NULL, item_window_active);
	statusbar_item_register("window_empty", NULL, item_window_empty);
	statusbar_item_register("prompt", NULL, item_window_active);
	statusbar_item_register("prompt_empty", NULL, item_window_empty);
	statusbar_item_register("lag", NULL, item_lag);
	statusbar_item_register("act", NULL, item_act);
	statusbar_item_register("more", NULL, item_more);
	statusbar_item_register("input", NULL, item_input);

	input_entries = g_hash_table_new((GHashFunc) g_direct_hash,
					 (GCompareFunc) g_direct_equal);

	activity_list = NULL;
	signal_add("window activity", (SIGNAL_FUNC) sig_statusbar_activity_hilight);
	signal_add("window destroyed", (SIGNAL_FUNC) sig_statusbar_activity_window_destroyed);
	signal_add("window refnum changed", (SIGNAL_FUNC) sig_statusbar_activity_updated);

	signal_add("statusbar item created", (SIGNAL_FUNC) sig_statusbar_item_created);
	signal_add("statusbar item destroyed", (SIGNAL_FUNC) sig_statusbar_item_destroyed);
}

void statusbar_items_deinit(void)
{
        g_hash_table_destroy(input_entries);

	signal_remove("window activity", (SIGNAL_FUNC) sig_statusbar_activity_hilight);
	signal_remove("window destroyed", (SIGNAL_FUNC) sig_statusbar_activity_window_destroyed);
	signal_remove("window refnum changed", (SIGNAL_FUNC) sig_statusbar_activity_updated);

	g_list_free(activity_list);
        activity_list = NULL;

	signal_remove("statusbar item created", (SIGNAL_FUNC) sig_statusbar_item_created);
	signal_remove("statusbar item destroyed", (SIGNAL_FUNC) sig_statusbar_item_destroyed);
}
