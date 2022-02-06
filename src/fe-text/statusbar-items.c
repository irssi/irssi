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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include <irssi/src/core/signals.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/core/servers.h>

#include <irssi/src/fe-common/core/themes.h>
#include <irssi/src/fe-text/statusbar.h>
#include <irssi/src/fe-text/gui-entry.h>
#include <irssi/src/fe-text/gui-windows.h>

/* how often to redraw lagging time (seconds) */
#define LAG_REFRESH_TIME 10

static GList *activity_list;
static guint8 actlist_sort;
static char *actlist_separator;
static GSList *more_visible; /* list of MAIN_WINDOW_RECs which have --more-- */
static GHashTable *input_entries;
static int last_lag, last_lag_unknown, lag_timeout_tag;

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

static char *get_activity_list(MAIN_WINDOW_REC *window, int normal, int hilight)
{
        THEME_REC *theme;
	GString *str;
	GString *format;
	GList *tmp;
        char *ret, *name, *value;
        int is_det;
	int add_name = settings_get_bool("actlist_names");
	int pref_name = settings_get_bool("actlist_prefer_window_name");

	str = g_string_new(NULL);
	format = g_string_new(NULL);

	theme = window != NULL && window->active != NULL &&
		window->active->theme != NULL ?
		window->active->theme : current_theme;

	for (tmp = activity_list; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *window = tmp->data;

		is_det = window->data_level >= DATA_LEVEL_HILIGHT;
		if ((!is_det && !normal) || (is_det && !hilight))
                        continue;

                /* comma separator */
		if (str->len > 0) {
			g_string_printf(format, "{sb_act_sep %s}", actlist_separator);
			value = theme_format_expand(theme, format->str);
			g_string_append(str, value);
			g_free(value);
		}

		switch (window->data_level) {
		case DATA_LEVEL_NONE:
		case DATA_LEVEL_TEXT:
			name = "{sb_act_text %d";
			break;
		case DATA_LEVEL_MSG:
			name = "{sb_act_msg %d";
			break;
		default:
                        if (window->hilight_color == NULL)
				name = "{sb_act_hilight %d";
			else
                                name = NULL;
			break;
		}

		if (name != NULL)
			g_string_printf(format, name, window->refnum);
		else
			g_string_printf(format, "{sb_act_hilight_color %s %d",
						 window->hilight_color,
						 window->refnum);

		if (add_name && window->active != NULL)
			g_string_append_printf(format, ":%s",
				pref_name == 1 && window->name != NULL ?
				window->name : window->active->visible_name);
		g_string_append_c(format, '}');

		value = theme_format_expand(theme, format->str);
		g_string_append(str, value);
                g_free(value);
	}

	ret = str->len == 0 ? NULL : str->str;
        g_string_free(str, ret == NULL);
	g_string_free(format, TRUE);
        return ret;
}

/* redraw activity, FIXME: if we didn't get enough size, this gets buggy.
   At least "Det:" isn't printed properly. also we should rearrange the
   act list so that the highest priority items comes first. */
static void item_act(SBAR_ITEM_REC *item, int get_size_only)
{
	char *actlist;
	int max_size;

	if (get_size_only) {
		if (activity_list == NULL)
			item->min_size = item->max_size = 0;
		/* Skip activity calculation on regular trigger, only
		   set dirty */
		return;
	}

	actlist = get_activity_list(item->bar->parent_window, TRUE, TRUE);
	if (actlist == NULL) {
		return;
	}

	max_size = item->max_size;
	statusbar_item_default_handler(item, TRUE,
				       NULL, actlist, FALSE);
	statusbar_item_default_handler(item, FALSE,
				       NULL, actlist, FALSE);
	if (max_size != item->max_size) {
		/* Due to above hack of skipping the calculation, we
		   need to manually trigger the redraw process now or
		   we won't see the item */
		item->bar->dirty = item->dirty = TRUE;
		statusbar_redraw(item->bar, TRUE);
		statusbar_redraw_dirty();
	}

	g_free_not_null(actlist);
}

static int window_level_recent_cmp(WINDOW_REC *w1, WINDOW_REC *w2)
{
	if (w1->data_level >= w2->data_level)
		return -1;
	else
		return 1;
}

static int window_level_cmp(WINDOW_REC *w1, WINDOW_REC *w2)
{
	if (w1->data_level > w2->data_level ||
	    (w1->data_level == w2->data_level && w1->refnum < w2->refnum))
		return -1;
	else
		return 1;
}

static void sig_statusbar_activity_hilight(WINDOW_REC *window, gpointer oldlevel)
{
	GList *node;

	g_return_if_fail(window != NULL);

	node = g_list_find(activity_list, window);

	if (actlist_sort == 1) {
		/* Move the window to the first in the activity list */
		if (node != NULL)
			activity_list = g_list_delete_link(activity_list, node);
		if (window->data_level != 0)
			activity_list = g_list_prepend(activity_list, window);
		statusbar_items_redraw("act");
		return;
	}

	if (actlist_sort == 2) {
		if (node != NULL) {
			if (window->data_level == GPOINTER_TO_INT(oldlevel)) {
				if (window->hilight_color != 0)
					statusbar_items_redraw("act");
				return;
			}
			activity_list = g_list_delete_link(activity_list, node);
		}
		if (window->data_level != 0)
			activity_list = g_list_insert_sorted(activity_list, window, (GCompareFunc)
							     window_level_cmp);
		statusbar_items_redraw("act");
		return;
	}

	if (actlist_sort == 3) {
		if (node != NULL)
			activity_list = g_list_delete_link(activity_list, node);
		if (window->data_level != 0)
			activity_list = g_list_insert_sorted(activity_list, window, (GCompareFunc)
							     window_level_recent_cmp);
		statusbar_items_redraw("act");
		return;
	}

	if (node != NULL) {
		/* already in activity list */
		if (window->data_level == 0) {
			/* remove from activity list */
			activity_list = g_list_delete_link(activity_list, node);
			statusbar_items_redraw("act");
		} else if (window->data_level != GPOINTER_TO_INT(oldlevel) ||
			 window->hilight_color != 0) {
			/* different level as last time (or maybe different
			   hilight color?), just redraw it. */
			statusbar_items_redraw("act");
		}
		return;
	}

	if (window->data_level == 0)
		return;

	/* add window to activity list .. */
	activity_list = g_list_insert_sorted(activity_list, window, (GCompareFunc)
					     window_refnum_cmp);

	statusbar_items_redraw("act");
}

static void sig_statusbar_activity_window_destroyed(WINDOW_REC *window)
{
	GList *node;

	g_return_if_fail(window != NULL);

	node = g_list_find(activity_list, window);
	if (node != NULL)
		activity_list = g_list_delete_link(activity_list, node);
	statusbar_items_redraw("act");
}

static void sig_statusbar_activity_updated(void)
{
	statusbar_items_redraw("act");
}

static void item_more(SBAR_ITEM_REC *item, int get_size_only)
{
        MAIN_WINDOW_REC *mainwin;
	int visible;

	if (active_win == NULL) {
                mainwin = NULL;
		visible = FALSE;
	} else {
		mainwin = WINDOW_MAIN(active_win);
		visible = WINDOW_GUI(active_win)->view->more_text;
	}

	if (!visible) {
		if (mainwin != NULL)
			more_visible = g_slist_remove(more_visible, mainwin);
		if (get_size_only)
			item->min_size = item->max_size = 0;
		return;
	}

	more_visible = g_slist_prepend(more_visible, mainwin);
	statusbar_item_default_handler(item, get_size_only, NULL, "", FALSE);
}

static void sig_statusbar_more_updated(void)
{
	int visible;

	 /* no active window, for example during /window hide */
	if (active_win == NULL)
		return;

        visible = g_slist_find(more_visible, WINDOW_MAIN(active_win)) != NULL;
	if (WINDOW_GUI(active_win)->view->more_text != visible)
                statusbar_items_redraw("more");
}

/* Returns the lag in milliseconds. If we haven't been able to ask the lag
   for a while, unknown is set to TRUE. */
static int get_lag(SERVER_REC *server, int *unknown)
{
	long lag;

        *unknown = FALSE;

	if (server == NULL || server->lag_last_check == 0) {
                /* lag has not been asked even once yet */
		return 0;
	}

	if (server->lag_sent == 0) {
		/* no lag queries going on currently */
                return server->lag;
	}

	/* we're not sure about our current lag.. */
	*unknown = TRUE;

	lag = (long) (time(NULL) - (server->lag_sent / G_TIME_SPAN_SECOND));
	if (server->lag/1000 > lag) {
		/* we've been waiting the lag reply less time than
		   what last known lag was -> use the last known lag */
		return server->lag;
	}

        /* return how long we have been waiting for lag reply */
        return lag*1000;
}

static void item_lag(SBAR_ITEM_REC *item, int get_size_only)
{
	SERVER_REC *server;
        char str[MAX_INT_STRLEN+10];
	int lag, lag_unknown;

	server = active_win == NULL ? NULL : active_win->active_server;
	lag = get_lag(server, &lag_unknown);

	if (lag <= 0 || lag < settings_get_time("lag_min_show")) {
		/* don't print the lag item */
		if (get_size_only)
			item->min_size = item->max_size = 0;
		return;
	}

	lag /= 10;
	last_lag = lag;
	last_lag_unknown = lag_unknown;

	if (lag_unknown) {
		/* "??)" in C becomes ']'
		   See: https://en.wikipedia.org/wiki/Digraphs_and_trigraphs#C */
		g_snprintf(str, sizeof(str), "%d (?""?)", lag / 100);
	} else {
		if (lag % 100 == 0)
			g_snprintf(str, sizeof(str), "%d", lag / 100);
		else
			g_snprintf(str, sizeof(str), "%d.%02d", lag / 100, lag % 100);
	}

	statusbar_item_default_handler(item, get_size_only,
				       NULL, str, TRUE);
}

static void lag_check_update(void)
{
	SERVER_REC *server;
	int lag, lag_unknown;

	server = active_win == NULL ? NULL : active_win->active_server;
	lag = get_lag(server, &lag_unknown)/10;

	if (lag < settings_get_time("lag_min_show"))
		lag = 0;
	else
		lag /= 10;

	if (lag != last_lag || (lag > 0 && lag_unknown != last_lag_unknown))
                statusbar_items_redraw("lag");
}

static void sig_server_lag_updated(SERVER_REC *server)
{
	if (active_win != NULL && active_win->active_server == server)
                lag_check_update();
}

static int sig_lag_timeout(void)
{
        lag_check_update();
        return 1;
}

static void item_input(SBAR_ITEM_REC *item, int get_size_only)
{
	GUI_ENTRY_REC *rec;

	rec = g_hash_table_lookup(input_entries, item->bar->config->name);
	if (rec == NULL) {
		rec = gui_entry_create(ITEM_WINDOW_REAL_XPOS(item), item->bar->real_ypos,
				       item->size, term_type == TERM_TYPE_UTF8);
		gui_entry_set_active(rec);
		g_hash_table_insert(input_entries,
				    g_strdup(item->bar->config->name), rec);
	}

	if (get_size_only) {
		int max_width;
		WINDOW_REC *window;

		window = item->bar->parent_window != NULL
			? item->bar->parent_window->active
			: NULL;

		max_width = window != NULL ? window->width : term_width;

		item->min_size = 2+max_width/10;
		item->max_size = max_width;
		return;
	}

	gui_entry_move(rec, ITEM_WINDOW_REAL_XPOS(item), item->bar->real_ypos,
		       item->size);
	gui_entry_redraw(rec); /* FIXME: this is only necessary with ^L.. */
}

static void read_settings(void)
{
	const char *sep;
	if (active_entry != NULL)
		gui_entry_set_utf8(active_entry, term_type == TERM_TYPE_UTF8);

	actlist_sort = settings_get_choice("actlist_sort");

	sep = settings_get_str("actlist_separator");
	if (g_strcmp0(actlist_separator, sep) != 0) {
		g_free(actlist_separator);
		actlist_separator = g_strdup(sep);
		statusbar_items_redraw("act");
	}
}

void statusbar_items_init(void)
{
	settings_add_time("misc", "lag_min_show", "1sec");
	settings_add_choice("lookandfeel", "actlist_sort", 0, "refnum;recent;level;level,recent");
	settings_add_bool("lookandfeel", "actlist_names", FALSE);
	settings_add_str("lookandfeel", "actlist_separator", ",");
	settings_add_bool("lookandfeel", "actlist_prefer_window_name", FALSE);

	statusbar_item_register("window", NULL, item_window_active);
	statusbar_item_register("window_empty", NULL, item_window_empty);
	statusbar_item_register("prompt", NULL, item_window_active);
	statusbar_item_register("prompt_empty", NULL, item_window_empty);
	statusbar_item_register("topic", NULL, item_window_active);
	statusbar_item_register("topic_empty", NULL, item_window_empty);
	statusbar_item_register("lag", NULL, item_lag);
	statusbar_item_register("act", NULL, item_act);
	statusbar_item_register("more", NULL, item_more);
	statusbar_item_register("input", NULL, item_input);

        /* activity */
	activity_list = NULL;
	signal_add("window activity", (SIGNAL_FUNC) sig_statusbar_activity_hilight);
	signal_add("window destroyed", (SIGNAL_FUNC) sig_statusbar_activity_window_destroyed);
	signal_add("window refnum changed", (SIGNAL_FUNC) sig_statusbar_activity_updated);

        /* more */
        more_visible = NULL;
	signal_add("gui page scrolled", (SIGNAL_FUNC) sig_statusbar_more_updated);
	signal_add("window changed", (SIGNAL_FUNC) sig_statusbar_more_updated);
	signal_add_last("gui print text finished", (SIGNAL_FUNC) sig_statusbar_more_updated);
	signal_add_last("command clear", (SIGNAL_FUNC) sig_statusbar_more_updated);
	signal_add_last("command scrollback", (SIGNAL_FUNC) sig_statusbar_more_updated);

        /* lag */
	last_lag = 0; last_lag_unknown = FALSE;
	signal_add("server lag", (SIGNAL_FUNC) sig_server_lag_updated);
	signal_add("window changed", (SIGNAL_FUNC) lag_check_update);
	signal_add("window server changed", (SIGNAL_FUNC) lag_check_update);
        lag_timeout_tag = g_timeout_add(5000, (GSourceFunc) sig_lag_timeout, NULL);

        /* input */
	input_entries = g_hash_table_new((GHashFunc) g_str_hash,
					 (GCompareFunc) g_str_equal);

	read_settings();
        signal_add_last("setup changed", (SIGNAL_FUNC) read_settings);
}

void statusbar_items_deinit(void)
{
        /* activity */
	signal_remove("window activity", (SIGNAL_FUNC) sig_statusbar_activity_hilight);
	signal_remove("window destroyed", (SIGNAL_FUNC) sig_statusbar_activity_window_destroyed);
	signal_remove("window refnum changed", (SIGNAL_FUNC) sig_statusbar_activity_updated);
	g_list_free(activity_list);
        activity_list = NULL;

        /* more */
        g_slist_free(more_visible);
	signal_remove("gui page scrolled", (SIGNAL_FUNC) sig_statusbar_more_updated);
	signal_remove("window changed", (SIGNAL_FUNC) sig_statusbar_more_updated);
	signal_remove("gui print text finished", (SIGNAL_FUNC) sig_statusbar_more_updated);
	signal_remove("command clear", (SIGNAL_FUNC) sig_statusbar_more_updated);
	signal_remove("command scrollback", (SIGNAL_FUNC) sig_statusbar_more_updated);

        /* lag */
	signal_remove("server lag", (SIGNAL_FUNC) sig_server_lag_updated);
	signal_remove("window changed", (SIGNAL_FUNC) lag_check_update);
	signal_remove("window server changed", (SIGNAL_FUNC) lag_check_update);
        g_source_remove(lag_timeout_tag);

        /* input */
        g_hash_table_foreach(input_entries, (GHFunc) g_free, NULL);
	g_hash_table_destroy(input_entries);

        signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
}
