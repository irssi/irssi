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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include "signals.h"
#include "expandos.h"
#include "special-vars.h"

#include "themes.h"

#include "statusbar.h"
#include "statusbar-config.h"
#include "gui-windows.h"
#include "gui-printtext.h"

void statusbar_items_init(void);
void statusbar_items_deinit(void);

GSList *statusbar_groups;
STATUSBAR_GROUP_REC *active_statusbar_group;

/*
   sbar_item_defs: char *name => char *value
   sbar_item_funcs: char *name => STATUSBAR_FUNC func
   sbar_signal_items: int signal_id => GSList *(SBAR_ITEM_REC *items)
   sbar_item_signals: SBAR_ITEM_REC *item => GSList *(int *signal_ids)
   named_sbar_items: const char *name => GSList *(SBAR_ITEM_REC *items)
*/
static GHashTable *sbar_item_defs, *sbar_item_funcs;
static GHashTable *sbar_signal_items, *sbar_item_signals;
static GHashTable *named_sbar_items;
static int statusbar_need_recreate_items;

void statusbar_item_register(const char *name, const char *value,
			     STATUSBAR_FUNC func)
{
	gpointer hkey, hvalue;

	statusbar_need_recreate_items = TRUE;
	if (value != NULL) {
		if (g_hash_table_lookup_extended(sbar_item_defs,
						 name, &hkey, &hvalue)) {
			g_hash_table_remove(sbar_item_defs, name);
			g_free(hkey);
                        g_free(hvalue);
		}
		g_hash_table_insert(sbar_item_defs,
				    g_strdup(name), g_strdup(value));
	}

	if (func != NULL) {
		if (g_hash_table_lookup(sbar_item_funcs, name) == NULL) {
			g_hash_table_insert(sbar_item_funcs,
					    g_strdup(name), (void *) func);
		}
	}
}

void statusbar_item_unregister(const char *name)
{
	gpointer key, value;

	statusbar_need_recreate_items = TRUE;
	if (g_hash_table_lookup_extended(sbar_item_defs,
					 name, &key, &value)) {
		g_hash_table_remove(sbar_item_defs, key);
		g_free(key);
                g_free(value);
	}

	if (g_hash_table_lookup_extended(sbar_item_funcs,
					 name, &key, &value)) {
		g_hash_table_remove(sbar_item_funcs, key);
		g_free(key);
	}
}

void statusbar_item_set_size(struct SBAR_ITEM_REC *item, int min_size, int max_size)
{
	item->min_size = min_size;
	item->max_size = max_size;
}

STATUSBAR_GROUP_REC *statusbar_group_create(const char *name)
{
	STATUSBAR_GROUP_REC *rec;

	rec = g_new0(STATUSBAR_GROUP_REC, 1);
	rec->name = g_strdup(name);

        statusbar_groups = g_slist_append(statusbar_groups, rec);
	return rec;
}

void statusbar_group_destroy(STATUSBAR_GROUP_REC *rec)
{
	statusbar_groups = g_slist_remove(statusbar_groups, rec);

	while (rec->bars != NULL)
		statusbar_destroy(rec->bars->data);
	while (rec->config_bars != NULL)
                statusbar_config_destroy(rec, rec->config_bars->data);

        g_free(rec->name);
        g_free(rec);
}

STATUSBAR_GROUP_REC *statusbar_group_find(const char *name)
{
	GSList *tmp;

	for (tmp = statusbar_groups; tmp != NULL; tmp = tmp->next) {
		STATUSBAR_GROUP_REC *rec = tmp->data;

		if (strcmp(rec->name, name) == 0)
                        return rec;
	}

        return NULL;
}

static int sbar_item_cmp(SBAR_ITEM_REC *item1, SBAR_ITEM_REC *item2)
{
	return item1->config->priority == item2->config->priority ? 0 :
		item1->config->priority < item2->config->priority ? -1 : 1;
}

static int sbar_cmp_position(STATUSBAR_REC *bar1, STATUSBAR_REC *bar2)
{
	return bar1->config->position < bar2->config->position ? -1 : 1;
}

/* Shink all items in statusbar to their minimum requested size.
   The items list should be sorted by priority, highest first. */
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

/* shink the items in statusbar, even if their size gets smaller than
   their minimum requested size. The items list should be sorted by
   priority, highest first. */
static void statusbar_shrink_forced(GSList *items, int size, int max_width)
{
	GSList *tmp;

	for (tmp = items; tmp != NULL; tmp = tmp->next) {
		SBAR_ITEM_REC *rec = tmp->data;

		if (size-rec->size > max_width) {
			/* remove the whole item */
                        size -= rec->size;
			rec->size = 0;
		} else {
			/* shrink the item */
			rec->size -= size-max_width;
                        break;
		}
	}
}

static void statusbar_resize_items(STATUSBAR_REC *bar, int max_width)
{
	GSList *tmp, *prior_sorted;
        int width;

        /* first give items their max. size */
	prior_sorted = NULL;
	width = 0;
	for (tmp = bar->items; tmp != NULL; tmp = tmp->next) {
		SBAR_ITEM_REC *rec = tmp->data;

		rec->func(rec, TRUE);
		rec->size = rec->max_size;

		if (rec->size > 0) {
			width += rec->max_size;

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

#define SBAR_ITEM_REDRAW_NEEDED(_bar, _item, _xpos) \
	(((_bar)->dirty_xpos != -1 && (_xpos) >= (_bar)->dirty_xpos) || \
	 (_item)->xpos != (_xpos) || (_item)->current_size != (_item)->size)

static void statusbar_calc_item_positions(STATUSBAR_REC *bar)
{
        WINDOW_REC *old_active_win;
	GSList *tmp, *right_items;
	int xpos, rxpos;

	old_active_win = active_win;
        if (bar->parent_window != NULL)
		active_win = bar->parent_window->active;

	statusbar_resize_items(bar, term_width);

        /* left-aligned items */
	xpos = 0;
	for (tmp = bar->items; tmp != NULL; tmp = tmp->next) {
		SBAR_ITEM_REC *rec = tmp->data;

		if (!rec->config->right_alignment &&
		    (rec->size > 0 || rec->current_size > 0)) {
			if (SBAR_ITEM_REDRAW_NEEDED(bar, rec, xpos)) {
                                /* redraw the item */
				rec->dirty = TRUE;
				if (bar->dirty_xpos == -1 ||
				    xpos < bar->dirty_xpos) {
                                        irssi_set_dirty();
					bar->dirty = TRUE;
					bar->dirty_xpos = xpos;
				}

				rec->xpos = xpos;
			}
			xpos += rec->size;
		}
	}

	/* right-aligned items - first copy them to a new list backwards,
	   easier to draw them in right order */
        right_items = NULL;
	for (tmp = bar->items; tmp != NULL; tmp = tmp->next) {
		SBAR_ITEM_REC *rec = tmp->data;

		if (rec->config->right_alignment) {
                        if (rec->size > 0)
				right_items = g_slist_prepend(right_items, rec);
			else if (rec->current_size > 0 &&
				 (bar->dirty_xpos == -1 ||
				  rec->xpos < bar->dirty_xpos)) {
				/* item was hidden - set the dirty position
				   to begin from the item's old xpos */
				irssi_set_dirty();
				bar->dirty = TRUE;
                                bar->dirty_xpos = rec->xpos;
			}
		}
	}

	rxpos = term_width;
	for (tmp = right_items; tmp != NULL; tmp = tmp->next) {
		SBAR_ITEM_REC *rec = tmp->data;

		rxpos -= rec->size;
		if (SBAR_ITEM_REDRAW_NEEDED(bar, rec, rxpos)) {
			rec->dirty = TRUE;
			if (bar->dirty_xpos == -1 ||
			    rxpos < bar->dirty_xpos) {
				irssi_set_dirty();
				bar->dirty = TRUE;
				bar->dirty_xpos = rxpos;
			}
			rec->xpos = rxpos;
		}
	}
        g_slist_free(right_items);

	active_win = old_active_win;
}

void statusbar_redraw(STATUSBAR_REC *bar, int force)
{
	if (statusbar_need_recreate_items)
		return; /* don't bother yet */

	if (bar != NULL) {
		if (force) {
			irssi_set_dirty();
			bar->dirty = TRUE;
                        bar->dirty_xpos = 0;
		}
		statusbar_calc_item_positions(bar);
	} else if (active_statusbar_group != NULL) {
		g_slist_foreach(active_statusbar_group->bars,
				(GFunc) statusbar_redraw,
				GINT_TO_POINTER(force));
	}
}

void statusbar_item_redraw(SBAR_ITEM_REC *item)
{
        WINDOW_REC *old_active_win;

	g_return_if_fail(item != NULL);

	old_active_win = active_win;
        if (item->bar->parent_window != NULL)
		active_win = item->bar->parent_window->active;

	item->func(item, TRUE);

	item->dirty = TRUE;
	item->bar->dirty = TRUE;
	irssi_set_dirty();

	if (item->max_size != item->size) {
		/* item wants a new size - we'll need to redraw
		   the statusbar to see if this is allowed */
		statusbar_redraw(item->bar, FALSE);
	}

	active_win = old_active_win;
}

void statusbar_items_redraw(const char *name)
{
	g_slist_foreach(g_hash_table_lookup(named_sbar_items, name),
			(GFunc) statusbar_item_redraw, NULL);
}

static void statusbars_recalc_ypos(STATUSBAR_REC *bar)
{
	GSList *tmp, *bar_group;
        int ypos;

	/* get list of statusbars with same type and placement,
	   sorted by position */
        bar_group = NULL;
	tmp = bar->config->type == STATUSBAR_TYPE_ROOT ? bar->group->bars :
                bar->parent_window->statusbars;

        for (; tmp != NULL; tmp = tmp->next) {
		STATUSBAR_REC *rec = tmp->data;

		if (rec->config->type == bar->config->type &&
		    rec->config->placement == bar->config->placement) {
			bar_group = g_slist_insert_sorted(bar_group, rec,
							  (GCompareFunc)
							  sbar_cmp_position);
		}
	}

	if (bar_group == NULL) {
		/* we just destroyed the last statusbar in this
		   type/placement group */
		return;
	}

        /* get the Y-position for the first statusbar */
	if (bar->config->type == STATUSBAR_TYPE_ROOT) {
		ypos = bar->config->placement == STATUSBAR_TOP ? 0 :
			term_height - g_slist_length(bar_group);
	} else {
		ypos = bar->config->placement == STATUSBAR_TOP ?
			bar->parent_window->first_line :
			bar->parent_window->last_line -
			(g_slist_length(bar_group)-1);
	}

        /* set the Y-positions */
	while (bar_group != NULL) {
		bar = bar_group->data;

		if (bar->real_ypos != ypos) {
			bar->real_ypos = ypos;
                        statusbar_redraw(bar, TRUE);
		}

                ypos++;
                bar_group = g_slist_remove(bar_group, bar_group->data);
	}
}

static void sig_terminal_resized(void)
{
	GSList *tmp;

	for (tmp = active_statusbar_group->bars; tmp != NULL; tmp = tmp->next) {
		STATUSBAR_REC *bar = tmp->data;

		if (bar->config->type == STATUSBAR_TYPE_ROOT &&
		    bar->config->placement == STATUSBAR_BOTTOM) {
			statusbars_recalc_ypos(bar);
                        break;
		}
	}
}

static void mainwindow_recalc_ypos(MAIN_WINDOW_REC *window, int placement)
{
	GSList *tmp;

	for (tmp = window->statusbars; tmp != NULL; tmp = tmp->next) {
		STATUSBAR_REC *bar = tmp->data;

		if (bar->config->placement == placement) {
			statusbars_recalc_ypos(bar);
                        break;
		}
	}
}

static void sig_mainwindow_resized(MAIN_WINDOW_REC *window)
{
        mainwindow_recalc_ypos(window, STATUSBAR_TOP);
        mainwindow_recalc_ypos(window, STATUSBAR_BOTTOM);
}

STATUSBAR_REC *statusbar_create(STATUSBAR_GROUP_REC *group,
                                STATUSBAR_CONFIG_REC *config,
                                MAIN_WINDOW_REC *parent_window)
{
	STATUSBAR_REC *bar;
	THEME_REC *theme;
        GSList *tmp;
	char *name, *value;

        g_return_val_if_fail(group != NULL, NULL);
        g_return_val_if_fail(config != NULL, NULL);
	g_return_val_if_fail(config->type != STATUSBAR_TYPE_WINDOW ||
			     parent_window != NULL, NULL);

	bar = g_new0(STATUSBAR_REC, 1);
	group->bars = g_slist_append(group->bars, bar);

	bar->group = group;

        bar->config = config;
        bar->parent_window = parent_window;

	irssi_set_dirty();
	bar->dirty = TRUE;
        bar->dirty_xpos = 0;

        signal_remove("terminal resized", (SIGNAL_FUNC) sig_terminal_resized);
	signal_remove("mainwindow resized", (SIGNAL_FUNC) sig_mainwindow_resized);
	signal_remove("mainwindow moved", (SIGNAL_FUNC) sig_mainwindow_resized);

	if (config->type == STATUSBAR_TYPE_ROOT) {
		/* top/bottom of the screen */
		mainwindows_reserve_lines(config->placement == STATUSBAR_TOP,
					  config->placement == STATUSBAR_BOTTOM);
                theme = current_theme;
	} else {
		/* top/bottom of the window */
		parent_window->statusbars =
			g_slist_append(parent_window->statusbars, bar);
		mainwindow_set_statusbar_lines(parent_window,
					       config->placement == STATUSBAR_TOP,
					       config->placement == STATUSBAR_BOTTOM);
		theme = parent_window != NULL && parent_window->active != NULL &&
			parent_window->active->theme != NULL ?
			parent_window->active->theme : current_theme;
	}

        signal_add("terminal resized", (SIGNAL_FUNC) sig_terminal_resized);
	signal_add("mainwindow resized", (SIGNAL_FUNC) sig_mainwindow_resized);
	signal_add("mainwindow moved", (SIGNAL_FUNC) sig_mainwindow_resized);

        /* get background color from sb_background abstract */
        name = g_strdup_printf("{sb_%s_bg}", config->name);
	value = theme_format_expand(theme, name);
	g_free(name);

	if (*value == '\0') {
                /* try with the statusbar group name */
		g_free(value);

		name = g_strdup_printf("{sb_%s_bg}", group->name);
		value = theme_format_expand(theme, name);
		g_free(name);

		if (*value == '\0') {
			/* fallback to default statusbar background
			   (also provides backwards compatibility..) */
                        g_free(value);
			value = theme_format_expand(theme, "{sb_background}");
		}
	}

	if (*value == '\0') {
                g_free(value);
		value = g_strdup("%8");
	}
	bar->color = g_strconcat("%n", value, NULL);
	g_free(value);

        statusbars_recalc_ypos(bar);
        signal_emit("statusbar created", 1, bar);

        /* create the items to statusbar */
	for (tmp = config->items; tmp != NULL; tmp = tmp->next) {
		SBAR_ITEM_CONFIG_REC *rec = tmp->data;

                statusbar_item_create(bar, rec);
	}
	return bar;
}

void statusbar_destroy(STATUSBAR_REC *bar)
{
	int top;

	g_return_if_fail(bar != NULL);

	bar->group->bars = g_slist_remove(bar->group->bars, bar);
	if (bar->parent_window != NULL) {
		bar->parent_window->statusbars =
			g_slist_remove(bar->parent_window->statusbars, bar);
	}

        signal_emit("statusbar destroyed", 1, bar);

	while (bar->items != NULL)
		statusbar_item_destroy(bar->items->data);

        g_free(bar->color);

	if (bar->config->type != STATUSBAR_TYPE_WINDOW ||
	    bar->parent_window != NULL)
		statusbars_recalc_ypos(bar);

	top = bar->config->placement == STATUSBAR_TOP;
	if (bar->config->type == STATUSBAR_TYPE_ROOT) {
		/* top/bottom of the screen */
		mainwindows_reserve_lines(top ? -1 : 0, !top ? -1 : 0);
	} else if (bar->parent_window != NULL) {
		/* top/bottom of the window */
		mainwindow_set_statusbar_lines(bar->parent_window,
					       top ? -1 : 0, !top ? -1 : 0);
	}

	g_free(bar);
}

void statusbar_recreate_items(STATUSBAR_REC *bar)
{
	GSList *tmp;

	/* destroy */
	while (bar->items != NULL)
		statusbar_item_destroy(bar->items->data);

        /* create */
	for (tmp = bar->config->items; tmp != NULL; tmp = tmp->next) {
		SBAR_ITEM_CONFIG_REC *rec = tmp->data;

                statusbar_item_create(bar, rec);
	}

        statusbar_redraw(bar, TRUE);
}

void statusbars_recreate_items(void)
{
	if (active_statusbar_group != NULL) {
		g_slist_foreach(active_statusbar_group->bars,
				(GFunc) statusbar_recreate_items, NULL);
	}
}

STATUSBAR_REC *statusbar_find(STATUSBAR_GROUP_REC *group, const char *name,
			      MAIN_WINDOW_REC *window)
{
	GSList *tmp;

	for (tmp = group->bars; tmp != NULL; tmp = tmp->next) {
		STATUSBAR_REC *rec = tmp->data;

		if (rec->parent_window == window &&
		    strcmp(rec->config->name, name) == 0)
                        return rec;
	}

        return NULL;
}

static const char *statusbar_item_get_value(SBAR_ITEM_REC *item)
{
	const char *value;

	value = item->config->value;
	if (value == NULL) {
		value = g_hash_table_lookup(sbar_item_defs,
					    item->config->name);
	}

        return value;
}

static GString *finalize_string(const char *str, const char *color)
{
	GString *out;

	out = g_string_new(color);

	while (*str != '\0') {
		if ((unsigned char) *str < 32 ||
		    (term_type == TERM_TYPE_8BIT &&
		     (unsigned char) (*str & 0x7f) < 32)) {
			/* control char */
			g_string_append_printf(out, "%%8%c%%8",
					  'A'-1 + (*str & 0x7f));
		} else if (*str == '%' && str[1] == 'n') {
			g_string_append(out, color);
			str++;
		} else {
			g_string_append_c(out, *str);
		}

		str++;
	}

	return out;
}

void statusbar_item_default_handler(SBAR_ITEM_REC *item, int get_size_only,
				    const char *str, const char *data,
				    int escape_vars)
{
	SERVER_REC *server;
	WI_ITEM_REC *wiitem; 
	char *tmpstr, *tmpstr2;
	int len;

	if (str == NULL)
		str = statusbar_item_get_value(item);
	if (str == NULL || *str == '\0') {
		item->min_size = item->max_size = 0;
		return;
	}

	if (active_win == NULL) {
		server = NULL;
                wiitem = NULL;
	} else {
		server = active_win->active_server != NULL ?
			active_win->active_server : active_win->connect_server;
		wiitem = active_win->active;
	}

	/* expand templates */
	tmpstr = theme_format_expand_data(current_theme, &str,
					  'n', 'n',
					  NULL, NULL,
					  EXPAND_FLAG_ROOT |
					  EXPAND_FLAG_IGNORE_REPLACES |
					  EXPAND_FLAG_IGNORE_EMPTY);
	/* expand $variables */
	tmpstr2 = parse_special_string(tmpstr, server, wiitem, data, NULL,
				       (escape_vars ? PARSE_FLAG_ESCAPE_VARS : 0 ));
        g_free(tmpstr);

	/* remove color codes (not %formats) */
	tmpstr = strip_codes(tmpstr2);
        g_free(tmpstr2);

	if (get_size_only) {
		item->min_size = item->max_size = format_get_length(tmpstr);
	} else {
		GString *out;

		if (item->size < item->min_size) {
                        /* they're forcing us smaller than minimum size.. */
			len = format_real_length(tmpstr, item->size);
                        tmpstr[len] = '\0';
		}
		out = finalize_string(tmpstr, item->bar->color);
		/* make sure the str is big enough to fill the
		   requested size, so it won't corrupt screen */
		len = format_get_length(tmpstr);
		if (len < item->size) {
			int i;

			len = item->size-len;
			for (i = 0; i < len; i++)
				g_string_append_c(out, ' ');
		}

		gui_printtext(item->xpos, item->bar->real_ypos, out->str);
		g_string_free(out, TRUE);
	}
	g_free(tmpstr);
}

static void statusbar_item_default_func(SBAR_ITEM_REC *item, int get_size_only)
{
	statusbar_item_default_handler(item, get_size_only, NULL, "", TRUE);
}

static void statusbar_update_item(void)
{
	GSList *items;

	items = g_hash_table_lookup(sbar_signal_items,
				    GINT_TO_POINTER(signal_get_emitted_id()));
	while (items != NULL) {
		SBAR_ITEM_REC *item = items->data;

		statusbar_item_redraw(item);
		items = items->next;
	}
}

static void statusbar_update_server(SERVER_REC *server)
{
        SERVER_REC *item_server;
	GSList *items;

	items = g_hash_table_lookup(sbar_signal_items,
				    GINT_TO_POINTER(signal_get_emitted_id()));
	while (items != NULL) {
		SBAR_ITEM_REC *item = items->data;

		item_server = item->bar->parent_window != NULL ?
			item->bar->parent_window->active->active_server :
			active_win->active_server;

		if (item_server == server)
			statusbar_item_redraw(item);

		items = items->next;
	}
}

static void statusbar_update_window(WINDOW_REC *window)
{
        WINDOW_REC *item_window;
	GSList *items;

	items = g_hash_table_lookup(sbar_signal_items,
				    GINT_TO_POINTER(signal_get_emitted_id()));
	while (items != NULL) {
		SBAR_ITEM_REC *item = items->data;

		item_window = item->bar->parent_window != NULL ?
			item->bar->parent_window->active : active_win;

		if (item_window == window)
			statusbar_item_redraw(item);

		items = items->next;
	}
}

static void statusbar_update_window_item(WI_ITEM_REC *wiitem)
{
        WI_ITEM_REC *item_wi;
	GSList *items;

	items = g_hash_table_lookup(sbar_signal_items,
				    GINT_TO_POINTER(signal_get_emitted_id()));
	while (items != NULL) {
		SBAR_ITEM_REC *item = items->data;

		item_wi = item->bar->parent_window != NULL ?
			item->bar->parent_window->active->active :
			active_win->active;

		if (item_wi == wiitem)
			statusbar_item_redraw(item);

		items = items->next;
	}
}

static void statusbar_item_default_signals(SBAR_ITEM_REC *item)
{
	SIGNAL_FUNC func;
        GSList *list;
	const char *value;
        void *signal_id;
        int *signals, *pos;

	value = statusbar_item_get_value(item);
	if (value == NULL)
		return;

	signals = special_vars_get_signals(value);
	if (signals == NULL)
		return;

	for (pos = signals; *pos != -1; pos += 2) {
		/* update signal -> item mappings */
                signal_id = GINT_TO_POINTER(*pos);
		list = g_hash_table_lookup(sbar_signal_items, signal_id);
		if (list == NULL) {
			switch (pos[1]) {
			case EXPANDO_ARG_NONE:
				func = (SIGNAL_FUNC) statusbar_update_item;
				break;
			case EXPANDO_ARG_SERVER:
				func = (SIGNAL_FUNC) statusbar_update_server;
				break;
			case EXPANDO_ARG_WINDOW:
				func = (SIGNAL_FUNC) statusbar_update_window;
				break;
			case EXPANDO_ARG_WINDOW_ITEM:
				func = (SIGNAL_FUNC) statusbar_update_window_item;
				break;
			default:
                                func = NULL;
                                break;
			}
			if (func != NULL) {
				signal_add_full_id(MODULE_NAME,
						   SIGNAL_PRIORITY_DEFAULT,
						   *pos, func, NULL);
			}
		}

		if (g_slist_find(list, item) == NULL)
			list = g_slist_append(list, item);
		g_hash_table_insert(sbar_signal_items, signal_id, list);

                /* update item -> signal mappings */
		list = g_hash_table_lookup(sbar_item_signals, item);
                if (g_slist_find(list, signal_id) == NULL)
			list = g_slist_append(list, signal_id);
		g_hash_table_insert(sbar_item_signals, item, list);
	}
        g_free(signals);
}

SBAR_ITEM_REC *statusbar_item_create(STATUSBAR_REC *bar,
				     SBAR_ITEM_CONFIG_REC *config)
{
	SBAR_ITEM_REC *rec;
        GSList *items;

	g_return_val_if_fail(bar != NULL, NULL);
	g_return_val_if_fail(config != NULL, NULL);

	rec = g_new0(SBAR_ITEM_REC, 1);
	bar->items = g_slist_append(bar->items, rec);

	rec->bar = bar;
	rec->config = config;

	rec->func = (STATUSBAR_FUNC) g_hash_table_lookup(sbar_item_funcs,
							 config->name);
	if (rec->func == NULL)
		rec->func = statusbar_item_default_func;
	statusbar_item_default_signals(rec);

	items = g_hash_table_lookup(named_sbar_items, config->name);
	items = g_slist_append(items, rec);
        g_hash_table_insert(named_sbar_items, config->name, items);

	irssi_set_dirty();
	rec->dirty = TRUE;
	bar->dirty = TRUE;

        signal_emit("statusbar item created", 1, rec);
	return rec;
}

static void statusbar_signal_remove(int signal_id)
{
	signal_remove_id(signal_id, (SIGNAL_FUNC) statusbar_update_item, NULL);
	signal_remove_id(signal_id, (SIGNAL_FUNC) statusbar_update_server, NULL);
	signal_remove_id(signal_id, (SIGNAL_FUNC) statusbar_update_window, NULL);
	signal_remove_id(signal_id, (SIGNAL_FUNC) statusbar_update_window_item, NULL);
}

static void statusbar_item_remove_signal(SBAR_ITEM_REC *item, int signal_id)
{
	GSList *list;

        /* update signal -> item hash */
	list = g_hash_table_lookup(sbar_signal_items,
				   GINT_TO_POINTER(signal_id));
	list = g_slist_remove(list, item);
	if (list != NULL) {
		g_hash_table_insert(sbar_signal_items,
				    GINT_TO_POINTER(signal_id), list);
	} else {
		g_hash_table_remove(sbar_signal_items,
				    GINT_TO_POINTER(signal_id));
                statusbar_signal_remove(signal_id);
	}
}

void statusbar_item_destroy(SBAR_ITEM_REC *item)
{
	GSList *list;

	g_return_if_fail(item != NULL);

	item->bar->items = g_slist_remove(item->bar->items, item);

	list = g_hash_table_lookup(named_sbar_items, item->config->name);
	list = g_slist_remove(list, item);
	if (list == NULL)
		g_hash_table_remove(named_sbar_items, item->config->name);
        else
		g_hash_table_insert(named_sbar_items, item->config->name, list);

        signal_emit("statusbar item destroyed", 1, item);

	list = g_hash_table_lookup(sbar_item_signals, item);
        g_hash_table_remove(sbar_item_signals, item);

	while (list != NULL) {
                statusbar_item_remove_signal(item, GPOINTER_TO_INT(list->data));
		list = g_slist_remove(list, list->data);
	}

	g_free(item);
}

static void statusbar_redraw_needed_items(STATUSBAR_REC *bar)
{
        WINDOW_REC *old_active_win;
	GSList *tmp;
	char *str;

	old_active_win = active_win;
        if (bar->parent_window != NULL)
		active_win = bar->parent_window->active;

	if (bar->dirty_xpos >= 0) {
		str = g_strconcat(bar->color, "%>", NULL);
		gui_printtext(bar->dirty_xpos, bar->real_ypos, str);
		g_free(str);
	}

	for (tmp = bar->items; tmp != NULL; tmp = tmp->next) {
		SBAR_ITEM_REC *rec = tmp->data;

		if (rec->dirty ||
		    (bar->dirty_xpos != -1 &&
		     rec->xpos >= bar->dirty_xpos)) {
                        rec->current_size = rec->size;
			rec->func(rec, FALSE);
			rec->dirty = FALSE;
		}
	}

        active_win = old_active_win;
}

void statusbar_redraw_dirty(void)
{
	GSList *tmp;

	if (statusbar_need_recreate_items) {
		statusbar_need_recreate_items = FALSE;
		statusbars_recreate_items();
	}

	for (tmp = active_statusbar_group->bars; tmp != NULL; tmp = tmp->next) {
		STATUSBAR_REC *rec = tmp->data;

		if (rec->dirty) {
                        statusbar_redraw_needed_items(rec);
			rec->dirty = FALSE;
			rec->dirty_xpos = -1;
		}
	}
}

#define STATUSBAR_IS_VISIBLE(bar, window) \
	((bar)->visible == STATUSBAR_VISIBLE_ALWAYS || \
	(active_mainwin == (window) && \
	 (bar)->visible == STATUSBAR_VISIBLE_ACTIVE) || \
	(active_mainwin != (window) && \
	 (bar)->visible == STATUSBAR_VISIBLE_INACTIVE))

static void statusbars_remove_unvisible(MAIN_WINDOW_REC *window)
{
	GSList *tmp, *next;

	for (tmp = window->statusbars; tmp != NULL; tmp = next) {
		STATUSBAR_REC *bar = tmp->data;

		next = tmp->next;
                if (!STATUSBAR_IS_VISIBLE(bar->config, window))
                        statusbar_destroy(bar);
	}
}

static void statusbars_add_visible(MAIN_WINDOW_REC *window)
{
	STATUSBAR_GROUP_REC *group;
        STATUSBAR_REC *bar;
	GSList *tmp;

        group = active_statusbar_group;
	for (tmp = group->config_bars; tmp != NULL; tmp = tmp->next) {
		STATUSBAR_CONFIG_REC *config = tmp->data;

		if (config->type == STATUSBAR_TYPE_WINDOW &&
		    STATUSBAR_IS_VISIBLE(config, window) &&
		    statusbar_find(group, config->name, window) == NULL) {
			bar = statusbar_create(group, config, window);
			statusbar_redraw(bar, TRUE);
		}
	}
}

static void sig_mainwindow_destroyed(MAIN_WINDOW_REC *window)
{
	while (window->statusbars != NULL) {
		STATUSBAR_REC *bar = window->statusbars->data;

		bar->parent_window->statusbars =
			g_slist_remove(bar->parent_window->statusbars, bar);
		bar->parent_window = NULL;
		statusbar_destroy(bar);
	}
}

static void sig_window_changed(void)
{
	GSList *tmp;

	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		statusbars_remove_unvisible(rec);
                statusbars_add_visible(rec);
	}
}

static void sig_gui_window_created(WINDOW_REC *window)
{
        statusbars_add_visible(WINDOW_MAIN(window));
}

static void statusbar_item_def_destroy(void *key, void *value)
{
	g_free(key);
        g_free(value);
}

static void statusbar_signal_item_destroy(void *key, GSList *value)
{
	while (value != NULL) {
		statusbar_signal_remove(GPOINTER_TO_INT(value->data));
                value->data = g_slist_remove(value, value->data);
	}
}

static void statusbar_item_signal_destroy(void *key, GSList *value)
{
        g_slist_free(value);
}

void statusbars_create_window_bars(void)
{
        g_slist_foreach(mainwindows, (GFunc) statusbars_add_visible, NULL);
}

void statusbar_init(void)
{
        statusbar_need_recreate_items = FALSE;
	statusbar_groups = NULL;
	active_statusbar_group = NULL;
	sbar_item_defs = g_hash_table_new((GHashFunc) g_str_hash,
					  (GCompareFunc) g_str_equal);
	sbar_item_funcs = g_hash_table_new((GHashFunc) g_str_hash,
					   (GCompareFunc) g_str_equal);
	sbar_signal_items = g_hash_table_new((GHashFunc) g_direct_hash,
					     (GCompareFunc) g_direct_equal);
	sbar_item_signals = g_hash_table_new((GHashFunc) g_direct_hash,
					     (GCompareFunc) g_direct_equal);
	named_sbar_items = g_hash_table_new((GHashFunc) g_str_hash,
					    (GCompareFunc) g_str_equal);

        signal_add("terminal resized", (SIGNAL_FUNC) sig_terminal_resized);
	signal_add("mainwindow resized", (SIGNAL_FUNC) sig_mainwindow_resized);
	signal_add("mainwindow moved", (SIGNAL_FUNC) sig_mainwindow_resized);
	signal_add("gui window created", (SIGNAL_FUNC) sig_gui_window_created);
	signal_add("window changed", (SIGNAL_FUNC) sig_window_changed);
	signal_add("mainwindow destroyed", (SIGNAL_FUNC) sig_mainwindow_destroyed);

	statusbar_items_init();
	statusbar_config_init(); /* signals need to be before this call */
}

void statusbar_deinit(void)
{
	while (statusbar_groups != NULL)
		statusbar_group_destroy(statusbar_groups->data);

	g_hash_table_foreach(sbar_item_defs,
			     (GHFunc) statusbar_item_def_destroy, NULL);
	g_hash_table_destroy(sbar_item_defs);

	g_hash_table_foreach(sbar_item_funcs, (GHFunc) g_free, NULL);
	g_hash_table_destroy(sbar_item_funcs);

	g_hash_table_foreach(sbar_signal_items,
			     (GHFunc) statusbar_signal_item_destroy, NULL);
	g_hash_table_destroy(sbar_signal_items);
	g_hash_table_foreach(sbar_item_signals,
			     (GHFunc) statusbar_item_signal_destroy, NULL);
	g_hash_table_destroy(sbar_item_signals);
	g_hash_table_destroy(named_sbar_items);

        signal_remove("terminal resized", (SIGNAL_FUNC) sig_terminal_resized);
	signal_remove("mainwindow resized", (SIGNAL_FUNC) sig_mainwindow_resized);
	signal_remove("mainwindow moved", (SIGNAL_FUNC) sig_mainwindow_resized);
	signal_remove("gui window created", (SIGNAL_FUNC) sig_gui_window_created);
	signal_remove("window changed", (SIGNAL_FUNC) sig_window_changed);
	signal_remove("mainwindow destroyed", (SIGNAL_FUNC) sig_mainwindow_destroyed);

	statusbar_items_deinit();
	statusbar_config_deinit();
}
