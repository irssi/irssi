/*
 command-history.c : irssi

    Copyright (C) 1999 Timo Sirainen

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
#include <irssi/src/core/misc.h>
#include <irssi/src/core/special-vars.h>
#include <irssi/src/core/settings.h>

#include <irssi/src/fe-common/core/fe-windows.h>
#include <irssi/src/fe-common/core/window-items.h>

#include <irssi/src/fe-common/core/command-history.h>

/* command history */
static GList *history_entries;
static HISTORY_REC *global_history;
static int window_history;
static GSList *histories;

static HISTORY_ENTRY_REC *history_entry_new(HISTORY_REC *history, const char *text)
{
	HISTORY_ENTRY_REC *entry;

	entry = g_new0(HISTORY_ENTRY_REC, 1);
	entry->text = g_strdup(text);
	entry->history = history;
	entry->time = time(NULL);

	return entry;
}

static void history_entry_destroy(HISTORY_ENTRY_REC *entry)
{
	g_free((char *)entry->text);
	g_free(entry);
}

GList *command_history_list_last(HISTORY_REC *history)
{
	GList *link;

	link = g_list_last(history_entries);
	while (link != NULL && history != NULL && ((HISTORY_ENTRY_REC *)link->data)->history != history) {
		link = link->prev;
	}

	return link;
}

GList *command_history_list_first(HISTORY_REC *history)
{
	GList *link;

	link = history_entries;
	while (link != NULL && history != NULL && ((HISTORY_ENTRY_REC *)link->data)->history != history) {
		link = link->next;
	}

	return link;
}

GList *command_history_list_prev(HISTORY_REC *history, GList *pos)
{
	GList *link;

	link = pos != NULL ? pos->prev : NULL;
	while (link != NULL && history != NULL && ((HISTORY_ENTRY_REC *)link->data)->history != history) {
		link = link->prev;
	}

	return link;
}

GList *command_history_list_next(HISTORY_REC *history, GList *pos)
{
	GList *link;

	link = pos != NULL ? pos->next : NULL;
	while (link != NULL && history != NULL && ((HISTORY_ENTRY_REC *)link->data)->history != history) {
		link = link->next;
	}

	return link;
}

static void command_history_clear_pos_for_unlink_func(HISTORY_REC *history, GList* link)
{
	if (history->pos == link) {
		history->pos = command_history_list_next(history, link);
		history->redo = 1;
	}
}

static void history_list_delete_link_and_destroy(GList *link)
{
	g_slist_foreach(histories,
		       (GFunc) command_history_clear_pos_for_unlink_func, link);
	history_entry_destroy(link->data);
	history_entries = g_list_delete_link(history_entries, link);
}

void command_history_add(HISTORY_REC *history, const char *text)
{
	GList *link;

	g_return_if_fail(history != NULL);
	g_return_if_fail(text != NULL);

	link = command_history_list_last(history);
	if (link != NULL && g_strcmp0(((HISTORY_ENTRY_REC *)link->data)->text, text) == 0)
		return; /* same as previous entry */

	if (settings_get_int("max_command_history") < 1 ||
	    history->lines < settings_get_int("max_command_history"))
		history->lines++;
	else {
		link = command_history_list_first(history);
		history_list_delete_link_and_destroy(link);
	}

	history_entries = g_list_append(history_entries, history_entry_new(history, text));
}

HISTORY_REC *command_history_find(HISTORY_REC *history)
{
	GSList *tmp;
	tmp = g_slist_find(histories, history);

	if (tmp == NULL)
		return NULL;
	else
		return tmp->data;
}

HISTORY_REC *command_history_find_name(const char *name)
{
	GSList *tmp;

	if (name == NULL)
		return NULL;

	for (tmp = histories; tmp != NULL; tmp = tmp->next) {
		HISTORY_REC *rec = tmp->data;

		if (rec->name != NULL &&
		    g_ascii_strcasecmp(rec->name, name) == 0)
			return rec;
	}

	return NULL;
}

static int history_entry_after_time_sort(const HISTORY_ENTRY_REC *a, const HISTORY_ENTRY_REC *b)
{
	return a->time == b->time ? 1 : a->time - b->time;
}

void command_history_load_entry(time_t history_time, HISTORY_REC *history, const char *text)
{
	HISTORY_ENTRY_REC *entry;

	g_return_if_fail(history != NULL);
	g_return_if_fail(text != NULL);

	entry = g_new0(HISTORY_ENTRY_REC, 1);
	entry->text = g_strdup(text);
	entry->history = history;
	entry->time = history_time;

	history->lines++;

	history_entries = g_list_insert_sorted(history_entries, entry, (GCompareFunc)history_entry_after_time_sort);
}

static int history_entry_find_func(const HISTORY_ENTRY_REC *data, const HISTORY_ENTRY_REC *user_data)
{
	if ((user_data->time == -1 || (data->time == user_data->time)) &&
	    (user_data->history == NULL || (data->history == user_data->history)) &&
	    g_strcmp0(data->text, user_data->text) == 0) {
		return 0;
	} else {
		return -1;
	}
}

gboolean command_history_delete_entry(time_t history_time, HISTORY_REC *history, const char *text)
{
	GList *link;
	HISTORY_ENTRY_REC entry;

	g_return_val_if_fail(history != NULL, FALSE);
	g_return_val_if_fail(text != NULL, FALSE);

	entry.text = text;
	entry.history = history;
	entry.time = history_time;

	link = g_list_find_custom(history_entries, &entry, (GCompareFunc)history_entry_find_func);
	if (link != NULL) {
		((HISTORY_ENTRY_REC *)link->data)->history->lines--;
		history_list_delete_link_and_destroy(link);
		return TRUE;
	} else {
		return FALSE;
	}
}

HISTORY_REC *command_history_current(WINDOW_REC *window)
{
	HISTORY_REC *rec;

	if (window == NULL)
		return global_history;

	rec = command_history_find_name(window->history_name);
	if (rec != NULL)
		return rec;

	if (window_history)
		return window->history;

	return global_history;
}

static const char *command_history_prev_int(WINDOW_REC *window, const char *text, gboolean global)
{
	HISTORY_REC *history;
	GList *pos;

	history = command_history_current(window);
	pos = history->pos;
	history->redo = 0;

	if (pos != NULL) {
		/* don't go past the first entry (no wrap around) */
		GList *prev = command_history_list_prev(global ? NULL : history, history->pos);
		if (prev != NULL)
			history->pos = prev;
	} else {
		history->pos = command_history_list_last(global ? NULL : history);
	}

	if (*text != '\0' &&
	    (pos == NULL || g_strcmp0(((HISTORY_ENTRY_REC *)pos->data)->text, text) != 0)) {
		/* save the old entry to history */
		if (pos != NULL && settings_get_bool("command_history_editable")) {
			history_entry_destroy(pos->data);
			pos->data = history_entry_new(history, text);
		} else {
			command_history_add(history, text);
		}
	}

	return history->pos == NULL ? text : ((HISTORY_ENTRY_REC *)history->pos->data)->text;
}

const char *command_history_prev(WINDOW_REC *window, const char *text)
{
	return command_history_prev_int(window, text, FALSE);
}

const char *command_global_history_prev(WINDOW_REC *window, const char *text)
{
	return command_history_prev_int(window, text, TRUE);
}

static const char *command_history_next_int(WINDOW_REC *window, const char *text, gboolean global)
{
	HISTORY_REC *history;
	GList *pos;

	history = command_history_current(window);
	pos = history->pos;

	if (!(history->redo) && pos != NULL)
		history->pos = command_history_list_next(global ? NULL : history, history->pos);
	history->redo = 0;

	if (*text != '\0' &&
	    (pos == NULL || g_strcmp0(((HISTORY_ENTRY_REC *)pos->data)->text, text) != 0)) {
		/* save the old entry to history */
		if (pos != NULL && settings_get_bool("command_history_editable")) {
			history_entry_destroy(pos->data);
			pos->data = history_entry_new(history, text);
		} else {
			command_history_add(history, text);
		}
	}
	return history->pos == NULL ? "" : ((HISTORY_ENTRY_REC *)history->pos->data)->text;
}

const char *command_history_next(WINDOW_REC *window, const char *text)
{
	return command_history_next_int(window, text, FALSE);
}

const char *command_global_history_next(WINDOW_REC *window, const char *text)
{
	return command_history_next_int(window, text, TRUE);
}

const char *command_history_delete_current(WINDOW_REC *window, const char *text)
{
	HISTORY_REC *history;
	GList *pos;

	history = command_history_current(window);
	pos = history->pos;

	if (pos != NULL && g_strcmp0(((HISTORY_ENTRY_REC *)pos->data)->text, text) == 0) {
		((HISTORY_ENTRY_REC *)pos->data)->history->lines--;
		history_list_delete_link_and_destroy(pos);
	}

	history->redo = 0;
	return history->pos == NULL ? "" : ((HISTORY_ENTRY_REC *)history->pos->data)->text;
}

void command_history_clear_pos_func(HISTORY_REC *history, gpointer user_data)
{
	history->pos = NULL;
}

void command_history_clear_pos(WINDOW_REC *window)
{
	g_slist_foreach(histories,
		       (GFunc) command_history_clear_pos_func, NULL);
}

HISTORY_REC *command_history_create(const char *name)
{
	HISTORY_REC *rec;

	rec = g_new0(HISTORY_REC, 1);

	if (name != NULL)
		rec->name = g_strdup(name);

	histories = g_slist_append(histories, rec);

	return rec;
}

void command_history_clear(HISTORY_REC *history)
{
	GList *link, *next;

	g_return_if_fail(history != NULL);

	command_history_clear_pos_func(history, NULL);
	link = command_history_list_first(history);
	while (link != NULL) {
		next = command_history_list_next(history, link);
		history_list_delete_link_and_destroy(link);
		link = next;
	}
	history->lines = 0;
}

void command_history_destroy(HISTORY_REC *history)
{
	g_return_if_fail(history != NULL);

	/* history->refcount should be 0 here, or somthing is wrong... */
	g_return_if_fail(history->refcount == 0);

	histories = g_slist_remove(histories, history);
	command_history_clear(history);

	g_free_not_null(history->name);
	g_free(history);
}

void command_history_link(const char *name)
{
	HISTORY_REC *rec;
	rec = command_history_find_name(name);

	if (rec == NULL)
		rec = command_history_create(name);

	rec->refcount++;
}

void command_history_unlink(const char *name)
{
	HISTORY_REC *rec;
	rec = command_history_find_name(name);

	if (rec == NULL)
		return;

	if (--(rec->refcount) <= 0)
		command_history_destroy(rec);
}

static void sig_window_created(WINDOW_REC *window, int automatic)
{
	window->history = command_history_create(NULL);
}

static void sig_window_destroyed(WINDOW_REC *window)
{
	command_history_unlink(window->history_name);
	command_history_destroy(window->history);
	g_free_not_null(window->history_name);
}

static void sig_window_history_cleared(WINDOW_REC *window, const char *name) {
	HISTORY_REC *history;

	if (name == NULL || *name == '\0') {
		history = command_history_current(window);
	} else {
		history = command_history_find_name(name);
	}

	command_history_clear(history);
}

static void sig_window_history_changed(WINDOW_REC *window, const char *oldname)
{
	command_history_link(window->history_name);
	command_history_unlink(oldname);
}

static char *special_history_func(const char *text, void *item, int *free_ret)
{
	WINDOW_REC *window;
	HISTORY_REC *history;
	GList *tmp;
        char *findtext, *ret;

	window = item == NULL ? active_win : window_item_window(item);

	findtext = g_strdup_printf("*%s*", text);
	ret = NULL;

	history = command_history_current(window);
	for (tmp = command_history_list_first(history); tmp != NULL; tmp = command_history_list_next(history, tmp)) {
		const char *line = ((HISTORY_ENTRY_REC *)tmp->data)->text;

		if (match_wildcards(findtext, line)) {
			*free_ret = TRUE;
                        ret = g_strdup(line);
		}
	}
	g_free(findtext);

	return ret;
}

static void read_settings(void)
{
	window_history = settings_get_bool("window_history");
}

void command_history_init(void)
{
	settings_add_int("history", "max_command_history", 100);
	settings_add_bool("history", "window_history", FALSE);
	settings_add_bool("history", "command_history_editable", FALSE);

	special_history_func_set(special_history_func);

	history_entries = NULL;

	global_history = command_history_create(NULL);

	read_settings();
	signal_add("window created", (SIGNAL_FUNC) sig_window_created);
	signal_add("window destroyed", (SIGNAL_FUNC) sig_window_destroyed);
	signal_add("window history changed", (SIGNAL_FUNC) sig_window_history_changed);
	signal_add_last("window history cleared", (SIGNAL_FUNC) sig_window_history_cleared);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
}

void command_history_deinit(void)
{
	signal_remove("window created", (SIGNAL_FUNC) sig_window_created);
	signal_remove("window destroyed", (SIGNAL_FUNC) sig_window_destroyed);
	signal_remove("window history changed", (SIGNAL_FUNC) sig_window_history_changed);
	signal_remove("window history cleared", (SIGNAL_FUNC) sig_window_history_cleared);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);

	command_history_destroy(global_history);

	g_list_free_full(history_entries, (GDestroyNotify) history_entry_destroy);
}
