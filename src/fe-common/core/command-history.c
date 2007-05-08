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
#include "signals.h"
#include "misc.h"
#include "special-vars.h"
#include "settings.h"

#include "fe-windows.h"
#include "window-items.h"

#include "command-history.h"

/* command history */
static HISTORY_REC *global_history;
static int window_history;
static GSList *histories;

void command_history_add(HISTORY_REC *history, const char *text)
{
	GList *link;

	g_return_if_fail(history != NULL);
	g_return_if_fail(text != NULL);

	link = g_list_last(history->list);
	if (link != NULL && strcmp(link->data, text) == 0)
	  return; /* same as previous entry */

	if (settings_get_int("max_command_history") < 1 || 
	    history->lines < settings_get_int("max_command_history"))
		history->lines++;
	else {
		link = history->list;
		g_free(link->data);
		history->list = g_list_remove_link(history->list, link);
		g_list_free_1(link);
	}

	history->list = g_list_append(history->list, g_strdup(text));
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
		
		if (rec->name != NULL && g_strcasecmp(rec->name, name) == 0)
			return rec;
	}
	
	return NULL;
}

HISTORY_REC *command_history_current(WINDOW_REC *window)
{
	HISTORY_REC *rec;

	if (window == NULL)
		return global_history;

	if (window_history)
		return window->history;

	rec = command_history_find_name(window->history_name);
	if (rec != NULL)
		return rec;

	return global_history;
}

const char *command_history_prev(WINDOW_REC *window, const char *text)
{
	HISTORY_REC *history;
	GList *pos;

	history = command_history_current(window);
	pos = history->pos;

	if (pos != NULL) {
		history->pos = history->pos->prev;
		if (history->pos == NULL)
                        history->over_counter++;
	} else {
		history->pos = g_list_last(history->list);
	}

	if (*text != '\0' &&
	    (pos == NULL || strcmp(pos->data, text) != 0)) {
		/* save the old entry to history */
		command_history_add(history, text);
	}

	return history->pos == NULL ? "" : history->pos->data;
}

const char *command_history_next(WINDOW_REC *window, const char *text)
{
	HISTORY_REC *history;
	GList *pos;

	history = command_history_current(window);
	pos = history->pos; 

	if (pos != NULL)
		history->pos = history->pos->next;
	else if (history->over_counter > 0) {
		history->over_counter--;
		history->pos = history->list;
	}

	if (*text != '\0' &&
	    (pos == NULL || strcmp(pos->data, text) != 0)) {
		/* save the old entry to history */
		command_history_add(history, text);
	}
	return history->pos == NULL ? "" : history->pos->data;
}

void command_history_clear_pos_func(HISTORY_REC *history, gpointer user_data)
{
	history->over_counter = 0;
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

void command_history_destroy(HISTORY_REC *history)
{
	g_return_if_fail(history != NULL);

	/* history->refcount should be 0 here, or somthing is wrong... */
	g_return_if_fail(history->refcount == 0);

	histories = g_slist_remove(histories, history);

	g_list_foreach(history->list, (GFunc) g_free, NULL);
	g_list_free(history->list);

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
	for (tmp = history->list; tmp != NULL; tmp = tmp->next) {
		const char *line = tmp->data;

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

	special_history_func_set(special_history_func);

	global_history = command_history_create(NULL);

	read_settings();
	signal_add("window created", (SIGNAL_FUNC) sig_window_created);
	signal_add("window destroyed", (SIGNAL_FUNC) sig_window_destroyed);
	signal_add("window history changed", (SIGNAL_FUNC) sig_window_history_changed);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
}

void command_history_deinit(void)
{
	signal_remove("window created", (SIGNAL_FUNC) sig_window_created);
	signal_remove("window destroyed", (SIGNAL_FUNC) sig_window_destroyed);
	signal_remove("window history changed", (SIGNAL_FUNC) sig_window_history_changed);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);

	command_history_destroy(global_history);
}
