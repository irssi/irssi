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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "signals.h"
#include "misc.h"
#include "special-vars.h"
#include "settings.h"

#include "fe-windows.h"
#include "window-items.h"

/* command history */
static GList *history, *history_pos;
static int history_lines, history_over_counter;
static int window_history;

void command_history_add(WINDOW_REC *window, const char *text)
{
	GList **phistory, *link;
	int *phistory_lines;

	g_return_if_fail(text != NULL);

	if (window_history) {
		/* window specific command history */
		phistory = &window->history;
		phistory_lines = &window->history_lines;
	} else {
		/* global command history */
		phistory = &history;
		phistory_lines = &history_lines;
	}

	if (settings_get_int("max_command_history") < 1 || *phistory_lines < settings_get_int("max_command_history"))
		(*phistory_lines)++;
	else {
		link = *phistory;
		g_free(link->data);
		*phistory = g_list_remove_link(*phistory, link);
		g_list_free_1(link);
	}

	*phistory = g_list_append(*phistory, g_strdup(text));
}

const char *command_history_prev(WINDOW_REC *window, const char *text)
{
	GList *pos, **phistory_pos;
        int *phistory_over_counter;

	if (window_history) {
		phistory_pos = &window->history_pos;
		phistory_over_counter = &window->history_over_counter;
	} else {
		phistory_pos = &history_pos;
		phistory_over_counter = &history_over_counter;
	}

	pos = *phistory_pos;
	if (*phistory_pos != NULL) {
		*phistory_pos = (*phistory_pos)->prev;
		if (*phistory_pos == NULL)
                        (*phistory_over_counter)++;
	} else {
		*phistory_pos = g_list_last(window_history ?
					    window->history : history);
	}

	if (*text != '\0' &&
	    (pos == NULL || strcmp(pos->data, text) != 0)) {
		/* save the old entry to history */
		command_history_add(window, text);
	}

	return *phistory_pos == NULL ? "" : (*phistory_pos)->data;
}

const char *command_history_next(WINDOW_REC *window, const char *text)
{
	GList *pos, **phistory_pos;
        int *phistory_over_counter;

	if (window_history) {
		phistory_pos = &window->history_pos;
		phistory_over_counter = &window->history_over_counter;
	} else {
		phistory_pos = &history_pos;
		phistory_over_counter = &history_over_counter;
	}

	pos = *phistory_pos;

	if (pos != NULL)
		*phistory_pos = (*phistory_pos)->next;
	else if (*phistory_over_counter > 0) {
		(*phistory_over_counter)--;
		*phistory_pos = window_history ? window->history : history;
	}

	if (*text != '\0' &&
	    (pos == NULL || strcmp(pos->data, text) != 0)) {
		/* save the old entry to history */
		command_history_add(window, text);
	}
	return *phistory_pos == NULL ? "" : (*phistory_pos)->data;
}

void command_history_clear_pos(WINDOW_REC *window)
{
	window->history_over_counter = 0;
	window->history_pos = NULL;
        history_over_counter = 0;
	history_pos = NULL;
}

static void sig_window_destroyed(WINDOW_REC *window)
{
	g_list_foreach(window->history, (GFunc) g_free, NULL);
	g_list_free(window->history);
}

static char *special_history_func(const char *text, void *item, int *free_ret)
{
	WINDOW_REC *window;
	GList *tmp;
        char *findtext, *ret;

	window = item == NULL ? active_win : window_item_window(item);

	findtext = g_strdup_printf("*%s*", text);
	ret = NULL;

	tmp = window_history ? window->history : history;
	for (; tmp != NULL; tmp = tmp->next) {
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

	history_lines = 0; history_over_counter = 0;
	history = NULL; history_pos = NULL;

	read_settings();
	signal_add("window destroyed", (SIGNAL_FUNC) sig_window_destroyed);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
}

void command_history_deinit(void)
{
	signal_remove("window destroyed", (SIGNAL_FUNC) sig_window_destroyed);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);

	g_list_foreach(history, (GFunc) g_free, NULL);
	g_list_free(history);
}
