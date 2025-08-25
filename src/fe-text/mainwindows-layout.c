/*
 mainwindows-layout.c : irssi

    Copyright (C) 2001 Timo Sirainen

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
#include <irssi/src/lib-config/iconfig.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/core/levels.h>

#include <irssi/src/fe-text/mainwindows.h>
#include <irssi/src/fe-text/gui-windows.h>
#include <irssi/src/fe-text/textbuffer-view.h>

static void sig_layout_window_save(WINDOW_REC *window, CONFIG_NODE *node)
{
	WINDOW_REC *active;
	GUI_WINDOW_REC *gui;

	gui = WINDOW_GUI(window);
	if (gui->sticky) {
		iconfig_node_set_bool(node, "sticky", TRUE);
		active = gui->parent->active;
		if (window != active)
			iconfig_node_set_int(node, "parent", active->refnum);
	}

	if (gui->view->hidden_level != settings_get_level("window_default_hidelevel")) {
		char *level = bits2level(gui->view->hidden_level);
		iconfig_node_set_str(node, "hidelevel", level);
		g_free(level);
	} else {
		iconfig_node_set_str(node, "hidelevel", NULL);
	}

	if (gui->use_scroll)
		iconfig_node_set_bool(node, "scroll", gui->scroll);
}

static void sig_layout_window_restore(WINDOW_REC *window, CONFIG_NODE *node)
{
	WINDOW_REC *parent;
	GUI_WINDOW_REC *gui;
	const char *default_hidelevel = settings_get_str("window_default_hidelevel");

	gui = WINDOW_GUI(window);

	parent = window_find_refnum(config_node_get_int(node, "parent", -1));
	if (parent != NULL)
		gui_window_reparent(window, WINDOW_MAIN(parent));

	if (config_node_get_bool(node, "sticky", FALSE))
		gui_window_set_sticky(window);

	textbuffer_view_set_hidden_level(
	    gui->view, level2bits(config_node_get_str(node, "hidelevel", default_hidelevel), NULL));

	if (config_node_get_str(node, "scroll", NULL) != NULL) {
		gui->use_scroll = TRUE;
		gui->scroll = config_node_get_bool(node, "scroll", TRUE);
		textbuffer_view_set_scroll(gui->view, gui->scroll);
	}
}

static void main_window_save(MAIN_WINDOW_REC *window, CONFIG_NODE *node)
{
	char num[MAX_INT_STRLEN];

	ltoa(num, window->active->refnum);
	node = iconfig_node_section(node, num, NODE_TYPE_BLOCK);

	iconfig_node_set_int(node, "first_line", window->first_line);
	iconfig_node_set_int(node, "lines", window->height);
	iconfig_node_set_int(node, "first_column", window->first_column);
	iconfig_node_set_int(node, "columns", window->width);
}

static void sig_layout_save(void)
{
	CONFIG_NODE *node;

	iconfig_set_str(NULL, "mainwindows", NULL);
	node = iconfig_node_traverse("mainwindows", TRUE);

	g_slist_foreach(mainwindows, (GFunc) main_window_save, node);
}

static int window_node_cmp(CONFIG_NODE *n1, CONFIG_NODE *n2)
{
	return (config_node_get_int(n1, "first_line", 0) ==
	            config_node_get_int(n2, "first_line", 0) &&
	        config_node_get_int(n1, "first_column", 0) >
	            config_node_get_int(n2, "first_column", 0)) ||
	               config_node_get_int(n1, "first_line", 0) >
	                   config_node_get_int(n2, "first_line", 0) ?
	           -1 :
	           1;
}

/* Returns list of mainwindow nodes sorted by first_line
   (lowest in screen first) */
static GSList *get_sorted_windows_config(CONFIG_NODE *node)
{
	GSList *tmp, *output;

	output = NULL;
	tmp = config_node_first(node->value);
	for (; tmp != NULL; tmp = config_node_next(tmp)) {
		output = g_slist_insert_sorted(output, tmp->data, (GCompareFunc) window_node_cmp);
	}

	return output;
}

static GSList *get_windows_config_filter_line(GSList *in)
{
	GSList *tmp, *output;

	output = NULL;
	for (tmp = in; tmp != NULL; tmp = tmp->next) {
		CONFIG_NODE *node = tmp->data;
		if (config_node_get_int(node, "first_column", 0) == 0)
			output = g_slist_append(output, node);
	}

	return output;
}

static GSList *get_windows_config_filter_column(GSList *in, int first_line, int last_line)
{
	GSList *tmp, *output;

	output = NULL;
	for (tmp = in; tmp != NULL; tmp = tmp->next) {
		int l1, l2;
		CONFIG_NODE *node = tmp->data;
		l1 = config_node_get_int(node, "first_line", -1);
		l2 = l1 + config_node_get_int(node, "lines", 0) - 1;
		if (l1 >= first_line && l2 <= last_line)
			output = g_slist_prepend(output, node);
	}

	return output;
}

static void sig_layout_restore(void)
{
	MAIN_WINDOW_REC *lower_window;
	WINDOW_REC *window, *first;
	CONFIG_NODE *node;
	GSList *tmp, *sorted_config, *lines_config;
	int avail_height, height, *heights, *widths, max_wins_line;
	int i, lower_size, lines_count, columns_count, diff;

	node = iconfig_node_traverse("mainwindows", FALSE);
	if (node == NULL)
		return;

	sorted_config = get_sorted_windows_config(node);
	if (sorted_config == NULL)
		return;

	lines_config = get_windows_config_filter_line(sorted_config);
	lines_count = g_slist_length(lines_config);

	/* calculate the saved terminal height */
	avail_height = term_height - screen_reserved_top - screen_reserved_bottom;
	height = 0;
	heights = g_new0(int, lines_count);
	for (i = 0, tmp = lines_config; tmp != NULL; tmp = tmp->next, i++) {
		CONFIG_NODE *node = tmp->data;

		heights[i] = config_node_get_int(node, "lines", 0);
		height += heights[i];
	}

	max_wins_line = (term_width + 1) / (NEW_WINDOW_WIDTH + 1);
	if (max_wins_line < 1)
		max_wins_line = 1;

	if (avail_height <= (WINDOW_MIN_SIZE * 2) + 1) {
		/* we can fit only one window to screen -
		   give it all the height we can */
		lines_count = 1;
		heights[0] = avail_height;
	} else if (height != avail_height) {
		/* Terminal's height is different from the saved one.
		   Resize the windows so they fit to screen. */
		while (height > avail_height &&
		       lines_count * (WINDOW_MIN_SIZE + 1) > avail_height) {
			/* all windows can't fit into screen,
			   remove the lowest ones */
			lines_count--;
		}

		/* try to keep the windows' size about the same in percents */
		for (i = 0; i < lines_count; i++) {
			int size = avail_height * heights[i] / height;
			if (size < WINDOW_MIN_SIZE + 1)
				size = WINDOW_MIN_SIZE + 1;
			heights[i] = size;
		}

		/* give/remove the last bits */
		height = 0;
		for (i = 0; i < lines_count; i++)
			height += heights[i];

		diff = height < avail_height ? 1 : -1;
		for (i = 0; height != avail_height; i++) {
			if (i == lines_count)
				i = 0;

			if (heights[i] > WINDOW_MIN_SIZE + 1) {
				height += diff;
				heights[i] += diff;
			}
		}
	}

	/* create all the visible windows with correct size */
	lower_window = NULL;
	lower_size = 0;
	first = NULL;
	for (i = 0, tmp = lines_config; i < lines_count; tmp = tmp->next, i++) {
		GSList *tmp2, *columns_config, *line;
		int j, l1, l2;
		CONFIG_NODE *node = tmp->data;
		if (node->key == NULL)
			continue;

		l1 = config_node_get_int(node, "first_line", -1);
		l2 = l1 + config_node_get_int(node, "lines", 0) - 1;
		columns_config = get_windows_config_filter_column(sorted_config, l1, l2);

		window = NULL;
		columns_count = 0;
		widths = g_new0(int, max_wins_line);
		for (j = 0, tmp2 = columns_config; j < max_wins_line && tmp2 != NULL;
		     tmp2 = tmp2->next, j++) {
			int width;
			WINDOW_REC *new_win;
			CONFIG_NODE *node2 = tmp2->data;
			if (node2->key == NULL)
				continue;

			/* create a new window + mainwindow */
			signal_emit("gui window create override", 1,
			            GINT_TO_POINTER(window == NULL ? MAIN_WINDOW_TYPE_SPLIT :
			                                             MAIN_WINDOW_TYPE_RSPLIT));

			new_win = window_create(NULL, TRUE);

			window_set_refnum(new_win, atoi(node2->key));
			width = config_node_get_int(node2, "columns", NEW_WINDOW_WIDTH);
			widths[j] = width;
			columns_count += width + (window == NULL ? 0 : 1);

			if (window == NULL)
				window = new_win;
			if (first == NULL)
				first = new_win;

			window_set_active(new_win);
			active_mainwin = WINDOW_MAIN(new_win);
		}
		if (window == NULL)
			continue;
		line = g_slist_reverse(mainwindows_get_line(WINDOW_MAIN(window)));
		for (j = g_slist_length(line), tmp2 = line; tmp2 != NULL; tmp2 = tmp2->next, j--) {
			int width =
			    MAX(NEW_WINDOW_WIDTH, widths[j - 1] * term_width / columns_count);
			MAIN_WINDOW_REC *rec = tmp2->data;
			mainwindow_set_rsize(rec, width);
		}
		g_slist_free(line);
		g_free(widths);

		if (lower_size > 0)
			mainwindow_set_size(lower_window, lower_size, FALSE);

		lower_window = WINDOW_MAIN(window);
		lower_size = heights[i];
		if (lower_size < WINDOW_MIN_SIZE + 1)
			lower_size = WINDOW_MIN_SIZE + 1;
	}
	g_slist_free(sorted_config);
	g_free(heights);

	if (lower_size > 0)
		mainwindow_set_size(lower_window, lower_size, FALSE);

	if (first != NULL) {
		window_set_active(first);
		active_mainwin = WINDOW_MAIN(first);
	}
}

static void sig_layout_reset(void)
{
	iconfig_set_str(NULL, "mainwindows", NULL);
}

void mainwindows_layout_init(void)
{
	signal_add("layout save window", (SIGNAL_FUNC) sig_layout_window_save);
	signal_add("layout restore window", (SIGNAL_FUNC) sig_layout_window_restore);
	signal_add("layout save", (SIGNAL_FUNC) sig_layout_save);
	signal_add_first("layout restore", (SIGNAL_FUNC) sig_layout_restore);
	signal_add("layout reset", (SIGNAL_FUNC) sig_layout_reset);
}

void mainwindows_layout_deinit(void)
{
	signal_remove("layout save window", (SIGNAL_FUNC) sig_layout_window_save);
	signal_remove("layout restore window", (SIGNAL_FUNC) sig_layout_window_restore);
	signal_remove("layout save", (SIGNAL_FUNC) sig_layout_save);
	signal_remove("layout restore", (SIGNAL_FUNC) sig_layout_restore);
	signal_remove("layout reset", (SIGNAL_FUNC) sig_layout_reset);
}
