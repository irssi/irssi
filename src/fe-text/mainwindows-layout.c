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
#include "signals.h"
#include "misc.h"
#include "lib-config/iconfig.h"
#include "settings.h"

#include "mainwindows.h"
#include "gui-windows.h"
#include "textbuffer-view.h"

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

	if (gui->use_scroll)
                iconfig_node_set_bool(node, "scroll", gui->scroll);
}

static void sig_layout_window_restore(WINDOW_REC *window, CONFIG_NODE *node)
{
	WINDOW_REC *parent;
        GUI_WINDOW_REC *gui;

        gui = WINDOW_GUI(window);

	parent = window_find_refnum(config_node_get_int(node, "parent", -1));
	if (parent != NULL)
		gui_window_reparent(window, WINDOW_MAIN(parent));

	if (config_node_get_bool(node, "sticky", FALSE))
		gui_window_set_sticky(window);
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
	node = config_node_section(node, num, NODE_TYPE_BLOCK);

	iconfig_node_set_int(node, "first_line", window->first_line);
	iconfig_node_set_int(node, "lines", window->height);
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
	return config_node_get_int(n1, "first_line", 0) >
		config_node_get_int(n2, "first_line", 0) ? -1 : 1;
}

/* Returns list of mainwindow nodes sorted by first_line
   (lowest in screen first) */
static GSList *get_sorted_windows_config(CONFIG_NODE *node)
{
	GSList *tmp, *output;

        output = NULL;
	tmp = config_node_first(node->value);
	for (; tmp != NULL; tmp = config_node_next(tmp)) {
		output = g_slist_insert_sorted(output, tmp->data,
					       (GCompareFunc) window_node_cmp);
	}

        return output;
}

static void sig_layout_restore(void)
{
        MAIN_WINDOW_REC *lower_window;
        WINDOW_REC *window;
	CONFIG_NODE *node;
	GSList *tmp, *sorted_config;
        int avail_height, height, *heights;
	int i, lower_size, windows_count, diff;

	node = iconfig_node_traverse("mainwindows", FALSE);
	if (node == NULL) return;

	sorted_config = get_sorted_windows_config(node);
        windows_count = g_slist_length(sorted_config);

        /* calculate the saved terminal height */
	avail_height = term_height -
		screen_reserved_top - screen_reserved_bottom;
	height = 0;
        heights = g_new0(int, windows_count);
	for (i = 0, tmp = sorted_config; tmp != NULL; tmp = tmp->next, i++) {
		CONFIG_NODE *node = tmp->data;

                heights[i] = config_node_get_int(node, "lines", 0);
		height += heights[i];
	}

	if (avail_height <= (WINDOW_MIN_SIZE*2)+1) {
		/* we can fit only one window to screen -
		   give it all the height we can */
		windows_count = 1;
                heights[0] = avail_height;
	} else if (height != avail_height) {
		/* Terminal's height is different from the saved one.
		   Resize the windows so they fit to screen. */
		while (height > avail_height &&
		       windows_count*(WINDOW_MIN_SIZE+1) > avail_height) {
			/* all windows can't fit into screen,
			   remove the lowest ones */
                        windows_count--;
		}

                /* try to keep the windows' size about the same in percents */
		for (i = 0; i < windows_count; i++) {
			int size = avail_height*heights[i]/height;
			if (size < WINDOW_MIN_SIZE+1)
                                size = WINDOW_MIN_SIZE+1;
			heights[i] = size;
		}

		/* give/remove the last bits */
                height = 0;
		for (i = 0; i < windows_count; i++)
                        height += heights[i];

		diff = height < avail_height ? 1 : -1;
		for (i = 0; height != avail_height; i++) {
			if (i == windows_count)
				i = 0;

			if (heights[i] > WINDOW_MIN_SIZE+1) {
				height += diff;
				heights[i] += diff;
			}
		}
	}

	/* create all the visible windows with correct size */
	lower_window = NULL; lower_size = 0;
	for (i = 0, tmp = sorted_config; i < windows_count; tmp = tmp->next, i++) {
		CONFIG_NODE *node = tmp->data;

		/* create a new window + mainwindow */
		signal_emit("gui window create override", 1,
			    GINT_TO_POINTER(0));

		window = window_create(NULL, TRUE);
                window_set_refnum(window, atoi(node->key));

		if (lower_size > 0)
			mainwindow_set_size(lower_window, lower_size, FALSE);

		window_set_active(window);
                active_mainwin = WINDOW_MAIN(window);

                lower_window = WINDOW_MAIN(window);
		lower_size = heights[i];
		if (lower_size < WINDOW_MIN_SIZE+1)
			lower_size = WINDOW_MIN_SIZE+1;
	}
	g_slist_free(sorted_config);
	g_free(heights);

	if (lower_size > 0)
		mainwindow_set_size(lower_window, lower_size, FALSE);
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
