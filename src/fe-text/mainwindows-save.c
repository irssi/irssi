/*
 mainwindows-save.c : irssi

    Copyright (C) 2001 Timo Sirainen

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
#include "lib-config/iconfig.h"
#include "settings.h"

#include "mainwindows.h"
#include "gui-windows.h"

static void main_window_save(MAIN_WINDOW_REC *window, CONFIG_NODE *node)
{
	GSList *tmp;
	GString *str;
        char num[MAX_INT_STRLEN];

        ltoa(num, window->active->refnum);
	node = config_node_section(node, num, NODE_TYPE_BLOCK);

	iconfig_node_set_int(node, "first_line", window->first_line);
	iconfig_node_set_int(node, "lines", window->height);

	str = g_string_new(NULL);
	for (tmp = window->sticky_windows; tmp != NULL; tmp = tmp->next) {
                WINDOW_REC *rec = tmp->data;
                g_string_sprintfa(str, "%d ", rec->refnum);
	}
	if (str->len > 1) {
		g_string_truncate(str, str->len-1);
		iconfig_node_set_str(node, "sticky", str->str);
	}
        g_string_free(str, TRUE);
}

static void sig_windows_saved(void)
{
	CONFIG_NODE *node;

	iconfig_set_str(NULL, "mainwindows", NULL);
	node = iconfig_node_traverse("mainwindows", TRUE);

	g_slist_foreach(mainwindows, (GFunc) main_window_save, node);
}

static int window_node_cmp(CONFIG_NODE *n1, CONFIG_NODE *n2)
{
	return config_node_get_int(n1, "first_line", 0) <
		config_node_get_int(n2, "first_line", 0) ? -1 : 1;
}

static GSList *read_sorted_windows(CONFIG_NODE *node)
{
	GSList *tmp, *output;

        output = NULL;
	for (tmp = node->value; tmp != NULL; tmp = tmp->next) {
		output = g_slist_insert_sorted(output, tmp->data,
					       (GCompareFunc) window_node_cmp);
	}

        return output;
}

static void restore_sticky_windows(CONFIG_NODE *node,
				   MAIN_WINDOW_REC *mainwindow)
{
        WINDOW_REC *window;
        char **sticky_list, **sticky;

	sticky_list = g_strsplit(config_node_get_str(node, "sticky", ""), " ", -1);
	for (sticky = sticky_list; *sticky != NULL; sticky++) {
		window = window_find_refnum(atoi(*sticky));
		if (window != NULL) {
			mainwindow->sticky_windows =
				g_slist_append(mainwindow->sticky_windows,
					       window);
		}
	}
	g_strfreev(sticky_list);
}

static WINDOW_REC *window_find_hidden(void)
{
	GSList *tmp;

	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		if (!is_window_visible(rec))
                        return rec;
	}

        return NULL;
}

static void sig_windows_restored(void)
{
        MAIN_WINDOW_REC *mainwindow, *lowerwin;
        WINDOW_REC *window;
	CONFIG_NODE *node;
	GSList *tmp, *tmp2, *sorted_windows, *sorted_config;
        int count, newsize;

	node = iconfig_node_traverse("mainwindows", FALSE);
	if (node == NULL) return;

	/* create all windows, shrink the lower windows to minimum size */
        lowerwin = mainwindows->data;
	count = g_slist_length(node->value);
	while (count > 1) {
		window = window_find_hidden();
		if (window == NULL)
			break;

		mainwindow = mainwindow_create();
		if (mainwindow == NULL)
			break;

		mainwindow->active = window;
		WINDOW_GUI(window)->parent = mainwindow;

		active_mainwin = NULL;
		window_set_active(window);

                if (lowerwin->height > WINDOW_MIN_SIZE)
			mainwindow_set_size(lowerwin, WINDOW_MIN_SIZE);
		count--;

		lowerwin = mainwindow;
	}

        sorted_config = read_sorted_windows(node);
	sorted_windows = mainwindows_get_sorted(FALSE);
	for (tmp = sorted_windows, tmp2 = sorted_config;
	     tmp != NULL && tmp2 != NULL;
	     tmp = tmp->next, tmp2 = tmp2->next) {
		MAIN_WINDOW_REC *mainwindow = tmp->data;
                CONFIG_NODE *node = tmp2->data;

                window = window_find_refnum(atoi(node->key));
		if (window == NULL) {
			mainwindow_destroy(mainwindow);
                        continue;
		}

		if (is_window_visible(window)) {
                        active_mainwin = WINDOW_GUI(window)->parent;
			window_set_active(window_find_hidden());
		}

		active_mainwin = mainwindow;
		window_set_active(window);

		restore_sticky_windows(node, mainwindow);

		newsize = config_node_get_int(node, "lines", 0);
		if (newsize > 0)
                        mainwindow_set_size(mainwindow, newsize);
	}
	g_slist_free(sorted_windows);
	g_slist_free(sorted_config);

        irssi_redraw();
}

void mainwindows_save_init(void)
{
	signal_add("windows saved", (SIGNAL_FUNC) sig_windows_saved);
	signal_add("windows restored", (SIGNAL_FUNC) sig_windows_restored);
}

void mainwindows_save_deinit(void)
{
	signal_remove("windows saved", (SIGNAL_FUNC) sig_windows_saved);
	signal_remove("windows restored", (SIGNAL_FUNC) sig_windows_restored);
}
