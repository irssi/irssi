/*
 gui-windows.c : irssi

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
#include "misc.h"
#include "settings.h"
#include "special-vars.h"

#include "screen.h"
#include "gui-entry.h"
#include "gui-windows.h"
#include "gui-printtext.h"

static int window_create_override;

static char *prompt, *prompt_window;

static GUI_WINDOW_REC *gui_window_init(WINDOW_REC *window,
				       MAIN_WINDOW_REC *parent)
{
	GUI_WINDOW_REC *gui;

	window->width = parent->width;
        window->height = parent->height;

	gui = g_new0(GUI_WINDOW_REC, 1);
	gui->parent = parent;
	gui->view = textbuffer_view_create(textbuffer_create(),
					   window->width, window->height,
					   settings_get_int("indent"),
					   settings_get_bool("indent_always"));
	return gui;
}

static void gui_window_deinit(GUI_WINDOW_REC *gui)
{
        textbuffer_view_destroy(gui->view);
	g_free(gui);
}

static void sig_window_create_override(gpointer tab)
{
	window_create_override = GPOINTER_TO_INT(tab);
}

static void gui_window_created(WINDOW_REC *window)
{
	MAIN_WINDOW_REC *parent;

	g_return_if_fail(window != NULL);

	parent = window_create_override != 0 &&
		active_win != NULL && WINDOW_GUI(active_win) != NULL ?
		WINDOW_GUI(active_win)->parent : mainwindow_create();
	if (parent == NULL) {
		/* not enough space for new window, but we really can't
		   abort creation of the window anymore, so create hidden
		   window instead. */
		parent = WINDOW_GUI(active_win)->parent;
	}
	window_create_override = -1;

	if (settings_get_bool("autostick_split_windows") &&
	    (parent->sticky_windows != NULL ||
	     (mainwindows->next != NULL && parent->active == NULL))) {
                /* set the window sticky */
		parent->sticky_windows =
			g_slist_append(parent->sticky_windows, window);
	}

	if (parent->active == NULL) parent->active = window;
	window->gui_data = gui_window_init(window, parent);
	signal_emit("gui window created", 1, window);
}

static void gui_window_destroyed(WINDOW_REC *window)
{
	MAIN_WINDOW_REC *parent;
	GUI_WINDOW_REC *gui;

	g_return_if_fail(window != NULL);

	gui = WINDOW_GUI(window);
	parent = gui->parent;

	signal_emit("gui window destroyed", 1, window);

	gui_window_deinit(gui);
	window->gui_data = NULL;

	if (parent->active == window && mainwindows->next != NULL)
		mainwindow_destroy(parent);
}

void gui_window_resize(WINDOW_REC *window, int width, int height)
{
	GUI_WINDOW_REC *gui;

	gui = WINDOW_GUI(window);

        window->width = width;
	window->height = height;
        textbuffer_view_resize(gui->view, width, height);
}

void gui_window_scroll(WINDOW_REC *window, int lines)
{
	g_return_if_fail(window != NULL);

        textbuffer_view_scroll(WINDOW_GUI(window)->view, lines);
	signal_emit("gui page scrolled", 1, window);
}

void gui_window_scroll_line(WINDOW_REC *window, LINE_REC *line)
{
	g_return_if_fail(window != NULL);
	g_return_if_fail(line != NULL);

        textbuffer_view_scroll_line(WINDOW_GUI(window)->view, line);
	signal_emit("gui page scrolled", 1, window);
}

void window_update_prompt(void)
{
        const char *special;
	char *prompt, *text;
        int var_used;

	special = settings_get_str(active_win->active != NULL ?
				   "prompt" : "prompt_window");
	if (*special == '\0') {
		gui_entry_set_prompt("");
		return;
	}

	prompt = parse_special_string(special, active_win->active_server,
				      active_win->active, "", &var_used,
				      PARSE_FLAG_ISSET_ANY |
				      PARSE_FLAG_ESCAPE_VARS);
	if (!var_used && strchr(special, '$') != NULL) {
                /* none of the $vars had non-empty values, use empty prompt */
		*prompt = '\0';
	}

	/* set prompt */
	text = show_lowascii(prompt);
	gui_entry_set_prompt(text);
	g_free(text);

	g_free(prompt);
}

static void window_update_prompt_server(SERVER_REC *server)
{
	if (server == active_win->active_server)
                window_update_prompt();
}

static void window_update_prompt_window(WINDOW_REC *window)
{
	if (window == active_win)
                window_update_prompt();
}

static void window_update_prompt_window_item(WI_ITEM_REC *item)
{
	if (item == active_win->active)
                window_update_prompt();
}

void gui_window_reparent(WINDOW_REC *window, MAIN_WINDOW_REC *parent)
{
	MAIN_WINDOW_REC *oldparent;

	oldparent = WINDOW_GUI(window)->parent;
	if (oldparent == parent)
		return;

	textbuffer_view_set_window(WINDOW_GUI(window)->view, NULL);

	WINDOW_GUI(window)->parent = parent;
	if (parent->height != oldparent->height ||
	    parent->width != oldparent->width)
		gui_window_resize(window, parent->width, parent->height);
}

static MAIN_WINDOW_REC *mainwindow_find_unsticky(void)
{
	GSList *tmp;

	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		if (rec->sticky_windows == NULL)
                        return rec;
	}

        /* all windows are sticky, fallback to active window */
        return active_mainwin;
}

static void signal_window_changed(WINDOW_REC *window, WINDOW_REC *old_window)
{
	MAIN_WINDOW_REC *parent;

	g_return_if_fail(window != NULL);

        if (quitting) return;

        parent = WINDOW_GUI(window)->parent;
	if (is_window_visible(window)) {
		/* already visible */
		active_mainwin = parent;
	} else if (active_mainwin == NULL) {
                /* no main window set yet */
		active_mainwin = parent;
	} else if (g_slist_find(parent->sticky_windows, window) != NULL) {
                /* window is sticky, switch to correct main window */
		if (parent != active_mainwin)
                        active_mainwin = parent;
	} else {
		/* move window to active main window */
                if (active_mainwin->sticky_windows != NULL) {
			/* active mainwindow is sticky, we'll need to
			   set the window active somewhere else */
                        active_mainwin = mainwindow_find_unsticky();
		}
		gui_window_reparent(window, active_mainwin);
	}
	active_mainwin->active = window;

	if (old_window != NULL && !is_window_visible(old_window))
                textbuffer_view_set_window(WINDOW_GUI(old_window)->view, NULL);

	textbuffer_view_set_window(WINDOW_GUI(window)->view,
				   parent->curses_win);

	window_update_prompt();
}

static void sig_check_window_update(WINDOW_REC *window)
{
	if (window == active_win)
                window_update_prompt();
}

static void read_settings(void)
{
	GSList *tmp;

	SIGNAL_FUNC funcs[] = {
                (SIGNAL_FUNC) window_update_prompt,
                (SIGNAL_FUNC) window_update_prompt_server,
                (SIGNAL_FUNC) window_update_prompt_window,
                (SIGNAL_FUNC) window_update_prompt_window_item
	};

	if (prompt != NULL) {
		special_vars_remove_signals(prompt, 4, funcs);
		special_vars_remove_signals(prompt_window, 4, funcs);
		g_free(prompt);
                g_free(prompt_window);
	}
	prompt = g_strdup(settings_get_str("prompt"));
	prompt_window = g_strdup(settings_get_str("prompt_window"));

	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

                textbuffer_view_set_default_indent(WINDOW_GUI(rec)->view,
						   settings_get_int("indent"),
						   settings_get_bool("indent_always"));
	}

	special_vars_add_signals(prompt, 4, funcs);
	special_vars_add_signals(prompt_window, 4, funcs);

	if (active_win != NULL) window_update_prompt();
}

void gui_windows_init(void)
{
        settings_add_bool("lookandfeel", "autostick_split_windows", TRUE);
	settings_add_int("lookandfeel", "indent", 10);
	settings_add_bool("lookandfeel", "indent_always", FALSE);
	settings_add_str("lookandfeel", "prompt", "[$[.15]T] ");
	settings_add_str("lookandfeel", "prompt_window", "[$winname] ");

        prompt = NULL; prompt_window = NULL;
	window_create_override = -1;

	read_settings();
	signal_add("gui window create override", (SIGNAL_FUNC) sig_window_create_override);
	signal_add("window created", (SIGNAL_FUNC) gui_window_created);
	signal_add("window destroyed", (SIGNAL_FUNC) gui_window_destroyed);
	signal_add_first("window changed", (SIGNAL_FUNC) signal_window_changed);
	signal_add("window item remove", (SIGNAL_FUNC) sig_check_window_update);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
}

void gui_windows_deinit(void)
{
        g_free_not_null(prompt);
        g_free_not_null(prompt_window);

	while (windows != NULL)
		window_destroy(windows->data);

	signal_remove("gui window create override", (SIGNAL_FUNC) sig_window_create_override);
	signal_remove("window created", (SIGNAL_FUNC) gui_window_created);
	signal_remove("window destroyed", (SIGNAL_FUNC) gui_window_destroyed);
	signal_remove("window changed", (SIGNAL_FUNC) signal_window_changed);
	signal_remove("window item remove", (SIGNAL_FUNC) sig_check_window_update);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
}
