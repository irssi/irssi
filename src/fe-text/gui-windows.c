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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include "signals.h"
#include "misc.h"
#include "settings.h"
#include "special-vars.h"

#include "term.h"
#include "gui-entry.h"
#include "gui-windows.h"
#include "gui-printtext.h"

static int window_create_override;

static GUI_WINDOW_REC *gui_window_init(WINDOW_REC *window,
				       MAIN_WINDOW_REC *parent)
{
	GUI_WINDOW_REC *gui;

	window->width = parent->width;
        window->height = MAIN_WINDOW_TEXT_HEIGHT(parent);

	gui = g_new0(GUI_WINDOW_REC, 1);
	gui->parent = parent;
	gui->view = textbuffer_view_create(textbuffer_create(),
					   window->width, window->height,
					   settings_get_bool("scroll"),
					   term_type == TERM_TYPE_UTF8);
	textbuffer_view_set_default_indent(gui->view,
					   settings_get_int("indent"),
					   !settings_get_bool("indent_always"),
					   get_default_indent_func());
	if (parent->active == window)
		textbuffer_view_set_window(gui->view, parent->screen_win);
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

static void gui_window_created(WINDOW_REC *window, void *automatic)
{
	MAIN_WINDOW_REC *parent;
        int new_parent;

	g_return_if_fail(window != NULL);

	new_parent = window_create_override == 0 ||
		window_create_override == 2 ||
		active_win == NULL || WINDOW_GUI(active_win) == NULL;
	parent = !new_parent ? WINDOW_MAIN(active_win) : mainwindow_create();
	if (parent == NULL) {
		/* not enough space for new window, but we really can't
		   abort creation of the window anymore, so create hidden
		   window instead. */
		parent = WINDOW_MAIN(active_win);
	}
	window_create_override = -1;

	if (parent->active == NULL) parent->active = window;
	window->gui_data = gui_window_init(window, parent);

	/* set only non-automatic windows sticky so that the windows
	   irssi creates at startup wont get sticky. */
	if (automatic == NULL &&
	    (parent->sticky_windows ||
	     (new_parent && settings_get_bool("autostick_split_windows"))))
		gui_window_set_sticky(window);

	signal_emit("gui window created", 1, window);
}

static void gui_window_destroyed(WINDOW_REC *window)
{
	MAIN_WINDOW_REC *parent;
	GUI_WINDOW_REC *gui;

	g_return_if_fail(window != NULL);

	gui = WINDOW_GUI(window);
	parent = gui->parent;

	gui_window_set_unsticky(window);

	signal_emit("gui window destroyed", 1, window);

	gui_window_deinit(gui);
	window->gui_data = NULL;

	if (parent->active == window)
		mainwindow_change_active(parent, window);
}

void gui_window_resize(WINDOW_REC *window, int width, int height)
{
	GUI_WINDOW_REC *gui;

	if (window->width == width && window->height == height)
                return;

	gui = WINDOW_GUI(window);

	irssi_set_dirty();
        WINDOW_MAIN(window)->dirty = TRUE;

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

void gui_window_set_sticky(WINDOW_REC *window)
{
	GUI_WINDOW_REC *gui = WINDOW_GUI(window);

	if (!gui->sticky) {
		gui->sticky = TRUE;
		gui->parent->sticky_windows++;
	}
}

void gui_window_set_unsticky(WINDOW_REC *window)
{
	GUI_WINDOW_REC *gui = WINDOW_GUI(window);

	if (gui->sticky) {
		gui->sticky = FALSE;
		gui->parent->sticky_windows--;
	}
}

void gui_window_reparent(WINDOW_REC *window, MAIN_WINDOW_REC *parent)
{
	MAIN_WINDOW_REC *oldparent;

	oldparent = WINDOW_MAIN(window);
	if (oldparent == parent)
		return;

        gui_window_set_unsticky(window);
	textbuffer_view_set_window(WINDOW_GUI(window)->view, NULL);

	WINDOW_MAIN(window) = parent;
        if (parent->sticky_windows)
		gui_window_set_sticky(window);

	if (MAIN_WINDOW_TEXT_HEIGHT(parent) !=
	    MAIN_WINDOW_TEXT_HEIGHT(oldparent) ||
	    parent->width != oldparent->width) {
		gui_window_resize(window, parent->width,
				  MAIN_WINDOW_TEXT_HEIGHT(parent));
	}
}

void gui_windows_reset_settings(void)
{
	GSList *tmp;

	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;
                GUI_WINDOW_REC *gui = WINDOW_GUI(rec);

                textbuffer_view_set_default_indent(gui->view,
						   settings_get_int("indent"),
						   !settings_get_bool("indent_always"),
                                                   get_default_indent_func());

		textbuffer_view_set_scroll(gui->view,
					   gui->use_scroll ? gui->scroll :
					   settings_get_bool("scroll"));
	}
}

static MAIN_WINDOW_REC *mainwindow_find_unsticky(void)
{
	GSList *tmp;

	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		if (!rec->sticky_windows)
                        return rec;
	}

        /* all windows are sticky, fallback to active window */
        return active_mainwin;
}

static void signal_window_changed(WINDOW_REC *window)
{
	MAIN_WINDOW_REC *parent;
        WINDOW_REC *old_window;

	g_return_if_fail(window != NULL);

        if (quitting) return;

        parent = WINDOW_MAIN(window);
	if (is_window_visible(window)) {
		/* already visible */
		active_mainwin = parent;
	} else if (active_mainwin == NULL) {
                /* no main window set yet */
		active_mainwin = parent;
	} else if (WINDOW_GUI(window)->sticky) {
                /* window is sticky, switch to correct main window */
		if (parent != active_mainwin)
                        active_mainwin = parent;
	} else {
		/* move window to active main window */
                if (active_mainwin->sticky_windows) {
			/* active mainwindow is sticky, we'll need to
			   set the window active somewhere else */
                        active_mainwin = mainwindow_find_unsticky();
		}
		gui_window_reparent(window, active_mainwin);
	}

	old_window = active_mainwin->active;
	if (old_window != NULL && old_window != window)
		textbuffer_view_set_window(WINDOW_GUI(old_window)->view, NULL);

	active_mainwin->active = window;

	textbuffer_view_set_window(WINDOW_GUI(window)->view,
				   active_mainwin->screen_win);
	if (WINDOW_GUI(window)->view->dirty)
		active_mainwin->dirty = TRUE;
}

static void read_settings(void)
{
        gui_windows_reset_settings();
}

void gui_windows_init(void)
{
        settings_add_bool("lookandfeel", "autostick_split_windows", TRUE);
	settings_add_int("lookandfeel", "indent", 10);
	settings_add_bool("lookandfeel", "indent_always", FALSE);
	settings_add_bool("lookandfeel", "scroll", TRUE);

	window_create_override = -1;

	read_settings();
	signal_add("gui window create override", (SIGNAL_FUNC) sig_window_create_override);
	signal_add("window created", (SIGNAL_FUNC) gui_window_created);
	signal_add("window destroyed", (SIGNAL_FUNC) gui_window_destroyed);
	signal_add_first("window changed", (SIGNAL_FUNC) signal_window_changed);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
}

void gui_windows_deinit(void)
{
	while (windows != NULL)
		window_destroy(windows->data);

	signal_remove("gui window create override", (SIGNAL_FUNC) sig_window_create_override);
	signal_remove("window created", (SIGNAL_FUNC) gui_window_created);
	signal_remove("window destroyed", (SIGNAL_FUNC) gui_window_destroyed);
	signal_remove("window changed", (SIGNAL_FUNC) signal_window_changed);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
}
