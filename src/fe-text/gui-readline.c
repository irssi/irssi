/*
 gui-readline.c : irssi

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
#include "server.h"
#include "misc.h"

#include "completion.h"
#include "command-history.h"
#include "keyboard.h"
#include "translation.h"
#include "windows.h"

#include "screen.h"
#include "gui-entry.h"
#include "gui-mainwindows.h"
#include "gui-windows.h"

#include <signal.h>

static gint readtag, sigint_count = 0;
static time_t idle_time;

static void window_prev_page(void)
{
	gui_window_scroll(active_win, -(last_text_line-first_text_line)/2);
}

static void window_next_page(void)
{
	gui_window_scroll(active_win, (last_text_line-first_text_line)/2);
}

static char *get_key_name(int key)
{
	static char str[MAX_INT_STRLEN];

	switch (key) {
	case KEY_HOME:
		return "Home";
	case KEY_END:
		return "End";
	case KEY_PPAGE:
		return "Prior";
	case KEY_NPAGE:
		return "Next";
	case KEY_UP:
		return "Up";
	case KEY_DOWN:
		return "Down";
	case KEY_LEFT:
		return "Left";
	case KEY_RIGHT:
		return "Right";
	default:
		ltoa(str, key);
		return str;
	}
}

void handle_key(gint key)
{
    const char *text;
    char *str;
    int c;

    /* Quit if we get 5 CTRL-C's in a row. */
    if (key != 3)
	sigint_count = 0;
    else if (++sigint_count >= 5)
	raise(SIGTERM);

    idle_time = time(NULL);
    switch (key)
    {
    case 27:
	    c = getch();
	    if (c == toupper(c) && c != tolower(c))
		    str = g_strdup_printf("ALT-SHIFT-%c", c);
	    else {
		    if (c < 256)
			    str = g_strdup_printf("ALT-%c", toupper(c));
		    else
			    str = g_strdup_printf("ALT-%s", get_key_name(c));
	    }
	    key_pressed(str, NULL);
	    g_free(str);
	    break;

	case KEY_HOME:
            /* home */
            gui_entry_set_pos(0);
            gui_entry_move_pos(0);
            break;
        case KEY_END:
            /* end */
            gui_entry_set_pos(strlen(gui_entry_get_text()));
            gui_entry_move_pos(0);
            break;
        case KEY_PPAGE:
            /* page up */
            window_prev_page();
            break;
        case KEY_NPAGE:
            /* page down */
            window_next_page();
            break;

        case KEY_UP:
            /* up */
            text = command_history_prev(active_win, gui_entry_get_text());
            gui_entry_set_text(text);
            break;
        case KEY_DOWN:
            /* down */
            text = command_history_next(active_win, gui_entry_get_text());
            gui_entry_set_text(text);
            break;
        case KEY_RIGHT:
            /* right */
            gui_entry_move_pos(1);
            break;
        case KEY_LEFT:
            /* left */
            gui_entry_move_pos(-1);
            break;

	case 21:
            /* Ctrl-U, clear line */
            gui_entry_set_text("");
	    break;

	case 9:
	    key_pressed("Tab", NULL);
	    break;

	case 8:
	case 127:
        case KEY_BACKSPACE:
            gui_entry_erase(1);
            break;

        case KEY_DC:
            if (gui_entry_get_pos() < strlen(gui_entry_get_text()))
            {
                gui_entry_move_pos(1);
                gui_entry_erase(1);
            }
            break;

	case 0:
	    /* Ctrl-space - ignore */
	    break;
        case 1:
            /* C-A, home */
            gui_entry_set_pos(0);
            gui_entry_move_pos(0);
            break;
        case 5:
            /* C-E, end */
            gui_entry_set_pos(strlen(gui_entry_get_text()));
            gui_entry_move_pos(0);
            break;

        case '\n':
	case 13:
	    key_pressed("Return", NULL);

	    str = gui_entry_get_text();
	    if (*str == '\0') break;

	    translate_output(str);
	    signal_emit("send command", 3, str, active_win->active_server, active_win->active);

            command_history_add(active_win, gui_entry_get_text(), FALSE);
            gui_entry_set_text("");
            command_history_clear_pos(active_win);
            break;

	default:
	    if (key > 0 && key < 32)
	    {
		str = g_strdup_printf("CTRL-%c", key == 31 ? '-' : key+'A'-1);
		key_pressed(str, NULL);
		g_free(str);
		break;
	    }

	    if (key < 256)
	    {
		gchar str[2];

		str[0] = toupper(key); str[1] = '\0';
		key_pressed(str, NULL);
		gui_entry_insert_char((gchar) key);
	    }
            break;
    }
}

void readline(void)
{
    gint key;

    for (;;)
    {
        key = getch();
        if (key == ERR) break;

        handle_key(key);
    }
}

time_t get_idle_time(void)
{
	return idle_time;
}

static void sig_prev_page(void)
{
    window_prev_page();
}

static void sig_next_page(void)
{
    window_next_page();
}

static void sig_change_window(gchar *data)
{
    signal_emit("command window goto", 3, data, active_win->active_server, active_win->active);
}

static void sig_completion(void)
{
    gchar *line;
    gint pos;

    pos = gui_entry_get_pos();

    line = completion_line(active_win, gui_entry_get_text(), &pos);
    if (line != NULL)
    {
	gui_entry_set_text(line);
	gui_entry_set_pos(pos);
	g_free(line);
    }
}

static void sig_replace(void)
{
    gchar *line;
    gint pos;

    pos = gui_entry_get_pos();

    line = auto_completion(gui_entry_get_text(), &pos);
    if (line != NULL)
    {
	gui_entry_set_text(line);
	gui_entry_set_pos(pos);
	g_free(line);
    }
}

static void sig_prev_window(void)
{
    signal_emit("command window prev", 3, "", active_win->active_server, active_win->active);
}

static void sig_next_window(void)
{
    signal_emit("command window next", 3, "", active_win->active_server, active_win->active);
}

static void sig_window_goto_active(void)
{
    signal_emit("command window goto", 3, "active", active_win->active_server, active_win->active);
}

static void sig_prev_channel(void)
{
    signal_emit("command channel prev", 3, "", active_win->active_server, active_win->active);
}

static void sig_next_channel(void)
{
    signal_emit("command channel next", 3, "", active_win->active_server, active_win->active);
}

static void sig_addchar(gchar *data)
{
    gui_entry_insert_char(*data);
}

static void signal_window_auto_changed(WINDOW_REC *window)
{
	command_history_next(active_win, gui_entry_get_text());
	gui_entry_set_text("");
}

void gui_readline_init(void)
{
    static gchar changekeys[] = "1234567890QWERTYUIO";
    gchar *key, *data;
    gint n;

    idle_time = time(NULL);
    readtag = g_input_add(0, G_INPUT_READ, (GInputFunction) readline, NULL);

    key_bind("completion", NULL, "Nick completion", "Tab", (SIGNAL_FUNC) sig_completion);
    key_bind("check replaces", NULL, "Check word replaces", " ", (SIGNAL_FUNC) sig_replace);
    key_bind("check replaces", NULL, NULL, "Return", (SIGNAL_FUNC) sig_replace);
    key_bind("window prev", NULL, "Previous window", "CTRL-P", (SIGNAL_FUNC) sig_prev_window);
    key_bind("window prev", NULL, NULL, "ALT-Left", (SIGNAL_FUNC) sig_prev_window);
    key_bind("window next", NULL, "Next window", "CTRL-N", (SIGNAL_FUNC) sig_next_window);
    key_bind("window next", NULL, NULL, "ALT-Right", (SIGNAL_FUNC) sig_next_window);
    key_bind("window active", NULL, "Go to next window with the highest activity", "ALT-A", (SIGNAL_FUNC) sig_window_goto_active);
    key_bind("channel next", NULL, "Next channel", "CTRL-X", (SIGNAL_FUNC) sig_next_channel);
    key_bind("channel prev", NULL, "Next channel", NULL, (SIGNAL_FUNC) sig_prev_channel);

    key_bind("redraw", NULL, "Redraw window", "CTRL-L", (SIGNAL_FUNC) irssi_redraw);
    key_bind("prev page", NULL, "Previous page", "ALT-P", (SIGNAL_FUNC) sig_prev_page);
    key_bind("next page", NULL, "Next page", "ALT-N", (SIGNAL_FUNC) sig_next_page);

    key_bind("special char", "\x02", "Insert special character", "CTRL-B", (SIGNAL_FUNC) sig_addchar);
    key_bind("special char", "\x1f", NULL, "CTRL--", (SIGNAL_FUNC) sig_addchar);
    key_bind("special char", "\x03", NULL, "CTRL-C", (SIGNAL_FUNC) sig_addchar);
    key_bind("special char", "\x16", NULL, "CTRL-V", (SIGNAL_FUNC) sig_addchar);
    key_bind("special char", "\x07", NULL, "CTRL-G", (SIGNAL_FUNC) sig_addchar);
    key_bind("special char", "\x0f", NULL, "CTRL-O", (SIGNAL_FUNC) sig_addchar);

    for (n = 0; changekeys[n] != '\0'; n++)
    {
        key = g_strdup_printf("ALT-%c", changekeys[n]);
        data = g_strdup_printf("%d", n+1);
	key_bind("change window", data, "Change window", key, (SIGNAL_FUNC) sig_change_window);
	g_free(data); g_free(key);
    }

    signal_add("window changed automatic", (SIGNAL_FUNC) signal_window_auto_changed);
}

void gui_readline_deinit(void)
{
    g_source_remove(readtag);

    key_unbind("completion", (SIGNAL_FUNC) sig_completion);
    key_unbind("check replaces", (SIGNAL_FUNC) sig_replace);
    key_unbind("window prev", (SIGNAL_FUNC) sig_prev_window);
    key_unbind("window next", (SIGNAL_FUNC) sig_next_window);
    key_unbind("window active", (SIGNAL_FUNC) sig_window_goto_active);
    key_unbind("channel next", (SIGNAL_FUNC) sig_next_channel);
    key_unbind("channel prev", (SIGNAL_FUNC) sig_prev_channel);

    key_unbind("redraw", (SIGNAL_FUNC) irssi_redraw);
    key_unbind("prev page", (SIGNAL_FUNC) sig_prev_page);
    key_unbind("next page", (SIGNAL_FUNC) sig_next_page);

    key_unbind("special char", (SIGNAL_FUNC) sig_addchar);
    key_unbind("change window", (SIGNAL_FUNC) sig_change_window);

    signal_remove("window changed automatic", (SIGNAL_FUNC) signal_window_auto_changed);
}
