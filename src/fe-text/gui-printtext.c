/*
 gui-printtext.c : irssi

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
#include "settings.h"

#include "formats.h"
#include "printtext.h"

#include "term.h"
#include "gui-printtext.h"
#include "gui-windows.h"

int mirc_colors[] = { 15, 0, 1, 2, 12, 4, 5, 6, 14, 10, 3, 11, 9, 13, 8, 7 };
static int scrollback_lines, scrollback_time, scrollback_burst_remove;

static int next_xpos, next_ypos;

static GHashTable *indent_functions;
static INDENT_FUNC default_indent_func;

void gui_register_indent_func(const char *name, INDENT_FUNC func)
{
	gpointer key, value;
        GSList *list;

	if (g_hash_table_lookup_extended(indent_functions, name, &key, &value)) {
                list = value;
		g_hash_table_remove(indent_functions, key);
	} else {
		key = g_strdup(name);
                list = NULL;
	}

	list = g_slist_append(list, (void *) func);
	g_hash_table_insert(indent_functions, key, list);
}

void gui_unregister_indent_func(const char *name, INDENT_FUNC func)
{
	gpointer key, value;
        GSList *list;

	if (g_hash_table_lookup_extended(indent_functions, name, &key, &value)) {
		list = value;

		list = g_slist_remove(list, (void *) func);
		g_hash_table_remove(indent_functions, key);
		if (list == NULL)
			g_free(key);
                else
			g_hash_table_insert(indent_functions, key, list);
	}

	if (default_indent_func == func)
		gui_set_default_indent(NULL);

	textbuffer_views_unregister_indent_func(func);
}

void gui_set_default_indent(const char *name)
{
	GSList *list;

	list = name == NULL ? NULL :
		g_hash_table_lookup(indent_functions, name);
	default_indent_func = list == NULL ? NULL :
		(INDENT_FUNC) list->data;
        gui_windows_reset_settings();
}

INDENT_FUNC get_default_indent_func(void)
{
        return default_indent_func;
}

void gui_printtext(int xpos, int ypos, const char *str)
{
	next_xpos = xpos;
	next_ypos = ypos;

	printtext_gui(str);

	next_xpos = next_ypos = -1;
}

void gui_printtext_after(TEXT_DEST_REC *dest, LINE_REC *prev, const char *str)
{
	GUI_WINDOW_REC *gui;

	gui = WINDOW_GUI(dest->window);

	gui->use_insert_after = TRUE;
	gui->insert_after = prev;
	format_send_to_gui(dest, str);
	gui->use_insert_after = FALSE;
}

static void remove_old_lines(TEXT_BUFFER_VIEW_REC *view)
{
	LINE_REC *line;
	time_t old_time;

	old_time = time(NULL)-scrollback_time+1;
	if (view->buffer->lines_count >=
	    scrollback_lines+scrollback_burst_remove) {
                /* remove lines by line count */
		while (view->buffer->lines_count > scrollback_lines) {
			line = view->buffer->first_line;
			if (line->info.time >= old_time ||
			    scrollback_lines == 0) {
				/* too new line, don't remove yet - also
				   if scrollback_lines is 0, we want to check
				   only scrollback_time setting. */
				break;
			}
			textbuffer_view_remove_line(view, line);
		}
	}
}

static void get_colors(int flags, int *fg, int *bg, int *attr)
{
	if (flags & GUI_PRINT_FLAG_MIRC_COLOR) {
		/* mirc colors - real range is 0..15, but after 16
		   colors wrap to 0, 1, ... */
                if (*bg >= 0) *bg = mirc_colors[*bg % 16];
		if (*fg >= 0) *fg = mirc_colors[*fg % 16];
		if (settings_get_bool("mirc_blink_fix"))
			*bg &= ~0x08;
	}

	if (*fg < 0 || *fg > 15)
		*fg = -1;
	if (*bg < 0 || *bg > 15)
                *bg = -1;

	*attr = 0;
	if (flags & GUI_PRINT_FLAG_REVERSE) *attr |= ATTR_REVERSE;
	if (flags & GUI_PRINT_FLAG_BOLD) *attr |= ATTR_BOLD;
	if (flags & GUI_PRINT_FLAG_UNDERLINE) *attr |= ATTR_UNDERLINE;
	if (flags & GUI_PRINT_FLAG_BLINK) *attr |= ATTR_BLINK;
}

static void view_add_eol(TEXT_BUFFER_VIEW_REC *view, LINE_REC **line)
{
	static const unsigned char eol[] = { 0, LINE_CMD_EOL };

	*line = textbuffer_insert(view->buffer, *line, eol, 2, NULL);
	textbuffer_view_insert_line(view, *line);
}

static void sig_gui_print_text(WINDOW_REC *window, void *fgcolor,
			       void *bgcolor, void *pflags,
			       char *str, TEXT_DEST_REC *dest)
{
        GUI_WINDOW_REC *gui;
        TEXT_BUFFER_VIEW_REC *view;
	LINE_REC *insert_after;
        LINE_INFO_REC lineinfo;
	int fg, bg, flags, attr;

	flags = GPOINTER_TO_INT(pflags);
	fg = GPOINTER_TO_INT(fgcolor);
	bg = GPOINTER_TO_INT(bgcolor);
	get_colors(flags, &fg, &bg, &attr);

	if (window == NULL) {
                g_return_if_fail(next_xpos != -1);

		attr |= fg >= 0 ? fg : ATTR_RESETFG;
		attr |= bg >= 0 ? (bg << 4) : ATTR_RESETBG;
		term_set_color(root_window, attr);

		term_move(root_window, next_xpos, next_ypos);
		if (flags & GUI_PRINT_FLAG_CLRTOEOL)
			term_clrtoeol(root_window);
		term_addstr(root_window, str);
		next_xpos += strlen(str); /* FIXME utf8 or big5 */
                return;
	}

	lineinfo.level = dest == NULL ? 0 : dest->level;
        lineinfo.time = time(NULL);

        gui = WINDOW_GUI(window);
	view = gui->view;
	insert_after = gui->use_insert_after ?
		gui->insert_after : view->buffer->cur_line;

	if (flags & GUI_PRINT_FLAG_NEWLINE) {
                view_add_eol(view, &insert_after);
	}
	textbuffer_line_add_colors(view->buffer, &insert_after, fg, bg, flags);

	insert_after = textbuffer_insert(view->buffer, insert_after,
					 (unsigned char *) str,
					 strlen(str), &lineinfo);
	if (gui->use_insert_after)
                gui->insert_after = insert_after;
}

static void sig_gui_printtext_finished(WINDOW_REC *window)
{
	TEXT_BUFFER_VIEW_REC *view;
	LINE_REC *insert_after;

	view = WINDOW_GUI(window)->view;
	insert_after = WINDOW_GUI(window)->use_insert_after ?
		WINDOW_GUI(window)->insert_after : view->buffer->cur_line;

        view_add_eol(view, &insert_after);
	remove_old_lines(view);
}

static void read_settings(void)
{
	scrollback_lines = settings_get_int("scrollback_lines");
	scrollback_time = settings_get_time("scrollback_time")/1000;
        scrollback_burst_remove = settings_get_int("scrollback_burst_remove");
}

void gui_printtext_init(void)
{
	next_xpos = next_ypos = -1;
	default_indent_func = NULL;
	indent_functions = g_hash_table_new((GHashFunc) g_str_hash,
					    (GCompareFunc) g_str_equal);

	settings_add_int("history", "scrollback_lines", 500);
	settings_add_time("history", "scrollback_time", "1day");
	settings_add_int("history", "scrollback_burst_remove", 10);

	signal_add("gui print text", (SIGNAL_FUNC) sig_gui_print_text);
	signal_add("gui print text finished", (SIGNAL_FUNC) sig_gui_printtext_finished);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);

	read_settings();
}

void gui_printtext_deinit(void)
{
	g_hash_table_destroy(indent_functions);

	signal_remove("gui print text", (SIGNAL_FUNC) sig_gui_print_text);
	signal_remove("gui print text finished", (SIGNAL_FUNC) sig_gui_printtext_finished);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
}
