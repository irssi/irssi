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
#include <irssi/src/core/levels.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/core/signals.h>

#include <irssi/src/fe-common/core/formats.h>
#include <irssi/src/fe-common/core/printtext.h>
#include <irssi/src/fe-common/core/themes.h>

#include <irssi/src/fe-text/term.h>
#include <irssi/src/fe-text/gui-printtext.h>
#include <irssi/src/fe-text/gui-windows.h>

/* Terminal indexed colour map */
int mirc_colors[] = { 15, 0, 1, 2, 12, 4, 5, 6, 14, 10, 3, 11, 9, 13, 8, 7,
	 /* 16-27 */  52,  94, 100,  58,  22,  29,  23,  24,  17,  54,  53,  89,
	 /* 28-39 */  88, 130, 142,  64,  28,  35,  30,  25,  18,  91,  90, 125,
	 /* 40-51 */ 124, 166, 184, 106,  34,  49,  37,  33,  19, 129, 127, 161,
	 /* 52-63 */ 196, 208, 226, 154,  46,  86,  51,  75,  21, 171, 201, 198,
	 /* 64-75 */ 203, 215, 227, 191,  83, 122,  87, 111,  63, 177, 207, 205,
	 /* 76-87 */ 217, 223, 229, 193, 157, 158, 159, 153, 147, 183, 219, 212,
	 /* 88-98 */  16, 233, 235, 237, 239, 241, 244, 247, 250, 254, 231, -1 };

/* RGB colour map */
int mirc_colors24[] = { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	 /* 16-27 */ 0x470000, 0x472100, 0x474700, 0x324700, 0x004700, 0x00472c, 0x004747, 0x002747, 0x000047, 0x2e0047, 0x470047, 0x47002a,
	 /* 28-39 */ 0x740000, 0x743a00, 0x747400, 0x517400, 0x007400, 0x007449, 0x007474, 0x004074, 0x000074, 0x4b0074, 0x740074, 0x740045,
	 /* 40-51 */ 0xb50000, 0xb56300, 0xb5b500, 0x7db500, 0x00b500, 0x00b571, 0x00b5b5, 0x0063b5, 0x0000b5, 0x7500b5, 0xb500b5, 0xb5006b,
	 /* 52-63 */ 0xff0000, 0xff8c00, 0xffff00, 0xb2ff00, 0x00ff00, 0x00ffa0, 0x00ffff, 0x008cff, 0x0000ff, 0xa500ff, 0xff00ff, 0xff0098,
	 /* 64-75 */ 0xff5959, 0xffb459, 0xffff71, 0xcfff60, 0x6fff6f, 0x65ffc9, 0x6dffff, 0x59b4ff, 0x5959ff, 0xc459ff, 0xff66ff, 0xff59bc,
	 /* 76-87 */ 0xff9c9c, 0xffd39c, 0xffff9c, 0xe2ff9c, 0x9cff9c, 0x9cffdb, 0x9cffff, 0x9cd3ff, 0x9c9cff, 0xdc9cff, 0xff9cff, 0xff94d3,
	 /* 88-98 */ 0x000000, 0x131313, 0x282828, 0x363636, 0x4d4d4d, 0x656565, 0x818181, 0x9f9f9f, 0xbcbcbc, 0xe2e2e2, 0xffffff, -1 };

static int scrollback_lines, scrollback_time, scrollback_burst_remove;
/*
 * If positive, remove lines older than scrollback_max_age seconds.
 * Deletion is triggered by the "gui print text finished" signal (i.e. a message
 * for the window). Note: "Day changed to" message also cause messages to be
 * deleted within 1 day latency.
 */
static int scrollback_max_age;

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

void gui_printtext_internal(int xpos, int ypos, const char *str)
{
	next_xpos = xpos;
	next_ypos = ypos;

	printtext_gui_internal(str);

	next_xpos = next_ypos = -1;
}

static void view_add_eol(TEXT_BUFFER_VIEW_REC *view, LINE_REC **line);

void gui_printtext_after_time(TEXT_DEST_REC *dest, LINE_REC *prev, const char *str, time_t time)
{
	GUI_WINDOW_REC *gui;

	gui = WINDOW_GUI(dest->window);

	if (prev == NULL && !gui->view->buffer->last_eol) {
		/* we have an unfinished line in the buffer still */
		view_add_eol(gui->view, &gui->insert_after);
	}

	gui->use_insert_after = TRUE;
	gui->insert_after = prev;
	gui->insert_after_time = time;
	format_send_to_gui(dest, str);
	gui->use_insert_after = FALSE;
	signal_emit("gui print text after finished", 4, dest->window, gui->insert_after, prev,
	            dest);
}

void gui_printtext_after(TEXT_DEST_REC *dest, LINE_REC *prev, const char *str)
{
	gui_printtext_after_time(dest, prev, str, 0);
}

void gui_printtext_window_border(int x, int y)
{
	char *v0, *v1;
	int len;
	if (current_theme != NULL) {
		v1 = theme_format_expand(current_theme, "{window_border} ");
		len = format_real_length(v1, 1);
		v1[len] = '\0';
	}
	else {
		v1 = g_strdup(" ");
	}

	if (*v1 == '\0') {
		g_free(v1);
		v1 = g_strdup(" ");
	}

	if (clrtoeol_info->color != NULL) {
		char *color = g_strdup(clrtoeol_info->color);
		len = format_real_length(color, 0);
		color[len] = '\0';
		v0 = g_strconcat(color, v1, NULL);
		g_free(color);
		g_free(v1);
	} else {
		v0 = v1;
	}

	gui_printtext(x, y, v0);
	g_free(v0);
}

static void remove_old_lines(TEXT_BUFFER_VIEW_REC *view)
{
	LINE_REC *line;
	time_t cur_time = time(NULL);
	time_t old_time;

	old_time = cur_time - scrollback_time + 1;
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

	if (scrollback_max_age > 0) {
		old_time = cur_time - scrollback_max_age;
		while (view->buffer->lines_count > 0) {
			line = view->buffer->first_line;
			if (line->info.time >= old_time) {
				/*
				 * The first line is newer than the threshold
				 * time -> no need to remove more lines.
				 */
				break;
			}
			textbuffer_view_remove_line(view, line);
		}
	}
}

void gui_printtext_get_colors(int *flags, int *fg, int *bg, int *attr)
{
	*attr = 0;
	if (*flags & GUI_PRINT_FLAG_MIRC_COLOR) {
		/* mirc colors - extended colours proposal */
		gboolean use_24_map = FALSE;
		use_24_map = settings_get_bool("colors_ansi_24bit");
		if (*bg >= 0) {
			if (use_24_map && mirc_colors24[*bg % 100] != -1) {
				*bg = mirc_colors24[*bg % 100];
				*flags |= GUI_PRINT_FLAG_COLOR_24_BG;
			} else {
				*bg = mirc_colors[*bg % 100];
				*flags &= ~GUI_PRINT_FLAG_COLOR_24_BG;
				/* ignore mirc color 99 = -1 (reset) */
				if (*bg != -1 && settings_get_bool("mirc_blink_fix")) {
					if (*bg < 16) /* ansi bit flip :-( */
						*bg = (*bg&8) | (*bg&4)>>2 | (*bg&2) | (*bg&1)<<2;
					*bg = term_color256map[*bg&0xff] & 7;
				}
			}
		}
		if (*fg >= 0) {
			if (use_24_map && mirc_colors24[*fg % 100] != -1) {
				*fg = mirc_colors24[*fg % 100];
				*flags |= GUI_PRINT_FLAG_COLOR_24_FG;
			} else {
				*fg = mirc_colors[*fg % 100];
				*flags &= ~GUI_PRINT_FLAG_COLOR_24_FG;
			}
		}
	}

	if (*flags & GUI_PRINT_FLAG_COLOR_24_FG)
		*attr |= ATTR_FGCOLOR24;
	else if (*fg < 0 || *fg > 255) {
		*fg = -1;
		*attr |= ATTR_RESETFG;
	}
	else
		*attr |= *fg;

	if (*flags & GUI_PRINT_FLAG_COLOR_24_BG)
		*attr |= ATTR_BGCOLOR24;
	else if (*bg < 0 || *bg > 255) {
                *bg = -1;
		*attr |= ATTR_RESETBG;
	}
	else
		*attr |= (*bg << BG_SHIFT);

	if (*flags & GUI_PRINT_FLAG_REVERSE) *attr |= ATTR_REVERSE;
	if (*flags & GUI_PRINT_FLAG_ITALIC) *attr |= ATTR_ITALIC;
	if (*flags & GUI_PRINT_FLAG_BOLD) *attr |= ATTR_BOLD;
	if (*flags & GUI_PRINT_FLAG_UNDERLINE) *attr |= ATTR_UNDERLINE;
	if (*flags & GUI_PRINT_FLAG_BLINK) *attr |= ATTR_BLINK;
}

static void view_add_eol(TEXT_BUFFER_VIEW_REC *view, LINE_REC **line)
{
	static const unsigned char eol[] = { 0, LINE_CMD_EOL };

	*line = textbuffer_insert(view->buffer, *line, eol, 2, NULL);
	textbuffer_view_insert_line(view, *line);
}

static void print_text_no_window(int flags, int fg, int bg, int attr, const char *str)
{
	g_return_if_fail(next_xpos != -1);

	term_set_color2(root_window, attr, fg, bg);

	term_move(root_window, next_xpos, next_ypos);
	if (flags & GUI_PRINT_FLAG_CLRTOEOL) {
		if (clrtoeol_info->window != NULL) {
			term_window_clrtoeol_abs(clrtoeol_info->window, next_ypos);
		} else {
			term_clrtoeol(root_window);
		}
	}
	next_xpos += term_addstr(root_window, str);
}

static void sig_gui_print_text(WINDOW_REC *window, void *fgcolor,
			       void *bgcolor, void *pflags,
			       const char *str, TEXT_DEST_REC *dest)
{
        GUI_WINDOW_REC *gui;
        TEXT_BUFFER_VIEW_REC *view;
	LINE_REC *insert_after;
	LINE_INFO_REC lineinfo = { 0 };
	int fg, bg, flags, attr;

	flags = GPOINTER_TO_INT(pflags);
	fg = GPOINTER_TO_INT(fgcolor);
	bg = GPOINTER_TO_INT(bgcolor);
	gui_printtext_get_colors(&flags, &fg, &bg, &attr);

	if (window == NULL) {
		print_text_no_window(flags, fg, bg, attr, str);
		return;
	}

	if (dest != NULL && dest->flags & PRINT_FLAG_FORMAT) {
		return;
	}

        gui = WINDOW_GUI(window);
	view = gui->view;

	lineinfo.level = dest == NULL ? 0 : dest->level;
	lineinfo.time =
	    (gui->use_insert_after && gui->insert_after_time) ? gui->insert_after_time : time(NULL);
	lineinfo.format =
	    dest != NULL && dest->flags & PRINT_FLAG_FORMAT ? LINE_INFO_FORMAT_SET : NULL;

	insert_after = gui->use_insert_after ?
		gui->insert_after : view->buffer->cur_line;

	if (flags & GUI_PRINT_FLAG_NEWLINE) {
                view_add_eol(view, &insert_after);
	}
	textbuffer_line_add_colors(view->buffer, &insert_after, fg, bg, flags);

	/* for historical reasons, the \n will set
	   GUI_PRINT_FLAG_NEWLINE and print an empty string. in this
	   special case, ignore the empty string which would otherwise
	   start another new line */
	if (~flags & GUI_PRINT_FLAG_NEWLINE || *str != '\0') {
		insert_after = textbuffer_insert(view->buffer, insert_after, (unsigned char *) str,
		                                 strlen(str), &lineinfo);
	}

	if (gui->use_insert_after)
                gui->insert_after = insert_after;
}

static void sig_gui_printtext_finished(WINDOW_REC *window, TEXT_DEST_REC *dest)
{
	TEXT_BUFFER_VIEW_REC *view;
	LINE_REC *insert_after;

	view = WINDOW_GUI(window)->view;
	insert_after = WINDOW_GUI(window)->use_insert_after ?
		WINDOW_GUI(window)->insert_after : view->buffer->cur_line;

	if (insert_after != NULL)
		view_add_eol(view, &insert_after);
	remove_old_lines(view);
}

static void read_settings(void)
{
	scrollback_lines = settings_get_int("scrollback_lines");
	scrollback_time = settings_get_time("scrollback_time")/1000;
	scrollback_max_age = settings_get_time("scrollback_max_age")/1000;
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
	settings_add_time("history", "scrollback_max_age", "0");
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
