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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "signals.h"
#include "settings.h"

#include "formats.h"
#include "printtext.h"

#include "screen.h"
#include "gui-windows.h"

int mirc_colors[] = { 15, 0, 1, 2, 12, 6, 5, 4, 14, 10, 3, 11, 9, 13, 8, 7 };
static int scrollback_lines, scrollback_hours, scrollback_burst_remove;

static int scrollback_save_formats;
static GString *format;

static int last_color, last_flags;
static int next_xpos, next_ypos;

void gui_printtext(int xpos, int ypos, const char *str)
{
	next_xpos = xpos;
	next_ypos = ypos;

	printtext_gui(str);

	next_xpos = next_ypos = -1;
}

static void remove_old_lines(TEXT_BUFFER_VIEW_REC *view)
{
	LINE_REC *line;
	time_t old_time;

	old_time = time(NULL)-(scrollback_hours*3600)+1;
	if (view->buffer->lines_count >=
	    scrollback_lines+scrollback_burst_remove) {
                /* remove lines by line count */
		while (view->buffer->lines_count > scrollback_lines) {
			line = view->buffer->lines->data;
			if (line->info.time >= old_time) {
				/* too new line, don't remove yet */
				break;
			}
			textbuffer_view_remove_line(view, line);
		}
	}
}

static void get_colors(int flags, int *fg, int *bg)
{
	if (flags & PRINTFLAG_MIRC_COLOR) {
		/* mirc colors - real range is 0..15, but after 16
		   colors wrap to 0, 1, ... */
		*bg = *bg < 0 ? 0 : mirc_colors[*bg % 16];
		if (*fg > 0) *fg = mirc_colors[*fg % 16];
	} else {
		/* default colors */
		*bg = *bg < 0 || *bg > 15 ? 0 : *bg;
                if (*fg > 8) *fg &= ~8;
	}

	if (*fg < 0 || *fg > 15) {
		*fg = *bg == 0 ? current_theme->default_color :
			current_theme->default_real_color;
	}

	if (flags & PRINTFLAG_REVERSE) {
		int tmp;

		tmp = *fg; *fg = *bg; *bg = tmp;
	}

	if (*fg == 8) *fg |= ATTR_COLOR8;
	if (flags & PRINTFLAG_BOLD) {
		if (*fg == 0) *fg = current_theme->default_real_color;
		*fg |= 8;
	}
	if (flags & PRINTFLAG_UNDERLINE) *fg |= ATTR_UNDERLINE;
	if (flags & PRINTFLAG_BLINK) *bg |= 0x08;
}

static void line_add_colors(TEXT_BUFFER_REC *buffer, LINE_REC **line,
			    int fg, int bg, int flags)
{
	unsigned char data[12];
	int color, pos;

	/* color should never have last bit on or it would be treated as a
	   command! */
	color = (fg & 0x0f) | ((bg & 0x07) << 4);
	pos = 0;

	if (((fg & ATTR_COLOR8) == 0 && (fg|(bg << 4)) != last_color) ||
	    ((fg & ATTR_COLOR8) && (fg & 0xf0) != (last_color & 0xf0))) {
		data[pos++] = 0;
		data[pos++] = color == 0 ? LINE_CMD_COLOR0 : color;
	}

	if ((flags & PRINTFLAG_UNDERLINE) != (last_flags & PRINTFLAG_UNDERLINE)) {
		data[pos++] = 0;
		data[pos++] = LINE_CMD_UNDERLINE;
	}
	if (fg & ATTR_COLOR8) {
		data[pos++] = 0;
		data[pos++] = LINE_CMD_COLOR8;
	}
	if (bg & 0x08) {
		data[pos++] = 0;
		data[pos++] = LINE_CMD_BLINK;
	}
	if (flags & PRINTFLAG_INDENT) {
		data[pos++] = 0;
		data[pos++] = LINE_CMD_INDENT;
	}

	*line = textbuffer_insert(buffer, *line, data, pos, NULL);

	last_flags = flags;
	last_color = fg | (bg << 4);
}

static void view_add_eol(TEXT_BUFFER_VIEW_REC *view, LINE_REC **line)
{
	static const unsigned char eol[] = { 0, LINE_CMD_EOL };

	*line = textbuffer_insert(view->buffer, *line, eol, 2, NULL);
	textbuffer_view_insert_line(view, *line);
}

static void sig_gui_print_text(WINDOW_REC *window, void *fgcolor,
			       void *bgcolor, void *pflags,
			       char *str, void *level)
{
        TEXT_BUFFER_VIEW_REC *view;
	LINE_REC *insert_after;
        LINE_INFO_REC lineinfo;
	int fg, bg, flags;

	flags = GPOINTER_TO_INT(pflags);
	fg = GPOINTER_TO_INT(fgcolor);
	bg = GPOINTER_TO_INT(bgcolor);
	get_colors(flags, &fg, &bg);

	if (window == NULL) {
                g_return_if_fail(next_xpos != -1);

		wmove(stdscr, next_ypos, next_xpos);
		set_color(stdscr, fg | (bg << 4));
                addstr(str);
		next_xpos += strlen(str);
                return;
	}

	lineinfo.level = GPOINTER_TO_INT(level);
        lineinfo.time = time(NULL);

	view = WINDOW_GUI(window)->view;
	insert_after = WINDOW_GUI(window)->use_insert_after ?
		WINDOW_GUI(window)->insert_after : view->buffer->cur_line;

	if (flags & PRINTFLAG_NEWLINE)
                view_add_eol(view, &insert_after);
	line_add_colors(view->buffer, &insert_after, fg, bg, flags);
	textbuffer_insert(view->buffer, insert_after,
			  str, strlen(str), &lineinfo);
}

static void sig_printtext_finished(WINDOW_REC *window)
{
	TEXT_BUFFER_VIEW_REC *view;
	LINE_REC *insert_after;

        last_color = 0;
	last_flags = 0;

	view = WINDOW_GUI(window)->view;
	insert_after = WINDOW_GUI(window)->use_insert_after ?
		WINDOW_GUI(window)->insert_after : view->buffer->cur_line;

        view_add_eol(view, &insert_after);
	remove_old_lines(view);
}

static void sig_print_format(THEME_REC *theme, const char *module,
			     TEXT_DEST_REC *dest, void *formatnump,
			     char **args)
{
	FORMAT_REC *formats;
	int formatnum, n;

	if (!scrollback_save_formats)
		return;

	formatnum = GPOINTER_TO_INT(formatnump);
	formats = g_hash_table_lookup(default_formats, module);

	/* <module><format_name><arg...> */
	g_string_truncate(format, 0);

	g_string_append_c(format, '\0');
	g_string_append_c(format, (char)LINE_CMD_FORMAT);

        g_string_append(format, module);

	g_string_append_c(format, '\0');
	g_string_append_c(format, (char)LINE_CMD_FORMAT);

	g_string_append(format, formats[formatnum].tag);

	for (n = 0; n < formats[formatnum].params; n++) {
		g_string_append_c(format, '\0');
		g_string_append_c(format, (char)LINE_CMD_FORMAT);

		g_string_append(format, args[n]);
	}
}

static void read_settings(void)
{
	scrollback_lines = settings_get_int("scrollback_lines");
	scrollback_hours = settings_get_int("scrollback_hours");
        scrollback_burst_remove = settings_get_int("scrollback_burst_remove");
        scrollback_save_formats = settings_get_bool("scrollback_save_formats");
}

void gui_printtext_init(void)
{
	next_xpos = next_ypos = -1;
	format = g_string_new(NULL);

	settings_add_int("history", "scrollback_lines", 500);
	settings_add_int("history", "scrollback_hours", 24);
	settings_add_int("history", "scrollback_burst_remove", 10);
	settings_add_bool("history", "scrollback_save_formats", FALSE);

	signal_add("gui print text", (SIGNAL_FUNC) sig_gui_print_text);
	signal_add("print text finished", (SIGNAL_FUNC) sig_printtext_finished);
	signal_add("print format", (SIGNAL_FUNC) sig_print_format);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
	signal_add("beep", (SIGNAL_FUNC) beep);

	read_settings();
}

void gui_printtext_deinit(void)
{
	g_string_free(format, TRUE);

	signal_remove("gui print text", (SIGNAL_FUNC) sig_gui_print_text);
	signal_remove("print text finished", (SIGNAL_FUNC) sig_printtext_finished);
	signal_remove("print format", (SIGNAL_FUNC) sig_print_format);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
	signal_remove("beep", (SIGNAL_FUNC) beep);
}
