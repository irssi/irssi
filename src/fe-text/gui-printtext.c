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
#include "commands.h"
#include "settings.h"

#include "fe-windows.h"
#include "formats.h"
#include "printtext.h"
#include "themes.h"

#include "screen.h"
#include "gui-windows.h"

#define TEXT_CHUNK_USABLE_SIZE (LINE_TEXT_CHUNK_SIZE-2-(int)sizeof(char*))

int mirc_colors[] = { 15, 0, 1, 2, 12, 6, 5, 4, 14, 10, 3, 11, 9, 13, 8, 7 };
static int scrollback_lines, scrollback_hours;

static int scrollback_save_formats;
static GString *format;

static int next_xpos, next_ypos;

#define mark_temp_eol(text) \
	memcpy((text)->buffer + (text)->pos, "\0\200", 2);

static LINE_REC *create_line(GUI_WINDOW_REC *gui, int level)
{
	LINE_REC *rec;

	g_return_val_if_fail(gui != NULL, NULL);
	g_return_val_if_fail(gui->cur_text != NULL, NULL);

	rec = g_mem_chunk_alloc(gui->line_chunk);
	rec->text = gui->cur_text->buffer+gui->cur_text->pos;
	rec->level = GPOINTER_TO_INT(level);
	rec->time = time(NULL);

	mark_temp_eol(gui->cur_text);
	gui->cur_text->lines++;

	gui->last_color = -1;
	gui->last_flags = 0;

	if (gui->temp_line != NULL) {
		int pos = g_list_index(gui->lines, gui->temp_line);
		gui->lines = g_list_insert(gui->lines, rec, pos+1);
		gui->temp_line = rec;
	} else {
		gui->cur_line = rec;
		gui->lines = g_list_append(gui->lines, rec);
		if (gui->startline == NULL) {
			/* first line */
			gui->startline = gui->lines;
			gui->bottom_startline = gui->lines;
		}
	}
	return rec;
}

static TEXT_CHUNK_REC *create_text_chunk(GUI_WINDOW_REC *gui)
{
	TEXT_CHUNK_REC *rec;
	char *buffer, *ptr;

	g_return_val_if_fail(gui != NULL, NULL);

	rec = g_new(TEXT_CHUNK_REC, 1);
	rec->pos = 0;
	rec->lines = 0;

	if (gui->cur_line != NULL && gui->cur_line->text != NULL) {
		/* create a link to new block from the old block */
		buffer = gui->cur_text->buffer + gui->cur_text->pos;
		*buffer++ = 0; *buffer++ = (char) LINE_CMD_CONTINUE;

		ptr = rec->buffer;
		memcpy(buffer, &ptr, sizeof(char *));
	} else {
		/* just to be safe */
		mark_temp_eol(rec);
	}

	gui->cur_text = rec;
	gui->text_chunks = g_slist_append(gui->text_chunks, rec);
	return rec;
}

static void text_chunk_free(GUI_WINDOW_REC *gui, TEXT_CHUNK_REC *chunk)
{
	g_return_if_fail(gui != NULL);
	g_return_if_fail(chunk != NULL);

	gui->text_chunks = g_slist_remove(gui->text_chunks, chunk);
	g_free(chunk);
}

static TEXT_CHUNK_REC *text_chunk_find(GUI_WINDOW_REC *gui, const char *data)
{
	GSList *tmp;

	for (tmp = gui->text_chunks; tmp != NULL; tmp = tmp->next) {
		TEXT_CHUNK_REC *rec = tmp->data;

		if (data >= rec->buffer &&
		    data < rec->buffer+sizeof(rec->buffer))
                        return rec;
	}

	return NULL;
}

void gui_window_line_text_free(GUI_WINDOW_REC *gui, LINE_REC *line)
{
	TEXT_CHUNK_REC *chunk;
        const char *text;

	text = line->text;
	for (;;) {
		if (*text == '\0') {
                        text++;
			if ((unsigned char) *text == LINE_CMD_EOL)
				break;

			if ((unsigned char) *text == LINE_CMD_CONTINUE) {
				char *tmp;

				memcpy(&tmp, text+1, sizeof(char *));

				/* free the previous block */
				chunk = text_chunk_find(gui, text);
				if (--chunk->lines == 0)
					text_chunk_free(gui, chunk);

				text = tmp;
				continue;
			}
			if ((unsigned char) *text & 0x80)
				text++;
			continue;
		}

		text++;
	}

	/* free the last block */
	chunk = text_chunk_find(gui, text);
	if (--chunk->lines == 0) {
		if (gui->cur_text == chunk)
			chunk->pos = 0;
                else
			text_chunk_free(gui, chunk);
	}
}

void gui_window_line_remove(WINDOW_REC *window, LINE_REC *line, int redraw)
{
	GUI_WINDOW_REC *gui;
        GList *last;
        int screenchange;

	g_return_if_fail(window != NULL);
	g_return_if_fail(line != NULL);

	gui = WINDOW_GUI(window);

	if (gui->lines->next == NULL) {
                /* last line in window */
		gui_window_clear(window);
                return;
	}

        screenchange = g_list_find(gui->startline, line) != NULL;
        if (screenchange) gui->ypos -= gui_window_get_linecount(gui, line);

	gui_window_cache_remove(gui, line);
	gui_window_line_text_free(gui, line);
	if (gui->lastlog_last_check != NULL &&
	    gui->lastlog_last_check->data == line)
		gui->lastlog_last_check = NULL;
	if (gui->lastlog_last_away != NULL &&
	    gui->lastlog_last_away->data == line)
		gui->lastlog_last_away = NULL;

        last = g_list_last(gui->bottom_startline);
	if (last->data == line) {
                /* removing last line */
		gui->last_subline =
			gui_window_get_linecount(gui, last->prev->data)-1;
	}

        if (gui->bottom_startline->data == line) {
                /* bottom line removed */
                if (gui->bottom_startline->next != NULL) {
                        gui->bottom_startline = gui->bottom_startline->next;
                        gui->bottom_subline = 0;
                } else {
                        gui->bottom_startline = gui->bottom_startline->prev;
                        gui->bottom_subline = gui->last_subline+1;
                }
	}

	if (gui->startline->data == line) {
                /* first line in screen removed */
                if (gui->startline->next != NULL) {
                        gui->startline = gui->startline->next;
                        gui->subline = 0;
		} else {
                        gui->startline = gui->startline->prev;
			gui->subline = gui->last_subline+1;
			gui->ypos = -1;
			gui->empty_linecount = gui->parent->lines;
			gui->bottom = TRUE;
		}
        }

	window->lines--;
	g_mem_chunk_free(gui->line_chunk, line);
	gui->lines = g_list_remove(gui->lines, line);

        if (window->lines == 0)
                gui_window_clear(window);

        if (redraw && screenchange && is_window_visible(window))
                gui_window_redraw(window);
}

void gui_printtext(int xpos, int ypos, const char *str)
{
	next_xpos = xpos;
	next_ypos = ypos;

	printtext_gui(str);

	next_xpos = next_ypos = -1;
}

static void remove_old_lines(WINDOW_REC *window)
{
	GUI_WINDOW_REC *gui;
	LINE_REC *line;
	time_t old_time;

	gui = WINDOW_GUI(window);

	old_time = time(NULL)-(scrollback_hours*3600)+1;
	if (scrollback_lines > 0) {
                /* remove lines by line count */
		while (window->lines > scrollback_lines) {
			line = gui->lines->data;
			if (line->time >= old_time) {
				/* too new line, don't remove yet */
				break;
			}
			gui_window_line_remove(window, line, TRUE);
		}
	}
}

static void get_colors(int flags, int *fg, int *bg)
{
	if (flags & PRINTFLAG_MIRC_COLOR) {
		/* mirc colors - real range is 0..15, but after 16
		   colors wrap to 0, 1, ... */
		*fg = *fg < 0 ?
			current_theme->default_color : mirc_colors[*fg % 16];
		*bg = *bg < 0 ? 0 : mirc_colors[*bg % 16];
	} else {
		/* default colors */
		*fg = *fg < 0 || *fg > 15 ?
			current_theme->default_color : *fg;
		*bg = *bg < 0 || *bg > 15 ? 0 : *bg;

		if (*fg > 8) *fg -= 8;
	}

	if (flags & PRINTFLAG_REVERSE) {
		int tmp;

		tmp = *fg; *fg = *bg; *bg = tmp;
	}

	if (*fg == 8) *fg |= ATTR_COLOR8;
	if (flags & PRINTFLAG_BOLD) {
		if (*fg == 0) *fg = current_theme->default_bold_color;
		*fg |= 8;
	}
	if (flags & PRINTFLAG_UNDERLINE) *fg |= ATTR_UNDERLINE;
	if (flags & PRINTFLAG_BLINK) *bg |= 0x80;
}

static void linebuf_add(GUI_WINDOW_REC *gui, const char *str, int len)
{
	int left;

	if (len == 0) return;

	while (gui->cur_text->pos + len >= TEXT_CHUNK_USABLE_SIZE) {
		left = TEXT_CHUNK_USABLE_SIZE - gui->cur_text->pos;
		if (str[left-1] == 0) left--; /* don't split the commands */

		memcpy(gui->cur_text->buffer + gui->cur_text->pos, str, left);
		gui->cur_text->pos += left;

		create_text_chunk(gui);
		gui->cur_text->lines++;
		len -= left; str += left;
	}

	memcpy(gui->cur_text->buffer + gui->cur_text->pos, str, len);
	gui->cur_text->pos += len;
}

void gui_window_line_append(GUI_WINDOW_REC *gui, const char *str, int len)
{
	linebuf_add(gui, str, len);
	mark_temp_eol(gui->cur_text);
}

static void line_add_colors(GUI_WINDOW_REC *gui, int fg, int bg, int flags)
{
	unsigned char buffer[12];
	int color, pos;

	/* color should never have last bit on or it would be treated as a
	   command! */
	color = (fg & 0x0f) | ((bg & 0x07) << 4);
	pos = 0;

	if (((fg & ATTR_COLOR8) == 0 && (fg|(bg << 4)) != gui->last_color) ||
	    ((fg & ATTR_COLOR8) && (fg & 0xf0) != (gui->last_color & 0xf0))) {
		buffer[pos++] = 0;
		buffer[pos++] = color == 0 ? LINE_CMD_COLOR0 : color;
	}

	if ((flags & PRINTFLAG_UNDERLINE) != (gui->last_flags & PRINTFLAG_UNDERLINE)) {
		buffer[pos++] = 0;
		buffer[pos++] = LINE_CMD_UNDERLINE;
	}
	if (fg & ATTR_COLOR8) {
		buffer[pos++] = 0;
		buffer[pos++] = LINE_CMD_COLOR8;
	}
	if (bg & 0x08) {
		buffer[pos++] = 0;
		buffer[pos++] = LINE_CMD_BLINK;
	}
	if (flags & PRINTFLAG_INDENT) {
		buffer[pos++] = 0;
		buffer[pos++] = LINE_CMD_INDENT;
	}

	linebuf_add(gui, (char *) buffer, pos);

	gui->last_flags = flags;
	gui->last_color = fg | (bg << 4);
}

static void sig_gui_print_text(WINDOW_REC *window, void *fgcolor,
			       void *bgcolor, void *pflags,
			       char *str, void *level)
{
	GUI_WINDOW_REC *gui;
	LINE_REC *line;
	int fg, bg, flags, new_lines, n, visible, ypos, subline;

	flags = GPOINTER_TO_INT(pflags);
	fg = GPOINTER_TO_INT(fgcolor);
	bg = GPOINTER_TO_INT(bgcolor);
	get_colors(flags, &fg, &bg);

	if (window == NULL && next_xpos != -1) {
		wmove(stdscr, next_ypos, next_xpos);
		set_color(stdscr, fg | (bg << 4));
                addstr(str);
		next_xpos += strlen(str);
                return;
	}

	g_return_if_fail(window != NULL);

	gui = WINDOW_GUI(window);
	visible = is_window_visible(window) && gui->bottom;

	if (gui->cur_text == NULL)
		create_text_chunk(gui);

	/* newline can be only at the start of the line.. */
	if (flags & PRINTFLAG_NEWLINE) {
		remove_old_lines(window);
		if (!gui->eol_marked) {
			if (format->len > 0 || gui->temp_line != NULL) {
				/* mark format continuing to next line */
				char tmp[2] = { 0, (char)LINE_CMD_FORMAT_CONT };
				linebuf_add(gui, tmp, 2);
			}
			linebuf_add(gui, "\0\200", 2); /* mark EOL */
		}
		gui->eol_marked = FALSE;

                line = create_line(gui, 0);
		if (gui->temp_line == NULL ||
		    g_list_find(gui->startline, gui->temp_line) != NULL)
                        gui_window_newline(gui, visible);

		gui->last_subline = 0;
	} else {
		line = gui->temp_line != NULL ? gui->temp_line :
			gui->cur_line != NULL ? gui->cur_line :
			create_line(gui, 0);
		if (line->level == 0) line->level = GPOINTER_TO_INT(level);
	}

	line_add_colors(gui, fg, bg, flags);
	linebuf_add(gui, str, strlen(str));
	mark_temp_eol(gui->cur_text);

	gui_window_cache_remove(gui, line);

	if (gui->temp_line != NULL) {
		/* updating existing line - don't even
		   try to print it to screen */
		return;
	}

	new_lines = gui_window_get_linecount(gui, line)-1 - gui->last_subline;

	for (n = 0; n < new_lines; n++)
		gui_window_newline(gui, visible);

	if (visible) {
		/* draw the line to screen. */
                ypos = gui->ypos-new_lines;
		if (new_lines > 0) {
#ifdef USE_CURSES_WINDOWS
			set_color(gui->parent->curses_win, 0);
			wmove(gui->parent->curses_win, ypos, 0);
			wclrtoeol(gui->parent->curses_win);
#else
			set_color(stdscr, 0);
			move(ypos + gui->parent->first_line, 0);
			wclrtoeol(stdscr);
#endif
		}

		if (ypos >= 0)
			subline = gui->last_subline;
		else {
			/* *LONG* line - longer than screen height */
			subline = -ypos+gui->last_subline;
			ypos = 0;
		}
		gui_window_line_draw(gui, line, ypos, subline, -1);
	}

	gui->last_subline += new_lines;
}

static void window_clear_screen(GUI_WINDOW_REC *gui)
{
#ifdef USE_CURSES_WINDOWS
        wclear(gui->parent->curses_win);
	screen_refresh(gui->parent->curses_win);
#else
	int n;

	for (n = gui->parent->first_line; n < gui->parent->last_line; n++) {
		move(n, 0);
		clrtoeol();
	}
	screen_refresh(NULL);
#endif
}

static void window_clear(WINDOW_REC *window)
{
	GUI_WINDOW_REC *gui = WINDOW_GUI(window);

	if (is_window_visible(window))
		window_clear_screen(gui);

	gui->ypos = -1;
	gui->bottom_startline = gui->startline = g_list_last(gui->lines);
	gui->bottom_subline = gui->subline = gui->last_subline+1;
	gui->empty_linecount = gui->parent->lines;
	gui->bottom = TRUE;
}

/* SYNTAX: CLEAR */
static void cmd_clear(const char *data)
{
	GHashTable *optlist;
	void *free_arg;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, PARAM_FLAG_OPTIONS,
			    "clear", &optlist)) return;

	if (g_hash_table_lookup(optlist, "all") != NULL)
		g_slist_foreach(windows, (GFunc) window_clear, NULL);
	else
                window_clear(active_win);

	cmd_params_free(free_arg);
}

static void sig_printtext_finished(WINDOW_REC *window)
{
	GUI_WINDOW_REC *gui;

	gui = WINDOW_GUI(window);
	if (gui->cur_line == NULL)
                return;

	if (format->len > 0) {
                /* save format of the line */
		linebuf_add(gui, format->str, format->len);

		g_string_truncate(format, 0);
	}

	linebuf_add(gui, "\0\200", 2); /* mark EOL */
	gui->eol_marked = TRUE;

	if (is_window_visible(window)) {
#ifdef USE_CURSES_WINDOWS
		screen_refresh(gui->parent->curses_win);
#else
		screen_refresh(NULL);
#endif
	}
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
        scrollback_save_formats = settings_get_bool("scrollback_save_formats");
}

void gui_printtext_init(void)
{
	next_xpos = next_ypos = -1;
	format = g_string_new(NULL);

	settings_add_int("history", "scrollback_lines", 500);
	settings_add_int("history", "scrollback_hours", 24);
	settings_add_bool("history", "scrollback_save_formats", FALSE);

	signal_add("gui print text", (SIGNAL_FUNC) sig_gui_print_text);
	signal_add("print text finished", (SIGNAL_FUNC) sig_printtext_finished);
	signal_add("print format", (SIGNAL_FUNC) sig_print_format);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
	signal_add("beep", (SIGNAL_FUNC) beep);
	command_bind("clear", NULL, (SIGNAL_FUNC) cmd_clear);
	command_set_options("clear", "all");

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
	command_unbind("clear", (SIGNAL_FUNC) cmd_clear);
}
