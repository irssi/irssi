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

#include "printtext.h"
#include "windows.h"
#include "themes.h"

#include "screen.h"
#include "gui-windows.h"

#define TEXT_CHUNK_USABLE_SIZE (LINE_TEXT_CHUNK_SIZE-2-sizeof(char*))

int mirc_colors[] = { 15, 0, 1, 2, 12, 6, 5, 4, 14, 10, 3, 11, 9, 13, 8, 7, 15 };
static int scrollback_lines, scrollback_hours;

#define mark_temp_eol(text) \
	memcpy((text)->buffer + (text)->pos, "\0\x80", 2);

static LINE_REC *create_line(GUI_WINDOW_REC *gui, int level)
{
	g_return_val_if_fail(gui != NULL, NULL);
	g_return_val_if_fail(gui->cur_text != NULL, NULL);

	gui->cur_line = g_mem_chunk_alloc(gui->line_chunk);
	gui->cur_line->text = gui->cur_text->buffer+gui->cur_text->pos;
	gui->cur_line->level = GPOINTER_TO_INT(level);
	gui->cur_line->time = time(NULL);

	mark_temp_eol(gui->cur_text);

	gui->last_color = -1;
	gui->last_flags = 0;

	gui->lines = g_list_append(gui->lines, gui->cur_line);
	if (gui->startline == NULL) {
                /* first line */
		gui->startline = gui->lines;
		gui->bottom_startline = gui->lines;
	}
	return gui->cur_line;
}

static TEXT_CHUNK_REC *create_text_chunk(GUI_WINDOW_REC *gui)
{
	TEXT_CHUNK_REC *rec;
	char *buffer, *ptr;

	g_return_val_if_fail(gui != NULL, NULL);

	rec = g_new(TEXT_CHUNK_REC, 1);
	rec->overflow[0] = 0;
	rec->overflow[1] = (char) LINE_CMD_OVERFLOW;
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

static void remove_first_line(WINDOW_REC *window)
{
	GUI_WINDOW_REC *gui;
	TEXT_CHUNK_REC *chunk;

	g_return_if_fail(window != NULL);

	gui = WINDOW_GUI(window);
	chunk = gui->text_chunks->data;

	if (--chunk->lines == 0)
		text_chunk_free(gui, chunk);

	if (gui->lastlog_last_check != NULL &&
	    gui->lastlog_last_check->data == window)
		gui->lastlog_last_check = NULL;
	if (gui->lastlog_last_away != NULL &&
	    gui->lastlog_last_away->data == window)
		gui->lastlog_last_away = NULL;

	if (gui->startline->prev == NULL) {
                /* first line in screen removed */
		gui->startline = gui->startline->next;
		gui->subline = 0;
		gui->ypos--;
	}
	if (gui->bottom_startline->prev == NULL) {
                /* bottom line removed (shouldn't happen?) */
		gui->bottom_startline = gui->bottom_startline->next;
		gui->bottom_subline = 0;
	}

	window->lines--;
	g_mem_chunk_free(gui->line_chunk, gui->lines->data);
	gui->lines = g_list_remove(gui->lines, gui->lines->data);

	if (gui->startline->prev == NULL && is_window_visible(window))
		gui_window_redraw(window);
}

static void remove_old_lines(WINDOW_REC *window)
{
	GUI_WINDOW_REC *gui;
	LINE_REC *line;
	time_t old_time;

	gui = WINDOW_GUI(window);

	old_time = time(NULL)-(scrollback_hours*3600);
	if (scrollback_lines > 0) {
                /* remove lines by line count */
		while (window->lines > scrollback_lines) {
			line = gui->lines->data;
			if (line->time >= old_time) {
				/* too new line, don't remove yet */
				break;
			}
			remove_first_line(window);
		}
	}
}

static void get_colors(int flags, int *fg, int *bg)
{
	if (flags & PRINTFLAG_MIRC_COLOR) {
		/* mirc colors */
		*fg = *fg < 0 || *fg > 16 ?
			current_theme->default_color : mirc_colors[*fg];
		*bg = *bg < 0 || *bg > 16 ? 0 : mirc_colors[*bg];
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
	if (flags & PRINTFLAG_BOLD) *fg |= 8;
	if (flags & PRINTFLAG_UNDERLINE) *fg |= ATTR_UNDERLINE;
	if (flags & PRINTFLAG_BLINK) *bg |= 0x80;
}

static void linebuf_add(GUI_WINDOW_REC *gui, char *str, int len)
{
	int left;

	if (len == 0) return;

	while (gui->cur_text->pos + len >= TEXT_CHUNK_USABLE_SIZE) {
		left = TEXT_CHUNK_USABLE_SIZE - gui->cur_text->pos;
		if (str[left-1] == 0) left--; /* don't split the commands */

		memcpy(gui->cur_text->buffer + gui->cur_text->pos, str, left);
		gui->cur_text->pos += left;

		create_text_chunk(gui);
		len -= left; str += left;
	}

	memcpy(gui->cur_text->buffer + gui->cur_text->pos, str, len);
	gui->cur_text->pos += len;
}

static void line_add_colors(GUI_WINDOW_REC *gui, int fg, int bg, int flags)
{
	unsigned char buffer[12];
	int color, pos;

	/* color should never have last bit on or it would be treated as a
	   command! */
	color = (fg & 0x0f) | ((bg & 0x0f) << 4);
	pos = 0;

	if (((fg & ATTR_COLOR8) == 0 && (fg|(bg << 4)) != gui->last_color) ||
	    ((fg & ATTR_COLOR8) && (fg & 0xf0) != (gui->last_color & 0xf0))) {
		buffer[pos++] = 0;
		buffer[pos++] = color;
	}

	if ((flags & PRINTFLAG_UNDERLINE) != (gui->last_flags & PRINTFLAG_UNDERLINE)) {
		buffer[pos++] = 0;
		buffer[pos++] = LINE_CMD_UNDERLINE;
	}
	if (fg & ATTR_COLOR8) {
		buffer[pos++] = 0;
		buffer[pos++] = LINE_CMD_COLOR8;
	}
	if (flags & PRINTFLAG_INDENT) {
		buffer[pos++] = 0;
		buffer[pos++] = LINE_CMD_INDENT;
	}
	if (flags & PRINTFLAG_BEEP)
                beep();

	linebuf_add(gui, (char *) buffer, pos);

	gui->last_flags = flags;
	gui->last_color = fg | (bg << 4);
}

static void gui_printtext(WINDOW_REC *window, gpointer fgcolor, gpointer bgcolor, gpointer pflags, char *str, gpointer level)
{
	GUI_WINDOW_REC *gui;
	LINE_REC *line;
	int fg, bg, flags, new_lines, n, visible, ypos, subline;

	g_return_if_fail(window != NULL);

	remove_old_lines(window);

	gui = WINDOW_GUI(window);
	visible = is_window_visible(window) && gui->bottom;
	flags = GPOINTER_TO_INT(pflags);
	fg = GPOINTER_TO_INT(fgcolor);
	bg = GPOINTER_TO_INT(bgcolor);

	if (gui->cur_text == NULL)
		create_text_chunk(gui);

	/* \n can be only at the start of the line.. */
	if (*str == '\n') {
		str++;
		linebuf_add(gui, "\0\x80", 2); /* mark EOL */

		line = create_line(gui, 0);
		gui_window_newline(gui, visible);

		gui->cur_text->lines++;
		gui->last_subline = 0;
	} else {
		line = gui->cur_line != NULL ? gui->cur_line :
			create_line(gui, 0);
		if (line->level == 0) line->level = GPOINTER_TO_INT(level);
	}

	get_colors(flags, &fg, &bg);
	line_add_colors(gui, fg, bg, flags);
	linebuf_add(gui, str, strlen(str));
	mark_temp_eol(gui->cur_text);

	gui_window_cache_remove(gui, line);
	new_lines = gui_window_get_linecount(gui, line)-1 - gui->last_subline;

	for (n = 0; n < new_lines; n++)
		gui_window_newline(gui, visible);

	if (visible) {
		/* draw the line to screen. */
                ypos = gui->ypos-new_lines;
		if (new_lines > 0) {
			set_color(0);
			move(gui->parent->first_line+ypos, 0); clrtoeol();
		}

		if (ypos >= 0)
			subline = gui->last_subline;
		else {
			/* *LONG* line - longer than screen height */
			subline = -ypos+gui->last_subline;
			ypos = 0;
		}
		ypos += gui->parent->first_line;
		gui_window_line_draw(gui, line, ypos, subline, -1);
	}

	gui->last_subline += new_lines;
}

static void window_clear(GUI_WINDOW_REC *gui)
{
	int n;

	for (n = gui->parent->first_line; n <= gui->parent->last_line; n++) {
		move(n, 0);
		clrtoeol();
	}
	screen_refresh();
}

static void cmd_clear(void)
{
	GUI_WINDOW_REC *gui;

	gui = WINDOW_GUI(active_win);

	if (is_window_visible(active_win))
		window_clear(gui);

	gui->ypos = -1;
	gui->bottom_startline = gui->startline = g_list_last(gui->lines);
	gui->bottom_subline = gui->subline = gui->last_subline+1;
	gui->empty_linecount = gui->parent->last_line-gui->parent->first_line+1;
	gui->bottom = TRUE;
}

static void sig_printtext_finished(WINDOW_REC *window)
{
	if (is_window_visible(window))
		screen_refresh();
}

static void read_settings(void)
{
	scrollback_lines = settings_get_int("scrollback_lines");
	scrollback_hours = settings_get_int("scrollback_hours");
}

void gui_printtext_init(void)
{
	settings_add_int("history", "scrollback_lines", 500);
	settings_add_int("history", "scrollback_hours", 24);

	signal_add("gui print text", (SIGNAL_FUNC) gui_printtext);
	signal_add("print text finished", (SIGNAL_FUNC) sig_printtext_finished);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
	command_bind("clear", NULL, (SIGNAL_FUNC) cmd_clear);

	read_settings();
}

void gui_printtext_deinit(void)
{
	signal_remove("gui print text", (SIGNAL_FUNC) gui_printtext);
	signal_remove("print text finished", (SIGNAL_FUNC) sig_printtext_finished);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
	command_unbind("clear", (SIGNAL_FUNC) cmd_clear);
}
