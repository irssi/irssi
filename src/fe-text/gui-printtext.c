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
#include "gui-mainwindows.h"
#include "gui-windows.h"

#define TEXT_CHUNK_USABLE_SIZE (LINE_TEXT_CHUNK_SIZE-2-sizeof(char*))

static gint mirc_colors[] = { 15, 0, 1, 2, 4, 6, 5, 4, 14, 10, 3, 11, 9, 13, 8, 7, 15 };
static gint max_textwidget_lines;

static LINE_REC *create_line(GUI_WINDOW_REC *gui, gint level)
{
    g_return_val_if_fail(gui != NULL, NULL);
    g_return_val_if_fail(gui->cur_text != NULL, NULL);

    gui->cur_line = g_mem_chunk_alloc(gui->line_chunk);
    gui->cur_line->text = gui->cur_text->buffer+gui->cur_text->pos;
    gui->cur_line->level = (gint32) GPOINTER_TO_INT(level);
    gui->cur_line->time = time(NULL);

    gui->last_color = -1;
    gui->last_flags = 0;

    gui->lines = g_list_append(gui->lines, gui->cur_line);
    if (gui->startline == NULL)
    {
	gui->startline = gui->lines;
	gui->bottom_startline = gui->lines;
    }
    return gui->cur_line;
}

static TEXT_CHUNK_REC *create_text_chunk(GUI_WINDOW_REC *gui)
{
    TEXT_CHUNK_REC *rec;
    guchar *buffer;
    gchar *ptr;

    g_return_val_if_fail(gui != NULL, NULL);

    rec = g_new(TEXT_CHUNK_REC, 1);
    rec->pos = 0;
    rec->lines = 0;

    if (gui->cur_line != NULL && gui->cur_line->text != NULL)
    {
	/* mark the next block text block position.. */
	buffer = (guchar *) gui->cur_text->buffer+gui->cur_text->pos;
	if (gui->cur_text->pos+2+sizeof(gchar *) > LINE_TEXT_CHUNK_SIZE)
	    g_error("create_text_chunk() : buffer overflow?!");
        *buffer++ = 0; *buffer++ = LINE_CMD_CONTINUE;
	ptr = rec->buffer;
        memcpy(buffer, &ptr, sizeof(gchar *));
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

    if (gui->startline->prev == NULL)
    {
	gui->startline = gui->startline->next;
	gui->subline = 0;
    }
    if (gui->bottom_startline->prev == NULL)
    {
	gui->bottom_startline = gui->bottom_startline->next;
	gui->bottom_subline = 0;
    }

    window->lines--;
    g_mem_chunk_free(gui->line_chunk, gui->lines->data);
    gui->lines = g_list_remove(gui->lines, gui->lines->data);

    if (gui->startline->prev == NULL && is_window_visible(window))
	gui_window_redraw(window);
}

static void get_colors(gint flags, gint *fg, gint *bg)
{
    if (flags & PRINTFLAG_MIRC_COLOR)
    {
	/* mirc colors */
	*fg = *fg < 0 || *fg > 16 ?
	    current_theme->default_color : mirc_colors[*fg];
	*bg = *bg < 0 || *bg > 16 ? 0 : mirc_colors[*bg];
    }
    else
    {
	/* default colors */
	*fg = *fg < 0 || *fg > 15 ?
	    current_theme->default_color : *fg;
	*bg = *bg < 0 || *bg > 15 ? 0 : *bg;

	if (*fg > 8) *fg -= 8;
    }

    if (flags & PRINTFLAG_REVERSE)
    {
        gint tmp;

        tmp = *fg; *fg = *bg; *bg = tmp;
    }

    if (*fg == 8) *fg |= ATTR_COLOR8;
    if (flags & PRINTFLAG_BOLD) *fg |= 8;
    if (flags & PRINTFLAG_UNDERLINE) *fg |= ATTR_UNDERLINE;
    if (flags & PRINTFLAG_BLINK) *bg |= 0x80;
}

static void linebuf_add(GUI_WINDOW_REC *gui, gchar *str, gint len)
{
    gint left;

    if (len == 0) return;

    while (gui->cur_text->pos+len >= TEXT_CHUNK_USABLE_SIZE)
    {
	left = TEXT_CHUNK_USABLE_SIZE-gui->cur_text->pos;
	if (str[left-1] == 0) left--; /* don't split the command! */
	memcpy(gui->cur_text->buffer+gui->cur_text->pos, str, left);
	gui->cur_text->pos += left;
	create_text_chunk(gui);
	len -= left; str += left;
    }

    memcpy(gui->cur_text->buffer+gui->cur_text->pos, str, len);
    gui->cur_text->pos += len;
}

static void line_add_colors(GUI_WINDOW_REC *gui, gint fg, gint bg, gint flags)
{
    guchar buffer[12];
    gint color, pos;

    color = (fg & 0x0f) | (bg << 4);
    pos = 0;

    if (((fg & ATTR_COLOR8) == 0 && (fg|(bg << 4)) != gui->last_color) ||
	((fg & ATTR_COLOR8) && (fg & 0xf0) != (gui->last_color & 0xf0)))
    {
	buffer[pos++] = 0;
	buffer[pos++] = (gchar) color;
    }

    if ((flags & PRINTFLAG_UNDERLINE) != (gui->last_flags & PRINTFLAG_UNDERLINE))
    {
	buffer[pos++] = 0;
	buffer[pos++] = LINE_CMD_UNDERLINE;
    }
    if (fg & ATTR_COLOR8)
    {
	buffer[pos++] = 0;
	buffer[pos++] = LINE_CMD_COLOR8;
    }
    if (flags & PRINTFLAG_BEEP)
    {
	buffer[pos++] = 0;
	buffer[pos++] = LINE_CMD_BEEP;
    }
    if (flags & PRINTFLAG_INDENT)
    {
	buffer[pos++] = 0;
	buffer[pos++] = LINE_CMD_INDENT;
    }

    linebuf_add(gui, (gchar *) buffer, pos);

    gui->last_flags = flags;
    gui->last_color = fg | (bg << 4);
}

static void gui_printtext(WINDOW_REC *window, gpointer fgcolor, gpointer bgcolor, gpointer pflags, gchar *str, gpointer level)
{
    GUI_WINDOW_REC *gui;
    LINE_REC *line;
    gboolean visible;
    gint fg, bg, flags, lines, n;

    g_return_if_fail(window != NULL);

    gui = WINDOW_GUI(window);
    if (max_textwidget_lines > 0 && max_textwidget_lines <= window->lines)
	remove_first_line(window);

    visible = is_window_visible(window) && gui->bottom;
    flags = GPOINTER_TO_INT(pflags);
    fg = GPOINTER_TO_INT(fgcolor);
    bg = GPOINTER_TO_INT(bgcolor);

    if (gui->cur_text == NULL)
	create_text_chunk(gui);

    /* \n can be only at the start of the line.. */
    if (*str == '\n')
    {
	linebuf_add(gui, "\0\x80", 2); /* mark EOL */
	line = create_line(gui, 0);
	gui_window_newline(gui, visible);
	str++;
	gui->cur_text->lines++;
	gui->last_subline = 0;
    }
    else
    {
	line = gui->cur_line != NULL ? gui->cur_line :
	    create_line(gui, 0);
	if (line->level == 0) line->level = GPOINTER_TO_INT(level);
    }

    get_colors(flags, &fg, &bg);
    line_add_colors(gui, fg, bg, flags);
    linebuf_add(gui, str, strlen(str));

    /* temporarily mark the end of line. */
    memcpy(gui->cur_text->buffer+gui->cur_text->pos, "\0\x80", 2);

    if (visible)
    {
	/* draw the line to screen. */
	lines = gui_window_line_draw(gui, line, first_text_line+gui->ypos, gui->last_subline, -1);
    }
    else
    {
	/* we still need to update the bottom's position */
	lines = gui_window_get_linecount(gui, line)-1-gui->last_subline;
	for (n = 0; n < lines; n++)
	    gui_window_newline(gui, visible);
    }
    if (lines > 0) gui->last_subline += lines;
}

static void cmd_clear(gchar *data)
{
    GUI_WINDOW_REC *gui;
    gint n;

    gui = WINDOW_GUI(active_win);

    if (is_window_visible(active_win))
    {
        for (n = first_text_line; n < last_text_line; n++)
        {
            move(n, 0);
            clrtoeol();
        }
        screen_refresh();
    }

    gui->ypos = -1;
    gui->bottom_startline = gui->startline = g_list_last(gui->lines);
    gui->bottom_subline = gui->subline = gui->last_subline+1;
    gui->empty_linecount = last_text_line-first_text_line;
    gui->bottom = TRUE;
}

static void sig_printtext_finished(WINDOW_REC *window)
{
	if (is_window_visible(window))
		screen_refresh();
}

static void read_settings(void)
{
	max_textwidget_lines = settings_get_int("max_textwidget_lines");
}

void gui_printtext_init(void)
{
    signal_add("gui print text", (SIGNAL_FUNC) gui_printtext);
    command_bind("clear", NULL, (SIGNAL_FUNC) cmd_clear);
    signal_add("print text finished", (SIGNAL_FUNC) sig_printtext_finished);
    signal_add("setup changed", (SIGNAL_FUNC) read_settings);

    read_settings();
}

void gui_printtext_deinit(void)
{
    signal_remove("gui print text", (SIGNAL_FUNC) gui_printtext);
    command_unbind("clear", (SIGNAL_FUNC) cmd_clear);
    signal_remove("print text finished", (SIGNAL_FUNC) sig_printtext_finished);
    signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
}
