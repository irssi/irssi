/*
 gui-windows.c : irssi

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
#include "server.h"
#include "misc.h"

#include "irc.h"
#include "channels.h"
#include "windows.h"

#include "screen.h"
#include "gui-entry.h"
#include "gui-mainwindows.h"
#include "gui-windows.h"

#include <regex.h>

#define DEFAULT_INDENT_POS 10

int first_text_line = 0, last_text_line = 0;

static GUI_WINDOW_REC *gui_window_init(WINDOW_REC *window, MAIN_WINDOW_REC *parent)
{
	GUI_WINDOW_REC *gui;

	gui = g_new0(GUI_WINDOW_REC, 1);
	gui->parent = parent;

	gui->bottom = TRUE;
	gui->line_chunk = g_mem_chunk_new("line chunk", sizeof(LINE_REC),
					  sizeof(LINE_REC)*100, G_ALLOC_AND_FREE);
	gui->empty_linecount = last_text_line-first_text_line-1;

	return gui;
}

static void gui_window_deinit(GUI_WINDOW_REC *gui)
{
	g_slist_foreach(gui->text_chunks, (GFunc) g_free, NULL);
	g_slist_free(gui->text_chunks);

	g_mem_chunk_destroy(gui->line_chunk);
	g_list_free(gui->lines);

	g_free(gui);
}

static void gui_window_created(WINDOW_REC *window)
{
    MAIN_WINDOW_REC *parent;

    g_return_if_fail(window != NULL);

    parent = (active_win == NULL || WINDOW_GUI(active_win) == NULL) ?
	gui_mainwindow_create() : WINDOW_GUI(active_win)->parent;
    if (parent->children == NULL) parent->active = window;
    parent->children = g_list_append(parent->children, window);

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
	parent->children = g_list_remove(parent->children, window);

	signal_emit("gui window destroyed", 1, window);

	gui_window_deinit(gui);
	window->gui_data = NULL;

	if (parent->children == NULL)
		gui_mainwindow_destroy(parent);

	if (windows != NULL && active_win == window && !quitting)
		window_set_active(windows->data);
}

void gui_window_clear(WINDOW_REC *window)
{
    MAIN_WINDOW_REC *parent;

    g_return_if_fail(window != NULL);

    parent = WINDOW_GUI(window)->parent;
    gui_window_deinit(WINDOW_GUI(window));
    window->gui_data = gui_window_init(window, parent);

    window->lines = 0;

    if (is_window_visible(window))
	gui_window_redraw(window);
}

gint gui_window_update_bottom(GUI_WINDOW_REC *gui, gint lines)
{
    gint linecount, last_linecount;

    if (gui->bottom_startline == NULL)
	return -1;

    while (lines < 0)
    {
	if (gui->bottom_subline > 0)
	    gui->bottom_subline--;
	else
	{
	    if (gui->bottom_startline->prev == NULL)
		return -1;
	    gui->bottom_startline = gui->bottom_startline->prev;

	    linecount = gui_window_get_linecount(gui, gui->bottom_startline->data);
	    gui->bottom_subline = linecount-1;
	}
	lines++;
    }

    last_linecount = linecount = -1;
    while (lines > 0)
    {
	if (linecount == -1)
	    last_linecount = linecount = gui_window_get_linecount(gui, gui->bottom_startline->data);

	if (linecount > gui->bottom_subline+1)
	    gui->bottom_subline++;
	else
	{
	    gui->bottom_subline = 0;
	    linecount = -1;

	    if (gui->bottom_startline->next == NULL)
		break;
	    gui->bottom_startline = gui->bottom_startline->next;
	}
	lines--;
    }

    return last_linecount;
}

void gui_window_newline(GUI_WINDOW_REC *gui, gboolean visible)
{
    gboolean last_line;
    gint linecount;

    g_return_if_fail(gui != NULL);

    gui->xpos = 0;
    last_line = gui->ypos >= last_text_line-first_text_line-1;

    if (gui->empty_linecount > 0)
    {
	/* window buffer height isn't even the size of the screen yet */
        gui->empty_linecount--;
	linecount = gui_window_get_linecount(gui, gui->startline->data);
    }
    else
    {
	linecount = gui_window_update_bottom(gui, 1);
    }

    if (!last_line || !gui->bottom)
    {
	gui->ypos++;
    }
    else if (gui->bottom)
    {
	if (gui->subline >= linecount)
	{
	    /* after screen gets full after /CLEAR we end up here.. */
	    gui->startline = gui->startline->next;
	    gui->subline = 0;

	    linecount = gui_window_update_bottom(gui, 1);
	}

	if (linecount > 1+gui->subline)
	    gui->subline++;
	else
	{
	    gui->startline = gui->startline->next;
	    gui->subline = 0;
	}

	if (visible)
	{
	    scroll_up(first_text_line, last_text_line-1);
	    move(last_text_line-1, 0); clrtoeol();
	}
    }
}

/* get number of real lines that line record takes - this really should share
   at least some code with gui_window_line_draw().. */
gint gui_window_get_linecount(GUI_WINDOW_REC *gui, LINE_REC *line)
{
    gchar *ptr, *last_space_ptr, *tmp;
    gint lines, xpos, indent_pos, last_space;

    g_return_val_if_fail(gui != NULL, -1);
    g_return_val_if_fail(line != NULL, -1);

    if (line->text == NULL)
	return 0;

    xpos = 0; lines = 1; indent_pos = DEFAULT_INDENT_POS;
    last_space = 0; last_space_ptr = NULL;
    for (ptr = line->text;; ptr++)
    {
	if (*ptr == '\0')
	{
	    /* command */
	    ptr++;
	    switch ((guchar) *ptr)
	    {
		case LINE_CMD_EOL:
                    return lines;
		case LINE_CMD_CONTINUE:
		    memcpy(&tmp, ptr+1, sizeof(gchar *));
                    ptr = tmp-1;
		    break;
		case LINE_CMD_INDENT:
		    indent_pos = xpos;
                    break;
	    }
	    continue;
	}

	if (xpos == COLS)
	{
	    xpos = indent_pos >= COLS-5 ? DEFAULT_INDENT_POS : indent_pos;

	    if (last_space > indent_pos && last_space > 10)
	    {
		ptr = last_space_ptr;
		while (*ptr == ' ') ptr++;
	    }

	    last_space = 0;
	    lines++;
	    ptr--;
	    continue;
	}

	xpos++;
	if (*ptr == ' ')
	{
	    last_space = xpos-1;
	    last_space_ptr = ptr+1;
	}
    }
}

/* draw line - ugly code.. */
gint gui_window_line_draw(GUI_WINDOW_REC *gui, LINE_REC *line, gint ypos, gint skip, gint max)
{
    gchar *ptr, *last_space_ptr, *tmp;
    gint lines, xpos, color, indent_pos, last_space, last_space_color;

    g_return_val_if_fail(gui != NULL, -1);
    g_return_val_if_fail(line != NULL, -1);

    if (line->text == NULL)
	return 0;

    move(ypos, 0);
    xpos = 0; color = 0; lines = -1; indent_pos = DEFAULT_INDENT_POS;
    last_space = last_space_color = 0; last_space_ptr = NULL;
    for (ptr = line->text;; ptr++)
    {
	if (*ptr == '\0')
	{
	    /* command */
	    ptr++;
	    if ((*ptr & 0x80) == 0)
	    {
		/* set color */
                color = (color & ATTR_UNDERLINE) | *ptr;
	    }
	    else switch ((guchar) *ptr)
	    {
		case LINE_CMD_EOL:
                    return lines;
		case LINE_CMD_CONTINUE:
		    memcpy(&tmp, ptr+1, sizeof(gchar *));
		    ptr = tmp-1;
		    break;
		case LINE_CMD_UNDERLINE:
		    color ^= ATTR_UNDERLINE;
		    break;
		case LINE_CMD_COLOR8:
		    color &= 0xfff0;
		    color |= 8|ATTR_COLOR8;
		    break;
		case LINE_CMD_BEEP:
		    beep();
		    break;
		case LINE_CMD_INDENT:
		    indent_pos = xpos;
                    break;
	    }
	    set_color(color);
	    continue;
	}

	if (xpos == COLS)
	{
	    xpos = indent_pos >= COLS-5 ? DEFAULT_INDENT_POS : indent_pos;

	    if (last_space > indent_pos && last_space > 10)
	    {
		/* remove the last word */
		if (!skip)
		{
		    move(ypos, last_space);
		    set_color(0);
		    clrtoeol();
		}

		/* skip backwards to draw the line again. */
		ptr = last_space_ptr;
		color = last_space_color;
		if (!skip) set_color(color);
		while (*ptr == ' ') ptr++;
	    }
	    last_space = 0;

	    if (skip > 0)
	    {
		if (--skip == 0) set_color(color);
	    }
	    else
	    {
		if (lines == max)
		    return lines;
		if (max != -1)
		    ypos++;
		else
		{
		    gui_window_newline(gui, TRUE);
		    ypos = first_text_line+gui->ypos;
		}
		lines++;
	    }
	    move(ypos, indent_pos);

	    /* we could have \0.. */
	    ptr--;
	    continue;
	}

	xpos++;
	if (*ptr == ' ')
	{
	    last_space = xpos-1;
	    last_space_color = color;
	    last_space_ptr = ptr+1;
	}

	if (skip) continue;
	if (lines == -1) lines = 0;

	if ((guchar) *ptr >= 32)
	    addch((guchar) *ptr);
	else
	{
	    /* low-ascii */
	    set_color(ATTR_REVERSE);
	    addch(*ptr+'A'-1);
	    set_color(color);
	}
    }
}

void gui_window_redraw(WINDOW_REC *window)
{
    GUI_WINDOW_REC *gui;
    GList *line;
    gint ypos, lines, skip, max;

    g_return_if_fail(window != NULL);

    gui = WINDOW_GUI(window);

    for (ypos = first_text_line; ypos < last_text_line; ypos++)
    {
	set_color(0);
        move(ypos, 0);
        clrtoeol();
    }

    skip = gui->subline;
    ypos = first_text_line;
    for (line = gui->startline; line != NULL; line = line->next)
    {
        LINE_REC *rec = line->data;

	max = last_text_line - ypos-1;
	if (max < 0) break;

	lines = gui_window_line_draw(gui, rec, ypos, skip, max);
	skip = 0;

	ypos += lines+1;
    }
    screen_refresh();
}

static void gui_window_scroll_up(GUI_WINDOW_REC *gui, gint lines)
{
    LINE_REC *line;
    gint count, linecount;

    if (gui->startline == NULL)
	return;

    count = lines-gui->subline; gui->ypos += gui->subline;
    gui->subline = 0;

    while (gui->startline->prev != NULL && count > 0)
    {
	gui->startline = gui->startline->prev;

        line = gui->startline->data;
	linecount = gui_window_get_linecount(gui, line);
	count -= linecount;
	gui->ypos += linecount;
    }

    if (count < 0)
    {
	gui->subline = -count;
	gui->ypos -= -count;
    }

    gui->bottom = (gui->ypos >= -1 && gui->ypos <= last_text_line-first_text_line-1);
}

static void gui_window_scroll_down(GUI_WINDOW_REC *gui, gint lines)
{
    LINE_REC *line;
    gint count, linecount;

    if (gui->startline == gui->bottom_startline && gui->subline == gui->bottom_subline)
	return;

    count = lines+gui->subline; gui->ypos += gui->subline;
    gui->subline = 0;

    while (count > 0)
    {
	line = gui->startline->data;

	linecount = gui_window_get_linecount(gui, line);
	count -= linecount;
	gui->ypos -= linecount;

	if (gui->startline == gui->bottom_startline &&
	   linecount+count > gui->bottom_subline)
	{
	    /* reached the last screenful of text */
	    gui->subline = gui->bottom_subline;
	    gui->ypos += linecount;
	    gui->ypos -= gui->subline;
	    break;
	}

	if (count <= 0)
	{
	    gui->subline = linecount+count;
	    gui->ypos += -count;
	    break;
	}

	if (gui->startline->next == NULL)
	{
	    gui->subline = linecount;
	    break;
	}
        gui->startline = gui->startline->next;
    }

    gui->bottom = (gui->ypos >= -1 && gui->ypos <= last_text_line-first_text_line-1);
}

void gui_window_scroll(WINDOW_REC *window, gint lines)
{
    GUI_WINDOW_REC *gui;

    g_return_if_fail(window != NULL);

    gui = WINDOW_GUI(window);

    if (lines < 0)
	gui_window_scroll_up(gui, -lines);
    else
	gui_window_scroll_down(gui, lines);

    if (is_window_visible(window))
	gui_window_redraw(window);
    signal_emit("gui page scrolled", 1, window);
}

static void window_update_prompt(WINDOW_REC *window)
{
	WI_ITEM_REC *item;
	char *text, *str;

	if (window != active_win) return;

	item = window->active;
	if (item != NULL)
		text = item->name;
	else if (window->name != NULL)
		text = window->name;
	else {
		gui_entry_set_prompt("");
		return;
	}

	/* set prompt */
	str = g_strdup_printf("[%1.17s] ", text);
	gui_entry_set_prompt(str);
	if (*str != '\0') g_free(str);
}

static void signal_window_changed(WINDOW_REC *window)
{
	g_return_if_fail(window != NULL);

	WINDOW_GUI(window)->parent->active = window;

	screen_refresh_freeze();
	window_update_prompt(window);
	gui_window_redraw(window);
	screen_refresh_thaw();
}

static void signal_window_item_update(WINDOW_REC *window)
{
	CHANNEL_REC *channel;

	channel = irc_item_channel(window->active);
	if (channel != NULL) {
		/* redraw channel widgets */
		signal_emit("channel topic changed", 1, channel);
		signal_emit("channel mode changed", 1, channel);
	}

	window_update_prompt(window);
}

GList *gui_window_find_text(WINDOW_REC *window, gchar *text, GList *startline, int regexp, int fullword)
{
    regex_t preg;
    GList *tmp;
    GList *matches;
    gchar *str, *ptr;
    gint n, size;

    g_return_val_if_fail(window != NULL, NULL);
    g_return_val_if_fail(text != NULL, NULL);

    text = g_strdup(text); g_strup(text);
    matches = NULL; size = 1024; str = g_malloc(1024);

    if (regcomp(&preg, text, REG_EXTENDED|REG_NOSUB) != 0) {
	    g_free(text);
	    return 0;
    }

    if (startline == NULL) startline = WINDOW_GUI(window)->lines;
    for (tmp = startline; tmp != NULL; tmp = tmp->next)
    {
        LINE_REC *rec = tmp->data;

	for (n = 0, ptr = rec->text; ; ptr++)
	{
	    if (*ptr != 0)
	    {
		if (n+2 > size)
		{
		    size += 1024;
                    str = g_realloc(str, size);
		}
		str[n++] = toupper(*ptr);
	    }
	    else
	    {
		ptr++;

		if ((guchar) *ptr == LINE_CMD_CONTINUE)
		{
		    gchar *tmp;

		    memcpy(&tmp, ptr+1, sizeof(gchar *));
		    ptr = tmp-1;
		}
                else if ((guchar) *ptr == LINE_CMD_EOL)
		    break;
	    }
	}
        str[n] = '\0';

	if (regexp ? /*regexec(&preg, str, 0, NULL, 0) == 0*/regexp_match(str, text) :
	    fullword ? stristr_full(str, text) != NULL :
	    strstr(str, text) != NULL) {
                /* matched */
		matches = g_list_append(matches, rec);
	}
    }
    regfree(&preg);

    if (str != NULL) g_free(str);
    g_free(text);
    return matches;
}

static void gui_window_horiz_resize(WINDOW_REC *window)
{
    GUI_WINDOW_REC *gui;
    gint linecount;

    gui = WINDOW_GUI(window);
    if (gui->lines == NULL) return;

    linecount = gui_window_get_linecount(gui, g_list_last(gui->lines)->data);
    gui->last_subline = linecount-1;

    /* fake a /CLEAR and scroll window up one page */
    gui->ypos = -1;
    gui->bottom = TRUE;
    gui->empty_linecount = last_text_line-first_text_line-1;

    gui->bottom_startline = gui->startline = g_list_last(gui->lines);
    gui->bottom_subline = gui->subline = gui->last_subline+1;
    gui_window_scroll(window, -gui->empty_linecount-1);

    gui->bottom_startline = gui->startline;
    gui->bottom_subline = gui->subline;

    /* remove the empty lines from the end */
    if (gui->bottom && gui->startline == gui->lines)
	gui->empty_linecount = (last_text_line-first_text_line-1);
    else
	gui->empty_linecount = 0;
}

void gui_windows_resize(gint ychange, gboolean xchange)
{
    GUI_WINDOW_REC *gui;
    WINDOW_REC *window;
    GSList *tmp;

    screen_refresh_freeze();
    for (tmp = windows; tmp != NULL; tmp = tmp->next)
    {
	window = tmp->data;

	gui = WINDOW_GUI(window);

	if (xchange)
	{
            /* window width changed, we'll need to recalculate a few things.. */
	    gui_window_horiz_resize(window);
	    continue;
	}

	if (ychange < 0 && gui->empty_linecount > 0)
	{
	    /* empty space at the bottom of the screen - just eat it. */
	    gui->empty_linecount += ychange;
	    if (gui->empty_linecount < 0)
		gui->empty_linecount = 0;
	}
        else if (gui->bottom && gui->startline == gui->lines && ychange > 0)
	{
	    /* less than screenful of text, add empty space */
	    gui->empty_linecount += ychange;
	}
	else
	{
	    gui_window_update_bottom(WINDOW_GUI(window), -ychange);
	    gui_window_scroll(window, -ychange);
	}
    }

    irssi_redraw();
    screen_refresh_thaw();
}

static void cmd_window_move(gchar *data)
{
    GSList *w1, *w2;
    WINDOW_REC *window;

    g_return_if_fail(data != NULL);

    window = active_win;
    w1 = g_slist_find(windows, window);
    if (g_strcasecmp(data, "LEFT") == 0 || g_strncasecmp(data, "PREV", 4) == 0)
    {
        w2 = g_slist_nth(windows, g_slist_index(windows, window)-1);
	if (w2 == NULL)
	{
	    window = w1->data;
	    windows = g_slist_remove(windows, window);
	    windows = g_slist_append(windows, window);
            w2 = g_slist_last(windows);
	}
    }
    else if (g_strcasecmp(data, "RIGHT") == 0 || g_strcasecmp(data, "NEXT") == 0)
    {
	w2 = w1->next;
	if (w2 == NULL)
	{
	    window = w1->data;
	    windows = g_slist_remove(windows, window);
	    windows = g_slist_prepend(windows, window);
	}
    }
    else
        return;

    if (w2 != NULL)
    {
	window = w1->data;
	w1->data = w2->data;
	w2->data = window;
    }

    window_set_active(window);
}

void gui_windows_init(void)
{
    signal_add("window created", (SIGNAL_FUNC) gui_window_created);
    signal_add("window destroyed", (SIGNAL_FUNC) gui_window_destroyed);
    signal_add("window changed", (SIGNAL_FUNC) signal_window_changed);
    signal_add("window item changed", (SIGNAL_FUNC) signal_window_item_update);
    signal_add("window name changed", (SIGNAL_FUNC) signal_window_item_update);
    signal_add("window item remove", (SIGNAL_FUNC) signal_window_item_update);
    command_bind("window move", NULL, (SIGNAL_FUNC) cmd_window_move);
}

void gui_windows_deinit(void)
{
    signal_remove("window created", (SIGNAL_FUNC) gui_window_created);
    signal_remove("window destroyed", (SIGNAL_FUNC) gui_window_destroyed);
    signal_remove("window changed", (SIGNAL_FUNC) signal_window_changed);
    signal_remove("window item changed", (SIGNAL_FUNC) signal_window_item_update);
    signal_remove("window name changed", (SIGNAL_FUNC) signal_window_item_update);
    signal_remove("window item remove", (SIGNAL_FUNC) signal_window_item_update);
    command_unbind("window move", (SIGNAL_FUNC) cmd_window_move);
}
