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
#include "servers.h"
#include "misc.h"
#include "settings.h"
#include "special-vars.h"

#include "irc.h"
#include "channels.h"
#include "fe-windows.h"
#include "formats.h"

#include "screen.h"
#include "gui-entry.h"
#include "gui-windows.h"
#include "gui-printtext.h"

#ifdef HAVE_REGEX_H
#  include <regex.h>
#endif

/* how often to scan line cache for lines not accessed for a while (ms) */
#define LINE_CACHE_CHECK_TIME (5*60*1000)
/* how long to keep line cache in memory (seconds) */
#define LINE_CACHE_KEEP_TIME (10*60)

static int linecache_tag;
static int window_create_override;
static int default_indent_pos;

static char *prompt, *prompt_window;

static GUI_WINDOW_REC *gui_window_init(WINDOW_REC *window, MAIN_WINDOW_REC *parent)
{
	GUI_WINDOW_REC *gui;

	window->width = COLS;
        window->height = parent->lines;

	gui = g_new0(GUI_WINDOW_REC, 1);
	gui->parent = parent;

	gui->bottom = TRUE;
        gui->line_cache = g_hash_table_new((GHashFunc) g_direct_hash, (GCompareFunc) g_direct_equal);
	gui->line_chunk = g_mem_chunk_new("line chunk", sizeof(LINE_REC),
					  sizeof(LINE_REC)*100, G_ALLOC_AND_FREE);
	gui->empty_linecount = parent->lines-1;

	return gui;
}

int line_cache_destroy(void *key, LINE_CACHE_REC *cache)
{
	g_free_not_null(cache->lines);
	g_free(cache);

	return TRUE;
}

static void gui_window_deinit(GUI_WINDOW_REC *gui)
{
	g_hash_table_foreach(gui->line_cache, (GHFunc) line_cache_destroy, NULL);
	g_hash_table_destroy(gui->line_cache);

	g_slist_foreach(gui->text_chunks, (GFunc) g_free, NULL);
	g_slist_free(gui->text_chunks);

	g_mem_chunk_destroy(gui->line_chunk);
	g_list_free(gui->lines);

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

/* update bottom_startline and bottom_subline of window. */
static int gui_window_update_bottom(GUI_WINDOW_REC *gui, int lines)
{
	int linecount, last_linecount;

	if (gui->bottom_startline == NULL)
		return -1;

	for (; lines < 0; lines++) {
		if (gui->bottom_subline > 0) {
			gui->bottom_subline--;
			continue;
		}

		if (gui->bottom_startline->prev == NULL)
			return -1;
		gui->bottom_startline = gui->bottom_startline->prev;

		linecount = gui_window_get_linecount(gui, gui->bottom_startline->data);
		gui->bottom_subline = linecount-1;
	}

	last_linecount = -1;
	for (; lines > 0; lines--) {
		last_linecount = linecount =
			gui_window_get_linecount(gui, gui->bottom_startline->data);

		if (linecount > gui->bottom_subline+1)
			gui->bottom_subline++;
		else {
			gui->bottom_subline = 0;
			if (gui->bottom_startline->next == NULL)
				break;
			gui->bottom_startline = gui->bottom_startline->next;
		}
	}

	return last_linecount;
}

void gui_window_newline(GUI_WINDOW_REC *gui, int visible)
{
	/* FIXME: I'm pretty sure this could be done cleaner :) */
	int lines;

	g_return_if_fail(gui != NULL);

	gui->xpos = 0;

	lines = gui_window_get_linecount(gui, gui->bottom_startline->data);
	if (gui->bottom_subline >= lines) {
		/* after screen gets full after /CLEAR we end up here.. */
		gui->bottom_startline = gui->bottom_startline->next;
		gui->bottom_subline = 0;
	}

	lines = gui_window_get_linecount(gui, gui->startline->data);
	if (gui->subline >= lines) {
		/* after screen gets full after /CLEAR we end up here.. */
		gui->startline = gui->startline->next;
		gui->subline = 0;
	}

	if (gui->empty_linecount > 0) {
		/* window buffer height isn't even the size of the screen yet */
		gui->empty_linecount--;
		if (!gui->bottom) {
			gui->ypos++;
			return;
		}
	}

	if (gui->ypos >= -1 && gui->ypos < gui->parent->lines-1) {
		gui->ypos++;
		return;
	}

	if (!gui->bottom || (gui->startline == gui->bottom_startline &&
			     gui->subline >= gui->bottom_subline)) {
		lines = gui_window_update_bottom(gui, 1);

		if (!gui->bottom) {
			gui->ypos++;
			return;
		}
	} else {
		lines = gui_window_get_linecount(gui, gui->startline->data);
	}

	if (lines > 1+gui->subline)
		gui->subline++;
	else {
		gui->startline = gui->startline->next;
		gui->subline = 0;
	}

	if (visible) {
		WINDOW *cwin;

#ifdef USE_CURSES_WINDOWS
		cwin = gui->parent->curses_win;
#else
		cwin = stdscr;
		setscrreg(gui->parent->first_line, gui->parent->last_line);
#endif
		scrollok(cwin, TRUE);
		wscrl(cwin, 1);
		scrollok(cwin, FALSE);
	}
}

static LINE_CACHE_REC *gui_window_line_cache(GUI_WINDOW_REC *gui,
					     LINE_REC *line)
{
	LINE_CACHE_REC *rec;
	LINE_CACHE_SUB_REC *sub;
	GSList *lines;
	unsigned char *ptr, *last_space_ptr;
	int xpos, pos, indent_pos, last_space, last_color, color;

	g_return_val_if_fail(line->text != NULL, NULL);

	rec = g_new(LINE_CACHE_REC, 1);
        rec->last_access = time(NULL);

	xpos = 0; color = 0; indent_pos = default_indent_pos;
	last_space = last_color = 0; last_space_ptr = NULL; sub = NULL;

	rec->count = 1; lines = NULL;
	for (ptr = (unsigned char *) line->text;;) {
		if (*ptr == '\0') {
			/* command */
			ptr++;
			if (*ptr == LINE_CMD_EOL || *ptr == LINE_CMD_FORMAT)
				break;

			if (*ptr == LINE_CMD_CONTINUE) {
				unsigned char *tmp;

				memcpy(&tmp, ptr+1, sizeof(char *));
				ptr = tmp;
				continue;
			}

			if ((*ptr & 0x80) == 0) {
				/* set color */
				color = (color & ATTR_UNDERLINE) | *ptr;
			} else switch (*ptr) {
			case LINE_CMD_UNDERLINE:
				color ^= ATTR_UNDERLINE;
				break;
			case LINE_CMD_COLOR0:
				color = color & ATTR_UNDERLINE;
				break;
			case LINE_CMD_COLOR8:
				color &= 0xfff0;
				color |= 8|ATTR_COLOR8;
				break;
			case LINE_CMD_BLINK:
				color |= 0x80;
				break;
			case LINE_CMD_INDENT:
				/* set indentation position here - don't do
				   it if we're too close to right border */
				if (xpos < COLS-5) indent_pos = xpos;
				break;
			}

			ptr++;
			continue;
		}

		if (xpos == COLS && sub != NULL &&
		    (last_space <= indent_pos || last_space <= 10)) {
                        /* long word, remove the indentation from this line */
			xpos -= sub->indent;
                        sub->indent = 0;
		}

		if (xpos == COLS) {
			xpos = indent_pos;

			sub = g_new(LINE_CACHE_SUB_REC, 1);
			if (last_space > indent_pos && last_space > 10) {
                                /* go back to last space */
                                color = last_color;
				ptr = last_space_ptr;
				while (*ptr == ' ') ptr++;
			} else {
				/* long word, no indentation in next line */
				xpos = 0;
				sub->continues = TRUE;
			}

			sub->start = (char *) ptr;
			sub->indent = xpos;
			sub->color = color;

			lines = g_slist_append(lines, sub);
			rec->count++;

			last_space = 0;
			continue;
		}

		xpos++;
		if (*ptr++ == ' ') {
			last_space = xpos-1;
			last_space_ptr = ptr;
			last_color = color;
		}
	}

	if (rec->count < 2)
		rec->lines = NULL;
	else {
		rec->lines = g_new(LINE_CACHE_SUB_REC, rec->count-1);
		for (pos = 0; lines != NULL; pos++) {
			memcpy(&rec->lines[pos], lines->data, sizeof(LINE_CACHE_SUB_REC));

			g_free(lines->data);
			lines = g_slist_remove(lines, lines->data);
		}
	}

	g_hash_table_insert(gui->line_cache, line, rec);
	return rec;
}

void gui_window_cache_remove(GUI_WINDOW_REC *gui, LINE_REC *line)
{
	LINE_CACHE_REC *cache;

	g_return_if_fail(gui != NULL);
	g_return_if_fail(line != NULL);

	cache = g_hash_table_lookup(gui->line_cache, line);
	if (cache != NULL) {
		g_hash_table_remove(gui->line_cache, line);
		line_cache_destroy(NULL, cache);
	}
}

int gui_window_get_linecount(GUI_WINDOW_REC *gui, LINE_REC *line)
{
	LINE_CACHE_REC *cache;

	g_return_val_if_fail(gui != NULL, -1);
	g_return_val_if_fail(line != NULL, -1);

	cache = g_hash_table_lookup(gui->line_cache, line);
	if (cache == NULL)
		cache = gui_window_line_cache(gui, line);
        else
		cache->last_access = time(NULL);

        return cache->count;
}

static void single_line_draw(GUI_WINDOW_REC *gui, int ypos,
			     LINE_CACHE_SUB_REC *rec, const char *text,
			     const char *text_end)
{
	WINDOW *cwin;
	char *tmp;
	int xpos, color;

	if (rec == NULL) {
		xpos = 0; color = 0;
	} else {
		xpos = rec->indent;
		color = rec->color;
	}

#ifdef USE_CURSES_WINDOWS
	cwin = gui->parent->curses_win;
#else
	cwin = stdscr;
	ypos += gui->parent->first_line;
#endif
	wmove(cwin, ypos, xpos);
	set_color(cwin, color);

	while (text != text_end) {
		if (*text == '\0') {
			/* command */
			text++;
			if ((*text & 0x80) == 0) {
				/* set color */
				color = (color & ATTR_UNDERLINE) | *text;
			} else if (*text == (char) LINE_CMD_CONTINUE) {
                                /* jump to next block */
				memcpy(&tmp, text+1, sizeof(char *));
				text = tmp;
				continue;
			} else switch ((unsigned char) *text) {
			case LINE_CMD_EOL:
			case LINE_CMD_FORMAT:
				return;
			case LINE_CMD_UNDERLINE:
				color ^= ATTR_UNDERLINE;
				break;
			case LINE_CMD_COLOR0:
				color = color & ATTR_UNDERLINE;
				break;
			case LINE_CMD_COLOR8:
				color &= 0xfff0;
				color |= 8|ATTR_COLOR8;
				break;
			case LINE_CMD_BLINK:
				color |= 0x80;
                                break;
			}
			set_color(cwin, color);
			text++;
			continue;
		}

		if (((unsigned char) *text & 127) >= 32)
			waddch(cwin, (unsigned char) *text);
		else {
			/* low-ascii */
			set_color(cwin, ATTR_REVERSE);
			waddch(cwin, (*text & 127)+'A'-1);
			set_color(cwin, color);
		}
		text++;
	}
}

int gui_window_line_draw(GUI_WINDOW_REC *gui, LINE_REC *line, int ypos, int skip, int max)
{
	LINE_CACHE_REC *cache;
	LINE_CACHE_SUB_REC *sub;
	char *pos, *next_pos;
	int n;

	g_return_val_if_fail(gui != NULL, -1);
	g_return_val_if_fail(line != NULL, -1);

	cache = g_hash_table_lookup(gui->line_cache, line);
	if (cache == NULL)
		cache = gui_window_line_cache(gui, line);
	else
		cache->last_access = time(NULL);

	if (max < 0) max = cache->count;

	for (n = skip; n < cache->count && max > 0; n++, ypos++, max--) {
		sub = n == 0 ? NULL : &cache->lines[n-1];
		pos = sub == NULL ? line->text : sub->start;
		next_pos = (n+1 < cache->count) ?
			cache->lines[n].start : NULL;

		single_line_draw(gui, ypos, sub, pos, next_pos);
	}

#ifdef USE_CURSES_WINDOWS
	screen_refresh(gui->parent->curses_win);
#else
	screen_refresh(NULL);
#endif

	return cache->count;
}

void gui_window_redraw(WINDOW_REC *window)
{
	GUI_WINDOW_REC *gui;
	WINDOW *cwin;
	GList *line;
	int ypos, lines, skip, max;

	g_return_if_fail(window != NULL);

	gui = WINDOW_GUI(window);
#ifdef USE_CURSES_WINDOWS
	cwin = gui->parent->curses_win;
#else
        cwin = stdscr;
#endif

	/* clear the lines first */
	set_color(cwin, 0);
#ifdef USE_CURSES_WINDOWS
	for (ypos = 0; ypos <= gui->parent->lines; ypos++) {
#else
	for (ypos = gui->parent->first_line; ypos <= gui->parent->last_line; ypos++) {
#endif
		wmove(cwin, ypos, 0);
		wclrtoeol(cwin);
	}

	skip = gui->subline;
	ypos = 0;
	for (line = gui->startline; line != NULL; line = line->next) {
		LINE_REC *rec = line->data;

		max = gui->parent->lines-1 - ypos+1;
		if (max < 0) break;

		lines = gui_window_line_draw(gui, rec, ypos, skip, max);
		ypos += lines-skip;
		skip = 0;
	}

        screen_refresh(cwin);
}

static void gui_window_scroll_up(GUI_WINDOW_REC *gui, int lines)
{
	LINE_REC *line;
	int count, linecount;

	if (gui->startline == NULL)
		return;

	count = lines-gui->subline; gui->ypos += gui->subline;
	gui->subline = 0;

	while (gui->startline->prev != NULL && count > 0) {
		gui->startline = gui->startline->prev;

		line = gui->startline->data;
		linecount = gui_window_get_linecount(gui, line);
		count -= linecount;
		gui->ypos += linecount;
	}

	if (count < 0) {
		gui->subline = -count;
		gui->ypos -= -count;
	}

	gui->bottom = is_window_bottom(gui);
}

#define is_scrolled_bottom(gui) \
	((gui)->startline == (gui)->bottom_startline && \
	(gui)->subline >= (gui)->bottom_subline)

static void gui_window_scroll_down(GUI_WINDOW_REC *gui, int lines)
{
	LINE_REC *line;
	int count, linecount;

	if (is_scrolled_bottom(gui))
		return;

	count = lines+gui->subline; gui->ypos += gui->subline;
	gui->subline = 0;

	while (count > 0) {
		line = gui->startline->data;

		linecount = gui_window_get_linecount(gui, line);
		count -= linecount;
		gui->ypos -= linecount;

		if (gui->startline == gui->bottom_startline &&
		    linecount+count > gui->bottom_subline) {
			/* reached the last screenful of text */
			gui->subline = gui->bottom_subline;
			gui->ypos += linecount;
			gui->ypos -= gui->subline;
			break;
		}

		if (count == 0) {
			if (gui->startline->next == NULL) {
				gui->subline = linecount;
				break;
			}
			gui->startline = gui->startline->next;
			break;
		}

		if (count < 0) {
			gui->subline = linecount+count;
			gui->ypos += -count;
			break;
		}

		gui->startline = gui->startline->next;
	}

	gui->bottom = is_window_bottom(gui);
}

void gui_window_scroll(WINDOW_REC *window, int lines)
{
	GUI_WINDOW_REC *gui;

	g_return_if_fail(window != NULL);

	gui = WINDOW_GUI(window);

	if (lines < 0) {
		if (gui->startline == NULL || gui->startline->prev == NULL)
			return;
		gui_window_scroll_up(gui, -lines);
	} else {
		if (is_scrolled_bottom(gui))
			return;
		gui_window_scroll_down(gui, lines);
	}

	if (is_window_visible(window))
		gui_window_redraw(window);
	signal_emit("gui page scrolled", 1, window);
}

void gui_window_update_ypos(GUI_WINDOW_REC *gui)
{
	GList *tmp;

	g_return_if_fail(gui != NULL);

	gui->ypos = -gui->subline-1;
	for (tmp = gui->startline; tmp != NULL; tmp = tmp->next)
		gui->ypos += gui_window_get_linecount(gui, tmp->data);
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
				      PARSE_FLAG_ISSET_ANY);
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
	int ychange;

	oldparent = WINDOW_GUI(window)->parent;
	if (oldparent == parent)
		return;

	WINDOW_GUI(window)->parent = parent;

	ychange = parent->lines - oldparent->lines;
	if (ychange != 0) gui_window_resize(window, ychange, FALSE);
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

static void signal_window_changed(WINDOW_REC *window)
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

	screen_refresh_freeze();
	window_update_prompt();
	gui_window_redraw(window);
	screen_refresh_thaw();
}

GList *gui_window_find_text(WINDOW_REC *window, const char *text,
			    GList *startline, int regexp, int fullword)
{
#ifdef HAVE_REGEX_H
    regex_t preg;
#endif
    GList *tmp;
    GList *matches;
    gchar *str, *ptr;
    gint n, size;

    g_return_val_if_fail(window != NULL, NULL);
    g_return_val_if_fail(text != NULL, NULL);

    matches = NULL; size = 1024; str = g_malloc(1024);

#ifdef HAVE_REGEX_H
    if (regcomp(&preg, text, REG_ICASE|REG_EXTENDED|REG_NOSUB) != 0)
	    return 0;
#endif

    if (startline == NULL) startline = WINDOW_GUI(window)->lines;
    for (tmp = startline; tmp != NULL; tmp = tmp->next)
    {
        LINE_REC *rec = tmp->data;

	if (*text == '\0') {
		matches = g_list_append(matches, rec);
		continue;
	}

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
		else if ((guchar) *ptr == LINE_CMD_EOL ||
			 (guchar) *ptr == LINE_CMD_FORMAT)
		    break;
	    }
	}
        str[n] = '\0';

	if (
#ifdef HAVE_REGEX_H
		regexp ? regexec(&preg, str, 0, NULL, 0) == 0 :
#endif
	    fullword ? stristr_full(str, text) != NULL :
	    stristr(str, text) != NULL) {
                /* matched */
		matches = g_list_append(matches, rec);
	}
    }
#ifdef HAVE_REGEX_H
    regfree(&preg);
#endif
    if (str != NULL) g_free(str);
    return matches;
}

static void gui_update_bottom_startline(GUI_WINDOW_REC *gui)
{
	GList *tmp;
        int linecount, total;

	if (gui->empty_linecount == 0) {
		/* no empty lines in screen, don't try to keep the old
		   bottom startline */
                gui->bottom_startline = NULL;
	}

        total = 0;
	for (tmp = g_list_last(gui->lines); tmp != NULL; tmp = tmp->prev) {
		LINE_REC *line = tmp->data;

		linecount = gui_window_get_linecount(gui, line);
		if (tmp == gui->bottom_startline) {
			/* keep the old one, make sure that subline is ok */
			if (gui->bottom_subline > linecount+1)
				gui->bottom_subline = linecount+1;
			gui->empty_linecount = gui->parent->lines-total-
				gui->bottom_subline;
                        return;
		}

                total += linecount;
		if (total >= gui->parent->lines) {
			gui->bottom_startline = tmp;
			gui->bottom_subline = total-gui->parent->lines;
                        gui->empty_linecount = 0;
                        return;
		}
	}

        /* not enough lines so we must be at the beginning of the window */
	gui->bottom_startline = gui->lines;
	gui->bottom_subline = 0;
	gui->empty_linecount = gui->parent->lines-total;
}

static void gui_window_horiz_resize(WINDOW_REC *window)
{
	GUI_WINDOW_REC *gui;
	int linecount, diff;

	gui = WINDOW_GUI(window);
	if (gui->lines == NULL) return;

	g_hash_table_foreach_remove(gui->line_cache, (GHRFunc) line_cache_destroy, NULL);

	linecount = gui_window_get_linecount(gui, gui->startline->data);
	if (gui->subline > linecount+1)
                gui->subline = linecount+1;

	gui_window_update_ypos(gui);
	gui_update_bottom_startline(gui);

	if (gui->bottom) {
		if (g_list_find(gui->startline,
				gui->bottom_startline->data) == NULL ||
		    (gui->startline == gui->bottom_startline &&
		     gui->subline > gui->bottom_subline)) {
			gui->startline = gui->bottom_startline;
			gui->subline = gui->bottom_subline;
			gui_window_update_ypos(gui);
		} else {
			diff = gui->ypos+1-gui->parent->lines;
			if (diff > 0) gui_window_scroll(window, diff);
		}
	}
}

void gui_window_resize(WINDOW_REC *window, int ychange, int xchange)
{
	GUI_WINDOW_REC *gui;

	gui = WINDOW_GUI(window);

        window->width = COLS;
        window->height = gui->parent->lines;

	if (xchange) {
		/* window width changed, we'll need to recalculate a
		   few things.. */
		gui_window_horiz_resize(window);
		return;
	}

	if (ychange < 0 && gui->empty_linecount > 0) {
		/* empty space at the bottom of the screen - just eat it. */
		gui->empty_linecount += ychange;
		if (gui->empty_linecount >= 0)
			ychange = 0;
		else {
			ychange = gui->empty_linecount;
			gui->empty_linecount = 0;
		}
	}

	if (ychange > 0 && gui->bottom && gui->empty_linecount > 0)
		gui->empty_linecount += ychange;
	else {
		gui_window_update_bottom(WINDOW_GUI(window), -ychange);
		gui_window_scroll(window, -ychange);

		if (ychange > 0 && gui->bottom &&
		    gui->ypos+1 < gui->parent->lines) {
			gui->empty_linecount += gui->parent->lines-gui->ypos-1;
		}
	}
}

static int window_remove_linecache(void *key, LINE_CACHE_REC *cache,
				   time_t *now)
{
	if (cache->last_access+LINE_CACHE_KEEP_TIME > *now)
		return FALSE;

	line_cache_destroy(NULL, cache);
	return TRUE;
}

static int sig_check_linecache(void)
{
	GSList *tmp;
        time_t now;

        now = time(NULL);
	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		g_hash_table_foreach_remove(WINDOW_GUI(rec)->line_cache,
					    (GHRFunc) window_remove_linecache,
					    &now);
	}
	return 1;
}

static char *line_read_format(unsigned const char **text)
{
	GString *str;
	char *ret;

	str = g_string_new(NULL);
	for (;;) {
		if (**text == '\0') {
			if ((*text)[1] == LINE_CMD_EOL) {
				/* leave text at \0<eof> */
				break;
			}
			if ((*text)[1] == LINE_CMD_FORMAT_CONT) {
				/* leave text at \0<format_cont> */
				break;
			}
			(*text)++;

			if (**text == LINE_CMD_FORMAT) {
				/* move text to start after \0<format> */
				(*text)++;
				break;
			}

			if (**text == LINE_CMD_CONTINUE) {
				unsigned char *tmp;

				memcpy(&tmp, (*text)+1, sizeof(char *));
				*text = tmp;
				continue;
			} else if (**text & 0x80)
				(*text)++;
			continue;
		}

		g_string_append_c(str, (char) **text);
		(*text)++;
	}

	ret = str->str;
	g_string_free(str, FALSE);
	return ret;
}

static char *gui_window_line_get_format(WINDOW_REC *window, LINE_REC *line,
					GString *raw)
{
	const unsigned char *text;
	char *module, *format_name, *args[MAX_FORMAT_PARAMS], *ret;
	TEXT_DEST_REC dest;
	int formatnum, argcount;

	text = (const unsigned char *) line->text;

	/* skip the beginning of the line until we find the format */
	g_free(line_read_format(&text));
	if (text[1] == LINE_CMD_FORMAT_CONT) {
		g_string_append_c(raw, '\0');
		g_string_append_c(raw, (char)LINE_CMD_FORMAT_CONT);
		return NULL;
	}

	/* read format information */
        module = line_read_format(&text);
	format_name = line_read_format(&text);

	if (raw != NULL) {
		g_string_append_c(raw, '\0');
		g_string_append_c(raw, (char)LINE_CMD_FORMAT);

		g_string_append(raw, module);

		g_string_append_c(raw, '\0');
		g_string_append_c(raw, (char)LINE_CMD_FORMAT);

		g_string_append(raw, format_name);
	}

	formatnum = format_find_tag(module, format_name);
	if (formatnum == -1)
		ret = NULL;
	else {
                argcount = 0;
                memset(args, 0, sizeof(args));
		while (*text != '\0' || text[1] != LINE_CMD_EOL) {
			args[argcount] = line_read_format(&text);
			if (raw != NULL) {
				g_string_append_c(raw, '\0');
				g_string_append_c(raw,
						  (char)LINE_CMD_FORMAT);

				g_string_append(raw, args[argcount]);
			}
			argcount++;
		}

		/* get the format text */
		format_create_dest(&dest, NULL, NULL, line->level, window);
		ret = format_get_text_theme_charargs(current_theme,
						     module, &dest,
						     formatnum, args);
		while (argcount > 0)
			g_free(args[--argcount]);
	}

	g_free(module);
	g_free(format_name);

	return ret;
}

void gui_window_reformat_line(WINDOW_REC *window, LINE_REC *line)
{
	GUI_WINDOW_REC *gui;
	TEXT_DEST_REC dest;
	GString *raw;
	char *str, *tmp, *prestr, *linestart, *leveltag;

	gui = WINDOW_GUI(window);

	raw = g_string_new(NULL);
	str = gui_window_line_get_format(window, line, raw);

        if (str == NULL && raw->len == 2 &&
            raw->str[1] == (char)LINE_CMD_FORMAT_CONT) {
                /* multiline format, format explained in one the
                   following lines. remove this line. */
                gui_window_line_remove(window, line, FALSE);
	} else if (str != NULL) {
                /* FIXME: ugly ugly .. and this can't handle
                   non-formatted lines.. */
		g_string_append_c(raw, '\0');
		g_string_append_c(raw, (char)LINE_CMD_EOL);

                gui_window_line_text_free(gui, line);

                gui->temp_line = line;
		gui->temp_line->text = gui->cur_text->buffer+gui->cur_text->pos;
                gui->cur_text->lines++;
		gui->eol_marked = FALSE;

		format_create_dest(&dest, NULL, NULL, line->level, window);

		linestart = format_get_line_start(current_theme, &dest, line->time);
		leveltag = format_get_level_tag(current_theme, &dest);

		prestr = g_strconcat(linestart == NULL ? "" : linestart,
				     leveltag, NULL);
		g_free_not_null(linestart);
		g_free_not_null(leveltag);

		tmp = format_add_linestart(str, prestr);
		g_free(str);
		g_free(prestr);

		format_send_to_gui(&dest, tmp);
		g_free(tmp);

		gui_window_line_append(gui, raw->str, raw->len);

		gui->eol_marked = TRUE;
		gui->temp_line = NULL;
	}
	g_string_free(raw, TRUE);
}

static void sig_check_window_update(WINDOW_REC *window)
{
	if (window == active_win)
                window_update_prompt();
}

static void read_settings(void)
{
	SIGNAL_FUNC funcs[] = {
                (SIGNAL_FUNC) window_update_prompt,
                (SIGNAL_FUNC) window_update_prompt_server,
                (SIGNAL_FUNC) window_update_prompt_window,
                (SIGNAL_FUNC) window_update_prompt_window_item
	};

        default_indent_pos = settings_get_int("indent");

	if (prompt != NULL) {
		special_vars_remove_signals(prompt, 4, funcs);
		special_vars_remove_signals(prompt_window, 4, funcs);
		g_free(prompt);
                g_free(prompt_window);
	}
	prompt = g_strdup(settings_get_str("prompt"));
	prompt_window = g_strdup(settings_get_str("prompt_window"));

	special_vars_add_signals(prompt, 4, funcs);
	special_vars_add_signals(prompt_window, 4, funcs);

	if (active_win != NULL) window_update_prompt();
}

void gui_windows_init(void)
{
	settings_add_int("lookandfeel", "indent", 10);
	settings_add_str("lookandfeel", "prompt", "[$[.15]T] ");
	settings_add_str("lookandfeel", "prompt_window", "[$winname] ");

        prompt = NULL; prompt_window = NULL;
	window_create_override = -1;
	linecache_tag = g_timeout_add(LINE_CACHE_CHECK_TIME, (GSourceFunc) sig_check_linecache, NULL);

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
	g_source_remove(linecache_tag);
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
