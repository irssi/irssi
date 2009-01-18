/*
 textbuffer-view.c : Text buffer handling

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

#define	G_LOG_DOMAIN "TextBufferView"

#include "module.h"
#include "textbuffer-view.h"
#include "utf8.h"

typedef struct {
	char *name;
        LINE_REC *line;
} BOOKMARK_REC;

/* how often to scan line cache for lines not accessed for a while (ms) */
#define LINE_CACHE_CHECK_TIME (5*60*1000)
/* how long to keep line cache in memory (seconds) */
#define LINE_CACHE_KEEP_TIME (10*60)

static int linecache_tag;
static GSList *views;

#define view_is_bottom(view) \
        ((view)->ypos >= -1 && (view)->ypos < (view)->height)

#define view_get_linecount(view, line) \
        textbuffer_view_get_line_cache(view, line)->count

static GSList *textbuffer_get_views(TEXT_BUFFER_REC *buffer)
{
	GSList *tmp, *list;

	for (tmp = views; tmp != NULL; tmp = tmp->next) {
		TEXT_BUFFER_VIEW_REC *view = tmp->data;

		if (view->buffer == buffer) {
			list = g_slist_copy(view->siblings);
                        return g_slist_prepend(list, view);
		}
	}

        return NULL;
}

static TEXT_BUFFER_CACHE_REC *
textbuffer_cache_get(GSList *views, int width)
{
	TEXT_BUFFER_CACHE_REC *cache;

        /* check if there's existing cache with correct width */
	while (views != NULL) {
		TEXT_BUFFER_VIEW_REC *view = views->data;

		if (view->width == width) {
			view->cache->refcount++;
			return view->cache;
		}
                views = views->next;
	}

        /* create new cache */
	cache = g_new0(TEXT_BUFFER_CACHE_REC, 1);
	cache->refcount = 1;
        cache->width = width;
	cache->line_cache = g_hash_table_new((GHashFunc) g_direct_hash,
					     (GCompareFunc) g_direct_equal);
        return cache;
}

static int line_cache_destroy(void *key, LINE_CACHE_REC *cache)
{
	g_free(cache);
	return TRUE;
}

static void textbuffer_cache_destroy(TEXT_BUFFER_CACHE_REC *cache)
{
	g_hash_table_foreach(cache->line_cache,
			     (GHFunc) line_cache_destroy, NULL);
	g_hash_table_destroy(cache->line_cache);
        g_free(cache);
}

static void textbuffer_cache_unref(TEXT_BUFFER_CACHE_REC *cache)
{
	if (--cache->refcount == 0)
                textbuffer_cache_destroy(cache);
}

#define FGATTR (ATTR_NOCOLORS | ATTR_RESETFG | 0x0f)
#define BGATTR (ATTR_NOCOLORS | ATTR_RESETBG | 0xf0)

static void update_cmd_color(unsigned char cmd, int *color)
{
	if ((cmd & 0x80) == 0) {
		if (cmd & LINE_COLOR_BG) {
			/* set background color */
			*color &= FGATTR;
			if ((cmd & LINE_COLOR_DEFAULT) == 0)
				*color |= (cmd & 0x0f) << 4;
			else {
				*color = (*color & FGATTR) | ATTR_RESETBG;
			}
		} else {
			/* set foreground color */
			*color &= BGATTR;
			if ((cmd & LINE_COLOR_DEFAULT) == 0)
				*color |= cmd & 0x0f;
			else {
				*color = (*color & BGATTR) | ATTR_RESETFG;
			}
		}
	} else switch (cmd) {
	case LINE_CMD_UNDERLINE:
		*color ^= ATTR_UNDERLINE;
		break;
	case LINE_CMD_REVERSE:
		*color ^= ATTR_REVERSE;
		break;
	case LINE_CMD_BLINK:
		*color ^= ATTR_BLINK;
		break;
	case LINE_CMD_BOLD:
		*color ^= ATTR_BOLD;
		break;
	case LINE_CMD_COLOR0:
		*color &= BGATTR;
		break;
	}
}

static inline unichar read_unichar(const unsigned char *data, const unsigned char **next, int *width)
{
	unichar chr = g_utf8_get_char_validated(data, -1);

	if (chr & 0x80000000) {
		chr = 0xfffd;
		*next = data + 1;
		*width = 1;
	} else {
		*next = g_utf8_next_char(data);
		*width = unichar_isprint(chr) ? mk_wcwidth(chr) : 1;
	}
	return chr;
}

static LINE_CACHE_REC *
view_update_line_cache(TEXT_BUFFER_VIEW_REC *view, LINE_REC *line)
{
        INDENT_FUNC indent_func;
	LINE_CACHE_REC *rec;
	LINE_CACHE_SUB_REC *sub;
	GSList *lines;
        unsigned char cmd;
	const unsigned char *ptr, *next_ptr, *last_space_ptr;
	int xpos, pos, indent_pos, last_space, last_color, color, linecount;
	int char_width;

	g_return_val_if_fail(line->text != NULL, NULL);

	color = ATTR_RESETFG | ATTR_RESETBG;
	xpos = 0; indent_pos = view->default_indent;
	last_space = last_color = 0; last_space_ptr = NULL; sub = NULL;

        indent_func = view->default_indent_func;
        linecount = 1;
	lines = NULL;
	for (ptr = line->text;;) {
		if (*ptr == '\0') {
			/* command */
			ptr++;
			cmd = *ptr;
                        ptr++;

			if (cmd == LINE_CMD_EOL)
				break;

			if (cmd == LINE_CMD_CONTINUE) {
				unsigned char *tmp;

				memcpy(&tmp, ptr, sizeof(char *));
				ptr = tmp;
				continue;
			}

			if (cmd == LINE_CMD_INDENT) {
				/* set indentation position here - don't do
				   it if we're too close to right border */
				if (xpos < view->width-5) indent_pos = xpos;
			} else
				update_cmd_color(cmd, &color);
			continue;
		}

		if (!view->utf8) {
			/* MH */
			if (term_type != TERM_TYPE_BIG5 ||
			    ptr[1] == '\0' || !is_big5(ptr[0], ptr[1]))
				char_width = 1;
			else
				char_width = 2;
			next_ptr = ptr+char_width;
		} else {
			read_unichar(ptr, &next_ptr, &char_width);
		}

		if (xpos + char_width > view->width && sub != NULL &&
		    (last_space <= indent_pos || last_space <= 10) &&
		    view->longword_noindent) {
                        /* long word, remove the indentation from this line */
			xpos -= sub->indent;
                        sub->indent = 0;
		}

		if (xpos + char_width > view->width) {
			xpos = indent_func == NULL ? indent_pos :
				indent_func(view, line, -1);

			sub = g_new0(LINE_CACHE_SUB_REC, 1);
			if (last_space > indent_pos && last_space > 10) {
                                /* go back to last space */
                                color = last_color;
				ptr = last_space_ptr;
				while (*ptr == ' ') ptr++;
			} else if (view->longword_noindent) {
				/* long word, no indentation in next line */
				xpos = 0;
				sub->continues = TRUE;
			}

			sub->start = ptr;
			sub->indent = xpos;
                        sub->indent_func = indent_func;
			sub->color = color;

			lines = g_slist_append(lines, sub);
			linecount++;

			last_space = 0;
			continue;
		}

		if (!view->utf8 && char_width > 1) {
			last_space = xpos;
			last_space_ptr = next_ptr;
			last_color = color;
		} else if (*ptr == ' ') {
			last_space = xpos;
			last_space_ptr = ptr;
			last_color = color;
		}

		xpos += char_width;
		ptr = next_ptr;
	}

	rec = g_malloc(sizeof(LINE_CACHE_REC)-sizeof(LINE_CACHE_SUB_REC) +
		       sizeof(LINE_CACHE_SUB_REC) * (linecount-1));
	rec->last_access = time(NULL);
	rec->count = linecount;

	if (rec->count > 1) {
		for (pos = 0; lines != NULL; pos++) {
			void *data = lines->data;

			memcpy(&rec->lines[pos], data,
			       sizeof(LINE_CACHE_SUB_REC));

			lines = g_slist_remove(lines, data);
			g_free(data);
		}
	}

	g_hash_table_insert(view->cache->line_cache, line, rec);
	return rec;
}

static void view_remove_cache(TEXT_BUFFER_VIEW_REC *view, LINE_REC *line,
			      unsigned char update_counter)
{
	LINE_CACHE_REC *cache;

	if (view->cache->update_counter == update_counter)
		return;
	view->cache->update_counter = update_counter;

	cache = g_hash_table_lookup(view->cache->line_cache, line);
	if (cache != NULL) {
                g_free(cache);
		g_hash_table_remove(view->cache->line_cache, line);
	}
}

static void view_update_cache(TEXT_BUFFER_VIEW_REC *view, LINE_REC *line,
			      unsigned char update_counter)
{
	view_remove_cache(view, line, update_counter);

	if (view->buffer->cur_line == line)
		view->cache->last_linecount = view_get_linecount(view, line);
}

static void view_reset_cache(TEXT_BUFFER_VIEW_REC *view)
{
	GSList *tmp;

	/* destroy line caches - note that you can't do simultaneously
	   unrefs + cache_get()s or it will keep using the old caches */
	textbuffer_cache_unref(view->cache);
        g_slist_foreach(view->siblings, (GFunc) textbuffer_cache_unref, NULL);

	view->cache = textbuffer_cache_get(view->siblings, view->width);
	for (tmp = view->siblings; tmp != NULL; tmp = tmp->next) {
		TEXT_BUFFER_VIEW_REC *rec = tmp->data;

		rec->cache = textbuffer_cache_get(rec->siblings, rec->width);
	}
}

static int view_line_draw(TEXT_BUFFER_VIEW_REC *view, LINE_REC *line,
			  int subline, int ypos, int max)
{
        INDENT_FUNC indent_func;
	LINE_CACHE_REC *cache;
        const unsigned char *text, *end, *text_newline;
	unsigned char *tmp;
	unichar chr;
	int xpos, color, drawcount, first, need_move, need_clrtoeol, char_width;

	if (view->dirty) /* don't bother drawing anything - redraw is coming */
                return 0;

	cache = textbuffer_view_get_line_cache(view, line);
	if (subline >= cache->count)
                return 0;

        color = ATTR_RESET;
        need_move = TRUE; need_clrtoeol = FALSE;
	xpos = drawcount = 0; first = TRUE;
	text_newline = text =
		subline == 0 ? line->text : cache->lines[subline-1].start;
	for (;;) {
		if (text == text_newline) {
			if (need_clrtoeol && xpos < term_width) {
				term_set_color(view->window, ATTR_RESET);
				term_clrtoeol(view->window);
			}

			if (first)
				first = FALSE;
			else {
				ypos++;
                                if (--max == 0)
					break;
			}

			if (subline > 0) {
                                /* continuing previous line - indent it */
				indent_func = cache->lines[subline-1].indent_func;
				if (indent_func == NULL)
					xpos = cache->lines[subline-1].indent;
                                color = cache->lines[subline-1].color;
			} else {
				indent_func = NULL;
			}

			if (xpos == 0 && indent_func == NULL)
                                need_clrtoeol = TRUE;
			else {
				/* line was indented - need to clear the
                                   indented area first */
				term_set_color(view->window, ATTR_RESET);
				term_move(view->window, 0, ypos);
				term_clrtoeol(view->window);

				if (indent_func != NULL)
					xpos = indent_func(view, line, ypos);
			}

			if (need_move || xpos > 0)
				term_move(view->window, xpos, ypos);

			term_set_color(view->window, color);

			if (subline == cache->count-1) {
				text_newline = NULL;
				need_move = FALSE;
			} else {
				/* get the beginning of the next subline */
				text_newline = cache->lines[subline].start;
				need_move = !cache->lines[subline].continues;
			}
                        drawcount++;
			subline++;
		}

		if (*text == '\0') {
			/* command */
			text++;
			if (*text == LINE_CMD_EOL)
                                break;

			if (*text == LINE_CMD_CONTINUE) {
                                /* jump to next block */
				memcpy(&tmp, text+1, sizeof(unsigned char *));
				text = tmp;
				continue;
			} else {
				update_cmd_color(*text, &color);
				term_set_color(view->window, color);
			}
			text++;
			continue;
		}

		if (view->utf8) {
			chr = read_unichar(text, &end, &char_width);
		} else {
			chr = *text;
			end = text;
			if (term_type == TERM_TYPE_BIG5 &&
			    is_big5(end[0], end[1]))
				char_width = 2;
			else
				char_width = 1;
			end += char_width;
		}

		xpos += char_width;
		if (xpos <= term_width) {
			if (unichar_isprint(chr)) {
				if (view->utf8)
				term_add_unichar(view->window, chr);
				else
				for (; text < end; text++)
					term_addch(view->window, *text);
			} else {
				/* low-ascii */
				term_set_color(view->window, ATTR_RESET|ATTR_REVERSE);
				term_addch(view->window, (chr & 127)+'A'-1);
				term_set_color(view->window, color);
			}
		}
		text = end;
	}

	if (need_clrtoeol && xpos < term_width) {
		term_set_color(view->window, ATTR_RESET);
		term_clrtoeol(view->window);
	}

        return drawcount;
}

/* Recalculate view's bottom line information - try to keep the
   original if possible */
static void textbuffer_view_init_bottom(TEXT_BUFFER_VIEW_REC *view)
{
        LINE_REC *line;
        int linecount, total;

	if (view->empty_linecount == 0) {
		/* no empty lines in screen, no need to try to keep
		   the old bottom startline */
                view->bottom_startline = NULL;
	}

	total = 0;
        line = textbuffer_line_last(view->buffer);
	for (; line != NULL; line = line->prev) {
		linecount = view_get_linecount(view, line);
		if (line == view->bottom_startline) {
			/* keep the old one, make sure that subline is ok */
			if (view->bottom_subline > linecount)
				view->bottom_subline = linecount;
			view->empty_linecount = view->height - total -
				(linecount-view->bottom_subline);
                        return;
		}

                total += linecount;
		if (total >= view->height) {
			view->bottom_startline = line;
			view->bottom_subline = total - view->height;
                        view->empty_linecount = 0;
                        return;
		}
	}

        /* not enough lines so we must be at the beginning of the buffer */
	view->bottom_startline = view->buffer->first_line;
	view->bottom_subline = 0;
	view->empty_linecount = view->height - total;
}

static void textbuffer_view_init_ypos(TEXT_BUFFER_VIEW_REC *view)
{
        LINE_REC *line;

	g_return_if_fail(view != NULL);

	view->ypos = -view->subline-1;
	for (line = view->startline; line != NULL; line = line->next)
		view->ypos += view_get_linecount(view, line);
}

/* Create new view. */
TEXT_BUFFER_VIEW_REC *textbuffer_view_create(TEXT_BUFFER_REC *buffer,
					     int width, int height,
					     int scroll, int utf8)
{
	TEXT_BUFFER_VIEW_REC *view;

        g_return_val_if_fail(buffer != NULL, NULL);
        g_return_val_if_fail(width > 0, NULL);

	view = g_new0(TEXT_BUFFER_VIEW_REC, 1);
	view->buffer = buffer;
        view->siblings = textbuffer_get_views(buffer);

	view->width = width;
        view->height = height;
	view->scroll = scroll;
        view->utf8 = utf8;

	view->cache = textbuffer_cache_get(view->siblings, width);
	textbuffer_view_init_bottom(view);

	view->startline = view->bottom_startline;
        view->subline = view->bottom_subline;
	view->bottom = TRUE;

	textbuffer_view_init_ypos(view);

	view->bookmarks = g_hash_table_new((GHashFunc) g_str_hash,
					   (GCompareFunc) g_str_equal);

	views = g_slist_append(views, view);
        return view;
}

/* Destroy the view. */
void textbuffer_view_destroy(TEXT_BUFFER_VIEW_REC *view)
{
	GSList *tmp;

	g_return_if_fail(view != NULL);

	views = g_slist_remove(views, view);

	if (view->siblings == NULL) {
		/* last view for textbuffer, destroy */
                textbuffer_destroy(view->buffer);
	} else {
		/* remove ourself from siblings lists */
		for (tmp = view->siblings; tmp != NULL; tmp = tmp->next) {
			TEXT_BUFFER_VIEW_REC *rec = tmp->data;

			rec->siblings = g_slist_remove(rec->siblings, view);
		}
		g_slist_free(view->siblings);
	}

	g_hash_table_foreach(view->bookmarks, (GHFunc) g_free, NULL);
	g_hash_table_destroy(view->bookmarks);

        textbuffer_cache_unref(view->cache);
	g_free(view);
}

/* Change the default indent position */
void textbuffer_view_set_default_indent(TEXT_BUFFER_VIEW_REC *view,
					int default_indent,
					int longword_noindent,
					INDENT_FUNC indent_func)
{
        if (default_indent != -1)
		view->default_indent = default_indent;
        if (longword_noindent != -1)
		view->longword_noindent = longword_noindent;

	view->default_indent_func = indent_func;
}

static void view_unregister_indent_func(TEXT_BUFFER_VIEW_REC *view,
					INDENT_FUNC indent_func)
{
	if (view->default_indent_func == indent_func)
		view->default_indent_func = NULL;

	/* recreate cache so it won't contain references
	   to the indent function */
	view_reset_cache(view);
	view->cache = textbuffer_cache_get(view->siblings, view->width);
}

void textbuffer_views_unregister_indent_func(INDENT_FUNC indent_func)
{
	g_slist_foreach(views, (GFunc) view_unregister_indent_func,
			(void *) indent_func);
}

void textbuffer_view_set_scroll(TEXT_BUFFER_VIEW_REC *view, int scroll)
{
        view->scroll = scroll;
}

void textbuffer_view_set_utf8(TEXT_BUFFER_VIEW_REC *view, int utf8)
{
        view->utf8 = utf8;
}

static int view_get_linecount_all(TEXT_BUFFER_VIEW_REC *view, LINE_REC *line)
{
	int linecount;

        linecount = 0;
	while (line != NULL) {
		linecount += view_get_linecount(view, line);
                line = line->next;
	}

        return linecount;
}

static void view_draw(TEXT_BUFFER_VIEW_REC *view, LINE_REC *line,
		      int subline, int ypos, int lines, int fill_bottom)
{
	int linecount;

	if (view->dirty) /* don't bother drawing anything - redraw is coming */
                return;

	while (line != NULL && lines > 0) {
                linecount = view_line_draw(view, line, subline, ypos, lines);
		ypos += linecount; lines -= linecount;

		subline = 0;
                line = line->next;
	}

	if (fill_bottom) {
		/* clear the rest of the view */
		term_set_color(view->window, ATTR_RESET);
		while (lines > 0) {
			term_move(view->window, 0, ypos);
			term_clrtoeol(view->window);
			ypos++; lines--;
		}
	}
}

#define view_draw_top(view, lines, fill_bottom) \
	view_draw(view, (view)->startline, (view)->subline, \
		  0, lines, fill_bottom)

static void view_draw_bottom(TEXT_BUFFER_VIEW_REC *view, int lines)
{
	LINE_REC *line;
	int ypos, maxline, subline, linecount;

	maxline = view->height-lines;
	line = view->startline; ypos = -view->subline; subline = 0;
	while (line != NULL && ypos < maxline) {
                linecount = view_get_linecount(view, line);
		ypos += linecount;
		if (ypos > maxline) {
			subline = maxline-(ypos-linecount);
			break;
		}
                line = line->next;
	}

        view_draw(view, line, subline, maxline, lines, TRUE);
}

/* Returns number of lines actually scrolled */
static int view_scroll(TEXT_BUFFER_VIEW_REC *view, LINE_REC **lines,
		       int *subline, int scrollcount, int draw_nonclean)
{
	int linecount, realcount, scroll_visible;

	if (*lines == NULL)
                return 0;

	/* scroll down */
	scroll_visible = lines == &view->startline;

	realcount = -*subline;
	scrollcount += *subline;
        *subline = 0;
	while (scrollcount > 0) {
		linecount = view_get_linecount(view, *lines);

		if ((scroll_visible && *lines == view->bottom_startline) &&
		    (scrollcount >= view->bottom_subline)) {
			*subline = view->bottom_subline;
                        realcount += view->bottom_subline;
                        scrollcount = 0;
                        break;
		}

                realcount += linecount;
		scrollcount -= linecount;
		if (scrollcount < 0) {
                        realcount += scrollcount;
			*subline = linecount+scrollcount;
                        scrollcount = 0;
                        break;
		}

		if ((*lines)->next == NULL)
			break;

                *lines = (*lines)->next;
	}

        /* scroll up */
	while (scrollcount < 0 && (*lines)->prev != NULL) {
		*lines = (*lines)->prev;
		linecount = view_get_linecount(view, *lines);

                realcount -= linecount;
		scrollcount += linecount;
		if (scrollcount > 0) {
                        realcount += scrollcount;
			*subline = scrollcount;
                        break;
		}
	}

	if (scroll_visible && realcount != 0 && view->window != NULL) {
		if (realcount <= -view->height || realcount >= view->height) {
			/* scrolled more than screenful, redraw the
			   whole view */
                        textbuffer_view_redraw(view);
		} else {
			term_set_color(view->window, ATTR_RESET);
			term_window_scroll(view->window, realcount);

			if (draw_nonclean) {
				if (realcount < 0)
                                        view_draw_top(view, -realcount, TRUE);
				else
					view_draw_bottom(view, realcount);
			}

			term_refresh(view->window);
		}
	}

	return realcount >= 0 ? realcount : -realcount;
}

/* Resize the view. */
void textbuffer_view_resize(TEXT_BUFFER_VIEW_REC *view, int width, int height)
{
	int linecount;

        g_return_if_fail(view != NULL);
        g_return_if_fail(width > 0);

	if (view->width != width) {
                /* line cache needs to be recreated */
		textbuffer_cache_unref(view->cache);
		view->cache = textbuffer_cache_get(view->siblings, width);
	}

	view->width = width > 10 ? width : 10;
	view->height = height > 1 ? height : 1;

	if (view->buffer->first_line == NULL) {
                view->empty_linecount = height;
		return;
	}

	textbuffer_view_init_bottom(view);

	/* check that we didn't scroll lower than bottom startline.. */
	if (textbuffer_line_exists_after(view->bottom_startline->next,
					 view->startline)) {
		view->startline = view->bottom_startline;
                view->subline = view->bottom_subline;
	} else if (view->startline == view->bottom_startline &&
		   view->subline > view->bottom_subline) {
                view->subline = view->bottom_subline;
	} else {
		/* make sure the subline is still in allowed range */
		linecount = view_get_linecount(view, view->startline);
		if (view->subline > linecount)
                        view->subline = linecount;
	}

	textbuffer_view_init_ypos(view);
	if (view->bottom && !view_is_bottom(view)) {
		/* we scrolled to far up, need to get down. go right over
		   the empty lines if there's any */
		view->startline = view->bottom_startline;
		view->subline = view->bottom_subline;
		if (view->empty_linecount > 0) {
			view_scroll(view, &view->startline, &view->subline,
				    -view->empty_linecount, FALSE);
		}
		textbuffer_view_init_ypos(view);
	}

	view->bottom = view_is_bottom(view);
	if (view->bottom) {
		/* check if we left empty space at the bottom.. */
		linecount = view_get_linecount_all(view, view->startline) -
			view->subline;
                if (view->empty_linecount < view->height-linecount)
			view->empty_linecount = view->height-linecount;
                view->more_text = FALSE;
	}

	view->dirty = TRUE;
}

/* Clear the view, don't actually remove any lines from buffer. */
void textbuffer_view_clear(TEXT_BUFFER_VIEW_REC *view)
{
        g_return_if_fail(view != NULL);

	view->ypos = -1;
	view->bottom_startline = view->startline =
		textbuffer_line_last(view->buffer);
	view->bottom_subline = view->subline =
		view->buffer->cur_line == NULL ? 0 :
		view_get_linecount(view, view->buffer->cur_line);
	view->empty_linecount = view->height;
	view->bottom = TRUE;
	view->more_text = FALSE;

        textbuffer_view_redraw(view);
}

/* Scroll the view up/down */
void textbuffer_view_scroll(TEXT_BUFFER_VIEW_REC *view, int lines)
{
	int count;

        g_return_if_fail(view != NULL);

	count = view_scroll(view, &view->startline, &view->subline,
			    lines, TRUE);
	view->ypos += lines < 0 ? count : -count;
	view->bottom = view_is_bottom(view);
        if (view->bottom) view->more_text = FALSE;

        if (view->window != NULL)
		term_refresh(view->window);
}

/* Scroll to specified line */
void textbuffer_view_scroll_line(TEXT_BUFFER_VIEW_REC *view, LINE_REC *line)
{
        g_return_if_fail(view != NULL);

	if (textbuffer_line_exists_after(view->bottom_startline->next, line)) {
		view->startline = view->bottom_startline;
		view->subline = view->bottom_subline;
	} else {
		view->startline = line;
                view->subline = 0;
	}

	textbuffer_view_init_ypos(view);
	view->bottom = view_is_bottom(view);
        if (view->bottom) view->more_text = FALSE;

	textbuffer_view_redraw(view);
}

/* Return line cache */
LINE_CACHE_REC *textbuffer_view_get_line_cache(TEXT_BUFFER_VIEW_REC *view,
					       LINE_REC *line)
{
	LINE_CACHE_REC *cache;

        g_assert(view != NULL);
        g_assert(line != NULL);

	cache = g_hash_table_lookup(view->cache->line_cache, line);
	if (cache == NULL)
		cache = view_update_line_cache(view, line);
        else
		cache->last_access = time(NULL);

        return cache;
}

static void view_insert_line(TEXT_BUFFER_VIEW_REC *view, LINE_REC *line)
{
	int linecount, ypos, subline;

        if (!view->bottom)
		view->more_text = TRUE;

	if (view->bottom_startline == NULL) {
		view->startline = view->bottom_startline =
			view->buffer->first_line;
	}

	if (view->buffer->cur_line != line &&
	    !textbuffer_line_exists_after(view->bottom_startline, line))
		return;

	linecount = view->cache->last_linecount;
	view->ypos += linecount;
	if (view->empty_linecount > 0) {
		view->empty_linecount -= linecount;
		if (view->empty_linecount >= 0)
			linecount = 0;
		else {
			linecount = -view->empty_linecount;
			view->empty_linecount = 0;
		}
	}

	if (linecount > 0) {
		view_scroll(view, &view->bottom_startline,
			    &view->bottom_subline, linecount, FALSE);
	}

	if (view->bottom) {
		if (view->scroll && view->ypos >= view->height) {
			linecount = view->ypos-view->height+1;
			view_scroll(view, &view->startline,
				    &view->subline, linecount, FALSE);
			view->ypos -= linecount;
		} else {
			view->bottom = view_is_bottom(view);
		}

		if (view->window != NULL) {
			ypos = view->ypos+1 - view->cache->last_linecount;
			if (ypos >= 0)
				subline = 0;
			else {
				subline = -ypos;
				ypos = 0;
			}
			if (ypos < view->height) {
				view_line_draw(view, line, subline, ypos,
					       view->height - ypos);
			}
		}
	}

        if (view->window != NULL)
		term_refresh(view->window);
}

/* Update some line in the buffer which has been modified using
   textbuffer_append() or textbuffer_insert(). */
void textbuffer_view_insert_line(TEXT_BUFFER_VIEW_REC *view, LINE_REC *line)
{
        GSList *tmp;
	unsigned char update_counter;

	g_return_if_fail(view != NULL);
	g_return_if_fail(line != NULL);

	if (!view->buffer->last_eol)
                return;

        update_counter = view->cache->update_counter+1;
	view_update_cache(view, line, update_counter);
        view_insert_line(view, line);

	for (tmp = view->siblings; tmp != NULL; tmp = tmp->next) {
		TEXT_BUFFER_VIEW_REC *rec = tmp->data;

                view_update_cache(rec, line, update_counter);
		view_insert_line(rec, line);
	}
}

typedef struct {
	LINE_REC *remove_line;
        GSList *remove_list;
} BOOKMARK_FIND_REC;

static void bookmark_check_remove(char *key, LINE_REC *line,
				  BOOKMARK_FIND_REC *rec)
{
	if (line == rec->remove_line)
                rec->remove_list = g_slist_append(rec->remove_list, key);
}

static void view_bookmarks_check(TEXT_BUFFER_VIEW_REC *view, LINE_REC *line)
{
        BOOKMARK_FIND_REC rec;
	GSList *tmp;

        rec.remove_line = line;
        rec.remove_list = NULL;
	g_hash_table_foreach(view->bookmarks,
			     (GHFunc) bookmark_check_remove, &rec);

	if (rec.remove_list != NULL) {
		for (tmp = rec.remove_list; tmp != NULL; tmp = tmp->next) {
			g_hash_table_remove(view->bookmarks, tmp->data);
			g_free(tmp->data);
		}
		g_slist_free(rec.remove_list);
	}
}

/* Return number of real lines `lines' list takes -
   stops counting when the height reaches the view height */
static int view_get_lines_height(TEXT_BUFFER_VIEW_REC *view,
				 LINE_REC *line, int subline,
				 LINE_REC *skip_line)
{
	int height, linecount;

        height = -subline;
	while (line != NULL && height < view->height) {
		if (line != skip_line) {
                        linecount = view_get_linecount(view, line);
			height += linecount;
		}
                line = line->next;
	}

	return height < view->height ? height : view->height;
}

static void view_remove_line_update_startline(TEXT_BUFFER_VIEW_REC *view,
					      LINE_REC *line, int linecount)
{
	int scroll;

	if (view->startline == line) {
		view->startline = view->startline->prev != NULL ?
			view->startline->prev : view->startline->next;
		view->subline = 0;
	} else {
		scroll = view->height -
			view_get_lines_height(view, view->startline,
					      view->subline, line);
		if (scroll > 0) {
			view_scroll(view, &view->startline,
				    &view->subline, -scroll, FALSE);
		}
	}

	/* FIXME: this is slow and unnecessary, but it's easy and
	   really works :) */
	textbuffer_view_init_ypos(view);
	if (textbuffer_line_exists_after(view->startline, line))
		view->ypos -= linecount;
}

static void view_remove_line(TEXT_BUFFER_VIEW_REC *view, LINE_REC *line,
			     int linecount)
{
	int realcount;

	view_bookmarks_check(view, line);

	if (view->buffer->cur_line == line) {
                /* the last line is being removed */
		LINE_REC *prevline;

		prevline = view->buffer->first_line == line ? NULL :
			textbuffer_line_last(view->buffer);
		view->cache->last_linecount = prevline == NULL ? 0 :
			view_get_linecount(view, prevline);
	}

	if (view->buffer->first_line == line) {
		/* first line in the buffer - this is the most commonly
		   removed line.. */
		if (view->bottom_startline == line) {
			/* very small scrollback.. */
                        view->bottom_startline = view->bottom_startline->next;
			view->bottom_subline = 0;
		}

		if (view->startline == line) {
                        /* removing the first line in screen */
			int is_last = view->startline->next == NULL;

			realcount = view_scroll(view, &view->startline,
						&view->subline,
						linecount, FALSE);
			view->ypos -= realcount;
			view->empty_linecount += linecount-realcount;
			if (is_last == 1)
				view->startline = NULL;
		}
	} else {
		if (textbuffer_line_exists_after(view->bottom_startline,
						 line)) {
			realcount = view_scroll(view, &view->bottom_startline,
						&view->bottom_subline,
						-linecount, FALSE);
			view->empty_linecount += linecount-realcount;
		}

		if (textbuffer_line_exists_after(view->startline,
						 line)) {
			view_remove_line_update_startline(view, line,
							  linecount);
		}
	}

	view->bottom = view_is_bottom(view);
        if (view->bottom) view->more_text = FALSE;
        if (view->window != NULL)
		term_refresh(view->window);
}

/* Remove one line from buffer. */
void textbuffer_view_remove_line(TEXT_BUFFER_VIEW_REC *view, LINE_REC *line)
{
        GSList *tmp;
	unsigned char update_counter;
        int linecount;

	g_return_if_fail(view != NULL);
	g_return_if_fail(line != NULL);

        linecount = view_get_linecount(view, line);
        update_counter = view->cache->update_counter+1;

        view_remove_line(view, line, linecount);
	view_remove_cache(view, line, update_counter);

	for (tmp = view->siblings; tmp != NULL; tmp = tmp->next) {
		TEXT_BUFFER_VIEW_REC *rec = tmp->data;

		view_remove_line(rec, line, linecount);
		view_remove_cache(rec, line, update_counter);
	}

	textbuffer_remove(view->buffer, line);
}

void textbuffer_view_remove_lines_by_level(TEXT_BUFFER_VIEW_REC *view, int level)
{
	LINE_REC *line, *next;
	
	term_refresh_freeze();
	line = textbuffer_view_get_lines(view);

	while (line != NULL) {
		next = line->next;

		if (line->info.level & level)
			textbuffer_view_remove_line(view, line);
		line = next;
	}
	textbuffer_view_redraw(view);
	term_refresh_thaw();
}

static int g_free_true(void *data)
{
	g_free(data);
        return TRUE;
}

/* Remove all lines from buffer. */
void textbuffer_view_remove_all_lines(TEXT_BUFFER_VIEW_REC *view)
{
	g_return_if_fail(view != NULL);

	textbuffer_remove_all_lines(view->buffer);

	g_hash_table_foreach_remove(view->bookmarks,
				    (GHRFunc) g_free_true, NULL);

	view_reset_cache(view);
	textbuffer_view_clear(view);
	g_slist_foreach(view->siblings, (GFunc) textbuffer_view_clear, NULL);
}

/* Set a bookmark in view */
void textbuffer_view_set_bookmark(TEXT_BUFFER_VIEW_REC *view,
				  const char *name, LINE_REC *line)
{
	gpointer key, value;

	g_return_if_fail(view != NULL);
	g_return_if_fail(name != NULL);

	if (g_hash_table_lookup_extended(view->bookmarks, name,
					 &key, &value)) {
		g_hash_table_remove(view->bookmarks, key);
                g_free(key);
	}

	g_hash_table_insert(view->bookmarks, g_strdup(name), line);
}

/* Set a bookmark in view to the bottom line */
void textbuffer_view_set_bookmark_bottom(TEXT_BUFFER_VIEW_REC *view,
					 const char *name)
{
	LINE_REC *line;

	g_return_if_fail(view != NULL);
	g_return_if_fail(name != NULL);

	if (view->bottom_startline != NULL) {
                line = textbuffer_line_last(view->buffer);
		textbuffer_view_set_bookmark(view, name, line);
	}
}

/* Return the line for bookmark */
LINE_REC *textbuffer_view_get_bookmark(TEXT_BUFFER_VIEW_REC *view,
				       const char *name)
{
	g_return_val_if_fail(view != NULL, NULL);
	g_return_val_if_fail(name != NULL, NULL);

        return g_hash_table_lookup(view->bookmarks, name);
}

/* Specify window where the changes in view should be drawn,
   NULL disables it. */
void textbuffer_view_set_window(TEXT_BUFFER_VIEW_REC *view,
				TERM_WINDOW *window)
{
	g_return_if_fail(view != NULL);

	if (view->window != window) {
		view->window = window;
                if (window != NULL)
			view->dirty = TRUE;
	}
}

/* Redraw a view to window */
void textbuffer_view_redraw(TEXT_BUFFER_VIEW_REC *view)
{
	g_return_if_fail(view != NULL);

	if (view->window != NULL) {
		view->dirty = FALSE;
		view_draw_top(view, view->height, TRUE);
		term_refresh(view->window);
	}
}

static int line_cache_check_remove(void *key, LINE_CACHE_REC *cache,
				   time_t *now)
{
	if (cache->last_access+LINE_CACHE_KEEP_TIME > *now)
		return FALSE;

	line_cache_destroy(NULL, cache);
	return TRUE;
}

static int sig_check_linecache(void)
{
	GSList *tmp, *caches;
        time_t now;

        now = time(NULL); caches = NULL;
	for (tmp = views; tmp != NULL; tmp = tmp->next) {
		TEXT_BUFFER_VIEW_REC *rec = tmp->data;

		if (g_slist_find(caches, rec->cache) != NULL)
			continue;

		caches = g_slist_append(caches, rec->cache);
		g_hash_table_foreach_remove(rec->cache->line_cache,
					    (GHRFunc) line_cache_check_remove,
					    &now);
	}

        g_slist_free(caches);
	return 1;
}

void textbuffer_view_init(void)
{
	linecache_tag = g_timeout_add(LINE_CACHE_CHECK_TIME, (GSourceFunc) sig_check_linecache, NULL);
}

void textbuffer_view_deinit(void)
{
	g_source_remove(linecache_tag);
}
