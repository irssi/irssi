/*
 textbuffer.c : Text buffer handling

    Copyright (C) 1999-2001 Timo Sirainen

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

#define	G_LOG_DOMAIN "TextBuffer"

#include "module.h"
#include "misc.h"
#include "formats.h"

#include "textbuffer.h"

#ifdef HAVE_REGEX_H
#  include <regex.h>
#endif

#define TEXT_CHUNK_USABLE_SIZE (LINE_TEXT_CHUNK_SIZE-2-(int)sizeof(char*))

static GMemChunk *buffer_chunk, *line_chunk, *text_chunk;

TEXT_BUFFER_REC *textbuffer_create(void)
{
	TEXT_BUFFER_REC *buffer;

	buffer = g_mem_chunk_alloc0(buffer_chunk);
	buffer->last_eol = TRUE;
        return buffer;
}

void textbuffer_destroy(TEXT_BUFFER_REC *buffer)
{
	g_return_if_fail(buffer != NULL);

	textbuffer_remove_all_lines(buffer);
        g_mem_chunk_free(buffer_chunk, buffer);
}

static TEXT_CHUNK_REC *text_chunk_find(TEXT_BUFFER_REC *buffer,
				       const unsigned char *data)
{
	GSList *tmp;

	for (tmp = buffer->text_chunks; tmp != NULL; tmp = tmp->next) {
		TEXT_CHUNK_REC *rec = tmp->data;

		if (data >= rec->buffer &&
		    data < rec->buffer+sizeof(rec->buffer))
                        return rec;
	}

	return NULL;
}

#define mark_temp_eol(chunk) G_STMT_START { \
	(chunk)->buffer[(chunk)->pos] = 0; \
	(chunk)->buffer[(chunk)->pos+1] = LINE_CMD_EOL; \
	} G_STMT_END

static TEXT_CHUNK_REC *text_chunk_create(TEXT_BUFFER_REC *buffer)
{
	TEXT_CHUNK_REC *rec;
	unsigned char *buf, *ptr, **pptr;

	rec = g_mem_chunk_alloc(text_chunk);
	rec->pos = 0;
	rec->refcount = 0;

	if (buffer->cur_line != NULL && buffer->cur_line->text != NULL) {
		/* create a link to new block from the old block */
		buf = buffer->cur_text->buffer + buffer->cur_text->pos;
		*buf++ = 0; *buf++ = (char) LINE_CMD_CONTINUE;

		/* we want to store pointer to beginning of the new text
		   block to char* buffer. this probably isn't ANSI-C
		   compatible, and trying this without the pptr variable
		   breaks at least NetBSD/Alpha, so don't go "optimize"
		   it :) */
		ptr = rec->buffer; pptr = &ptr;
		memcpy(buf, pptr, sizeof(unsigned char *));
	} else {
		/* just to be safe */
		mark_temp_eol(rec);
	}

	buffer->cur_text = rec;
	buffer->text_chunks = g_slist_append(buffer->text_chunks, rec);
	return rec;
}

static void text_chunk_destroy(TEXT_BUFFER_REC *buffer, TEXT_CHUNK_REC *chunk)
{
	buffer->text_chunks = g_slist_remove(buffer->text_chunks, chunk);
	g_mem_chunk_free(text_chunk, chunk);
}

static void text_chunk_line_free(TEXT_BUFFER_REC *buffer, LINE_REC *line)
{
	TEXT_CHUNK_REC *chunk;
	const unsigned char *text;
        unsigned char cmd, *tmp = NULL;

	for (text = line->text;; text++) {
		if (*text != '\0')
                        continue;

		text++;
		cmd = *text;
		if (cmd == LINE_CMD_CONTINUE || cmd == LINE_CMD_EOL) {
			if (cmd == LINE_CMD_CONTINUE)
				memcpy(&tmp, text+1, sizeof(char *));

			/* free the previous block */
			chunk = text_chunk_find(buffer, text);
			if (--chunk->refcount == 0) {
				if (buffer->cur_text == chunk)
					chunk->pos = 0;
				else
					text_chunk_destroy(buffer, chunk);
			}

			if (cmd == LINE_CMD_EOL)
				break;

			text = tmp-1;
		} else if (cmd == LINE_CMD_INDENT_FUNC) {
			text += sizeof(int (*) ());
		}
	}
}

static void text_chunk_append(TEXT_BUFFER_REC *buffer,
			      const unsigned char *data, int len)
{
        TEXT_CHUNK_REC *chunk;
	int left;

	if (len == 0)
                return;

        chunk = buffer->cur_text;
	while (chunk->pos + len >= TEXT_CHUNK_USABLE_SIZE) {
		left = TEXT_CHUNK_USABLE_SIZE - chunk->pos;
		if (left > 0 && data[left-1] == 0)
			left--; /* don't split the commands */

		memcpy(chunk->buffer + chunk->pos, data, left);
		chunk->pos += left;

		chunk = text_chunk_create(buffer);
		chunk->refcount++;
		len -= left; data += left;
	}

	memcpy(chunk->buffer + chunk->pos, data, len);
	chunk->pos += len;

	mark_temp_eol(chunk);
}

static LINE_REC *textbuffer_line_create(TEXT_BUFFER_REC *buffer)
{
	LINE_REC *rec;

	if (buffer->cur_text == NULL)
                text_chunk_create(buffer);

	rec = g_mem_chunk_alloc(line_chunk);
        rec->refcount = 1;
	rec->text = buffer->cur_text->buffer + buffer->cur_text->pos;

	buffer->cur_text->refcount++;
        return rec;
}

static LINE_REC *textbuffer_line_insert(TEXT_BUFFER_REC *buffer,
					LINE_REC *prev)
{
	LINE_REC *line;

	line = textbuffer_line_create(buffer);
	line->prev = prev;
	if (prev == NULL) {
		line->next = buffer->first_line;
                if (buffer->first_line != NULL)
			buffer->first_line->prev = line;
		buffer->first_line = line;
	} else {
		line->next = prev->next;
                if (line->next != NULL)
			line->next->prev = line;
		prev->next = line;
	}

	if (prev == buffer->cur_line)
		buffer->cur_line = line;
        buffer->lines_count++;

        return line;
}

void textbuffer_line_ref(LINE_REC *line)
{
	g_return_if_fail(line != NULL);

	if (++line->refcount == 255)
                g_error("line reference counter wrapped - shouldn't happen");
}

void textbuffer_line_unref(TEXT_BUFFER_REC *buffer, LINE_REC *line)
{
	g_return_if_fail(buffer != NULL);
	g_return_if_fail(line != NULL);

	if (--line->refcount == 0) {
		text_chunk_line_free(buffer, line);
		g_mem_chunk_free(line_chunk, line);
	}
}

void textbuffer_line_unref_list(TEXT_BUFFER_REC *buffer, GList *list)
{
	g_return_if_fail(buffer != NULL);

	while (list != NULL) {
                if (list->data != NULL)
			textbuffer_line_unref(buffer, list->data);
                list = list->next;
	}
}

LINE_REC *textbuffer_line_last(TEXT_BUFFER_REC *buffer)
{
	LINE_REC *line;

	line = buffer->cur_line;
	if (line != NULL) {
		while (line->next != NULL)
			line = line->next;
	}
        return line;
}

int textbuffer_line_exists_after(LINE_REC *line, LINE_REC *search)
{
	while (line != NULL) {
		if (line == search)
			return TRUE;
                line = line->next;
	}
        return FALSE;
}

LINE_REC *textbuffer_append(TEXT_BUFFER_REC *buffer,
			    const unsigned char *data, int len,
			    LINE_INFO_REC *info)
{
        return textbuffer_insert(buffer, buffer->cur_line, data, len, info);
}

LINE_REC *textbuffer_insert(TEXT_BUFFER_REC *buffer, LINE_REC *insert_after,
			    const unsigned char *data, int len,
			    LINE_INFO_REC *info)
{
	LINE_REC *line;

	g_return_val_if_fail(buffer != NULL, NULL);
	g_return_val_if_fail(data != NULL, NULL);

	if (len == 0)
                return insert_after;

	line = !buffer->last_eol ? insert_after :
		textbuffer_line_insert(buffer, insert_after);

	if (info != NULL)
		memcpy(&line->info, info, sizeof(line->info));

	text_chunk_append(buffer, data, len);

	buffer->last_eol = len >= 2 &&
		data[len-2] == 0 && data[len-1] == LINE_CMD_EOL;

        return line;
}

void textbuffer_remove(TEXT_BUFFER_REC *buffer, LINE_REC *line)
{
	g_return_if_fail(buffer != NULL);
	g_return_if_fail(line != NULL);

	if (buffer->first_line == line)
		buffer->first_line = line->next;
	if (line->prev != NULL)
		line->prev->next = line->next;
	if (line->next != NULL)
		line->next->prev = line->prev;

	if (buffer->cur_line == line) {
		buffer->cur_line = line->next != NULL ?
			line->next : line->prev;
	}

        line->prev = line->next = NULL;

	buffer->lines_count--;
        textbuffer_line_unref(buffer, line);
}

/* Removes all lines from buffer, ignoring reference counters */
void textbuffer_remove_all_lines(TEXT_BUFFER_REC *buffer)
{
	GSList *tmp;
        LINE_REC *line;

	g_return_if_fail(buffer != NULL);

	for (tmp = buffer->text_chunks; tmp != NULL; tmp = tmp->next)
                g_mem_chunk_free(text_chunk, tmp->data);
	g_slist_free(buffer->text_chunks);
	buffer->text_chunks = NULL;

	while (buffer->first_line != NULL) {
		line = buffer->first_line->next;
		g_mem_chunk_free(line_chunk, buffer->first_line);
                buffer->first_line = line;
	}
	buffer->lines_count = 0;

        buffer->cur_line = NULL;
        buffer->cur_text = NULL;

	buffer->last_eol = TRUE;
}

static void set_color(GString *str, int cmd, int *last_fg, int *last_bg)
{
	if (cmd & LINE_COLOR_DEFAULT) {
		g_string_sprintfa(str, "\004%c", FORMAT_STYLE_DEFAULTS);

		/* need to reset the fg/bg color */
		if (cmd & LINE_COLOR_BG) {
                        *last_bg = -1;
			if (*last_fg != -1) {
				g_string_sprintfa(str, "\004%c%c",
						  *last_fg,
						  FORMAT_COLOR_NOCHANGE);
			}
		} else {
                        *last_fg = -1;
			if (*last_bg != -1) {
				g_string_sprintfa(str, "\004%c%c",
						  FORMAT_COLOR_NOCHANGE,
						  *last_bg);
			}
		}
                return;
	}

	if ((cmd & LINE_COLOR_BG) == 0) {
                /* change foreground color */
                *last_fg = (cmd & 0x0f)+'0';
		g_string_sprintfa(str, "\004%c%c", *last_fg,
				  FORMAT_COLOR_NOCHANGE);
	} else {
		/* change background color */
                *last_bg = (cmd & 0x0f)+'0';
		g_string_sprintfa(str, "\004%c%c",
				  FORMAT_COLOR_NOCHANGE, *last_bg);
	}
}

void textbuffer_line2text(LINE_REC *line, int coloring, GString *str)
{
        unsigned char cmd, *ptr, *tmp;
        int last_fg, last_bg;

	g_return_if_fail(line != NULL);
	g_return_if_fail(str != NULL);

        g_string_truncate(str, 0);

        last_fg = last_bg = -1;
	for (ptr = line->text;;) {
		if (*ptr != 0) {
			g_string_append_c(str, (char) *ptr);
                        ptr++;
			continue;
		}

		ptr++;
                cmd = *ptr;
		ptr++;

		if (cmd == LINE_CMD_EOL || cmd == LINE_CMD_FORMAT) {
                        /* end of line */
			break;
		}

		if (cmd == LINE_CMD_CONTINUE) {
                        /* line continues in another address.. */
			memcpy(&tmp, ptr, sizeof(unsigned char *));
			ptr = tmp;
                        continue;
		}

		if (!coloring) {
			/* no colors, skip coloring commands */
                        continue;
		}

		if ((cmd & 0x80) == 0) {
			/* set color */
                        set_color(str, cmd, &last_fg, &last_bg);
		} else switch (cmd) {
		case LINE_CMD_UNDERLINE:
			g_string_append_c(str, 31);
			break;
		case LINE_CMD_REVERSE:
			g_string_append_c(str, 22);
			break;
		case LINE_CMD_COLOR0:
			g_string_sprintfa(str, "\004%c%c",
					  '0', FORMAT_COLOR_NOCHANGE);
			break;
		case LINE_CMD_INDENT:
			break;
		case LINE_CMD_INDENT_FUNC:
                        ptr += sizeof(void *);
			break;
		}
	}
}

GList *textbuffer_find_text(TEXT_BUFFER_REC *buffer, LINE_REC *startline,
			    int level, int nolevel, const char *text,
			    int before, int after,
			    int regexp, int fullword, int case_sensitive)
{
#ifdef HAVE_REGEX_H
	regex_t preg;
#endif
        LINE_REC *line, *pre_line;
	GList *matches;
	GString *str;
        int i, match_after, line_matched;

	g_return_val_if_fail(buffer != NULL, NULL);
	g_return_val_if_fail(text != NULL, NULL);

	if (regexp) {
#ifdef HAVE_REGEX_H
		int flags = REG_EXTENDED | REG_NOSUB |
			(case_sensitive ? 0 : REG_ICASE);
		if (regcomp(&preg, text, flags) != 0)
			return NULL;
#else
		return NULL;
#endif
	}

	matches = NULL; match_after = 0;
        str = g_string_new(NULL);

	line = startline != NULL ? startline : buffer->first_line;

	for (; line != NULL; line = line->next) {
		if ((line->info.level & level) == 0 ||
		    (line->info.level & nolevel) != 0)
                        continue;

		if (*text == '\0') {
                        /* no search word, everything matches */
                        textbuffer_line_ref(line);
			matches = g_list_append(matches, line);
			continue;
		}

                textbuffer_line2text(line, FALSE, str);

		line_matched =
#ifdef HAVE_REGEX_H
			regexp ? regexec(&preg, str->str, 0, NULL, 0) == 0 :
#endif
			fullword ? strstr_full_case(str->str, text, !case_sensitive) != NULL :
			case_sensitive ? strstr(str->str, text) != NULL :
			stristr(str->str, text) != NULL;
		if (line_matched) {
                        /* add the -before lines */
			pre_line = line;
			for (i = 0; i < before; i++) {
				if (pre_line->prev == NULL ||
				    g_list_find(matches, pre_line->prev) != NULL)
					break;
                                pre_line = pre_line->prev;
			}

			for (; pre_line != line; pre_line = pre_line->next) {
				textbuffer_line_ref(pre_line);
				matches = g_list_append(matches, pre_line);
			}

			match_after = after;
		}

		if (line_matched || match_after > 0) {
			/* matched */
                        textbuffer_line_ref(line);
			matches = g_list_append(matches, line);

			if ((!line_matched && --match_after == 0) ||
			    (line_matched && match_after == 0 && before > 0))
				matches = g_list_append(matches, NULL);
		}
	}
#ifdef HAVE_REGEX_H
	if (regexp) regfree(&preg);
#endif
        g_string_free(str, TRUE);
	return matches;
}

void textbuffer_init(void)
{
	buffer_chunk = g_mem_chunk_new("text buffer chunk",
				       sizeof(TEXT_BUFFER_REC),
				       sizeof(TEXT_BUFFER_REC)*32, G_ALLOC_AND_FREE);
	line_chunk = g_mem_chunk_new("line chunk", sizeof(LINE_REC),
				     sizeof(LINE_REC)*1024, G_ALLOC_AND_FREE);
	text_chunk = g_mem_chunk_new("text chunk", sizeof(TEXT_CHUNK_REC),
				     sizeof(TEXT_CHUNK_REC)*32, G_ALLOC_AND_FREE);
}

void textbuffer_deinit(void)
{
	g_mem_chunk_destroy(buffer_chunk);
	g_mem_chunk_destroy(line_chunk);
	g_mem_chunk_destroy(text_chunk);
}
