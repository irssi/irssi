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
	char *buf, *ptr, **pptr;

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
		memcpy(buf, pptr, sizeof(char *));
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
        unsigned char *tmp = NULL;

	for (text = line->text;; text++) {
		if (*text != '\0')
                        continue;

		text++;
		if (*text == LINE_CMD_CONTINUE || *text == LINE_CMD_EOL) {
			if (*text == LINE_CMD_CONTINUE)
				memcpy(&tmp, text+1, sizeof(char *));

			/* free the previous block */
			chunk = text_chunk_find(buffer, text);
			if (--chunk->refcount == 0) {
				if (buffer->cur_text == chunk)
					chunk->pos = 0;
				else
					text_chunk_destroy(buffer, chunk);
			}

			if (*text == LINE_CMD_EOL)
				break;

			text = tmp-1;
		}
	}
}

static void text_chunk_append(TEXT_BUFFER_REC *buffer,
			      const char *data, int len)
{
        TEXT_CHUNK_REC *chunk;
	int left;

	if (len == 0)
                return;

        chunk = buffer->cur_text;
	while (chunk->pos + len >= TEXT_CHUNK_USABLE_SIZE) {
		left = TEXT_CHUNK_USABLE_SIZE - chunk->pos;
		if (data[left-1] == 0) left--; /* don't split the commands */

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
	if (prev == buffer->cur_line) {
		buffer->cur_line = line;
		buffer->lines = g_list_append(buffer->lines, buffer->cur_line);
	} else {
		buffer->lines = g_list_insert(buffer->lines, line,
					      g_list_index(buffer->lines, prev)+1);
	}
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
                textbuffer_line_unref(buffer, list->data);
                list = list->next;
	}
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

	buffer->lines = g_list_remove(buffer->lines, line);

	if (buffer->cur_line == line) {
		buffer->cur_line = buffer->lines == NULL ? NULL :
			g_list_last(buffer->lines)->data;
	}

	buffer->lines_count--;
        textbuffer_line_unref(buffer, line);
}

/* Removes all lines from buffer, ignoring reference counters */
void textbuffer_remove_all_lines(TEXT_BUFFER_REC *buffer)
{
	GSList *tmp;

	g_return_if_fail(buffer != NULL);

	for (tmp = buffer->text_chunks; tmp != NULL; tmp = tmp->next)
                g_mem_chunk_free(text_chunk, tmp->data);
	g_slist_free(buffer->text_chunks);
        buffer->text_chunks = NULL;

	g_list_free(buffer->lines);
        buffer->lines = NULL;

        buffer->cur_line = NULL;
	buffer->lines_count = 0;
}

void textbuffer_line2text(LINE_REC *line, int coloring, GString *str)
{
        unsigned char cmd;
	char *ptr, *tmp;

	g_return_if_fail(line != NULL);
	g_return_if_fail(str != NULL);

        g_string_truncate(str, 0);

	for (ptr = line->text;;) {
		if (*ptr != 0) {
			g_string_append_c(str, *ptr);
                        ptr++;
			continue;
		}

		ptr++;
                cmd = (unsigned char) *ptr;
		ptr++;

		if (cmd == LINE_CMD_EOL || cmd == LINE_CMD_FORMAT) {
                        /* end of line */
			break;
		}

		if (cmd == LINE_CMD_CONTINUE) {
                        /* line continues in another address.. */
			memcpy(&tmp, ptr, sizeof(char *));
			ptr = tmp;
                        continue;
		}

		if (!coloring) {
			/* no colors, skip coloring commands */
                        continue;
		}

		if ((cmd & 0x80) == 0) {
			/* set color */
			g_string_sprintfa(str, "\004%c%c",
					  (cmd & 0x0f)+'0',
					  ((cmd & 0xf0) >> 4)+'0');
		} else switch (cmd) {
		case LINE_CMD_UNDERLINE:
			g_string_append_c(str, 31);
			break;
		case LINE_CMD_COLOR0:
			g_string_sprintfa(str, "\004%c%c",
					  '0', FORMAT_COLOR_NOCHANGE);
			break;
		case LINE_CMD_COLOR8:
			g_string_sprintfa(str, "\004%c%c",
					  '8', FORMAT_COLOR_NOCHANGE);
			break;
		case LINE_CMD_BLINK:
			g_string_sprintfa(str, "\004%c", FORMAT_STYLE_BLINK);
			break;
		case LINE_CMD_INDENT:
			break;
		}
	}
}

GList *textbuffer_find_text(TEXT_BUFFER_REC *buffer, LINE_REC *startline,
			    int level, int nolevel, const char *text,
			    int regexp, int fullword, int case_sensitive)
{
#ifdef HAVE_REGEX_H
	regex_t preg;
#endif
	GList *line, *tmp;
	GList *matches;
        GString *str;

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

	matches = NULL;
        str = g_string_new(NULL);

        line = g_list_find(buffer->lines, startline);
	if (line == NULL)
		line = buffer->lines;

	for (tmp = line; tmp != NULL; tmp = tmp->next) {
		LINE_REC *rec = tmp->data;

		if ((rec->info.level & level) == 0 ||
		    (rec->info.level & nolevel) != 0)
                        continue;

		if (*text == '\0') {
                        /* no search word, everything matches */
                        textbuffer_line_ref(rec);
			matches = g_list_append(matches, rec);
			continue;
		}

                textbuffer_line2text(rec, FALSE, str);

                if (
#ifdef HAVE_REGEX_H
		    regexp ? regexec(&preg, str->str, 0, NULL, 0) == 0 :
#endif
		    fullword ? strstr_full_case(str->str, text,
						!case_sensitive) != NULL :
		    case_sensitive ? strstr(str->str, text) != NULL :
				     stristr(str->str, text) != NULL) {
			/* matched */
                        textbuffer_line_ref(rec);
			matches = g_list_append(matches, rec);
		}
	}
#ifdef HAVE_REGEX_H
	if (regexp) regfree(&preg);
#endif
        g_string_free(str, TRUE);
	return matches;
}

#if 0 /* FIXME: saving formats is broken */
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

static char *textbuffer_line_get_format(WINDOW_REC *window, LINE_REC *line,
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

void textbuffer_reformat_line(WINDOW_REC *window, LINE_REC *line)
{
	GUI_WINDOW_REC *gui;
	TEXT_DEST_REC dest;
	GString *raw;
	char *str, *tmp, *prestr, *linestart, *leveltag;

	gui = WINDOW_GUI(window);

	raw = g_string_new(NULL);
	str = textbuffer_line_get_format(window, line, raw);

        if (str == NULL && raw->len == 2 &&
            raw->str[1] == (char)LINE_CMD_FORMAT_CONT) {
                /* multiline format, format explained in one the
                   following lines. remove this line. */
                textbuffer_line_remove(window, line, FALSE);
	} else if (str != NULL) {
                /* FIXME: ugly ugly .. and this can't handle
                   non-formatted lines.. */
		g_string_append_c(raw, '\0');
		g_string_append_c(raw, (char)LINE_CMD_EOL);

                textbuffer_line_text_free(gui, line);

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

		textbuffer_line_append(gui, raw->str, raw->len);

		gui->eol_marked = TRUE;
		gui->temp_line = NULL;
	}
	g_string_free(raw, TRUE);
}
#endif

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
