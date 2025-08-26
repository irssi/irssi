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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#define	G_LOG_DOMAIN "TextBuffer"

#include "module.h"
#include <irssi/src/core/misc.h>
#include <irssi/src/fe-common/core/formats.h>
#include <irssi/src/core/utf8.h>
#include <irssi/src/core/iregex.h>

#include <irssi/src/fe-text/textbuffer-formats.h>
#include <irssi/src/fe-text/textbuffer.h>

#define TEXT_CHUNK_USABLE_SIZE (LINE_TEXT_CHUNK_SIZE-2-(int)sizeof(char*))

TEXT_BUFFER_REC *textbuffer_create(WINDOW_REC *window)
{
	TEXT_BUFFER_REC *buffer;

	buffer = g_slice_new0(TEXT_BUFFER_REC);
	buffer->window = window;
	buffer->last_eol = TRUE;
	buffer->last_fg = -1;
	buffer->last_bg = -1;
	buffer->cur_text = g_string_sized_new(TEXT_CHUNK_USABLE_SIZE);
	return buffer;
}

void textbuffer_destroy(TEXT_BUFFER_REC *buffer)
{
	GSList *tmp;

	g_return_if_fail(buffer != NULL);

	textbuffer_remove_all_lines(buffer);
	g_string_free(buffer->cur_text, TRUE);
	for (tmp = buffer->cur_info; tmp != NULL; tmp = tmp->next) {
		LINE_INFO_REC *info = buffer->cur_info->data;
		textbuffer_line_info_free1(info);
		g_free(info);
	}
	g_slist_free(buffer->cur_info);

	buffer->window = NULL;
	g_slice_free(TEXT_BUFFER_REC, buffer);
}

void textbuffer_line_info_free1(LINE_INFO_REC *info)
{
	textbuffer_format_rec_free(info->format);
	textbuffer_meta_rec_free(info->meta);
	g_free(info->text);
}

static void text_chunk_append(TEXT_BUFFER_REC *buffer,
			      const unsigned char *data, int len)
{
	if (len == 0)
                return;

	/* g_string_append_len(buffer->cur_text, (const char *)data, len); */
	g_string_append(buffer->cur_text, (const char *) data);
}

static LINE_REC *textbuffer_line_create(TEXT_BUFFER_REC *buffer)
{
	LINE_REC *rec;

	rec = g_slice_new0(LINE_REC);
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

LINE_REC *textbuffer_line_last(TEXT_BUFFER_REC *buffer)
{
	return buffer->cur_line;
}

/* returns TRUE if `search' comes on or after `line' in the buffer */
int textbuffer_line_exists_after(LINE_REC *line, LINE_REC *search)
{
	while (line != NULL) {
		if (line == search)
			return TRUE;
                line = line->next;
	}
        return FALSE;
}

void textbuffer_line_add_colors(TEXT_BUFFER_REC *buffer, LINE_REC **line,
				int fg, int bg, int flags)
{
	GString *out = g_string_new(NULL);
	format_gui_flags(out, &buffer->last_fg, &buffer->last_bg, &buffer->last_flags, fg, bg,
	                 flags);

	if (*(out->str) != '\0') {
		*line =
		    textbuffer_insert(buffer, *line, (unsigned char *) out->str, out->len, NULL);
	}
	g_string_free(out, TRUE);
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

	if (buffer->last_eol) {
		if (!line->info.format) {
			line->info.text = g_strdup(buffer->cur_text->str);
			g_string_truncate(buffer->cur_text, 0);
		}

		buffer->last_fg = -1;
		buffer->last_bg = -1;
		buffer->last_flags = 0;
	}

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
		buffer->cur_line = line->prev;
	}

        line->prev = line->next = NULL;

	buffer->lines_count--;
	textbuffer_line_info_free1(&line->info);
	g_slice_free(LINE_REC, line);
}

/* Removes all lines from buffer */
void textbuffer_remove_all_lines(TEXT_BUFFER_REC *buffer)
{
        LINE_REC *line;

	g_return_if_fail(buffer != NULL);

	while (buffer->first_line != NULL) {
		line = buffer->first_line->next;
		textbuffer_line_info_free1(&buffer->first_line->info);
		g_slice_free(LINE_REC, buffer->first_line);
		buffer->first_line = line;
	}
	buffer->lines_count = 0;

        buffer->cur_line = NULL;
	g_string_truncate(buffer->cur_text, 0);

	buffer->last_eol = TRUE;
}

void textbuffer_line2text(TEXT_BUFFER_REC *buffer, LINE_REC *line, int coloring, GString *str)
{
	char *ptr, *tmp;

	g_return_if_fail(line != NULL);
	g_return_if_fail(str != NULL);

	g_string_truncate(str, 0);

	if ((ptr = textbuffer_line_get_text(buffer, line, coloring == COLORING_RAW)) != NULL) {
		if (coloring == COLORING_STRIP) {
			tmp = ptr;
			ptr = strip_codes(tmp);
			g_free(tmp);
		} else if (coloring == COLORING_UNEXPAND) {
			tmp = ptr;
			ptr = format_string_unexpand(tmp, 0);
			g_free(tmp);
		}
		g_string_append(str, ptr);
		g_free(ptr);
	}
}

GList *textbuffer_find_text(TEXT_BUFFER_REC *buffer, LINE_REC *startline,
			    int level, int nolevel, const char *text,
			    int before, int after,
			    int regexp, int fullword, int case_sensitive)
{
	Regex *preg;
        LINE_REC *line, *pre_line;
	GList *matches;
	GString *str;
        int i, match_after, line_matched;
	char * (*match_func)(const char *, const char *);

	g_return_val_if_fail(buffer != NULL, NULL);
	g_return_val_if_fail(text != NULL, NULL);

	preg = NULL;

	if (regexp) {
		preg = i_regex_new(text, case_sensitive ? 0 : G_REGEX_CASELESS, 0, NULL);

		if (preg == NULL)
			return NULL;
	}

	matches = NULL; match_after = 0;
        str = g_string_new(NULL);

	line = startline != NULL ? startline : buffer->first_line;

	if (fullword)
		match_func = case_sensitive ? strstr_full : stristr_full;
	else
		match_func = case_sensitive ? strstr : stristr;

	for (; line != NULL; line = line->next) {
		line_matched = (line->info.level & level) != 0 &&
			(line->info.level & nolevel) == 0;

		if (*text != '\0') {
			textbuffer_line2text(buffer, line, 0, str);

			if (line_matched) {
				line_matched = regexp ?
					i_regex_match(preg, str->str, 0, NULL)
					: match_func(str->str, text) != NULL;
			}
		}

		if (line_matched) {
                        /* add the -before lines */
			pre_line = line;
			for (i = 0; i < before; i++) {
				if (pre_line->prev == NULL ||
				    g_list_nth_data(matches, 0) == pre_line->prev ||
				    g_list_nth_data(matches, 1) == pre_line->prev)
					break;
                                pre_line = pre_line->prev;
			}

			for (; pre_line != line; pre_line = pre_line->next)
				matches = g_list_prepend(matches, pre_line);

			match_after = after;
		}

		if (line_matched || match_after > 0) {
			/* matched */
			matches = g_list_prepend(matches, line);

			if ((!line_matched && --match_after == 0) ||
			    (line_matched && match_after == 0 && before > 0))
				matches = g_list_prepend(matches, NULL);
		}
	}

	matches = g_list_reverse(matches);

	if (preg != NULL)
		i_regex_unref(preg);
        g_string_free(str, TRUE);
	return matches;
}

void textbuffer_init(void)
{
}

void textbuffer_deinit(void)
{
}
