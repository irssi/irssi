/*
 gui-entry.c : irssi

    Copyright (C) 1999 Timo Sirainen

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

#include "module.h"
#include "misc.h"
#include "utf8.h"
#include "formats.h"

#include "gui-entry.h"
#include "gui-printtext.h"
#include "term.h"

#undef i_toupper
#undef i_tolower
#undef i_isalnum

static unichar i_toupper(unichar c)
{
	if (term_type == TERM_TYPE_UTF8)
		return g_unichar_toupper(c);
	return (c >= 0 && c <= 255) ? toupper(c) : c;
}

static unichar i_tolower(unichar c)
{
	if (term_type == TERM_TYPE_UTF8)
		return g_unichar_tolower(c);
	return (c >= 0 && c <= 255) ? tolower(c) : c;
}

static int i_isalnum(unichar c)
{
	if (term_type == TERM_TYPE_UTF8)
		return (g_unichar_isalnum(c) || mk_wcwidth(c) == 0);
	return (c >= 0 && c <= 255) ? isalnum(c) : 0;
}

GUI_ENTRY_REC *active_entry;

static void entry_text_grow(GUI_ENTRY_REC *entry, int grow_size)
{
	if (entry->text_len+grow_size < entry->text_alloc)
		return;

	entry->text_alloc = nearest_power(entry->text_alloc+grow_size);
	entry->text = g_realloc(entry->text,
				sizeof(unichar) * entry->text_alloc);
}

GUI_ENTRY_REC *gui_entry_create(int xpos, int ypos, int width, int utf8)
{
	GUI_ENTRY_REC *rec;

	rec = g_new0(GUI_ENTRY_REC, 1);
	rec->xpos = xpos;
	rec->ypos = ypos;
        rec->width = width;
        rec->text_alloc = 1024;
	rec->text = g_new(unichar, rec->text_alloc);
        rec->text[0] = '\0';
        rec->utf8 = utf8;
	return rec;
}

void gui_entry_destroy(GUI_ENTRY_REC *entry)
{
        g_return_if_fail(entry != NULL);

	if (active_entry == entry)
		gui_entry_set_active(NULL);

        g_free(entry->text);
	g_free(entry->prompt);
        g_free(entry);
}

/* big5 functions */
#define big5_width(ch) ((ch)>0xff ? 2:1)

void unichars_to_big5(const unichar *str, char *out)
{
	for (; *str != '\0'; str++) {
		if (*str > 0xff)
			*out++ = (*str >> 8) & 0xff;
		*out++ = *str & 0xff;
	}
	*out = '\0';
}

int strlen_big5(const unsigned char *str)
{
	int len=0;

	while (*str != '\0') {
		if (is_big5(str[0], str[1]))
			str++;
		len++;
		str++;
	}
	return len;
}

void unichars_to_big5_with_pos(const unichar *str, int spos, char *out, int *opos)
{
	const unichar *sstart = str;
	char *ostart = out;

	*opos = 0;
	while(*str != '\0')
	{
		if(*str > 0xff)
			*out ++ = (*str >> 8) & 0xff;
		*out ++ = *str & 0xff;
		str ++;
		if(str - sstart == spos)
			*opos = out - ostart;
	}
	*out = '\0';
}

void big5_to_unichars(const char *str, unichar *out)
{
	const unsigned char *p = (const unsigned char *) str;

	while (*p != '\0') {
		if (is_big5(p[0], p[1])) {
			*out++ = p[0] << 8 | p[1];
			p += 2;
		} else {
			*out++ = *p++;
		}
	}
	*out = '\0';
}

/* ----------------------------- */

static int pos2scrpos(GUI_ENTRY_REC *entry, int pos)
{
	int i;
	int xpos = 0;

	for (i = 0; i < pos; i++) {
		unichar c = entry->text[i];

		if (term_type == TERM_TYPE_BIG5)
			xpos += big5_width(c);
		else if (entry->utf8)
			xpos += unichar_isprint(c) ? mk_wcwidth(c) : 1;
		else
			xpos++;
	}
	return xpos;
}

static int scrpos2pos(GUI_ENTRY_REC *entry, int pos)
{
	int i, width, xpos;

	for (i = 0, xpos = 0; i < entry->text_len; i++) {
		unichar c = entry->text[i];

		if (term_type == TERM_TYPE_BIG5)
			width = big5_width(c);
		else if (entry->utf8)
			width = unichar_isprint(c) ? mk_wcwidth(c) : 1;
		else
			width = 1;

		if (xpos + width > pos)
			break;
		xpos += width;
	}

	if (xpos == pos)
		return i;
	else
		return i-1;
}

/* Fixes the cursor position in screen */
static void gui_entry_fix_cursor(GUI_ENTRY_REC *entry)
{
	int old_scrstart;

	/* assume prompt len == prompt scrlen */
	int start = pos2scrpos(entry, entry->scrstart);
	int now = pos2scrpos(entry, entry->pos);

	old_scrstart = entry->scrstart;
	if (now-start < entry->width - 2 - entry->promptlen && now-start > 0)
		entry->scrpos = now-start;
	else if (now < entry->width - 1 - entry->promptlen) {
		entry->scrstart = 0;
		entry->scrpos = now;
	} else {
		entry->scrstart = scrpos2pos(entry, now-(entry->width -
							 entry->promptlen)*2/3);
		start = pos2scrpos(entry, entry->scrstart);
		entry->scrpos = now - start;
	}

	if (old_scrstart != entry->scrstart)
                entry->redraw_needed_from = 0;
}

static void gui_entry_draw_from(GUI_ENTRY_REC *entry, int pos)
{
	int i;
	int xpos, end_xpos;

	xpos = entry->xpos + entry->promptlen + 
		pos2scrpos(entry, pos + entry->scrstart) - 
		pos2scrpos(entry, entry->scrstart);
        end_xpos = entry->xpos + entry->width;

	if (xpos > end_xpos)
                return;

	term_set_color(root_window, ATTR_RESET);
	term_move(root_window, xpos, entry->ypos);

	for (i = entry->scrstart + pos; i < entry->text_len; i++) {
		unichar c = entry->text[i];

		if (entry->hidden)
			xpos++;
		else if (term_type == TERM_TYPE_BIG5)
			xpos += big5_width(c);
		else if (entry->utf8)
			xpos += unichar_isprint(c) ? mk_wcwidth(c) : 1;
		else
			xpos++;

		if (xpos > end_xpos)
			break;

		if (entry->hidden)
                        term_addch(root_window, ' ');
		else if (unichar_isprint(c))
			term_add_unichar(root_window, c);
		else {
			term_set_color(root_window, ATTR_RESET|ATTR_REVERSE);
			term_addch(root_window, (c & 127)+'A'-1);
			term_set_color(root_window, ATTR_RESET);
		}
	}

        /* clear the rest of the input line */
	if (xpos < end_xpos) {
		if (end_xpos == term_width)
			term_clrtoeol(root_window);
		else {
			while (xpos < end_xpos) {
				term_addch(root_window, ' ');
				xpos++;
			}
		}
	}
}

static void gui_entry_draw(GUI_ENTRY_REC *entry)
{
	if (entry->redraw_needed_from >= 0) {
		gui_entry_draw_from(entry, entry->redraw_needed_from);
                entry->redraw_needed_from = -1;
	}

	term_move_cursor(entry->xpos + entry->scrpos + entry->promptlen,
			 entry->ypos);
	term_refresh(NULL);
}

static void gui_entry_redraw_from(GUI_ENTRY_REC *entry, int pos)
{
	pos -= entry->scrstart;
	if (pos < 0) pos = 0;

	if (entry->redraw_needed_from == -1 ||
	    entry->redraw_needed_from > pos)
		entry->redraw_needed_from = pos;
}

void gui_entry_move(GUI_ENTRY_REC *entry, int xpos, int ypos, int width)
{
	int old_width;

        g_return_if_fail(entry != NULL);

	if (entry->xpos != xpos || entry->ypos != ypos) {
                /* position in screen changed - needs a full redraw */
		entry->xpos = xpos;
		entry->ypos = ypos;
		entry->width = width;
		gui_entry_redraw(entry);
                return;
	}

	if (entry->width == width)
                return; /* no changes */

	if (width > entry->width) {
                /* input line grew - need to draw text at the end */
                old_width = width;
		entry->width = width;
		gui_entry_redraw_from(entry, old_width);
	} else {
		/* input line shrinked - make sure the cursor
		   is inside the input line */
		entry->width = width;
		if (entry->pos - entry->scrstart >
		    entry->width-2 - entry->promptlen) {
			gui_entry_fix_cursor(entry);
		}
	}

	gui_entry_draw(entry);
}

void gui_entry_set_active(GUI_ENTRY_REC *entry)
{
	active_entry = entry;

	if (entry != NULL) {
		term_move_cursor(entry->xpos + entry->scrpos +
				 entry->promptlen, entry->ypos);
		term_refresh(NULL);
	}
}

void gui_entry_set_prompt(GUI_ENTRY_REC *entry, const char *str)
{
	int oldlen;

        g_return_if_fail(entry != NULL);

        oldlen = entry->promptlen;
	if (str != NULL) {
		g_free_not_null(entry->prompt);
		entry->prompt = g_strdup(str);
		entry->promptlen = format_get_length(str);
	}

        if (entry->prompt != NULL)
		gui_printtext(entry->xpos, entry->ypos, entry->prompt);

	if (entry->promptlen != oldlen) {
		gui_entry_fix_cursor(entry);
		gui_entry_draw(entry);
	}
}

void gui_entry_set_hidden(GUI_ENTRY_REC *entry, int hidden)
{
        g_return_if_fail(entry != NULL);

        entry->hidden = hidden;
}

void gui_entry_set_utf8(GUI_ENTRY_REC *entry, int utf8)
{
        g_return_if_fail(entry != NULL);

        entry->utf8 = utf8;
}

void gui_entry_set_text(GUI_ENTRY_REC *entry, const char *str)
{
	g_return_if_fail(entry != NULL);
	g_return_if_fail(str != NULL);

	entry->text_len = 0;
	entry->pos = 0;
	entry->text[0] = '\0';

	gui_entry_insert_text(entry, str);
}

char *gui_entry_get_text(GUI_ENTRY_REC *entry)
{
	char *buf;
        int i;

	g_return_val_if_fail(entry != NULL, NULL);

	if (entry->utf8)
		buf = g_ucs4_to_utf8(entry->text, -1, NULL, NULL, NULL);
	else {
		buf = g_malloc(entry->text_len*6 + 1);
		if (term_type == TERM_TYPE_BIG5)
			unichars_to_big5(entry->text, buf);
		else
			for (i = 0; i <= entry->text_len; i++)
				buf[i] = entry->text[i];
	}
	return buf;
}

char *gui_entry_get_text_and_pos(GUI_ENTRY_REC *entry, int *pos)
{
	char *buf;
        int i;

	g_return_val_if_fail(entry != NULL, NULL);

	if (entry->utf8) {
		buf = g_ucs4_to_utf8(entry->text, -1, NULL, NULL, NULL);
		*pos = g_utf8_offset_to_pointer(buf, entry->pos) - buf;
	} else {
		buf = g_malloc(entry->text_len*6 + 1);
		if(term_type==TERM_TYPE_BIG5)
			unichars_to_big5_with_pos(entry->text, entry->pos, buf, pos);
		else
		{
			for (i = 0; i <= entry->text_len; i++)
				buf[i] = entry->text[i];
			*pos = entry->pos;
		}
	}
	return buf;
}

void gui_entry_insert_text(GUI_ENTRY_REC *entry, const char *str)
{
        unichar chr;
	int i, len;
	const char *ptr;

        g_return_if_fail(entry != NULL);
	g_return_if_fail(str != NULL);

        gui_entry_redraw_from(entry, entry->pos);

	if (entry->utf8) {
		g_utf8_validate(str, -1, &ptr);
		len = g_utf8_pointer_to_offset(str, ptr);
	} else if (term_type == TERM_TYPE_BIG5)
		len = strlen_big5(str);
	else
		len = strlen(str);
        entry_text_grow(entry, len);

        /* make space for the string */
	g_memmove(entry->text + entry->pos + len, entry->text + entry->pos,
		  (entry->text_len-entry->pos + 1) * sizeof(unichar));

	if (!entry->utf8) {
		if (term_type == TERM_TYPE_BIG5) {
			chr = entry->text[entry->pos + len];
			big5_to_unichars(str, entry->text + entry->pos);
			entry->text[entry->pos + len] = chr;
		} else {
			for (i = 0; i < len; i++)
				entry->text[entry->pos + i] = str[i];
		}
	} else {
		ptr = str;
		for (i = 0; i < len; i++) {
			entry->text[entry->pos + i] = g_utf8_get_char(ptr);
			ptr = g_utf8_next_char(ptr);
		}
	}

	entry->text_len += len;
        entry->pos += len;

	gui_entry_fix_cursor(entry);
	gui_entry_draw(entry);
}

void gui_entry_insert_char(GUI_ENTRY_REC *entry, unichar chr)
{
        g_return_if_fail(entry != NULL);

	if (chr == 0 || chr == 13 || chr == 10)
		return; /* never insert NUL, CR or LF characters */

	if (entry->utf8 && entry->pos == 0 && mk_wcwidth(chr) == 0)
		return;

        gui_entry_redraw_from(entry, entry->pos);

	entry_text_grow(entry, 1);

	/* make space for the string */
	g_memmove(entry->text + entry->pos + 1, entry->text + entry->pos,
		  (entry->text_len-entry->pos + 1) * sizeof(unichar));

	entry->text[entry->pos] = chr;
	entry->text_len++;
        entry->pos++;

	gui_entry_fix_cursor(entry);
	gui_entry_draw(entry);
}

char *gui_entry_get_cutbuffer(GUI_ENTRY_REC *entry)
{
	char *buf;
        int i;

	g_return_val_if_fail(entry != NULL, NULL);

	if (entry->cutbuffer == NULL)
                return NULL;

	if (entry->utf8)
		buf = g_ucs4_to_utf8(entry->cutbuffer, -1, NULL, NULL, NULL);
	else {
		buf = g_malloc(entry->cutbuffer_len*6 + 1);
		if (term_type == TERM_TYPE_BIG5)
			unichars_to_big5(entry->cutbuffer, buf);
		else
			for (i = 0; i <= entry->cutbuffer_len; i++)
				buf[i] = entry->cutbuffer[i];
	}
	return buf;
}

void gui_entry_erase_to(GUI_ENTRY_REC *entry, int pos, int update_cutbuffer)
{
	int newpos, size = 0;

	g_return_if_fail(entry != NULL);

	for (newpos = gui_entry_get_pos(entry); newpos > pos; size++)
		newpos = newpos - 1;
	gui_entry_erase(entry, size, update_cutbuffer);
}

void gui_entry_erase(GUI_ENTRY_REC *entry, int size, int update_cutbuffer)
{
	size_t w = 0;

        g_return_if_fail(entry != NULL);

	if (size == 0 || entry->pos < size)
		return;

	if (update_cutbuffer) {
		/* put erased text to cutbuffer */
		if (entry->cutbuffer_len < size) {
			g_free(entry->cutbuffer);
			entry->cutbuffer = g_new(unichar, size+1);
		}

		entry->cutbuffer_len = size;
		entry->cutbuffer[size] = '\0';
		memcpy(entry->cutbuffer, entry->text + entry->pos - size,
		       size * sizeof(unichar));
	}

	if (entry->utf8)
		while (entry->pos-size-w > 0 &&
		       mk_wcwidth(entry->text[entry->pos-size-w]) == 0) w++;

	g_memmove(entry->text + entry->pos - size, entry->text + entry->pos,
		  (entry->text_len-entry->pos+1) * sizeof(unichar));

	entry->pos -= size;
        entry->text_len -= size;

	gui_entry_redraw_from(entry, entry->pos-w);
	gui_entry_fix_cursor(entry);
	gui_entry_draw(entry);
}

void gui_entry_erase_cell(GUI_ENTRY_REC *entry)
{
	int size = 1;

	g_return_if_fail(entry != NULL);

	if (entry->utf8)
		while (entry->pos+size < entry->text_len &&
		       mk_wcwidth(entry->text[entry->pos+size]) == 0) size++;

	g_memmove(entry->text + entry->pos, entry->text + entry->pos + size,
		  (entry->text_len-entry->pos-size+1) * sizeof(unichar));

	entry->text_len -= size;

	gui_entry_redraw_from(entry, entry->pos);
	gui_entry_draw(entry);
}

void gui_entry_erase_word(GUI_ENTRY_REC *entry, int to_space)
{
	int to;

        g_return_if_fail(entry != NULL);
	if (entry->pos == 0)
		return;

	to = entry->pos - 1;

	if (to_space) {
		while (entry->text[to] == ' ' && to > 0)
			to--;
		while (entry->text[to] != ' ' && to > 0)
			to--;
	} else {
		while (!i_isalnum(entry->text[to]) && to > 0)
			to--;
		while (i_isalnum(entry->text[to]) && to > 0)
			to--;
	}
	if (to > 0) to++;

        gui_entry_erase(entry, entry->pos-to, TRUE);
}

void gui_entry_erase_next_word(GUI_ENTRY_REC *entry, int to_space)
{
	int to, size;

        g_return_if_fail(entry != NULL);
	if (entry->pos == entry->text_len)
		return;

        to = entry->pos;
	if (to_space) {
		while (entry->text[to] == ' ' && to < entry->text_len)
			to++;
		while (entry->text[to] != ' ' && to < entry->text_len)
			to++;
	} else {
		while (!i_isalnum(entry->text[to]) && to < entry->text_len)
			to++;
		while (i_isalnum(entry->text[to]) && to < entry->text_len)
			to++;
	}

        size = to-entry->pos;
	entry->pos = to;
        gui_entry_erase(entry, size, TRUE);
}

void gui_entry_transpose_chars(GUI_ENTRY_REC *entry)
{
        unichar chr;

	if (entry->pos == 0 || entry->text_len < 2)
                return;

	if (entry->pos == entry->text_len)
                entry->pos--;

        /* swap chars */
	chr = entry->text[entry->pos];
	entry->text[entry->pos] = entry->text[entry->pos-1];
        entry->text[entry->pos-1] = chr;

        entry->pos++;

	gui_entry_redraw_from(entry, entry->pos-2);
	gui_entry_fix_cursor(entry);
	gui_entry_draw(entry);
}

void gui_entry_transpose_words(GUI_ENTRY_REC *entry)
{
	int spos1, epos1, spos2, epos2;

	/* find last position */
	epos2 = entry->pos;
	while (epos2 < entry->text_len && !i_isalnum(entry->text[epos2]))
		epos2++;
	while (epos2 < entry->text_len &&  i_isalnum(entry->text[epos2]))
		epos2++;

	/* find other position */
	spos2 = epos2;
	while (spos2 > 0 && !i_isalnum(entry->text[spos2-1]))
		spos2--;
	while (spos2 > 0 &&  i_isalnum(entry->text[spos2-1]))
		spos2--;

	epos1 = spos2;
	while (epos1 > 0 && !i_isalnum(entry->text[epos1-1]))
		epos1--;

	spos1 = epos1;
	while (spos1 > 0 && i_isalnum(entry->text[spos1-1]))
		spos1--;

	/* do wordswap if any found */
	if (spos1 < epos1 && epos1 < spos2 && spos2 < epos2) {
		unichar *first, *sep, *second;
		int i;

		first  = (unichar *) g_malloc( (epos1 - spos1) * sizeof(unichar) );
		sep    = (unichar *) g_malloc( (spos2 - epos1) * sizeof(unichar) );
		second = (unichar *) g_malloc( (epos2 - spos2) * sizeof(unichar) );

		for (i = spos1; i < epos1; i++)
			first[i-spos1] = entry->text[i];
		for (i = epos1; i < spos2; i++)
			sep[i-epos1] = entry->text[i];
		for (i = spos2; i < epos2; i++)
			second[i-spos2] = entry->text[i];

		entry->pos = spos1;
		for (i = 0; i < epos2-spos2; i++)
			entry->text[entry->pos++] = second[i];
		for (i = 0; i < spos2-epos1; i++)
			entry->text[entry->pos++] = sep[i];
		for (i = 0; i < epos1-spos1; i++)
			entry->text[entry->pos++] = first[i];

		g_free(first);
		g_free(sep);
		g_free(second);

	}
	
	gui_entry_redraw_from(entry, spos1);
	gui_entry_fix_cursor(entry);
	gui_entry_draw(entry);
}

void gui_entry_capitalize_word(GUI_ENTRY_REC *entry)
{
	int pos = entry->pos;
	while (pos < entry->text_len && !i_isalnum(entry->text[pos]))
		pos++;

	if (pos < entry->text_len) {
		entry->text[pos] = i_toupper(entry->text[pos]);
		pos++;
	}

	while (pos < entry->text_len && i_isalnum(entry->text[pos])) {
		entry->text[pos] = i_tolower(entry->text[pos]);
		pos++;
	}

	gui_entry_redraw_from(entry, entry->pos);
	entry->pos = pos;
	gui_entry_fix_cursor(entry);
	gui_entry_draw(entry);
}

void gui_entry_downcase_word(GUI_ENTRY_REC *entry)
{
	int pos = entry->pos;
	while (pos < entry->text_len && !i_isalnum(entry->text[pos]))
		pos++;

	while (pos < entry->text_len && i_isalnum(entry->text[pos])) {
		entry->text[pos] = i_tolower(entry->text[pos]);
		pos++;
	}

	gui_entry_redraw_from(entry, entry->pos);
	entry->pos = pos;
	gui_entry_fix_cursor(entry);
	gui_entry_draw(entry);
}

void gui_entry_upcase_word(GUI_ENTRY_REC *entry)
{
	int pos = entry->pos;
	while (pos < entry->text_len && !i_isalnum(entry->text[pos]))
		pos++;

	while (pos < entry->text_len && i_isalnum(entry->text[pos])) {
		entry->text[pos] = i_toupper(entry->text[pos]);
		pos++;
	}

	gui_entry_redraw_from(entry, entry->pos);
	entry->pos = pos;
	gui_entry_fix_cursor(entry);
	gui_entry_draw(entry);
}

int gui_entry_get_pos(GUI_ENTRY_REC *entry)
{
        g_return_val_if_fail(entry != NULL, 0);

	return entry->pos;
}

void gui_entry_set_pos(GUI_ENTRY_REC *entry, int pos)
{
        g_return_if_fail(entry != NULL);

	if (pos >= 0 && pos <= entry->text_len)
		entry->pos = pos;

	gui_entry_fix_cursor(entry);
	gui_entry_draw(entry);
}

void gui_entry_move_pos(GUI_ENTRY_REC *entry, int pos)
{
        g_return_if_fail(entry != NULL);

	if (entry->pos + pos >= 0 && entry->pos + pos <= entry->text_len)
		entry->pos += pos;

	if (entry->utf8) {
		int step = pos < 0 ? -1 : 1;
		while(mk_wcwidth(entry->text[entry->pos]) == 0 &&
		      entry->pos + step >= 0 && entry->pos + step <= entry->text_len)
			entry->pos += step;
	}

	gui_entry_fix_cursor(entry);
	gui_entry_draw(entry);
}

static void gui_entry_move_words_left(GUI_ENTRY_REC *entry, int count, int to_space)
{
	int pos;

	pos = entry->pos;
	while (count > 0 && pos > 0) {
		if (to_space) {
			while (pos > 0 && entry->text[pos-1] == ' ')
				pos--;
			while (pos > 0 && entry->text[pos-1] != ' ')
				pos--;
		} else {
			while (pos > 0 && !i_isalnum(entry->text[pos-1]))
				pos--;
			while (pos > 0 &&  i_isalnum(entry->text[pos-1]))
				pos--;
		}
		count--;
	}

        entry->pos = pos;
}

static void gui_entry_move_words_right(GUI_ENTRY_REC *entry, int count, int to_space)
{
	int pos;

	pos = entry->pos;
	while (count > 0 && pos < entry->text_len) {
		if (to_space) {
			while (pos < entry->text_len && entry->text[pos] == ' ')
				pos++;
			while (pos < entry->text_len && entry->text[pos] != ' ')
				pos++;
		} else {
			while (pos < entry->text_len && !i_isalnum(entry->text[pos]))
				pos++;
			while (pos < entry->text_len &&  i_isalnum(entry->text[pos]))
				pos++;
		}
		count--;
	}

        entry->pos = pos;
}

void gui_entry_move_words(GUI_ENTRY_REC *entry, int count, int to_space)
{
        g_return_if_fail(entry != NULL);

	if (count < 0)
		gui_entry_move_words_left(entry, -count, to_space);
	else if (count > 0)
		gui_entry_move_words_right(entry, count, to_space);

	gui_entry_fix_cursor(entry);
	gui_entry_draw(entry);
}

void gui_entry_redraw(GUI_ENTRY_REC *entry)
{
        g_return_if_fail(entry != NULL);

	gui_entry_set_prompt(entry, NULL);
        gui_entry_redraw_from(entry, 0);
	gui_entry_fix_cursor(entry);
	gui_entry_draw(entry);
}
