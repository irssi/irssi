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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "utf8.h"
#include "formats.h"

#include "gui-entry.h"
#include "gui-printtext.h"
#include "term.h"

GUI_ENTRY_REC *active_entry;

GUI_ENTRY_REC *gui_entry_create(int xpos, int ypos, int width, int utf8)
{
	GUI_ENTRY_REC *rec;

	rec = g_new0(GUI_ENTRY_REC, 1);
	rec->xpos = xpos;
	rec->ypos = ypos;
        rec->width = width;
	rec->text = g_string_new(NULL);
        rec->utf8 = utf8;
	return rec;
}

void gui_entry_destroy(GUI_ENTRY_REC *entry)
{
        g_return_if_fail(entry != NULL);

	if (active_entry == entry)
		gui_entry_set_active(NULL);

	g_free_not_null(entry->prompt);
	g_string_free(entry->text, TRUE);
        g_free(entry);
}

/* Fixes the cursor position in screen */
static void gui_entry_fix_cursor(GUI_ENTRY_REC *entry)
{
	int old_scrstart;

        old_scrstart = entry->scrstart;
	if (entry->pos - entry->scrstart < entry->width-2 - entry->promptlen &&
	    entry->pos - entry->scrstart > 0) {
		entry->scrpos = entry->pos - entry->scrstart;
	} else if (entry->pos < entry->width-1 - entry->promptlen) {
		entry->scrstart = 0;
		entry->scrpos = entry->pos;
	} else {
		entry->scrpos = (entry->width - entry->promptlen)*2/3;
		entry->scrstart = entry->pos - entry->scrpos;
	}

	if (old_scrstart != entry->scrstart)
                entry->redraw_needed_from = 0;
}

static void gui_entry_draw_from(GUI_ENTRY_REC *entry, int pos)
{
	const unsigned char *p, *end;
	int xpos, end_xpos;

	if (entry->utf8) {
		/* FIXME: a stupid kludge to make the chars output correctly */
		pos = 0;
	}

        xpos = entry->xpos + entry->promptlen + pos;
        end_xpos = entry->xpos + entry->width;
	if (xpos > end_xpos)
                return;

	term_set_color(root_window, ATTR_RESET);
	term_move(root_window, xpos, entry->ypos);

	p = (unsigned char *) (entry->scrstart + pos >= entry->text->len ? "" :
			       entry->text->str + entry->scrstart + pos);
	for (; *p != '\0' && xpos < end_xpos; p++, xpos++) {
                end = p;
		if (entry->utf8)
			get_utf8_char(&end);

		if (entry->hidden)
                        term_addch(root_window, ' ');
		else if (*p >= 32 && (end != p || (*p & 127) >= 32)) {
                        for (; p < end; p++)
				term_addch(root_window, *p);
			term_addch(root_window, *p);
		} else {
			term_set_color(root_window, ATTR_RESET|ATTR_REVERSE);
			term_addch(root_window, *p+'A'-1);
			term_set_color(root_window, ATTR_RESET);
		}
	}

        /* clear the rest of the input line */
        if (end_xpos == term_width)
		term_clrtoeol(root_window);
	else {
		while (xpos < end_xpos) {
                        term_addch(root_window, ' ');
                        xpos++;
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

	g_string_assign(entry->text, str);
	entry->pos = entry->text->len;

        gui_entry_redraw_from(entry, 0);
	gui_entry_fix_cursor(entry);
	gui_entry_draw(entry);
}

char *gui_entry_get_text(GUI_ENTRY_REC *entry)
{
	g_return_val_if_fail(entry != NULL, NULL);

	return entry->text->str;
}

void gui_entry_insert_text(GUI_ENTRY_REC *entry, const char *str)
{
        g_return_if_fail(entry != NULL);
	g_return_if_fail(str != NULL);

        gui_entry_redraw_from(entry, entry->pos);
	g_string_insert(entry->text, entry->pos, str);
	entry->pos += strlen(str);

	gui_entry_fix_cursor(entry);
	gui_entry_draw(entry);
}

void gui_entry_insert_char(GUI_ENTRY_REC *entry, char chr)
{
        g_return_if_fail(entry != NULL);

	if (chr == 0 || chr == 13 || chr == 10)
		return; /* never insert NUL, CR or LF characters */

        gui_entry_redraw_from(entry, entry->pos);
	g_string_insert_c(entry->text, entry->pos, chr);
	entry->pos++;

	gui_entry_fix_cursor(entry);
	gui_entry_draw(entry);
}

void gui_entry_erase(GUI_ENTRY_REC *entry, int size)
{
        g_return_if_fail(entry != NULL);

	if (entry->pos < size)
		return;

#ifdef WANT_BIG5
	if (is_big5(entry->text->str[entry->pos-2],
		    entry->text->str[entry->pos-1]))
		size++;
#endif

	entry->pos -= size;
	g_string_erase(entry->text, entry->pos, size);

	gui_entry_redraw_from(entry, entry->pos);
	gui_entry_fix_cursor(entry);
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
		while (entry->text->str[to] == ' ' && to > 0)
			to--;
		while (entry->text->str[to] != ' ' && to > 0)
			to--;
	} else {
		while (!i_isalnum(entry->text->str[to]) && to > 0)
			to--;
		while (i_isalnum(entry->text->str[to]) && to > 0)
			to--;
	}
	if (to > 0) to++;

	g_string_erase(entry->text, to, entry->pos - to);
	entry->pos = to;

        gui_entry_redraw_from(entry, entry->pos);
	gui_entry_fix_cursor(entry);
	gui_entry_draw(entry);
}

void gui_entry_erase_next_word(GUI_ENTRY_REC *entry, int to_space)
{
	int to;

        g_return_if_fail(entry != NULL);
	if (entry->pos == entry->text->len)
		return;

        to = entry->pos;
	if (to_space) {
		while (entry->text->str[to] == ' ' && to < entry->text->len)
			to++;
		while (entry->text->str[to] != ' ' && to < entry->text->len)
			to++;
	} else {
		while (!i_isalnum(entry->text->str[to]) && to < entry->text->len)
			to++;
		while (i_isalnum(entry->text->str[to]) && to < entry->text->len)
			to++;
	}

	g_string_erase(entry->text, entry->pos, to - entry->pos);

        gui_entry_redraw_from(entry, entry->pos);
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

	if (pos >= 0 && pos <= entry->text->len)
		entry->pos = pos;

	gui_entry_fix_cursor(entry);
	gui_entry_draw(entry);
}

void gui_entry_move_pos(GUI_ENTRY_REC *entry, int pos)
{
        g_return_if_fail(entry != NULL);

#ifdef WANT_BIG5
	if (pos > 0 && is_big5(entry->text->str[entry->pos],
			       entry->text->str[entry->pos+1]))
		pos++;
	else if (pos < 0 && is_big5(entry->text->str[entry->pos-1],
				    entry->text->str[entry->pos]))
		pos--;
#endif

	if (entry->pos+pos >= 0 && entry->pos+pos <= entry->text->len)
		entry->pos += pos;

	gui_entry_fix_cursor(entry);
	gui_entry_draw(entry);
}

static void gui_entry_move_words_left(GUI_ENTRY_REC *entry, int count, int to_space)
{
	int pos;

	pos = entry->pos;
	while (count > 0 && pos > 0) {
		if (to_space) {
			while (pos > 0 && entry->text->str[pos-1] == ' ')
				pos--;
			while (pos > 0 && entry->text->str[pos-1] != ' ')
				pos--;
		} else {
			while (pos > 0 && !i_isalnum(entry->text->str[pos-1]))
				pos--;
			while (pos > 0 &&  i_isalnum(entry->text->str[pos-1]))
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
	while (count > 0 && pos < entry->text->len) {
		if (to_space) {
			while (pos < entry->text->len && entry->text->str[pos] == ' ')
				pos++;
			while (pos < entry->text->len && entry->text->str[pos] != ' ')
				pos++;
		} else {
			while (pos < entry->text->len && !i_isalnum(entry->text->str[pos]))
				pos++;
			while (pos < entry->text->len &&  i_isalnum(entry->text->str[pos]))
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
