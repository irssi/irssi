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

#include "screen.h"

static GString *entry;
static int promptlen, permanent_prompt, pos, scrstart, scrpos;
static char *prompt;

static void entry_screenpos(void)
{
	if (pos-scrstart < COLS-1-promptlen && pos-scrstart > 0) {
		scrpos = pos-scrstart;
		return;
	}

	if (pos < COLS-1-promptlen) {
		scrstart = 0;
		scrpos = pos;
	} else {
		scrpos = COLS-1-promptlen;
		scrstart = pos-scrpos;
	}
}

static void entry_update(void)
{
	char *p;
	int n, len;

	len = entry->len-scrstart > COLS-promptlen ?
		COLS-promptlen : entry->len-scrstart;

	set_color(0);
	move(LINES-1, promptlen);

	for (p = entry->str+scrstart, n = 0; n < len; n++, p++) {
		if ((unsigned char) *p >= 32)
			addch((unsigned char) *p);
		else {
			set_color(ATTR_REVERSE);
			addch(*p+'A'-1);
			set_color(0);
		}
	}
	clrtoeol();

	move_cursor(LINES-1, scrpos+promptlen);
	screen_refresh();
}

void gui_entry_set_prompt(const char *str)
{
	if (str != NULL) {
		if (permanent_prompt) return;

		g_free_not_null(prompt);
		prompt = g_strdup(str);
		promptlen = strlen(prompt);
	}

	set_color(0);
	mvaddstr(LINES-1, 0, prompt);

	entry_screenpos();
	entry_update();
}

void gui_entry_set_perm_prompt(const char *str)
{
	g_return_if_fail(str != NULL);

	g_free_not_null(prompt);
	prompt = g_strdup(str);
	promptlen = strlen(prompt);

	permanent_prompt = TRUE;
	gui_entry_set_prompt(NULL);
}

void gui_entry_remove_perm_prompt(void)
{
        permanent_prompt = FALSE;
}

void gui_entry_set_text(const char *str)
{
	g_return_if_fail(str != NULL);

	g_string_assign(entry, str);
	pos = entry->len;

	entry_screenpos();
	entry_update();
}

char *gui_entry_get_text(void)
{
	return entry->str;
}

void gui_entry_insert_text(const char *str)
{
	g_return_if_fail(str != NULL);

	g_string_insert(entry, pos, str);
	pos += strlen(str);

	entry_screenpos();
	entry_update();
}

void gui_entry_insert_char(char chr)
{
	g_string_insert_c(entry, pos, chr);
	pos++;

	entry_screenpos();
	entry_update();
}

void gui_entry_erase(int size)
{
	if (pos < size) return;

	pos -= size;
	g_string_erase(entry, pos, size);

	entry_screenpos();
	entry_update();
}

int gui_entry_get_pos(void)
{
	return pos;
}

void gui_entry_set_pos(int p)
{
	if (p >= 0 && p <= entry->len)
		pos = p;
}

void gui_entry_move_pos(int p)
{
	if (pos+p >= 0 && pos+p <= entry->len)
		pos += p;

	entry_screenpos();
	entry_update();
}

void gui_entry_redraw(void)
{
	gui_entry_set_prompt(NULL);

	entry_screenpos();
	entry_update();
}

void gui_entry_init(void)
{
	entry = g_string_new(NULL);

	pos = scrpos = 0;
	prompt = NULL; promptlen = 0;
	permanent_prompt = FALSE;
}

void gui_entry_deinit(void)
{
	if (prompt != NULL) g_free(prompt);
	g_string_free(entry, TRUE);
}
