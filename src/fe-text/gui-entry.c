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
#include <irssi/src/core/misc.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/core/utf8.h>
#include <irssi/src/fe-common/core/formats.h>
#include <irssi/src/fe-common/core/printtext.h>

#include <irssi/src/fe-text/gui-entry.h>
#include <irssi/src/fe-text/gui-printtext.h>
#include <irssi/src/fe-text/term.h>
#include <irssi/src/core/recode.h>

#ifdef HAVE_LIBUTF8PROC
#include <utf8proc.h>
#endif

#undef i_toupper
#undef i_tolower
#undef i_isalnum

#define KILL_RING_MAX 10

static unichar i_toupper(unichar c)
{
	if (term_type == TERM_TYPE_UTF8)
		return g_unichar_toupper(c);
	return c <= 255 ? toupper(c) : c;
}

static unichar i_tolower(unichar c)
{
	if (term_type == TERM_TYPE_UTF8)
		return g_unichar_tolower(c);
	return c <= 255 ? tolower(c) : c;
}

static int is_combining_char(unichar c)
{
	if (term_type != TERM_TYPE_UTF8)
		return 0;

#ifdef HAVE_LIBUTF8PROC
	/* Use utf8proc for precise combining character detection */
	return unichar_isprint(c) && utf8proc_charwidth(c) == 0;
#else
	/* Fallback to unichar_width for compatibility */
	return unichar_isprint(c) && unichar_width(c) == 0;
#endif
}

static int i_isalnum(unichar c)
{
	if (term_type == TERM_TYPE_UTF8)
		return (g_unichar_isalnum(c) || is_combining_char(c));
	return c <= 255 ? isalnum(c) : 0;
}

GUI_ENTRY_REC *active_entry;

static void entry_text_grow(GUI_ENTRY_REC *entry, int grow_size)
{
	if (entry->text_len+grow_size < entry->text_alloc)
		return;

	entry->text_alloc = nearest_power(entry->text_alloc+grow_size);
	entry->text = g_realloc(entry->text,
				sizeof(unichar) * entry->text_alloc);

	if (entry->uses_extents)
		entry->extents = g_realloc(entry->extents,
				   sizeof(char *) * entry->text_alloc);
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
	rec->extents = NULL;
	rec->text[0] = '\0';
	rec->utf8 = utf8;
	return rec;
}

static void destroy_extents(GUI_ENTRY_REC *entry)
{
	if (entry->uses_extents) {
		int i;
		for (i = 0; i < entry->text_alloc; i++) {
			if (entry->extents[i] != NULL) {
				g_free(entry->extents[i]);
			}
		}
	}
	g_free(entry->extents);
	entry->extents = NULL;
	entry->uses_extents = FALSE;
}

void gui_entry_destroy(GUI_ENTRY_REC *entry)
{
	GSList *tmp;

        g_return_if_fail(entry != NULL);

	if (active_entry == entry)
		gui_entry_set_active(NULL);

	for (tmp = entry->kill_ring; tmp != NULL; tmp = tmp->next) {
		GUI_ENTRY_CUTBUFFER_REC *rec = tmp->data;
		if (rec != NULL) {
			g_free(rec->cutbuffer);
			g_free(rec);
		}
	}
	g_slist_free(entry->kill_ring);

	destroy_extents(entry);
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

/* Return screen length of plain string */
static int scrlen_str(const char *str, int utf8)
{
	int len = 0;
	char *stripped;
	g_return_val_if_fail(str != NULL, 0);

	stripped = strip_codes(str);
	len = string_width(stripped, utf8 ? TREAT_STRING_AS_UTF8 : TREAT_STRING_AS_BYTES);
	g_free(stripped);
	return len;
}

/* ----------------------------- */

static int pos2scrpos(GUI_ENTRY_REC *entry, int pos, int cursor)
{
	int i;
	int xpos = 0;

	if (!cursor && pos <= 0)
		return 0;

	if (entry->uses_extents && entry->extents[0] != NULL) {
		xpos += scrlen_str(entry->extents[0], entry->utf8);
	}

	/* Process text using grapheme cluster aware advancement when possible */
	i = 0;
	while (i < entry->text_len && i < pos) {
		const char *extent = entry->uses_extents ? entry->extents[i+1] : NULL;
		int char_width;

		if (term_type == TERM_TYPE_BIG5) {
			char_width = big5_width(entry->text[i]);
			i++;
		} else if (entry->utf8) {
			/* Use grapheme cluster aware advancement */
			char_width = unichar_array_advance_cluster(entry->text, entry->text_len, &i);
		} else {
			char_width = 1;
			i++;
		}

		xpos += char_width;

		if (extent != NULL) {
			xpos += scrlen_str(extent, entry->utf8);
		}
	}
	return xpos + pos - i;
}

static int scrpos2pos(GUI_ENTRY_REC *entry, int pos)
{
	int i, width, xpos = 0;

	if (entry->uses_extents && entry->extents[0] != NULL) {
		xpos += scrlen_str(entry->extents[0], entry->utf8);
	}

	/* Process text using grapheme cluster aware advancement when possible */
	i = 0;
	while (i < entry->text_len && xpos < pos) {
		const char *extent = entry->uses_extents ? entry->extents[i+1] : NULL;

		if (term_type == TERM_TYPE_BIG5) {
			width = big5_width(entry->text[i]);
			i++;
		} else if (entry->utf8) {
			/* Use grapheme cluster aware advancement */
			width = unichar_array_advance_cluster(entry->text, entry->text_len, &i);
		} else {
			width = 1;
			i++;
		}

		xpos += width;

		if (extent != NULL) {
			xpos += scrlen_str(extent, entry->utf8);
		}
	}
	return i;
}

/* Fixes the cursor position in screen */
static void gui_entry_fix_cursor(GUI_ENTRY_REC *entry)
{
	int old_scrstart;

	/* assume prompt len == prompt scrlen */
	int start = pos2scrpos(entry, entry->scrstart, FALSE);
	int now = pos2scrpos(entry, entry->pos, TRUE);

	old_scrstart = entry->scrstart;
	if (now-start < entry->width - 2 - entry->promptlen && now-start > 0) {
		entry->scrpos = now-start;
	} else if (now < entry->width - 1 - entry->promptlen) {
		entry->scrstart = 0;
		entry->scrpos = now;
	} else {
		entry->scrstart = scrpos2pos(entry, now-(entry->width -
							 entry->promptlen)*2/3);
		start = pos2scrpos(entry, entry->scrstart, FALSE);
		entry->scrpos = now - start;
	}

	if (old_scrstart != entry->scrstart)
                entry->redraw_needed_from = 0;
}

static char *text_effects_only(const char *p)
{
	GString *str;

	str = g_string_sized_new(strlen(p));
	for (; *p != '\0'; p++) {
		if (*p == 4 && p[1] != '\0') {
			if (p[1] >= FORMAT_STYLE_SPECIAL) {
				g_string_append_len(str, p, 2);
				p++;
				continue;
			}

			/* irssi color */
			if (p[2] != '\0') {
				if (p[1] == FORMAT_COLOR_24) {
					if (p[3] == '\0') p += 2;
					else if (p[4] == '\0') p += 3;
					else if (p[5] == '\0') p += 4;
					else {
						g_string_append_len(str, p, 6);
						p += 5;
					}
				} else {
					g_string_append_len(str, p, 3);
					p += 2;
				}
				continue;
			}
		}
	}

	return g_string_free(str, FALSE);
}

static void gui_entry_draw_from(GUI_ENTRY_REC *entry, int pos)
{
	int i, start;
	int start_xpos, xpos, new_xpos, end_xpos;
	char *tmp;
	GString *str;

	start = entry->scrstart + pos;

	start_xpos = xpos = entry->xpos + entry->promptlen +
		pos2scrpos(entry, start, FALSE) -
		pos2scrpos(entry, entry->scrstart, FALSE);
        end_xpos = entry->xpos + entry->width;

	if (xpos > end_xpos)
                return;

	str = g_string_sized_new(entry->text_alloc);

	term_set_color(root_window, ATTR_RESET);
	/* term_move(root_window, xpos, entry->ypos); */

	if (entry->uses_extents && entry->extents[0] != NULL) {
		g_string_append(str, entry->extents[0]);
	}
	for (i = 0; i < start && i < entry->text_len; i++) {
		const char *extent = entry->uses_extents ? entry->extents[i+1] : NULL;
		if (extent != NULL) {
			g_string_append(str, extent);
		}
	}
	if (i == 0) {
		xpos += scrlen_str(str->str, entry->utf8);
	} else {
		tmp = text_effects_only(str->str);
		g_string_assign(str, tmp);
		g_free(tmp);
	}

	/* Process remaining text using grapheme cluster aware advancement */
	while (i < entry->text_len) {
		const char *extent = entry->uses_extents ? entry->extents[i+1] : NULL;
		int char_width;
		int cluster_start = i;
		unichar c;
		new_xpos = xpos;

		c = entry->text[i];

		if (entry->hidden) {
			char_width = 1;
			i++;
		} else if (term_type == TERM_TYPE_BIG5) {
			char_width = big5_width(c);
			i++;
		} else if (entry->utf8) {
			/* Use grapheme cluster aware advancement */
			char_width = unichar_array_advance_cluster(entry->text, entry->text_len, &i);
		} else {
			char_width = 1;
			i++;
		}

		new_xpos += char_width;

		if (new_xpos > end_xpos)
			break;

		if (entry->hidden) {
                        g_string_append_c(str, ' ');
		} else if (entry->utf8 && cluster_start != i) {
			/* Render entire grapheme cluster for UTF-8 */
			for (int j = cluster_start; j < i; j++) {
				unichar cluster_char = entry->text[j];
				if (unichar_isprint(cluster_char))
					g_string_append_unichar(str, cluster_char);
				else if (cluster_char == 0)
					break;
			}
		} else if (unichar_isprint(c)) {
			if (entry->utf8) {
				g_string_append_unichar(str, c);
			} else if (term_type == TERM_TYPE_BIG5) {
				if(c > 0xff)
					g_string_append_c(str, (c >> 8) & 0xff);
				g_string_append_c(str, c & 0xff);
			} else {
				g_string_append_c(str, c);
			}
		} else {
			g_string_append_c(str, 4);
			g_string_append_c(str, FORMAT_STYLE_REVERSE);
			g_string_append_c(str, (c & 127)+'A'-1);
			g_string_append_c(str, 4);
			g_string_append_c(str, FORMAT_STYLE_REVERSE);
		}
		xpos = new_xpos;

		if (extent != NULL) {
			new_xpos += scrlen_str(extent, entry->utf8);

			if (new_xpos > end_xpos)
				break;

			g_string_append(str, extent);
			xpos = new_xpos;
		}
	}

        /* clear the rest of the input line */
	if (xpos < end_xpos) {
		if (end_xpos == term_width) {
			g_string_append_c(str, 4);
			g_string_append_c(str, FORMAT_STYLE_CLRTOEOL);
		} else {
			while (xpos < end_xpos) {
				g_string_append_c(str, ' ');
				xpos++;
			}
		}
	}

	gui_printtext_internal(start_xpos, entry->ypos, str->str);
	g_string_free(str, TRUE);
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
		entry->promptlen = scrlen_str(str, entry->utf8);
	}

        if (entry->prompt != NULL)
		gui_printtext_internal(entry->xpos, entry->ypos, entry->prompt);

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
	destroy_extents(entry);

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
		len = strlen_big5((const unsigned char *)str);
	else
		len = strlen(str);
        entry_text_grow(entry, len);

        /* make space for the string */
	memmove(entry->text + entry->pos + len, entry->text + entry->pos,
	        (entry->text_len-entry->pos + 1) * sizeof(unichar));

	/* make space for the color */
	if (entry->uses_extents) {
		memmove(entry->extents + entry->pos + len + 1, entry->extents + entry->pos + 1,
		        (entry->text_len-entry->pos) * sizeof(char *));
		for (i = 0; i < len; i++) {
			entry->extents[entry->pos + i + 1] = NULL;
		}
	}

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

	if (entry->utf8 && entry->pos == 0 && is_combining_char(chr))
		return;

	gui_entry_redraw_from(entry, entry->pos);

	entry_text_grow(entry, 1);

	/* make space for the string */
	memmove(entry->text + entry->pos + 1, entry->text + entry->pos,
	        (entry->text_len-entry->pos + 1) * sizeof(unichar));

	if (entry->uses_extents) {
		memmove(entry->extents + entry->pos + 1 + 1, entry->extents + entry->pos + 1,
		        (entry->text_len-entry->pos) * sizeof(char *));
		entry->extents[entry->pos + 1] = NULL;
	}

	entry->text[entry->pos] = chr;
	entry->text_len++;
	entry->pos++;

	gui_entry_fix_cursor(entry);
	gui_entry_draw(entry);
}

char *gui_entry_get_cutbuffer(GUI_ENTRY_REC *entry)
{
	GUI_ENTRY_CUTBUFFER_REC *tmp;
	char *buf;
        int i;

	g_return_val_if_fail(entry != NULL, NULL);

	if (entry->kill_ring == NULL || entry->kill_ring->data == NULL)
		return NULL;

	tmp = entry->kill_ring->data;

	if (tmp->cutbuffer == NULL)
                return NULL;

	if (entry->utf8)
		buf = g_ucs4_to_utf8(tmp->cutbuffer, -1, NULL, NULL, NULL);
	else {
		buf = g_malloc(tmp->cutbuffer_len*6 + 1);
		if (term_type == TERM_TYPE_BIG5)
			unichars_to_big5(tmp->cutbuffer, buf);
		else
			for (i = 0; i <= tmp->cutbuffer_len; i++)
				buf[i] = tmp->cutbuffer[i];
	}
	return buf;
}

char *gui_entry_get_next_cutbuffer(GUI_ENTRY_REC *entry)
{
	GUI_ENTRY_CUTBUFFER_REC *tmp;

	g_return_val_if_fail(entry != NULL, NULL);

	if (entry->kill_ring == NULL)
		return NULL;

	tmp = entry->kill_ring->data;

	entry->kill_ring = g_slist_remove(entry->kill_ring, tmp);
	entry->kill_ring = g_slist_append(entry->kill_ring, tmp);

	return gui_entry_get_cutbuffer(entry);
}

void gui_entry_erase_to(GUI_ENTRY_REC *entry, int pos, CUTBUFFER_UPDATE_OP update_cutbuffer)
{
	int newpos, size = 0;

	g_return_if_fail(entry != NULL);

	for (newpos = gui_entry_get_pos(entry); newpos > pos; size++)
		newpos = newpos - 1;
	gui_entry_erase(entry, size, update_cutbuffer);
}

static GUI_ENTRY_CUTBUFFER_REC *get_cutbuffer_rec(GUI_ENTRY_REC *entry, CUTBUFFER_UPDATE_OP update_cutbuffer)
{
	GUI_ENTRY_CUTBUFFER_REC *tmp;

	g_return_val_if_fail(entry != NULL, NULL);

	if (entry->kill_ring == NULL) {
		/* no kill ring exists */
		entry->kill_ring = g_slist_prepend(entry->kill_ring, (void *)NULL);
	} else {
		tmp = entry->kill_ring->data;

		if (tmp != NULL && tmp->cutbuffer_len > 0
		    && (!entry->previous_append_next_kill
			|| update_cutbuffer == CUTBUFFER_UPDATE_REPLACE)) {
			/* a cutbuffer exists and should be replaced */
			entry->kill_ring = g_slist_prepend(entry->kill_ring, (void *)NULL);
		}
	}

	if (g_slist_length(entry->kill_ring) > KILL_RING_MAX) {
		GUI_ENTRY_CUTBUFFER_REC *rec = g_slist_last(entry->kill_ring)->data;
		entry->kill_ring = g_slist_remove(entry->kill_ring, rec);
		if (rec != NULL) g_free(rec->cutbuffer);
		g_free(rec);
	}

	if (entry->kill_ring->data == NULL) {
		entry->kill_ring->data = g_new0(GUI_ENTRY_CUTBUFFER_REC, 1);
	}

	return entry->kill_ring->data;
}

void gui_entry_erase(GUI_ENTRY_REC *entry, int size, CUTBUFFER_UPDATE_OP update_cutbuffer)
{
	gboolean clear_enabled;
	size_t i, w = 0;

        g_return_if_fail(entry != NULL);
	clear_enabled = settings_get_bool("empty_kill_clears_cutbuffer");

	if (entry->pos < size || (size == 0 && !clear_enabled))
		return;

	if (update_cutbuffer != CUTBUFFER_UPDATE_NOOP) {
		int cutbuffer_new_size;
		unichar *tmpcutbuffer;
		GUI_ENTRY_CUTBUFFER_REC *tmp = get_cutbuffer_rec(entry, update_cutbuffer);

		if (tmp->cutbuffer_len == 0) {
			update_cutbuffer = CUTBUFFER_UPDATE_REPLACE;
		}

		cutbuffer_new_size = tmp->cutbuffer_len + size;
		tmpcutbuffer = tmp->cutbuffer;
		entry->append_next_kill = TRUE;
		switch (update_cutbuffer) {
		case CUTBUFFER_UPDATE_APPEND:
			tmp->cutbuffer = g_new(unichar, cutbuffer_new_size + 1);
			memcpy(tmp->cutbuffer, tmpcutbuffer, tmp->cutbuffer_len * sizeof(unichar));
			memcpy(tmp->cutbuffer + tmp->cutbuffer_len, entry->text + entry->pos - size,
			       size * sizeof(unichar));

			tmp->cutbuffer_len = cutbuffer_new_size;
			tmp->cutbuffer[cutbuffer_new_size] = '\0';
			g_free(tmpcutbuffer);
			break;

		case CUTBUFFER_UPDATE_PREPEND:
			tmp->cutbuffer = g_new(unichar, cutbuffer_new_size + 1);
			memcpy(tmp->cutbuffer, entry->text + entry->pos - size,
			       size * sizeof(unichar));
			memcpy(tmp->cutbuffer + size, tmpcutbuffer,
			       tmp->cutbuffer_len * sizeof(unichar));

			tmp->cutbuffer_len = cutbuffer_new_size;
			tmp->cutbuffer[cutbuffer_new_size] = '\0';
			g_free(tmpcutbuffer);
			break;

		case CUTBUFFER_UPDATE_REPLACE:
			/* put erased text to cutbuffer */
			if (tmp->cutbuffer_len < size || tmp->cutbuffer == NULL) {
				g_free(tmp->cutbuffer);
				tmp->cutbuffer = g_new(unichar, size + 1);
			}

			tmp->cutbuffer_len = size;
			tmp->cutbuffer[size] = '\0';
			memcpy(tmp->cutbuffer, entry->text + entry->pos - size,
			       size * sizeof(unichar));
			break;

		case CUTBUFFER_UPDATE_NOOP:
			/* cannot happen, handled in "if" */
			break;
		}
	}

	if (size == 0) {
		/* we just wanted to clear the cutbuffer */
		return;
	}

	if (entry->utf8)
		while (entry->pos > size + w && is_combining_char(entry->text[entry->pos - size - w]))
			w++;

	memmove(entry->text + entry->pos - size, entry->text + entry->pos,
	        (entry->text_len-entry->pos+1) * sizeof(unichar));

	if (entry->uses_extents) {
		for (i = entry->pos - size; i < entry->pos; i++) {
			if (entry->extents[i+1] != NULL) {
				g_free(entry->extents[i+1]);
			}
		}
		memmove(entry->extents + entry->pos - size + 1, entry->extents + entry->pos + 1,
		        (entry->text_len - entry->pos) * sizeof(void *)); /* no null terminator here */
		for (i = 0; i < size; i++) {
			entry->extents[entry->text_len - i] = NULL;
		}
		if (entry->text_len == size && entry->extents[0] != NULL) {
			g_free(entry->extents[0]);
			entry->extents[0] = NULL;
		}
	}

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
		       is_combining_char(entry->text[entry->pos+size])) size++;

	memmove(entry->text + entry->pos, entry->text + entry->pos + size,
	        (entry->text_len-entry->pos-size+1) * sizeof(unichar));

	if (entry->uses_extents) {
		int i;
		for (i = 0; i < size; i++) {
			g_free(entry->extents[entry->pos + i + 1]);
		}
		memmove(entry->extents + entry->pos + 1, entry->extents + entry->pos + size + 1,
		        (entry->text_len-entry->pos-size) * sizeof(char *));
		for (i = 0; i < size; i++) {
			entry->extents[entry->text_len - i] = NULL;
		}
		if (entry->text_len == size && entry->extents[0] != NULL) {
			g_free(entry->extents[0]);
			entry->extents[0] = NULL;
		}
	}

	entry->text_len -= size;

	gui_entry_redraw_from(entry, entry->pos);
	gui_entry_fix_cursor(entry);
	gui_entry_draw(entry);
}

void gui_entry_erase_word(GUI_ENTRY_REC *entry, int to_space, CUTBUFFER_UPDATE_OP cutbuffer_op)
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

	gui_entry_erase(entry, entry->pos-to, cutbuffer_op);
}

void gui_entry_erase_next_word(GUI_ENTRY_REC *entry, int to_space, CUTBUFFER_UPDATE_OP cutbuffer_op)
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
        gui_entry_erase(entry, size, cutbuffer_op);
}

void gui_entry_transpose_chars(GUI_ENTRY_REC *entry)
{
        unichar chr;
	char *extent;

	if (entry->pos == 0 || entry->text_len < 2)
                return;

	if (entry->pos == entry->text_len)
                entry->pos--;

        /* swap chars */
	chr = entry->text[entry->pos];
	entry->text[entry->pos] = entry->text[entry->pos-1];
        entry->text[entry->pos-1] = chr;

	if (entry->uses_extents) {
		extent = entry->extents[entry->pos+1];
		entry->extents[entry->pos+1] = entry->extents[entry->pos];
		entry->extents[entry->pos] = extent;
	}

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
		char **first_extent, **sep_extent, **second_extent;
		int i;

		first  = (unichar *) g_malloc( (epos1 - spos1) * sizeof(unichar) );
		sep    = (unichar *) g_malloc( (spos2 - epos1) * sizeof(unichar) );
		second = (unichar *) g_malloc( (epos2 - spos2) * sizeof(unichar) );

		first_extent  = (char **) g_malloc( (epos1 - spos1) * sizeof(char *) );
		sep_extent    = (char **) g_malloc( (spos2 - epos1) * sizeof(char *) );
		second_extent = (char **) g_malloc( (epos2 - spos2) * sizeof(char *) );

		for (i = spos1; i < epos1; i++) {
			first[i-spos1] = entry->text[i];
			if (entry->uses_extents)
				first_extent[i-spos1] = entry->extents[i+1];
		}
		for (i = epos1; i < spos2; i++) {
			sep[i-epos1] = entry->text[i];
			if (entry->uses_extents)
				sep_extent[i-epos1] = entry->extents[i+1];
		}
		for (i = spos2; i < epos2; i++) {
			second[i-spos2] = entry->text[i];
			if (entry->uses_extents)
				second_extent[i-spos2] = entry->extents[i+1];
		}

		entry->pos = spos1;
		for (i = 0; i < epos2-spos2; i++) {
			entry->text[entry->pos] = second[i];
			if (entry->uses_extents)
				entry->extents[entry->pos+1] = second_extent[i];
			entry->pos++;
		}
		for (i = 0; i < spos2-epos1; i++) {
			entry->text[entry->pos] = sep[i];
			if (entry->uses_extents)
				entry->extents[entry->pos+1] = sep_extent[i];
			entry->pos++;
		}
		for (i = 0; i < epos1-spos1; i++) {
			entry->text[entry->pos] = first[i];
			if (entry->uses_extents)
				entry->extents[entry->pos+1] = first_extent[i];
			entry->pos++;
		}

		g_free(first);
		g_free(sep);
		g_free(second);

		g_free(first_extent);
		g_free(sep_extent);
		g_free(second_extent);
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

	if (pos >= 0 && pos <= entry->text_len) {
		entry->pos = pos;

		/* For UTF-8, ensure we're at the start of a grapheme cluster */
		if (entry->utf8) {
			entry->pos = unichar_array_find_cluster_start(entry->text, entry->text_len, entry->pos);
		}
	}

	gui_entry_fix_cursor(entry);
	gui_entry_draw(entry);
}

void gui_entry_set_text_and_pos_bytes(GUI_ENTRY_REC *entry, const char *str, int pos_bytes)
{
	int pos, extents_alloc;
	char **extents;
	const char *ptr;

	g_return_if_fail(entry != NULL);

	extents = entry->extents;
	extents_alloc = entry->text_alloc;
	entry->extents = NULL;
	entry->uses_extents = FALSE;

	gui_entry_set_text(entry, str);

	if (entry->utf8) {
		g_utf8_validate(str, pos_bytes, &ptr);
		pos = g_utf8_pointer_to_offset(str, ptr);
	} else if (term_type == TERM_TYPE_BIG5)
		pos = strlen_big5((const unsigned char *)str) - strlen_big5((const unsigned char *)(str + pos_bytes));
	else
		pos = pos_bytes;

	if (extents != NULL) {
		entry->uses_extents = TRUE;
		entry->extents = extents;
		if (extents_alloc < entry->text_alloc) {
			int i;
			entry->extents = g_realloc(entry->extents,
				   sizeof(char *) * entry->text_alloc);
			for (i = extents_alloc; i < entry->text_alloc; i++) {
				entry->extents[i] = NULL;
			}
		}
	}
	gui_entry_redraw_from(entry, 0);
	gui_entry_set_pos(entry, pos);
}

void gui_entry_move_pos(GUI_ENTRY_REC *entry, int pos)
{
        g_return_if_fail(entry != NULL);

	if (!entry->utf8) {
		/* Legacy behavior for non-UTF8 */
		if (entry->pos + pos >= 0 && entry->pos + pos <= entry->text_len)
			entry->pos += pos;
	} else {
		/* UTF-8: Move by grapheme clusters for proper UX */
		int i, before_advance, cluster_start;

		if (pos > 0) {
			/* Move forward by grapheme clusters */
			for (i = 0; i < pos && entry->pos < entry->text_len; i++) {
				before_advance = entry->pos;
				unichar_array_advance_cluster(entry->text, entry->text_len, &entry->pos);
				/* Safety: if position didn't change and we're not at end, stop */
				if (entry->pos == before_advance && entry->pos < entry->text_len)
					break;
			}
		} else if (pos < 0) {
			/* Move backward by grapheme clusters */
			for (i = 0; i > pos && entry->pos > 0; i--) {
				unichar_array_move_cluster_backward(entry->text, entry->text_len, &entry->pos);
			}
		}

		/* Ensure we're always at the start of a grapheme cluster */
		cluster_start = unichar_array_find_cluster_start(entry->text, entry->text_len, entry->pos);
		entry->pos = cluster_start;
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

static void gui_entry_alloc_extents(GUI_ENTRY_REC *entry)
{
	entry->uses_extents = TRUE;
	entry->extents = g_new0(char *, entry->text_alloc);
}

void gui_entry_set_extent(GUI_ENTRY_REC *entry, int pos, const char *text)
{
	int update = FALSE;

	g_return_if_fail(entry != NULL);

	if (pos < 0 || pos > entry->text_len)
		return;

	if (text == NULL)
		return;

	if (!entry->uses_extents) {
		gui_entry_alloc_extents(entry);
	}

	if (g_strcmp0(entry->extents[pos], text) != 0) {
		g_free(entry->extents[pos]);
		if (*text == '\0') {
			entry->extents[pos] = NULL;
		} else {
			entry->extents[pos] = g_strdup(text);
		}
		update = TRUE;
	}

	if (update) {
		gui_entry_redraw_from(entry, pos - 1);
		gui_entry_fix_cursor(entry);
		gui_entry_draw(entry);
	}
}

void gui_entry_set_extents(GUI_ENTRY_REC *entry, int pos, int len, const char *left, const char *right)
{
	int end, update = FALSE;

	g_return_if_fail(entry != NULL);

	if (pos < 0 || len < 0 || pos > entry->text_len)
		return;

	end = pos + len;

	if (end > entry->text_len)
		end = entry->text_len;

	if (!entry->uses_extents) {
		gui_entry_alloc_extents(entry);
	}

	if (g_strcmp0(entry->extents[pos], left) != 0) {
		g_free(entry->extents[pos]);
		if (*left == '\0') {
			entry->extents[pos] = NULL;
		} else {
			entry->extents[pos] = g_strdup(left);
		}
		update = TRUE;
	}

	if (pos != end && g_strcmp0(entry->extents[end], right) != 0) {
		g_free(entry->extents[end]);
		if (*right == '\0') {
			entry->extents[end] = NULL;
		} else {
			entry->extents[end] = g_strdup(right);
		}
		update = TRUE;
	}

	if (update) {
		gui_entry_redraw_from(entry, pos - 1);
		gui_entry_fix_cursor(entry);
		gui_entry_draw(entry);
	}
}

void gui_entry_clear_extents(GUI_ENTRY_REC *entry, int pos, int len)
{
	int i, end, update = FALSE;

	g_return_if_fail(entry != NULL);

	if (pos < 0 || len < 0 || pos > entry->text_len)
		return;

	end = pos + len;

	if (end > entry->text_len)
		end = entry->text_len;

	if (!entry->uses_extents) {
		return;
	}

	for (i = pos; i <= end; i++) {
		if (entry->extents[i] != NULL) {
			g_free(entry->extents[i]);
			entry->extents[i] = NULL;
			update = TRUE;
		}
	}

	if (update) {
		gui_entry_redraw_from(entry, pos);
		gui_entry_fix_cursor(entry);
		gui_entry_draw(entry);
	}
}

char *gui_entry_get_extent(GUI_ENTRY_REC *entry, int pos)
{
	g_return_val_if_fail(entry != NULL, NULL);

	if (!entry->uses_extents)
		return NULL;

	if (pos < 0 || pos >= entry->text_len)
		return NULL;

	return entry->extents[pos];
}

#define POS_FLAG "%|"
GSList *gui_entry_get_text_and_extents(GUI_ENTRY_REC *entry)
{
	GSList *list = NULL;
	GString *str;
	int i;

	g_return_val_if_fail(entry != NULL, NULL);

	if (entry->uses_extents && entry->extents[0] != NULL) {
		if (entry->pos == 0) {
			list = g_slist_prepend(list, g_strconcat(entry->extents[0], POS_FLAG, NULL));
		} else {
			list = g_slist_prepend(list, g_strdup(entry->extents[0]));
		}
	} else {
		if (entry->pos == 0) {
			list = g_slist_prepend(list, g_strdup(POS_FLAG));
		} else {
			list = g_slist_prepend(list, NULL);
		}
	}

	str = g_string_sized_new(entry->text_alloc);
	for (i = 0; i < entry->text_len; i++) {
		if (entry->utf8) {
			g_string_append_unichar(str, entry->text[i]);
		} else if (term_type == TERM_TYPE_BIG5) {
			if(entry->text[i] > 0xff)
				g_string_append_c(str, (entry->text[i] >> 8) & 0xff);
			g_string_append_c(str, entry->text[i] & 0xff);
		} else {
			g_string_append_c(str, entry->text[i]);
		}
		if (entry->pos == i+1 || (entry->uses_extents && entry->extents[i+1] != NULL)) {
			list = g_slist_prepend(list, g_strdup(str->str));
			g_string_truncate(str, 0);
			if (entry->uses_extents && entry->extents[i+1] != NULL) {
				if (entry->pos == i+1) {
					list = g_slist_prepend(list, g_strconcat(entry->extents[i+1], POS_FLAG, NULL));
				} else {
					list = g_slist_prepend(list, g_strdup(entry->extents[i+1]));
				}
			} else if (entry->pos == i+1) {
				list = g_slist_prepend(list, g_strdup(POS_FLAG));
			}
		}
	}
	if (str->len > 0) {
		list = g_slist_prepend(list, g_strdup(str->str));
	}
	list = g_slist_reverse(list);
	g_string_free(str, TRUE);

	return list;
}

void gui_entry_set_text_and_extents(GUI_ENTRY_REC *entry, GSList *list)
{
	GSList *tmp;
	int pos = -1;
	int is_extent = 1;

	gui_entry_set_text(entry, "");
	for (tmp = list, is_extent = TRUE; tmp != NULL; tmp = tmp->next, is_extent ^= 1) {
		if (is_extent) {
			char *extent;
			int len;

			if (tmp->data == NULL)
				continue;

			extent = g_strdup(tmp->data);
			len = strlen(extent);
			if (len >= strlen(POS_FLAG) && g_strcmp0(&extent[len-strlen(POS_FLAG)], POS_FLAG) == 0) {
				char *tmp;
				tmp = extent;
				extent = g_strndup(tmp, len - strlen(POS_FLAG));
				g_free(tmp);
				pos = entry->pos;
			}

			if (strlen(extent) > 0) {
				gui_entry_set_extent(entry, entry->pos, extent);
			}
			g_free(extent);
		} else {
			gui_entry_insert_text(entry, tmp->data);
		}
	}
	gui_entry_set_pos(entry, pos);
}

void gui_entry_init(void)
{
	settings_add_bool("lookandfeel", "empty_kill_clears_cutbuffer", FALSE);
}

void gui_entry_deinit(void)
{
}
