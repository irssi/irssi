/* utf8.c - Operations on UTF-8 strings.
 *
 * Copyright (C) 2002 Timo Sirainen
 *
 * Based on GLib code by
 *
 * Copyright (C) 1999 Tom Tromey
 * Copyright (C) 2000 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <glib.h>
#include "module.h"

/*
 * Return the width (number of columns when displayed) of the character pointed
 * by c.
 */
int get_utf8_char_width(const gchar *c) {
	gunichar uc;
	int char_width;
	uc = g_utf8_get_char(c);
	char_width = g_unichar_isprint(uc) ? (1 + g_unichar_iswide(uc)) : 0;
	return char_width;
}

/*
 * Return the number of columns taken by the s string, assuming its end is
 * marked with a '\0' character and assuming it is a UTF-8 (multibyte) string.
 * If s is NULL, this function returns -1.
 * By default, this function takes care to validate s by calling
 * g_utf8_validate(s, -1, NULL). If this check is deemed unnecessary, passing a
 * non-zero value as skip_validation will skip that step. If the validation
 * fails, this function returns -1. Otherwise, it will strive to provide a
 * value as close as possible to what is expected.
 */
int get_utf8_string_width(const gchar *s, int skip_validation) {
	const gchar *c;
	int str_width;

	/* Ensure s is non-NULL: */
	if (!s) {
		return -1;
	}

	/* Validate the string, unless required otherwise: */
	if (!skip_validation) {
		if (!g_utf8_validate(s, -1, NULL)) {
			/* Another possibility here would be to return strlen(s). */
			return -1;
		}
	}

	/* Iterate over characters to determine the width: */
	str_width = 0;
	for (c = s; *c; c = g_utf8_next_char(c)) {
		str_width += get_utf8_char_width(c);
	}
	/* Note: there probably are some Unicode subtleties (Fitzpatrick
	 * modifiers?) that make the above implementation somewhat naive, but we
	 * have to start somewhere.
	 */
	return str_width;
}
