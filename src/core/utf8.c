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

#include "utf8.h"
#include "module.h"
#include "wcwidth.c"
/* Provide is_utf8(): */
#include "recode.h"

int string_advance(char const **str, int policy)
{
	if (policy == TREAT_STRING_AS_UTF8) {
		gunichar c;

		c = g_utf8_get_char(*str);
		*str = g_utf8_next_char(*str);

		return unichar_isprint(c) ? mk_wcwidth(c) : 1;
	} else {
		/* Assume TREAT_STRING_AS_BYTES: */
		*str += 1;

		return 1;
	}
}

int string_policy(const char *str)
{
	if (is_utf8()) {
		if (!str || g_utf8_validate(str, -1, NULL)) {
			/* No string provided or valid UTF-8 string: treat as UTF-8: */
			return TREAT_STRING_AS_UTF8;
		}
	}
	return TREAT_STRING_AS_BYTES;
}

int string_length(const char *str, int policy)
{
	g_return_val_if_fail(str != NULL, 0);

	if (policy == -1) {
		policy = string_policy(str);
	}

	if (policy == TREAT_STRING_AS_UTF8) {
		return g_utf8_strlen(str, -1);
	}
	else {
		/* Assume TREAT_STRING_AS_BYTES: */
		return strlen(str);
	}
}

int string_width(const char *str, int policy)
{
	int len;

	g_return_val_if_fail(str != NULL, 0);

	if (policy == -1) {
		policy = string_policy(str);
	}

	len = 0;
	while (*str != '\0') {
		len += string_advance(&str, policy);
	}
	return len;
}
