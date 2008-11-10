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

#include "module.h"

int strlen_utf8(const char *str)
{
	const unsigned char *p = (const unsigned char *) str;
        int len;
	unichar chr_r;

	len = 0;
	while (*p != '\0') {
		chr_r = g_utf8_get_char_validated(p, -1);
		if (chr_r & 0x80000000)
			break;
		len++;
                p = g_utf8_next_char(p);
	}
        return len;
}

void utf8_to_utf16(const char *str, unichar *out)
{
	const unsigned char *p = (const unsigned char *) str;
	unichar result;

	while (*p != '\0') {
		result = g_utf8_get_char_validated(p, -1);
		if (result & 0x80000000)
			break;

                p = g_utf8_next_char(p);
                *out++ = result;
	}

	*out = '\0';
}

void utf16_to_utf8(const unichar *str, char *out)
{
	int len;

	while (*str != '\0') {
		len = g_unichar_to_utf8(*str, out);
                out += len;

		str++;
	}
	*out = '\0';
}

void utf16_to_utf8_with_pos(const unichar *str, int spos, char *out, int *opos)
{
	int len;
	const unichar *sstart = str;
	char *ostart = out;

	*opos = 0;
	while (*str != '\0') {
		len = g_unichar_to_utf8(*str, out);
                out += len;

		str++;
		if(str - sstart == spos)
			*opos = out - ostart;
	}
	*out = '\0';
}
