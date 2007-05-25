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

#define UTF8_COMPUTE(Char, Mask, Len)					      \
  if (Char < 128)							      \
    {									      \
      Len = 1;								      \
      Mask = 0x7f;							      \
    }									      \
  else if ((Char & 0xe0) == 0xc0)					      \
    {									      \
      Len = 2;								      \
      Mask = 0x1f;							      \
    }									      \
  else if ((Char & 0xf0) == 0xe0)					      \
    {									      \
      Len = 3;								      \
      Mask = 0x0f;							      \
    }									      \
  else if ((Char & 0xf8) == 0xf0)					      \
    {									      \
      Len = 4;								      \
      Mask = 0x07;							      \
    }									      \
  else if ((Char & 0xfc) == 0xf8)					      \
    {									      \
      Len = 5;								      \
      Mask = 0x03;							      \
    }									      \
  else if ((Char & 0xfe) == 0xfc)					      \
    {									      \
      Len = 6;								      \
      Mask = 0x01;							      \
    }									      \
  else									      \
    Len = -1;

#define UTF8_GET(Result, Chars, Count, Mask, Len)			      \
  (Result) = (Chars)[0] & (Mask);					      \
  for ((Count) = 1; (Count) < (Len); ++(Count))				      \
    {									      \
      if (((Chars)[(Count)] & 0xc0) != 0x80)				      \
	{								      \
	  (Result) = -1;						      \
	  break;							      \
	}								      \
      (Result) <<= 6;							      \
      (Result) |= ((Chars)[(Count)] & 0x3f);				      \
    }

int get_utf8_char(const unsigned char **ptr, int len, unichar *chr_r)
{
	int i, result, mask, chrlen;

        mask = 0;
	UTF8_COMPUTE(**ptr, mask, chrlen);
	if (chrlen == -1)
		return -2;

	if (chrlen > len)
                return -1;

	UTF8_GET(result, *ptr, i, mask, chrlen);
	if (result == -1)
                return -2;
	
	*chr_r = (unichar) result;
	*ptr += chrlen-1;
        return result;
}

int strlen_utf8(const char *str)
{
	const unsigned char *p = (const unsigned char *) str;
        int len;
	unichar chr_r;

	len = 0;
	while (*p != '\0' && get_utf8_char(&p, 6, &chr_r) > 0) {
		len++;
                p++;
	}
        return len;
}

int utf16_char_to_utf8(unichar c, char *outbuf)
{
	int len, i, first;

        len = 0;
	if (c < 0x80) {
		first = 0;
		len = 1;
	} else if (c < 0x800) {
		first = 0xc0;
		len = 2;
	} else if (c < 0x10000) {
		first = 0xe0;
		len = 3;
	} else if (c < 0x200000) {
		first = 0xf0;
		len = 4;
	} else if (c < 0x4000000) {
		first = 0xf8;
		len = 5;
	} else {
		first = 0xfc;
		len = 6;
	}

	if (outbuf) {
		for (i = len - 1; i > 0; --i) {
			outbuf[i] = (c & 0x3f) | 0x80;
			c >>= 6;
		}
		outbuf[0] = c | first;
	}

	return len;
}

void utf8_to_utf16(const char *str, unichar *out)
{
	const unsigned char *p = (const unsigned char *) str;
        int i, result, mask, len;

	while (*p != '\0') {
                mask = 0;
		UTF8_COMPUTE(*p, mask, len);
		if (len == -1)
                        break;

		UTF8_GET(result, p, i, mask, len);
		if (result == -1)
                        break;

                p += len;
                *out++ = result;
	}

	*out = '\0';
}

void utf16_to_utf8(const unichar *str, char *out)
{
	int len;

	while (*str != '\0') {
		len = utf16_char_to_utf8(*str, out);
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
		len = utf16_char_to_utf8(*str, out);
                out += len;

		str++;
		if(str - sstart == spos)
			*opos = out - ostart;
	}
	*out = '\0';
}
