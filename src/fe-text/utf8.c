/* utf8.c - Operations on UTF-8 strings.
 *
 * Copyright (C) 2002 Timo Sirainen
 *
 * Based on GLib code by
 *
 * Copyright (C) 1999 Tom Tromey
 * Copyright (C) 2000 Red Hat, Inc.
 *
 * UTF-8 width tables based on locale data from GNU libc by
 *
 * Copyright (C) 1991-2002 Free Software Foundation, Inc.
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
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

unichar get_utf8_char(const unsigned char **ptr, int len)
{
	int i, result, mask, chrlen;

        mask = 0;
	UTF8_COMPUTE(**ptr, mask, chrlen);
	if (chrlen == -1)
		return (unichar) -2;

	if (chrlen > len)
                return (unichar) -1;

	UTF8_GET(result, *ptr, i, mask, chrlen);
	if (result == -1)
                return (unichar) -2;

	*ptr += chrlen-1;
        return result;
}

int strlen_utf8(const char *str)
{
	const unsigned char *p = (const unsigned char *) str;
        int len;

	len = 0;
	while (*p != '\0' && get_utf8_char(&p, 6) > 0) {
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

static const unichar wcc[] = {
	0x0, 0x300, 0x34F, 0x360, 0x363, 0x483, 0x487, 0x488, 0x48A, 0x591,
	0x5A2, 0x5A3, 0x5BA, 0x5BB, 0x5BE, 0x5BF, 0x5C0, 0x5C1, 0x5C3, 0x5C4,
	0x5C5, 0x64B, 0x656, 0x670, 0x671, 0x6D6, 0x6E5, 0x6E7, 0x6E9, 0x6EA,
	0x6EE, 0x70F, 0x710, 0x711, 0x712, 0x730, 0x74B, 0x7A6, 0x7B1, 0x901,
	0x903, 0x93C, 0x93D, 0x941, 0x949, 0x94D, 0x94E, 0x951, 0x955, 0x962,
	0x964, 0x981, 0x982, 0x9BC, 0x9BD, 0x9C1, 0x9C5, 0x9CD, 0x9CE, 0x9E2,
	0x9E4, 0xA02, 0xA03, 0xA3C, 0xA3D, 0xA41, 0xA43, 0xA47, 0xA49, 0xA4B,
	0xA4E, 0xA70, 0xA72, 0xA81, 0xA83, 0xABC, 0xABD, 0xAC1, 0xAC6, 0xAC7,
	0xAC9, 0xACD, 0xACE, 0xB01, 0xB02, 0xB3C, 0xB3D, 0xB3F, 0xB40, 0xB41,
	0xB44, 0xB4D, 0xB4E, 0xB56, 0xB57, 0xB82, 0xB83, 0xBC0, 0xBC1, 0xBCD,
	0xBCE, 0xC3E, 0xC41, 0xC46, 0xC49, 0xC4A, 0xC4E, 0xC55, 0xC57, 0xCBF,
	0xCC0, 0xCC6, 0xCC7, 0xCCC, 0xCCE, 0xD41, 0xD44, 0xD4D, 0xD4E, 0xDCA,
	0xDCB, 0xDD2, 0xDD5, 0xDD6, 0xDD7, 0xE31, 0xE32, 0xE34, 0xE3B, 0xE47,
	0xE4F, 0xEB1, 0xEB2, 0xEB4, 0xEBA, 0xEBB, 0xEBD, 0xEC8, 0xECE, 0xF18,
	0xF1A, 0xF35, 0xF36, 0xF37, 0xF38, 0xF39, 0xF3A, 0xF71, 0xF7F, 0xF80,
	0xF85, 0xF86, 0xF88, 0xF90, 0xF98, 0xF99, 0xFBD, 0xFC6, 0xFC7, 0x102D,
	0x1031, 0x1032, 0x1033, 0x1036, 0x1038, 0x1039, 0x103A, 0x1058, 0x105A,
	0x1100, 0x1160, 0x17B7, 0x17BE, 0x17C6, 0x17C7, 0x17C9, 0x17D4, 0x180B,
	0x180F, 0x18A9, 0x18AA, 0x200B, 0x2010, 0x202A, 0x202F, 0x206A, 0x2070,
	0x20D0, 0x20E4, 0x2E80, 0x3008, 0x300C, 0x3014, 0x3016, 0x3018, 0x301C,
	0x302A, 0x3030, 0x303F, 0x3041, 0x3095, 0x3099, 0x309B, 0xA4C7, 0xAC00,
	0xD7A4, 0xF8F0, 0xF900, 0xFA2E, 0xFB1E, 0xFB1F, 0xFE20, 0xFE24, 0xFE30,
	0xFE6C, 0xFEFF, 0xFF00, 0xFF01, 0xFF5F, 0xFFE0, 0xFFE7, 0xFFF9, 0xFFFC,
#if 1
	0x1D167, 0x1D16A, 0x1D173, 0x1D183, 0x1D185, 0x1D18C, 0x1D1AA, 0x1D1AE,
	0x20000, 0x2A6D7, 0x2F800, 0x2FA1E, 0xE0001, 0xE0002, 0xE0020, 0xE0080
#endif
};

static const int wccnum = sizeof(wcc) / sizeof(wcc[0]) - 1;

static const char wws[] = {
	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
	1, 2, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 2, 1, 2,
	1, 2, 1, 2, 0, 2, 1, 2, 1, 0, 2, 1, 2, 1, 0, 2, 1, 0, 1, 0, 1, 2, 1, 0,
	1, 2, 1, 2, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 2, 1, 2, 1, 0, 1, 0, 1, -1
};

int utf8_width(unichar c)
{
	int p, q, r;
	unichar d;

	if (c < wcc[1])
		return 1;

	p = 0;
	q = wccnum;

	while (p < q - 1) {
		r = (p + q)/2;
		d = wcc[r];
		if (d < c)
			p = r;
		else if (d > c)
			q = r;
		else
			return wws[r];
	}

	return wws[p];
}
