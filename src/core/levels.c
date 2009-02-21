/*
 levels.c : irssi

    Copyright (C) 1999-2000 Timo Sirainen

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
#include "levels.h"

static const char *levels[] = {
	"CRAP",
	"MSGS",
	"PUBLICS",
	"NOTICES",
	"SNOTES",
	"CTCPS",
	"ACTIONS",
	"JOINS",
	"PARTS",
	"QUITS",
	"KICKS",
	"MODES",
	"TOPICS",
	"WALLOPS",
	"INVITES",
	"NICKS",
	"DCC",
	"DCCMSGS",
	"CLIENTNOTICES",
	"CLIENTCRAP",
	"CLIENTERRORS",
	"HILIGHTS",

	"NOHILIGHT",
	NULL
};

int level_get(const char *level)
{
	int n, len, match;

	if (g_ascii_strcasecmp(level, "ALL") == 0 || strcmp(level, "*") == 0)
		return MSGLEVEL_ALL;

	if (g_ascii_strcasecmp(level, "NEVER") == 0)
		return MSGLEVEL_NEVER;

	len = strlen(level);
	if (len == 0) return 0;

	/* partial match allowed, as long as it's the only one that matches */
	match = 0;
	for (n = 0; levels[n] != NULL; n++) {
		if (g_ascii_strncasecmp(levels[n], level, len) == 0) {
			if ((int)strlen(levels[n]) == len) {
				/* full match */
				return 1L << n;
			}
			if (match > 0) {
				/* ambiguous - abort */
				return 0;
			}
			match = 1L << n;
		}
	}

	return match;
}

int level2bits(const char *level, int *errorp)
{
	char *orig, *str, *ptr;
	int ret, singlelevel, negative;

	if (errorp != NULL)
		*errorp = FALSE;

	g_return_val_if_fail(level != NULL, 0);

	if (*level == '\0')
		return 0;

	orig = str = g_strdup(level);

	ret = 0;
	for (ptr = str; ; str++) {
		if (*str == ' ')
			*str++ = '\0';
		else if (*str != '\0')
			continue;

		negative = *ptr == '-';
		if (*ptr == '-' || *ptr == '+') ptr++;

		singlelevel = level_get(ptr);
		if (singlelevel != 0) {
			ret = !negative ? (ret | singlelevel) :
				(ret & ~singlelevel);
		} else if (errorp != NULL)
			*errorp = TRUE;

       		while (*str == ' ') str++;
		if (*str == '\0') break;

       		ptr = str;
	}
	g_free(orig);

	return ret;
}

char *bits2level(int bits)
{
	GString *str;
	char *ret;
	int n;

	if (bits == 0)
		return g_strdup("");

	if (bits == MSGLEVEL_ALL)
		return g_strdup("ALL");

	str = g_string_new(NULL);
	if (bits & MSGLEVEL_NEVER)
		g_string_append(str, "NEVER ");

	for (n = 0; levels[n] != NULL; n++) {
		if (bits & (1L << n))
			g_string_append_printf(str, "%s ", levels[n]);
	}
        if (str->len > 0)
		g_string_truncate(str, str->len-1);

	ret = str->str;
	g_string_free(str, FALSE);

	return ret;
}

int combine_level(int dest, const char *src)
{
	char **list, **item, *itemname;
	int itemlevel;

	g_return_val_if_fail(src != NULL, dest);

	list = g_strsplit(src, " ", -1);
	for (item = list; *item != NULL; item++) {
		itemname = *item + (**item == '+' || **item == '-' ? 1 : 0);
		itemlevel = level_get(itemname);

		if (strcmp(itemname, "NONE") == 0)
                        dest = 0;
		else if (**item == '-')
			dest &= ~(itemlevel);
		else
			dest |= itemlevel;
	}
	g_strfreev(list);

	return dest;
}
