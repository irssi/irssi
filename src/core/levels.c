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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "levels.h"

static const char *levels[] =
{
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
	"CLIENTNOTICES",
	"CLIENTCRAP",
	"CLIENTERRORS",
	"HILIGHT",

	"NOHILIGHT",
	NULL
};

int level_get(const char *level)
{
	int n, len;

	if (strcmp(level, "ALL") == 0)
		return MSGLEVEL_ALL;

	if (strcmp(level, "NEVER") == 0)
		return MSGLEVEL_NEVER;

	/* I never remember if it was PUBLIC or PUBLICS, MSG or MSGS, etc.
	   So, make it work with both. */
	len = strlen(level);
	if (toupper(level[len-1]) == 'S') len--;

	for (n = 0; levels[n] != NULL; n++) {
		if (strncmp(levels[n], level, len) == 0 &&
		    (levels[n][len] == '\0' || strcmp(levels[n]+len, "S") == 0))
			return 1 << n;
	}

	return 0;
}

int level2bits(const char *level)
{
	char *orig, *str, *ptr;
	int ret, slevel, neg;

	g_return_val_if_fail(level != NULL, 0);

	if (*level == '\0')
		return 0;

	orig = str = g_strdup(level);
	g_strup(str);

	ret = 0;
	for (ptr = str; ; str++) {
		if (*str == ' ')
			*str++ = '\0';
		else if (*str != '\0')
			continue;

		neg = *ptr == '-' ? 1 : 0;
		if (*ptr == '-' || *ptr == '+') ptr++;

		slevel = level_get(ptr);
		if (slevel != 0) {
			ret = !neg ? (ret | slevel) :
				(ret & ~slevel);
		}

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
		if (bits & (1 << n))
			g_string_sprintfa(str, "%s ", levels[n]);
	}
	g_string_truncate(str, str->len-1);

	ret = str->str;
	g_string_free(str, FALSE);

	return ret;
}

int combine_level(int dest, const char *src)
{
	char **list, **item;
	int itemlevel;

	g_return_val_if_fail(src != NULL, dest);

	list = g_strsplit(src, " ", -1);
	for (item = list; *item != NULL; item++) {
                g_strup(*item);
		itemlevel = level_get(*item + (**item == '+' || **item == '-' ? 1 : 0));
		if (**item == '-')
			dest &= ~(itemlevel);
		else
			dest |= itemlevel;
	}
	g_strfreev(list);

	return dest;
}
