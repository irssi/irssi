/*
 masks.c : irssi

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
#include <irssi/src/core/network.h>
#include <irssi/src/core/misc.h>

#include <irssi/src/core/servers.h>

/* Returns TRUE if mask contains '!' ie. address should be checked too.
   Also checks if mask contained any wildcards. */
static int check_address(const char *mask, int *wildcards)
{
	int ret;

	*wildcards = FALSE;
	ret = FALSE;
	while (*mask != '\0') {
		if (*mask == '!') {
			if (*wildcards) return TRUE;
			ret = TRUE;
		}

		if (*mask == '?' || *mask == '*') {
			*wildcards = TRUE;
			if (ret) return TRUE;
		}
		mask++;
	}

	return ret;
}

static int check_mask(SERVER_REC *server, const char *mask,
		      const char *str, int wildcards)
{
	if (server != NULL && server->mask_match_func != NULL) {
		/* use server specified mask match function */
		return server->mask_match_func(mask, str);
	}

	return wildcards ? match_wildcards(mask, str) :
		g_ascii_strcasecmp(mask, str) == 0;
}

int mask_match(SERVER_REC *server, const char *mask,
	       const char *nick, const char *user, const char *host)
{
	char *str;
	int ret, wildcards;

	g_return_val_if_fail(server == NULL || IS_SERVER(server), FALSE);
	g_return_val_if_fail(mask != NULL && nick != NULL &&
			     user != NULL && host != NULL, FALSE);

	str = !check_address(mask, &wildcards) ? (char *) nick :
		g_strdup_printf("%s!%s@%s", nick, user, host);
	ret = check_mask(server, mask, str, wildcards);
	if (str != nick) g_free(str);

	return ret;
}

int mask_match_address(SERVER_REC *server, const char *mask,
		       const char *nick, const char *address)
{
	char *str;
	int ret, wildcards;

	g_return_val_if_fail(server == NULL || IS_SERVER(server), FALSE);
	g_return_val_if_fail(mask != NULL && nick != NULL, FALSE);
	if (address == NULL) address = "";

	str = !check_address(mask, &wildcards) ? (char *) nick :
		g_strdup_printf("%s!%s", nick, address);
	ret = check_mask(server, mask, str, wildcards);
	if (str != nick) g_free(str);

	return ret;
}

int masks_match(SERVER_REC *server, const char *masks,
		const char *nick, const char *address)
{
	int (*mask_match_func)(const char *, const char *);
	char **list, **tmp, *mask;
	int found;

	g_return_val_if_fail(server == NULL || IS_SERVER(server), FALSE);
	g_return_val_if_fail(masks != NULL &&
			     nick != NULL && address != NULL, FALSE);

	if (*masks == '\0')
                return FALSE;

	mask_match_func = server != NULL && server->mask_match_func != NULL ?
		server->mask_match_func : match_wildcards;

	found = FALSE;
	mask = g_strdup_printf("%s!%s", nick, address);
	list = g_strsplit(masks, " ", -1);
	for (tmp = list; *tmp != NULL; tmp++) {
		if (g_ascii_strcasecmp(*tmp, nick) == 0) {
                        found = TRUE;
			break;
		}

		if (mask_match_func(*tmp, mask)) {
			found = TRUE;
			break;
		}
	}
	g_strfreev(list);
	g_free(mask);

	return found;
}
