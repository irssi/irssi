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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "network.h"
#include "misc.h"

#include "irc.h"
#include "masks.h"

static int check_mask(const char *mask, int *wildcards)
{
	while (*mask != '\0') {
		if (*mask == '!')
			return TRUE;

		if (*mask == '?' || *mask == '*')
			*wildcards = TRUE;
		mask++;
	}

	return FALSE;
}

int irc_mask_match(const char *mask, const char *nick, const char *user, const char *host)
{
	char *str;
	int ret, wildcards;

	if (!check_mask(mask, &wildcards)) {
		return wildcards ?
			match_wildcards(mask, nick) :
			g_strcasecmp(mask, nick) == 0;
	}

	str = g_strdup_printf("%s!%s@%s", nick, user, host);
	ret = match_wildcards(mask, str);
	g_free(str);

	return ret;
}

int irc_mask_match_address(const char *mask, const char *nick, const char *address)
{
	char *str;
	int ret, wildcards;

	g_return_val_if_fail(address != NULL, FALSE);

	if (!check_mask(mask, &wildcards)) {
		return wildcards ?
			match_wildcards(mask, nick) :
			g_strcasecmp(mask, nick) == 0;
	}

	str = g_strdup_printf("%s!%s", nick, address);
	ret = match_wildcards(mask, str);
	g_free(str);

	return ret;
}

int irc_masks_match(const char *masks, const char *nick, const char *address)
{
	char **list, **tmp, *mask;

	g_return_val_if_fail(masks != NULL, FALSE);

	mask = g_strdup_printf("%s!%s", nick, address);
	list = g_strsplit(masks, " ", -1);
	for (tmp = list; *tmp != NULL; tmp++) {
		if (strchr(*tmp, '!') == NULL && g_strcasecmp(*tmp, nick) == 0)
			break;

		if (match_wildcards(*tmp, mask))
			break;
	}
	g_strfreev(list);
	g_free(mask);

	return *tmp != NULL;
}

static char *get_domain_mask(char *host)
{
	char *ptr;

	if (strchr(host, '.') == NULL) {
                /* no dots - toplevel domain or IPv6 address */
		ptr = strrchr(host, ':');
		if (ptr != NULL) {
			/* IPv6 address, ban the last 64k addresses */
			if (ptr[1] != '\0') strcpy(ptr+1, "*");
		}

		return host;
	}

        if (is_ipv4_address(host)) {
		/* it's an IP address, change last digit to * */
		ptr = strrchr(host, '.');
		if (ptr != NULL && isdigit(ptr[1]))
			strcpy(ptr+1, "*");
	} else {
		/* if more than one dot, skip the first
		   (dyn123.blah.net -> *.blah.net) */
		ptr = strchr(host, '.');
		if (ptr != NULL && strchr(ptr+1, '.') != NULL) {
			host = ptr-1;
                        host[0] = '*';
		}
	}

	return host;
}

char *irc_get_mask(const char *nick, const char *address, int flags)
{
	char *ret, *user, *host;

	/* strip -, ^ or ~ from start.. */
	user = g_strconcat("*", ishostflag(*address) ? address+1 : address, NULL);

	/* split user and host */
	host = strchr(user, '@');
	if (host == NULL) {
		g_free(user);
		return NULL;
	}
	*host++ = '\0';

	switch (flags & (IRC_MASK_HOST|IRC_MASK_DOMAIN)) {
	case IRC_MASK_HOST:
                /* we already have the host */
		break;
	case IRC_MASK_DOMAIN:
		/* domain - *.blah.org */
		host = get_domain_mask(host);
		break;
	default:
		/* no domain/host */
		host = "*";
		break;
	}

	ret = g_strdup_printf("%s!%s@%s",
			      (flags & IRC_MASK_NICK) ? nick : "*",
			      (flags & IRC_MASK_USER) ? user : "*",
			      host);
	g_free(user);

	return ret;
}
