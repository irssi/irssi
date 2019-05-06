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

#include <irssi/src/irc/core/irc-masks.h>

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
		if (ptr != NULL && i_isdigit(ptr[1]))
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
	user = g_strconcat("*", ishostflag(*address) ?
			   address+1 : address, NULL);

	/* split user and host */
	host = strchr(user, '@');
	if (host == NULL) {
		g_free(user);
		return NULL;
	}
	*host++ = '\0';

	if (flags & IRC_MASK_HOST) {
		/* we already have the host */
	} else if (flags & IRC_MASK_DOMAIN) {
		/* domain - *.blah.org */
		host = get_domain_mask(host);
	} else {
		/* no domain/host */
		host = "*";
	}

	ret = g_strdup_printf("%s!%s@%s",
			      (flags & IRC_MASK_NICK) ? nick : "*",
			      (flags & IRC_MASK_USER) ? user : "*",
			      host);
	g_free(user);

	return ret;
}
