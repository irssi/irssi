/*
 irc-hilight-text.c : irssi

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

#include "hilight-text.h"

char *irc_hilight_find_nick(const char *channel, const char *nick, const char *address)
{
	GSList *tmp;
        char *color;
	int len, best_match;

	g_return_val_if_fail(channel != NULL, NULL);
	g_return_val_if_fail(nick != NULL, NULL);
	g_return_val_if_fail(address != NULL, NULL);

	color = NULL; best_match = 0;
	for (tmp = hilights; tmp != NULL; tmp = tmp->next) {
		HILIGHT_REC *rec = tmp->data;

		if (!rec->nickmask)
			continue;

		len = strlen(rec->text);
		if (best_match < len) {
			best_match = len;
			color = rec->color;
		}
	}

	if (best_match == 0)
		return NULL;

	if (color == NULL) color = "\00316";
	return g_strconcat(isdigit(*color) ? "\003" : "", color, NULL);
}
