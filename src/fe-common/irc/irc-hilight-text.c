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
#include "signals.h"
#include "settings.h"

#include "hilight-text.h"

static int last_color;

char *irc_hilight_find_nick(const char *channel, const char *nick,
			    const char *address, int level, const char *msg)
{
	char *color, *mask;

        mask = g_strdup_printf("%s!%s", nick, address);
	color = hilight_match(channel, mask, level, msg);
	g_free(mask);

	last_color = (color != NULL && *color == 3) ?
		atoi(color+1) : 0;
	return color;
}

int irc_hilight_last_color(void)
{
	return last_color;
}

static void event_privmsg(void)
{
        last_color = 0;
}

void irc_hilight_text_init(void)
{
	last_color = 0;
	signal_add_last("event privmsg", (SIGNAL_FUNC) event_privmsg);
}

void irc_hilight_text_deinit(void)
{
	signal_remove("event privmsg", (SIGNAL_FUNC) event_privmsg);
}
