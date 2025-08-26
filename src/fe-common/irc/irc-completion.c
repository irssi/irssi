/*
 irc-completion.c : irssi

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
#include <irssi/src/core/signals.h>
#include <irssi/src/fe-common/core/chat-completion.h>

static void sig_complete_stats(GList **list, WINDOW_REC *window,
			       const char *word, const char *line,
			       int *want_space)
{
	*list = completion_get_servers(word);
	if (*list != NULL) signal_stop();
}

void irc_completion_init(void)
{
	signal_add("complete command stats", (SIGNAL_FUNC) sig_complete_stats);
}

void irc_completion_deinit(void)
{
	signal_remove("complete command stats", (SIGNAL_FUNC) sig_complete_stats);
}
