/*
 irc-window-activity.c : irssi

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
#include "levels.h"

#include "irc.h"
#include "ignore.h"
#include "irc-server.h"
#include "nicklist.h"

#include "completion.h"
#include "windows.h"
#include "window-items.h"

static void event_privmsg(const char *data, IRC_SERVER_REC *server, const char *nick, const char *addr)
{
	WINDOW_REC *window;
	WI_ITEM_REC *item;
	char *params, *target, *msg;
	int level;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST, &target, &msg);

	/* get window and window item */
	level = ischannel(*target) ? MSGLEVEL_PUBLIC : MSGLEVEL_MSGS;
	item = window_item_find(server, ischannel(*target) ? target : nick);
	window = item == NULL ?
		window_find_closest(server, target, GPOINTER_TO_INT(level)) :
		window_item_window(item);

	/* check that msg wasn't send to current window and
	   that it didn't get ignored */
        if (window != active_win && !ignore_check(server, nick, addr, target, msg, level)) {
                /* hilight */
		level = !ischannel(*target) ||
			irc_nick_match(server->nick, msg) ?
			NEWDATA_MSG_FORYOU : NEWDATA_MSG;
		if (item != NULL && item->new_data < level) {
			item->new_data = level;
			signal_emit("window item hilight", 1, item);
		} else {
			int oldlevel = window->new_data;

			if (window->new_data < level) {
				window->new_data = level;
				signal_emit("window hilight", 2, window, GINT_TO_POINTER(oldlevel));
			}
			signal_emit("window activity", 2, window, GINT_TO_POINTER(oldlevel));
		}
	}

	g_free(params);
}

void irc_window_activity_init(void)
{
	signal_add_last("event privmsg", (SIGNAL_FUNC) event_privmsg);
}

void irc_window_activity_deinit(void)
{
	signal_remove("event privmsg", (SIGNAL_FUNC) event_privmsg);
}
