/*
 fe-irc-channels.c : irssi

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
#include "module-formats.h"
#include "signals.h"
#include "levels.h"

#include "irc-servers.h"
#include "irc-channels.h"
#include "channel-rejoin.h"

#include "printtext.h"
#include "fe-windows.h"
#include "window-items.h"

static void sig_channel_rejoin(SERVER_REC *server, REJOIN_REC *rec)
{
	g_return_if_fail(rec != NULL);

	printformat(server, NULL, MSGLEVEL_CLIENTNOTICE,
		    IRCTXT_CHANNEL_REJOIN, rec->channel);
}

static void sig_event_forward(SERVER_REC *server, const char *data,
			      const char *nick)
{
	IRC_CHANNEL_REC *channel;
	char *params, *from, *to;

	params = event_get_params(data, 3, NULL, &from, &to);
	if (from != NULL && to != NULL && ischannel(*from) && ischannel(*to)) {
		channel = irc_channel_find(server, from);
		if (channel != NULL && irc_channel_find(server, to) == NULL) {
			window_bind_add(window_item_window(channel),
					server->tag, to);
		}
	}
	g_free(params);
}

void fe_irc_channels_init(void)
{
	signal_add("channel rejoin new", (SIGNAL_FUNC) sig_channel_rejoin);
	signal_add_first("event 470", (SIGNAL_FUNC) sig_event_forward);
}

void fe_irc_channels_deinit(void)
{
	signal_remove("channel rejoin new", (SIGNAL_FUNC) sig_channel_rejoin);
	signal_remove("event 470", (SIGNAL_FUNC) sig_event_forward);
}
