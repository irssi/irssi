/*
 fe-channels.c : irssi

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
#include "module-formats.h"
#include "modules.h"
#include "signals.h"
#include "commands.h"
#include "levels.h"

#include "irc.h"
#include "channels.h"

#include "windows.h"
#include "window-items.h"

static void signal_channel_created(CHANNEL_REC *channel, gpointer automatic)
{
	window_item_create((WI_ITEM_REC *) channel, GPOINTER_TO_INT(automatic));
}

static void signal_channel_created_curwin(CHANNEL_REC *channel)
{
	g_return_if_fail(channel != NULL);

	window_add_item(active_win, (WI_ITEM_REC *) channel, FALSE);
	signal_stop();
}

static void signal_channel_destroyed(CHANNEL_REC *channel)
{
	WINDOW_REC *window;

	g_return_if_fail(channel != NULL);

	window = window_item_window((WI_ITEM_REC *) channel);
	if (window != NULL) window_remove_item(window, (WI_ITEM_REC *) channel);
}

static void signal_window_item_removed(WINDOW_REC *window, WI_ITEM_REC *item)
{
	CHANNEL_REC *channel;

	g_return_if_fail(window != NULL);

	channel = irc_item_channel(item);
        if (channel != NULL) channel_destroy(channel);
}

static void sig_disconnected(IRC_SERVER_REC *server)
{
	WINDOW_REC *window;
	GSList *tmp;

	g_return_if_fail(server != NULL);
	if (!irc_server_check(server))
		return;

	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *channel = tmp->data;

		window = window_item_window((WI_ITEM_REC *) channel);
		window->waiting_channels =
			g_slist_append(window->waiting_channels, g_strdup_printf("%s %s", server->tag, channel->name));
	}
}

static void signal_window_item_changed(WINDOW_REC *window, WI_ITEM_REC *item)
{
	g_return_if_fail(item != NULL);

	if (g_slist_length(window->items) > 1 && irc_item_channel(item)) {
		printformat(item->server, item->name, MSGLEVEL_CLIENTNOTICE,
			    IRCTXT_TALKING_IN, item->name);
                signal_stop();
	}
}

static void cmd_wjoin(const char *data, void *server, WI_ITEM_REC *item)
{
	signal_add("channel created", (SIGNAL_FUNC) signal_channel_created_curwin);
	signal_emit("command join", 3, data, server, item);
	signal_remove("channel created", (SIGNAL_FUNC) signal_channel_created_curwin);
}

void fe_channels_init(void)
{
	signal_add("channel created", (SIGNAL_FUNC) signal_channel_created);
	signal_add("channel destroyed", (SIGNAL_FUNC) signal_channel_destroyed);
	signal_add("window item remove", (SIGNAL_FUNC) signal_window_item_removed);
	signal_add_last("window item changed", (SIGNAL_FUNC) signal_window_item_changed);
	signal_add_last("server disconnected", (SIGNAL_FUNC) sig_disconnected);

	command_bind("wjoin", NULL, (SIGNAL_FUNC) cmd_wjoin);
}

void fe_channels_deinit(void)
{
	signal_remove("channel created", (SIGNAL_FUNC) signal_channel_created);
	signal_remove("channel destroyed", (SIGNAL_FUNC) signal_channel_destroyed);
	signal_remove("window item remove", (SIGNAL_FUNC) signal_window_item_removed);
	signal_remove("window item changed", (SIGNAL_FUNC) signal_window_item_changed);
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_disconnected);

	command_unbind("wjoin", (SIGNAL_FUNC) cmd_wjoin);
}
