/*
 fe-irc-layout.c : irssi

    Copyright (C) 2000-2002 Timo Sirainen

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
#include "lib-config/iconfig.h"

#include "irc-servers.h"
#include "irc-channels.h"

#include "fe-windows.h"

static void sig_layout_save_item(WINDOW_REC *window, WI_ITEM_REC *item,
				 CONFIG_NODE *node)
{
	CONFIG_NODE *subnode;
	IRC_CHANNEL_REC *channel;
	char *name;

	channel = IRC_CHANNEL(item);
	if (channel == NULL || *channel->name != '!')
		return;

	/* save !ABCDEchannels using just short name */
	subnode = config_node_section(node, NULL, NODE_TYPE_BLOCK);

	name = g_strconcat("!", channel->name+6, NULL);
	iconfig_node_set_str(subnode, "type", "CHANNEL");
	iconfig_node_set_str(subnode, "chat_type", "IRC");
	iconfig_node_set_str(subnode, "name", name);
	iconfig_node_set_str(subnode, "tag", channel->server->tag);
	g_free(name);

	signal_stop();
}

void fe_irc_layout_init(void)
{
	signal_add("layout save item", (SIGNAL_FUNC) sig_layout_save_item);
}

void fe_irc_layout_deinit(void)
{
	signal_remove("layout save item", (SIGNAL_FUNC) sig_layout_save_item);
}
