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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "module-formats.h"
#include "signals.h"
#include "commands.h"
#include "levels.h"
#include "servers.h"

#include "irc.h"
#include "channel-rejoin.h"

static void sig_channel_rejoin(IRC_SERVER_REC *server, REJOIN_REC *rec)
{
	g_return_if_fail(rec != NULL);

	printformat(server, NULL, MSGLEVEL_CLIENTNOTICE,
		    IRCTXT_CHANNEL_REJOIN, rec->channel);
}

static void cmd_channel(const char *data, SERVER_REC *server)
{
	if (ischannel(*data)) {
		signal_emit("command join", 2, data, server);
		signal_stop();
	}
}

void fe_irc_channels_init(void)
{
	signal_add("channel rejoin new", (SIGNAL_FUNC) sig_channel_rejoin);
	command_bind("channel", NULL, (SIGNAL_FUNC) cmd_channel);
}

void fe_irc_channels_deinit(void)
{
	signal_remove("channel rejoin new", (SIGNAL_FUNC) sig_channel_rejoin);
	command_unbind("channel", (SIGNAL_FUNC) cmd_channel);
}
