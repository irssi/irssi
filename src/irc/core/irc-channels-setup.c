/*
 irc-channels-setup.c : irssi

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
#include "nicklist.h"
#include "servers.h"
#include "special-vars.h"

#include "servers-setup.h"
#include "channels-setup.h"

#include "irc.h"
#include "irc-chatnets.h"
#include "irc-servers.h"
#include "irc-channels.h"

/* connected to server, autojoin to channels. */
static void event_connected(IRC_SERVER_REC *server)
{
	GString *chans;
	GSList *tmp;

	if (!IS_IRC_SERVER(server) || server->connrec->reconnection)
		return;

	/* join to the channels marked with autojoin in setup */
	chans = g_string_new(NULL);
	for (tmp = setupchannels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_SETUP_REC *rec = tmp->data;

		if (!rec->autojoin ||
		    !channel_chatnet_match(rec->chatnet,
					   server->connrec->chatnet))
			continue;

		g_string_sprintfa(chans, "%s,", rec->name);
	}

	if (chans->len > 0) {
		g_string_truncate(chans, chans->len-1);
		irc_channels_join(server, chans->str, TRUE);
	}

	g_string_free(chans, TRUE);
}

/* channel wholist received: send the auto send command */
static void channel_wholist(CHANNEL_REC *channel)
{
	CHANNEL_SETUP_REC *rec;
	NICK_REC *nick;
	char **bots, **bot;

	g_return_if_fail(IS_CHANNEL(channel));

	rec = channels_setup_find(channel->name, channel->server->connrec->chatnet);
	if (rec == NULL || rec->autosendcmd == NULL || !*rec->autosendcmd)
		return;

	if (rec->botmasks == NULL || !*rec->botmasks) {
		/* just send the command. */
		eval_special_string(rec->autosendcmd, "", channel->server, channel);
		return;
	}

	/* find first available bot.. */
	bots = g_strsplit(rec->botmasks, " ", -1);
	for (bot = bots; *bot != NULL; bot++) {
		const char *botnick = *bot;

		nick = nicklist_find(channel, isnickflag(*botnick) ?
				     botnick+1 : botnick);
		if (nick == NULL)
			continue;
		if ((*botnick == '@' && !nick->op) ||
		    (*botnick == '+' && !nick->voice && !nick->op))
			continue;

		/* got one! */
		eval_special_string(rec->autosendcmd, nick->nick, channel->server, channel);
		break;
	}
	g_strfreev(bots);
}

void irc_channels_setup_init(void)
{
	signal_add("event connected", (SIGNAL_FUNC) event_connected);
	signal_add("channel wholist", (SIGNAL_FUNC) channel_wholist);
}

void irc_channels_setup_deinit(void)
{
	signal_remove("event connected", (SIGNAL_FUNC) event_connected);
	signal_remove("channel wholist", (SIGNAL_FUNC) channel_wholist);
}
