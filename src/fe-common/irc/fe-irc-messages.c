/*
 fe-irc-messages.c : irssi

    Copyright (C) 2001 Timo Sirainen

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
#include "channels.h"

#include "irc.h"

#include "../core/module-formats.h"
#include "module-formats.h"
#include "printtext.h"
#include "fe-messages.h"

static void sig_message_own_public(SERVER_REC *server, const char *msg,
				   const char *target, const char *origtarget)
{
	char *nickmode;

	if (IS_IRC_SERVER(server) && target != NULL &&
	    *target == '@' && ischannel(target[1])) {
		/* Hybrid 6 feature, send msg to all ops in channel */
		nickmode = channel_get_nickmode(channel_find(server, target+1),
						server->nick);

		printformat_module("fe-common/core", server, target+1,
				   MSGLEVEL_PUBLIC | MSGLEVEL_NOHILIGHT |
				   MSGLEVEL_NO_ACT,
				   TXT_OWN_MSG_CHANNEL,
				   server->nick, target, msg, nickmode);
                signal_stop();
	}
}

static void sig_message_irc_op_public(SERVER_REC *server, const char *msg,
				      const char *nick, const char *address,
				      const char *target)
{
	char *nickmode, *optarget;

	nickmode = channel_get_nickmode(channel_find(server, target),
					server->nick);

        optarget = g_strconcat("@", target, NULL);
	printformat_module("fe-common/core", server, target,
			   MSGLEVEL_PUBLIC | MSGLEVEL_HILIGHT,
			   TXT_PUBMSG_ME_CHANNEL,
			   nick, optarget, msg, nickmode);
        g_free(optarget);
}

static void sig_message_irc_ctcp(IRC_SERVER_REC *server, const char *msg,
				 const char *nick, const char *addr,
				 const char *target)
{
	printformat(server, ischannel(*target) ? target : nick, MSGLEVEL_CTCPS,
		    IRCTXT_CTCP_REQUESTED, nick, addr, msg, target);
}

void fe_irc_messages_init(void)
{
        signal_add("message own_public", (SIGNAL_FUNC) sig_message_own_public);
        signal_add("message irc op_public", (SIGNAL_FUNC) sig_message_irc_op_public);
        signal_add("message irc ctcp", (SIGNAL_FUNC) sig_message_irc_ctcp);
}

void fe_irc_messages_deinit(void)
{
        signal_remove("message own_public", (SIGNAL_FUNC) sig_message_own_public);
        signal_remove("message irc op_public", (SIGNAL_FUNC) sig_message_irc_op_public);
        signal_remove("message irc ctcp", (SIGNAL_FUNC) sig_message_irc_ctcp);
}
