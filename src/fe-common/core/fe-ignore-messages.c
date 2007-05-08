/*
 fe-ignore-messages.c : irssi

    Copyright (C) 2000 Timo Sirainen

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
#include "signals.h"
#include "levels.h"
#include "ignore.h"
#include "servers.h"

static void sig_message_public(SERVER_REC *server, const char *msg,
			       const char *nick, const char *address,
			       const char *target)
{
	if (ignore_check(server, nick, address, target, msg, MSGLEVEL_PUBLIC))
		signal_stop();
}

static void sig_message_private(SERVER_REC *server, const char *msg,
				const char *nick, const char *address)
{
	if (ignore_check(server, nick, address, NULL, msg, MSGLEVEL_MSGS))
		signal_stop();
}

static void sig_message_join(SERVER_REC *server, const char *channel,
			     const char *nick, const char *address)
{
	if (ignore_check(server, nick, address, channel, NULL, MSGLEVEL_JOINS))
		signal_stop();
}

static void sig_message_part(SERVER_REC *server, const char *channel,
			     const char *nick, const char *address,
			     const char *reason)
{
	if (ignore_check(server, nick, address, channel, NULL, MSGLEVEL_PARTS))
		signal_stop();
}

static void sig_message_quit(SERVER_REC *server, const char *nick,
			     const char *address, const char *reason)
{
	if (ignore_check(server, nick, address, NULL, reason, MSGLEVEL_QUITS))
		signal_stop();
}

static void sig_message_kick(SERVER_REC *server, const char *channel,
			     const char *nick, const char *kicker,
			     const char *address, const char *reason)
{
        /* never ignore if you were kicked */
	if (g_strcasecmp(nick, server->nick) != 0 &&
	    ignore_check(server, kicker, address,
			 channel, reason, MSGLEVEL_KICKS))
		signal_stop();
}

static void sig_message_nick(SERVER_REC *server, const char *newnick,
			     const char *oldnick, const char *address)
{
	if (ignore_check(server, oldnick, address,
			 NULL, NULL, MSGLEVEL_NICKS) ||
	    ignore_check(server, newnick, address,
			 NULL, NULL, MSGLEVEL_NICKS))
		signal_stop();
}

static void sig_message_own_nick(SERVER_REC *server, const char *newnick,
				 const char *oldnick, const char *address)
{
	if (ignore_check(server, oldnick, address, NULL, NULL, MSGLEVEL_NICKS))
		signal_stop();
}

static void sig_message_invite(SERVER_REC *server, const char *channel,
			       const char *nick, const char *address)
{
	if (*channel == '\0' ||
	    ignore_check(server, nick, address,
			 channel, NULL, MSGLEVEL_INVITES))
		signal_stop();
}

static void sig_message_topic(SERVER_REC *server, const char *channel,
			      const char *topic,
			      const char *nick, const char *address)
{
	if (ignore_check(server, nick, address,
			 channel, topic, MSGLEVEL_TOPICS))
		signal_stop();
}

void fe_ignore_messages_init(void)
{
	signal_add_first("message public", (SIGNAL_FUNC) sig_message_public);
	signal_add_first("message private", (SIGNAL_FUNC) sig_message_private);
	signal_add_first("message join", (SIGNAL_FUNC) sig_message_join);
	signal_add_first("message part", (SIGNAL_FUNC) sig_message_part);
	signal_add_first("message quit", (SIGNAL_FUNC) sig_message_quit);
	signal_add_first("message kick", (SIGNAL_FUNC) sig_message_kick);
	signal_add_first("message nick", (SIGNAL_FUNC) sig_message_nick);
	signal_add_first("message own_nick", (SIGNAL_FUNC) sig_message_own_nick);
	signal_add_first("message invite", (SIGNAL_FUNC) sig_message_invite);
	signal_add_first("message topic", (SIGNAL_FUNC) sig_message_topic);
}

void fe_ignore_messages_deinit(void)
{
	signal_remove("message public", (SIGNAL_FUNC) sig_message_public);
	signal_remove("message private", (SIGNAL_FUNC) sig_message_private);
	signal_remove("message join", (SIGNAL_FUNC) sig_message_join);
	signal_remove("message part", (SIGNAL_FUNC) sig_message_part);
	signal_remove("message quit", (SIGNAL_FUNC) sig_message_quit);
	signal_remove("message kick", (SIGNAL_FUNC) sig_message_kick);
	signal_remove("message nick", (SIGNAL_FUNC) sig_message_nick);
	signal_remove("message own_nick", (SIGNAL_FUNC) sig_message_own_nick);
	signal_remove("message invite", (SIGNAL_FUNC) sig_message_invite);
	signal_remove("message topic", (SIGNAL_FUNC) sig_message_topic);
}
