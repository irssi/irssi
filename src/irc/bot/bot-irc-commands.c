/*
 bot-irc-commands.c : IRC bot plugin for irssi

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
#include "signals.h"
#include "commands.h"

#include "irc.h"
#include "irc-servers.h"
#include "channels.h"
#include "nicklist.h"
#include "irc-masks.h"

#include "bot-users.h"
#include "botnet-users.h"

static void event_privmsg(IRC_SERVER_REC *server, const char *data,
			  const char *nick, const char *address)
{
	char *params, *target, *msg, *args, *str;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST, &target, &msg);
	if (ischannel(*target)) {
		g_free(params);
		return;
	}

	/* private message for us */
	str = g_strconcat("bot command ", msg, NULL);
	args = strchr(str+12, ' ');
	if (args != NULL) *args++ = '\0'; else args = "";

	g_strdown(str);
	if (signal_emit(str, 4, server, args, nick, address)) {
		/* msg was a command - the msg event. */
		signal_stop();
	}
	g_free(str);
	g_free(params);
}

static void botcmd_op(IRC_SERVER_REC *server, const char *data,
		      const char *nick, const char *address)
{
	CHANNEL_REC *channel;
	USER_REC *user;
	USER_CHAN_REC *userchan;
	GSList *tmp;

	g_return_if_fail(data != NULL);

	if (*data == '\0') {
		/* no password given? .. */
		return;
	}

	user = botuser_find(nick, address);
	if (user == NULL || (user->not_flags & USER_OP) ||
	    !botuser_verify_password(user, data)) {
		/* not found, can't op with this mask or failed password */
		return;
	}

	/* find the channels where to op.. */
	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		channel = tmp->data;

		userchan = g_hash_table_lookup(user->channels, channel->name);
		if ((user->flags & USER_OP) || (userchan->flags & USER_OP))
			signal_emit("command op", 3, nick, server, channel);
	}
}

static void botcmd_ident(IRC_SERVER_REC *server, const char *data,
			 const char *nick, const char *address)
{
	USER_REC *user;
	char *mask;

	g_return_if_fail(data != NULL);

	user = botuser_find(nick, address);
	if (user != NULL) {
		/* Already know this host */
		return;
	}

	user = botuser_find(nick, NULL);
	if (user == NULL || !botuser_verify_password(user, data)) {
		/* failed password */
		return;
	}

	/* add the new mask */
	mask = irc_get_mask(nick, address, IRC_MASK_USER | IRC_MASK_DOMAIN);
	botcmd_user_add_mask(user, mask);

	irc_send_cmdv(server, "NOTICE %s :Added new mask %s", nick, mask);
	g_free(mask);
}

static void botcmd_pass(IRC_SERVER_REC *server, const char *data,
			const char *nick, const char *address)
{
	USER_REC *user;
	char *params, *pass, *newpass;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, &pass, &newpass);

	user = botuser_find(nick, address);
	if (user == NULL || *pass == '\0') {
		g_free(params);
		return;
	}

	if (user->password != NULL &&
	    (*newpass == '\0' || !botuser_verify_password(user, pass))) {
		g_free(params);
		return;
	}

	/* change the password */
	botcmd_user_set_password(user, user->password == NULL ? pass : newpass);
	irc_send_cmdv(server, "NOTICE %s :Password changed", nick);

	g_free(params);
}

void bot_irc_commands_init(void)
{
	signal_add("event privmsg", (SIGNAL_FUNC) event_privmsg);
	signal_add_last("bot command op", (SIGNAL_FUNC) botcmd_op);
	signal_add_last("bot command ident", (SIGNAL_FUNC) botcmd_ident);
	signal_add_last("bot command pass", (SIGNAL_FUNC) botcmd_pass);
}

void bot_irc_commands_deinit(void)
{
	signal_remove("event privmsg", (SIGNAL_FUNC) event_privmsg);
	signal_remove("bot command op", (SIGNAL_FUNC) botcmd_op);
	signal_remove("bot command ident", (SIGNAL_FUNC) botcmd_ident);
	signal_remove("bot command pass", (SIGNAL_FUNC) botcmd_pass);
}
