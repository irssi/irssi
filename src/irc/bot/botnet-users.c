/*
 botnet-users.c : IRC bot plugin for irssi

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
#include "masks.h"

#include "bot-users.h"
#include "botnet.h"

void botcmd_user_add(const char *nick)
{
	char *str;

	botuser_add(nick);

	str = g_strdup_printf("USER_ADD %s", nick);
	botnet_broadcast(NULL, NULL, NULL, str);
	g_free(str);
}

void botcmd_user_set_flags(USER_REC *user, int flags)
{
	char *str, *flagstr;

	botuser_set_flags(user, flags);

	flagstr = botuser_value2flags(flags);
	str = g_strdup_printf("USER_FLAGS %s %s", user->nick, flagstr);
	g_free(flagstr);

	botnet_broadcast(NULL, NULL, NULL, str);
	g_free(str);
}

void botcmd_user_set_channel_flags(USER_REC *user, const char *channel, int flags)
{
	char *str, *flagstr;

        botuser_set_channel_flags(user, channel, flags);

	flagstr = botuser_value2flags(flags);
	str = g_strdup_printf("USER_CHAN_FLAGS %s %s %s", user->nick, channel, flagstr);
	g_free(flagstr);

	botnet_broadcast(NULL, NULL, NULL, str);
	g_free(str);
}

void botcmd_user_add_mask(USER_REC *user, const char *mask)
{
	char *str;

	botuser_add_mask(user, mask);

	str = g_strdup_printf("USER_ADD_MASK %s %s", user->nick, mask);
	botnet_broadcast(NULL, NULL, NULL, str);
	g_free(str);
}

void botcmd_user_set_mask_notflags(USER_REC *user, const char *mask, int not_flags)
{
	char *str, *flagstr;

        botuser_set_mask_notflags(user, mask, not_flags);

	flagstr = botuser_value2flags(not_flags);
	str = g_strdup_printf("USER_MASK_NOTFLAGS %s %s %s", user->nick, mask, flagstr);
	g_free(flagstr);

	botnet_broadcast(NULL, NULL, NULL, str);
	g_free(str);
}

void botcmd_user_set_password(USER_REC *user, const char *password)
{
	char *str;

	botuser_set_password(user, password);

	str = g_strdup_printf("USER_PASS %s %s", user->nick, password);
	botnet_broadcast(NULL, NULL, NULL, str);
	g_free(str);
}

static void botnet_event_user_add(BOT_REC *bot, const char *data, const char *sender)
{
	char *nick;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 1, &nick))
		return;

	botuser_add(nick);
        cmd_params_free(free_arg);
}

static void botnet_event_user_flags(BOT_REC *bot, const char *data, const char *sender)
{
	USER_REC *user;
	char *nick, *flags;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 2, &nick, &flags))
		return;

	user = botuser_find(nick, NULL);
	if (user == NULL) user = botuser_add(nick);
	botuser_set_flags(user, botuser_flags2value(flags));

        cmd_params_free(free_arg);
}

static void botnet_event_user_chan_flags(BOT_REC *bot, const char *data, const char *sender)
{
	USER_REC *user;
	char *nick, *channel, *flags;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 3, &nick, &channel, &flags))
		return;

	user = botuser_find(nick, NULL);
	if (user == NULL) user = botuser_add(nick);
	botuser_set_channel_flags(user, channel, botuser_flags2value(flags));

        cmd_params_free(free_arg);
}

static void botnet_event_user_add_mask(BOT_REC *bot, const char *data, const char *sender)
{
	USER_REC *user;
	char *nick, *mask;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 2, &nick, &mask))
		return;

	user = botuser_find(nick, NULL);
	if (user == NULL) user = botuser_add(nick);
	botuser_add_mask(user, mask);

        cmd_params_free(free_arg);
}

static void botnet_event_user_mask_notflags(BOT_REC *bot, const char *data, const char *sender)
{
	USER_REC *user;
	char *nick, *mask, *not_flags;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 3, &nick, &mask, &not_flags))
		return;

	user = botuser_find(nick, NULL);
	if (user == NULL) user = botuser_add(nick);
	botuser_set_mask_notflags(user, mask, botuser_flags2value(not_flags));

        cmd_params_free(free_arg);
}

static void botnet_event_user_pass(BOT_REC *bot, const char *data, const char *sender)
{
	USER_REC *user;
	char *nick, *pass;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 2, &nick, &pass))
		return;

	user = botuser_find(nick, NULL);
	if (user == NULL) user = botuser_add(nick);
	botuser_set_password(user, pass);

	cmd_params_free(free_arg);
}

void botnet_users_init(void)
{
	signal_add("botnet event user_add", (SIGNAL_FUNC) botnet_event_user_add);
	signal_add("botnet event user_flags", (SIGNAL_FUNC) botnet_event_user_flags);
	signal_add("botnet event user_chan_flags", (SIGNAL_FUNC) botnet_event_user_chan_flags);
	signal_add("botnet event user_add_mask", (SIGNAL_FUNC) botnet_event_user_add_mask);
	signal_add("botnet event user_mask_notflags", (SIGNAL_FUNC) botnet_event_user_mask_notflags);
	signal_add("botnet event user_pass", (SIGNAL_FUNC) botnet_event_user_pass);
}

void botnet_users_deinit(void)
{
	signal_remove("botnet event user_add", (SIGNAL_FUNC) botnet_event_user_add);
	signal_remove("botnet event user_flags", (SIGNAL_FUNC) botnet_event_user_flags);
	signal_remove("botnet event user_chan_flags", (SIGNAL_FUNC) botnet_event_user_chan_flags);
	signal_remove("botnet event user_add_mask", (SIGNAL_FUNC) botnet_event_user_add_mask);
	signal_remove("botnet event user_mask_notflags", (SIGNAL_FUNC) botnet_event_user_mask_notflags);
	signal_remove("botnet event user_pass", (SIGNAL_FUNC) botnet_event_user_pass);
}
