/*
 bot-events.c : IRC bot plugin for irssi

    Copyright (C) 1999 Timo Sirainen

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
#include "irc-channels.h"
#include "nicklist.h"
#include "modes.h"
#include "netsplit.h"

#include "bot-users.h"

static int get_flags(USER_REC *user, IRC_CHANNEL_REC *channel)
{
	USER_CHAN_REC *userchan;

	g_return_val_if_fail(user != NULL, 0);
	g_return_val_if_fail(channel != NULL, 0);

	userchan = g_hash_table_lookup(user->channels, channel->name);
	return (user->flags | (userchan == NULL ? 0 : userchan->flags)) &
		(~user->not_flags);
}

static void event_massjoin(IRC_CHANNEL_REC *channel, GSList *users)
{
	USER_REC *user;
	USER_CHAN_REC *userchan;
	NICK_REC *nick;
	GString *modestr, *nickstr;
	int flags;

	g_return_if_fail(channel != NULL);
	g_return_if_fail(users != NULL);

	modestr = g_string_new(NULL);
	nickstr = g_string_new(NULL);

	for (; users != NULL; users = users->next) {
		user = users->data;
		userchan = g_hash_table_lookup(user->channels, channel->name);
		nick = userchan->nickrec;

		flags = get_flags(user, channel);
		if (!nick->op && (flags & USER_AUTO_OP)) {
			g_string_sprintfa(modestr, "+o");
			g_string_sprintfa(nickstr, "%s,", nick->nick);
		}

		if (!nick->voice && !nick->op && (flags & USER_AUTO_VOICE)) {
			g_string_sprintfa(modestr, "+v");
			g_string_sprintfa(nickstr, "%s,", nick->nick);
		}
	}

	if (nickstr->len > 0) {
		g_string_truncate(nickstr, nickstr->len-1);
		g_string_sprintfa(modestr, " %s", nickstr->str);

		channel_set_mode(channel->server, channel->name, modestr->str);
	}

	g_string_free(modestr, TRUE);
	g_string_free(nickstr, TRUE);
}

/* Parse channel mode string */
static void parse_channel_mode(IRC_CHANNEL_REC *channel, const char *mode,
			       const char *nick, const char *address)
{
	NETSPLIT_CHAN_REC *splitnick;
	NICK_REC *nickrec;
	USER_REC *user;
	GString *str;
	char *ptr, *curmode, type, *dup, *modestr;
	int flags;

	g_return_if_fail(channel != NULL);
	g_return_if_fail(nick != NULL);
	g_return_if_fail(mode != NULL);

	user = botuser_find(nick, address);
	flags = user == NULL ? 0 : get_flags(user, channel);

	if (!channel->chanop || (flags & USER_MASTER) ||
	    g_strcasecmp(nick, channel->server->nick) == 0) {
		/* can't do anything or we/master did mode change,
		   don't bother checking what */
		return;
	}

	/* check if unwanted people got ops */
	str = g_string_new(NULL);
	dup = modestr = g_strdup(mode);

	type = '+';
	curmode = cmd_get_param(&modestr);
	for (; *curmode != '\0'; curmode++) {
		if (*curmode == '+' || *curmode == '-') {
			type = *curmode;
			continue;
		}

		if (!HAS_MODE_ARG(type, *curmode))
			ptr = NULL;
		else {
			ptr = cmd_get_param(&modestr);
			if (*ptr == '\0') continue;
		}

		if (*curmode != 'o')
			continue;

		if (type == '-' && strcmp(channel->server->nick, ptr) == 0) {
			/* we aren't chanop anymore .. */
			g_string_truncate(str, 0);
			break;
		}

		if (type != '+')
			continue;

		/* check that op is valid */
		nickrec = nicklist_find(CHANNEL(channel), ptr);
		if (nickrec == NULL || nickrec->host == NULL)
			continue;

		user = botuser_find(ptr, nickrec->host);
		flags = user == NULL ? 0 : get_flags(user, channel);
		if (flags & USER_OP)
			continue;

		if (address == NULL) {
			/* server opped, check if user was opped before netsplit. */
			splitnick = netsplit_find_channel(channel->server, nickrec->nick, nickrec->host, channel->name);
			if (splitnick != NULL && splitnick->op)
				continue;
		}

		/* this one isn't supposed to get ops! */
		g_string_sprintfa(str, "%s ", ptr);
	}
	g_free(dup);

	if (str->len != 0)
		signal_emit("command deop", 3, str->str, channel->server, channel);
	g_string_free(str, TRUE);
}

static void event_mode(IRC_SERVER_REC *server, const char *data,
		       const char *nick, const char *address)
{
	IRC_CHANNEL_REC *chanrec;
	char *params, *channel, *mode;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST, &channel, &mode);

	if (ischannel(*channel)) {
		/* channel mode change */
		chanrec = irc_channel_find(server, channel);
		if (chanrec != NULL)
			parse_channel_mode(chanrec, mode, nick, address);
	}

	g_free(params);
}

void bot_events_init(void)
{
	signal_add_last("bot massjoin", (SIGNAL_FUNC) event_massjoin);
	signal_add("event mode", (SIGNAL_FUNC) event_mode);
}

void bot_events_deinit(void)
{
	signal_remove("bot massjoin", (SIGNAL_FUNC) event_massjoin);
	signal_remove("event mode", (SIGNAL_FUNC) event_mode);
}
