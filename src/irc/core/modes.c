/*
 modes.c : irssi

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
#include "commands.h"
#include "signals.h"

#include "irc.h"
#include "modes.h"
#include "mode-lists.h"
#include "nicklist.h"

/* Change nick's mode in channel */
static void nick_mode_change(CHANNEL_REC *channel, const char *nick, const char mode, gboolean set)
{
	NICK_REC *nickrec;

	g_return_if_fail(channel != NULL);
	g_return_if_fail(nick != NULL);

	nickrec = nicklist_find(channel, nick);
	if (nickrec == NULL) return; /* No /names list got yet */

	if (mode == '@') nickrec->op = set;
	if (mode == '+') nickrec->voice = set;

	signal_emit("nick mode changed", 2, channel, nickrec);
}

/* Parse channel mode string */
void parse_channel_modes(CHANNEL_REC *channel, const char *setby, const char *mode)
{
	char *dup, *modestr, *ptr, *curmode, type;

	g_return_if_fail(channel != NULL);
	g_return_if_fail(setby != NULL);
	g_return_if_fail(modestr != NULL);

	type = '+';

	dup = modestr = g_strdup(mode);
	curmode = cmd_get_param(&modestr);
	while (*curmode != '\0') {
		switch (*curmode) {
		case '+':
		case '-':
			type = *curmode;
			break;

		case 'b':
			ptr = cmd_get_param(&modestr);
			if (*ptr == '\0') break;

			if (type == '+')
				banlist_add(channel, ptr, setby, time(NULL));
			else
				banlist_remove(channel, ptr);
			break;

		case 'e':
			ptr = cmd_get_param(&modestr);
			if (*ptr == '\0') break;

			if (type == '+')
				banlist_exception_add(channel, ptr, setby, time(NULL));
			else
				banlist_exception_remove(channel, ptr);
			break;

		case 'I':
			ptr = cmd_get_param(&modestr);
			if (*ptr == '\0') break;

			if (type == '+')
				invitelist_add(channel, ptr);
			else
				invitelist_remove(channel, ptr);
			break;

		case 'v':
			ptr = cmd_get_param(&modestr);
			if (*ptr != '\0')
				nick_mode_change(channel, ptr, '+', type == '+');
			break;

		case 'o':
			ptr = cmd_get_param(&modestr);
			if (*ptr == '\0') break;

			if (g_strcasecmp(channel->server->nick, ptr) == 0)
				channel->chanop = type == '+' ? TRUE : FALSE;
			nick_mode_change(channel, ptr, '@', type == '+');
			break;

		case 'l':
			if (type == '-')
				channel->limit = 0;
			else {
				ptr = cmd_get_param(&modestr);
				sscanf(ptr, "%d", &channel->limit);
			}
			signal_emit("channel mode changed", 1, channel);
			break;
		case 'k':
			ptr = cmd_get_param(&modestr);
			if (*ptr != '\0' || type == '-') {
				g_free_and_null(channel->key);
				channel->mode_key = type == '+';
				if (type == '+')
					channel->key = g_strdup(ptr);
			}
			signal_emit("channel mode changed", 1, channel);
			break;

		default:
			switch (*curmode) {
			case 'i':
				channel->mode_invite = type == '+';
				break;
			case 'm':
				channel->mode_moderate = type == '+';
				break;
			case 's':
				channel->mode_secret = type == '+';
				break;
			case 'p':
				channel->mode_private = type == '+';
				break;
			case 'n':
				channel->mode_nomsgs = type == '+';
				break;
			case 't':
				channel->mode_optopic = type == '+';
				break;
			case 'a':
				channel->mode_anonymous = type == '+';
				break;
			case 'r':
				channel->mode_reop = type == '+';
				break;
			}
			signal_emit("channel mode changed", 1, channel);
			break;
		}

		curmode++;
	}
	g_free(dup);

	if (!channel->mode_key && channel->key != NULL) {
		/* join was used with key but there's no key set
		   in channel modes.. */
		g_free(channel->key);
		channel->key = NULL;
	}
}

static int compare_char(const void *p1, const void *p2)
{
	const char *c1 = p1, *c2 = p2;

	return *c1 < *c2 ? -1 :
		(*c1 > *c2 ? 1 : 0);
}

/* add `mode' to `old' - return newly allocated mode. */
char *modes_join(const char *old, const char *mode)
{
	GString *newmode;
	char type, *p;

        g_return_val_if_fail(mode != NULL, NULL);

	type = '+';
	newmode = g_string_new(old);
	while (*mode != '\0' && *mode != ' ') {
		if (*mode == '+' || *mode == '-') {
                        type = *mode;
		} else {
			p = strchr(newmode->str, *mode);

			if (type == '+' && p == NULL)
				g_string_append_c(newmode, *mode);
			else if (type == '-' && p != NULL)
				g_string_erase(newmode, (int) (p-newmode->str), 1);
		}

		mode++;
	}

	qsort(newmode->str, sizeof(char), newmode->len, compare_char);

	p = newmode->str;
	g_string_free(newmode, FALSE);
	return p;
}

/* Parse user mode string */
static void parse_user_mode(IRC_SERVER_REC *server, const char *modestr)
{
	char *newmode, *oldmode;

	g_return_if_fail(server != NULL);
	g_return_if_fail(modestr != NULL);

	newmode = modes_join(server->usermode, modestr);
	oldmode = server->usermode;
	server->usermode = newmode;
	server->server_operator = (strchr(newmode, 'o') != NULL);

	signal_emit("user mode changed", 2, server, oldmode);
	g_free_not_null(oldmode);
}

static void event_user_mode(const char *data, IRC_SERVER_REC *server)
{
	char *params, *nick, *mode;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &nick, &mode);
	parse_user_mode(server, mode);

	g_free(params);
}

static void event_mode(const char *data, IRC_SERVER_REC *server, const char *nick)
{
	CHANNEL_REC *chanrec;
	char *params, *channel, *mode;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST, &channel, &mode);

	if (!ischannel(*channel)) {
		/* user mode change */
		parse_user_mode(server, mode);
	} else {
		/* channel mode change */
		chanrec = channel_find(server, channel);
		if (chanrec != NULL)
			parse_channel_modes(chanrec, nick, mode);
	}

	g_free(params);
}

static void event_away(const char *data, IRC_SERVER_REC *server)
{
	g_return_if_fail(server != NULL);

	server->usermode_away = TRUE;
	signal_emit("away mode changed", 1, server);
}

static void event_unaway(const char *data, IRC_SERVER_REC *server)
{
	g_return_if_fail(server != NULL);

	server->usermode_away = FALSE;
	g_free_and_null(server->away_reason);
	signal_emit("away mode changed", 1, server);
}

void channel_set_singlemode(IRC_SERVER_REC *server, const char *channel, const char *nicks, const char *mode)
{
	GString *str;
	int num, modepos;
	char **nick, **nicklist;

	g_return_if_fail(server != NULL);
	g_return_if_fail(channel != NULL);
	g_return_if_fail(nicks != NULL);
	g_return_if_fail(mode != NULL);
	if (*nicks == '\0') return;

	num = modepos = 0;
	str = g_string_new(NULL);

	nicklist = g_strsplit(nicks, " ", -1);
	for (nick = nicklist; *nick != NULL; nick++) {
		if (*nick == '\0')
			continue;

		if (num == 0)
		{
			g_string_sprintf(str, "MODE %s %s", channel, mode);
			modepos = str->len;
		} else {
			/* insert the mode string */
			g_string_insert(str, modepos, mode);
		}

		g_string_sprintfa(str, " %s", *nick);

		if (++num == server->connrec->max_modes) {
			/* max. modes / command reached, send to server */
			irc_send_cmd(server, str->str);
			num = 0;
		}
	}
	if (num > 0) irc_send_cmd(server, str->str);

	g_strfreev(nicklist);
	g_string_free(str, TRUE);
}

void channel_set_mode(IRC_SERVER_REC *server, const char *channel, const char *mode)
{
	char *modestr, *curmode, *orig;
	GString *tmode, *targs;
	int count;

	g_return_if_fail(server != NULL);
	g_return_if_fail(channel != NULL);
	g_return_if_fail(mode != NULL);

	tmode = g_string_new(NULL);
	targs = g_string_new(NULL);
	count = 0;

	orig = modestr = g_strdup(mode);

	curmode = cmd_get_param(&modestr);
	for (; *curmode != '\0'; curmode++) {
		if (count == server->connrec->max_modes && HAS_MODE_ARG(*curmode)) {
			irc_send_cmdv(server, "MODE %s %s%s", channel, tmode->str, targs->str);

			count = 0;
			g_string_truncate(tmode, 0);
			g_string_truncate(targs, 0);
		}

		g_string_append_c(tmode, *curmode);

		if (HAS_MODE_ARG(*curmode)) {
			char *arg;

			count++;
			arg = cmd_get_param(&modestr);
			if (*arg != '\0') g_string_sprintfa(targs, " %s", arg);
		}
	}

	if (tmode->len > 0)
		irc_send_cmdv(server, "MODE %s %s%s", channel, tmode->str, targs->str);

	g_string_free(tmode, TRUE);
	g_string_free(targs, TRUE);
	g_free(orig);
}

static char *get_nicks(WI_IRC_REC *item, const char *data, int op, int voice)
{
        GString *str;
	GSList *nicks, *tmp;
	char **matches, **match, *ret;

	str = g_string_new(NULL);
	matches = g_strsplit(data, " ", -1);
	for (match = matches; *match != NULL; match++) {
		if (strchr(*match, '*') == NULL && strchr(*match, '?') == NULL) {
			/* no wildcards */
                        g_string_sprintfa(str, "%s ", *match);
			continue;
		}

		/* wildcards */
		nicks = nicklist_find_multiple((CHANNEL_REC *) item, data);
		for (tmp = nicks; tmp != NULL; tmp = tmp->next) {
			NICK_REC *rec = tmp->data;

			if ((op == 1 && !rec->op) || (op == 0 && rec->op) ||
			    (voice == 1 && !rec->voice) || (voice == 0 && rec->voice))
				continue;

			if (g_strcasecmp(rec->nick, item->server->nick) == 0)
				continue;

			g_string_sprintfa(str, "%s ", rec->nick);
		}
		g_slist_free(nicks);
	}

	g_string_truncate(str, str->len-1);
	ret = str->str;
	g_string_free(str, FALSE);
	return ret;
}

static void cmd_op(const char *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	char *nicks;

	if (!irc_item_channel(item))
		return;

	nicks = get_nicks(item, data, 0, -1);
	if (*nicks != '\0')
		channel_set_singlemode(server, item->name, nicks, "+o");
	g_free(nicks);
}

static void cmd_deop(const char *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	char *nicks;

	if (!irc_item_channel(item))
		return;

	nicks = get_nicks(item, data, 1, -1);
	if (*nicks != '\0')
		channel_set_singlemode(server, item->name, nicks, "-o");
	g_free(nicks);
}

static void cmd_voice(const char *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	char *nicks;

	if (!irc_item_channel(item))
		return;

	nicks = get_nicks(item, data, 0, 0);
	if (*nicks != '\0')
		channel_set_singlemode(server, item->name, nicks, "+v");
	g_free(nicks);
}

static void cmd_devoice(const char *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	char *nicks;

	if (!irc_item_channel(item))
		return;

	nicks = get_nicks(item, data, 0, 1);
	if (*nicks != '\0')
		channel_set_singlemode(server, item->name, nicks, "-v");
	g_free(nicks);
}

static void cmd_mode(const char *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	char *params, *target, *mode;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !irc_server_check(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);

	params = cmd_get_params(data, 2 | PARAM_FLAG_GETREST, &target, &mode);
	if (strcmp(target, "*") == 0) {
		if (!irc_item_channel(item))
			cmd_return_error(CMDERR_NOT_JOINED);

		target = item->name;
	}
	if (*target == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	if (*mode == '\0')
		irc_send_cmdv(server, "MODE %s", target);
	else if (ischannel(*target))
		channel_set_mode(server, target, mode);
	else
		irc_send_cmdv(server, "MODE %s %s", target, mode);

	g_free(params);
}

void modes_init(void)
{
	signal_add("event 221", (SIGNAL_FUNC) event_user_mode);
	signal_add("event 305", (SIGNAL_FUNC) event_unaway);
	signal_add("event 306", (SIGNAL_FUNC) event_away);
	signal_add("event mode", (SIGNAL_FUNC) event_mode);

	command_bind("op", NULL, (SIGNAL_FUNC) cmd_op);
	command_bind("deop", NULL, (SIGNAL_FUNC) cmd_deop);
	command_bind("voice", NULL, (SIGNAL_FUNC) cmd_voice);
	command_bind("devoice", NULL, (SIGNAL_FUNC) cmd_devoice);
	command_bind("mode", NULL, (SIGNAL_FUNC) cmd_mode);
}

void modes_deinit(void)
{
	signal_remove("event 221", (SIGNAL_FUNC) event_user_mode);
	signal_remove("event 305", (SIGNAL_FUNC) event_unaway);
	signal_remove("event 306", (SIGNAL_FUNC) event_away);
	signal_remove("event mode", (SIGNAL_FUNC) event_mode);

	command_unbind("op", (SIGNAL_FUNC) cmd_op);
	command_unbind("deop", (SIGNAL_FUNC) cmd_deop);
	command_unbind("voice", (SIGNAL_FUNC) cmd_voice);
	command_unbind("devoice", (SIGNAL_FUNC) cmd_devoice);
	command_unbind("mode", (SIGNAL_FUNC) cmd_mode);
}
