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
static void nick_mode_change(IRC_CHANNEL_REC *channel, const char *nick,
			     const char mode, int type)
{
	NICK_REC *nickrec;

	g_return_if_fail(IS_IRC_CHANNEL(channel));
	g_return_if_fail(nick != NULL);

	nickrec = nicklist_find(CHANNEL(channel), nick);
	if (nickrec == NULL) return; /* No /names list got yet */

	if (mode == '@') nickrec->op = type == '+';
	if (mode == '+') nickrec->voice = type == '+';
	if (mode == '%') nickrec->halfop = type == '+';

	signal_emit("nick mode changed", 2, channel, nickrec);
}

static int mode_is_set(const char *str, char mode)
{
	char *end, *pos;

	g_return_val_if_fail(str != NULL, FALSE);

	end = strchr(str, ' ');
	pos = strchr(str, mode);
	return pos != NULL && (end == NULL || pos < end);
}

/* add argument to specified position */
static void mode_add_arg(GString *str, int pos, int updating, const char *arg)
{
	char *p;

	for (p = str->str; *p != '\0'; p++) {
		if (*p != ' ')
			continue;

		if (pos == 0)
			break;
		pos--;
	}

	pos = (int) (p-str->str);
	if (updating && *p != '\0') {
		/* remove the old argument */
                p++;
		while (*p != '\0' && *p != ' ') p++;
                g_string_erase(str, pos, (int) (p-str->str)-pos);
	}

	/* .. GLib shouldn't fail when inserting at the end of the string */
	if (pos == str->len) {
		g_string_append_c(str, ' ');
		g_string_append(str, arg);
	} else {
		g_string_insert_c(str, pos, ' ');
		g_string_insert(str, pos+1, arg);
	}
}

/* Add mode character to list sorted alphabetically */
static void mode_add_sorted(GString *str, char mode, const char *arg)
{
	char *p;
	int updating, argpos = 0;

	/* check that mode isn't already set */
	if (!HAS_MODE_ARG_SET(mode) && mode_is_set(str->str, mode))
		return;

	updating = FALSE;
	for (p = str->str; *p != '\0' && *p != ' '; p++) {
		if (mode < *p)
			break;
		if (mode == *p) {
                        updating = TRUE;
			break;
		}
		if (HAS_MODE_ARG_SET(*p))
			argpos++;
	}

	/* .. GLib shouldn't fail when inserting at the end of the string */
	if (!updating) {
		if (*p == '\0')
			g_string_append_c(str, mode);
		else
			g_string_insert_c(str, (int) (p-str->str), mode);
	}
	if (arg != NULL)
                mode_add_arg(str, argpos, updating, arg);
}

/* remove the n'th argument */
static void node_remove_arg(GString *str, int pos)
{
	char *p;
	int startpos;

	startpos = -1;
	for (p = str->str; *p != '\0'; p++) {
		if (*p != ' ')
			continue;

		if (pos < 0)
			break;
		if (pos == 0)
			startpos = (int) (p-str->str);
		pos--;
	}

	if (startpos == -1)
		return; /* not found */

        g_string_erase(str, startpos, (int) (p-str->str)-startpos);
}

/* remove mode (and it's argument) from string */
static void mode_remove(GString *str, char mode)
{
	char *p;
	int argpos = 0;

	for (p = str->str; *p != '\0' && *p != ' '; p++) {
		if (mode == *p) {
			g_string_erase(str, (int) (p-str->str), 1);
			if (HAS_MODE_ARG_SET(mode))
                                node_remove_arg(str, argpos);
			break;
		}
		if (HAS_MODE_ARG_SET(*p))
			argpos++;
	}
}

static void mode_set(GString *str, char type, char mode)
{
	g_return_if_fail(str != NULL);

	if (type == '-')
		mode_remove(str, mode);
        else
		mode_add_sorted(str, mode, NULL);
}

static void mode_set_arg(GString *str, char type, char mode, const char *arg)
{
	g_return_if_fail(str != NULL);
	g_return_if_fail(type == '-' || arg != NULL);

	if (type == '-')
		mode_remove(str, mode);
        else
		mode_add_sorted(str, mode, arg);
}

int channel_mode_is_set(IRC_CHANNEL_REC *channel, char mode)
{
	g_return_val_if_fail(IS_IRC_CHANNEL(channel), FALSE);

	return channel->mode == NULL ? FALSE :
		mode_is_set(channel->mode, mode);
}

/* Parse channel mode string */
void parse_channel_modes(IRC_CHANNEL_REC *channel, const char *setby,
			 const char *mode)
{
        GString *newmode;
	char *dup, *modestr, *arg, *curmode, type;

	g_return_if_fail(IS_IRC_CHANNEL(channel));
	g_return_if_fail(mode != NULL);

	type = '+';
	newmode = g_string_new(channel->mode);

	dup = modestr = g_strdup(mode);
	curmode = cmd_get_param(&modestr);
	while (*curmode != '\0') {
		if (HAS_MODE_ARG(type, *curmode)) {
			/* get the argument for the mode. since we're
			   expecting argument, ignore the mode if there's
			   no argument (shouldn't happen). */
			arg = cmd_get_param(&modestr);
			if (*arg == '\0')
				continue;
		} else {
			arg = NULL;
		}

		switch (*curmode) {
		case '+':
		case '-':
			type = *curmode;
			break;

		case 'b':
			if (type == '+')
				banlist_add(channel, arg, setby, time(NULL));
			else
				banlist_remove(channel, arg);
			break;
		case 'e':
			if (type == '+')
				banlist_exception_add(channel, arg, setby,
						      time(NULL));
			else
				banlist_exception_remove(channel, arg);
			break;
		case 'I':
			if (type == '+')
				invitelist_add(channel, arg);
			else
				invitelist_remove(channel, arg);
			break;

		case 'o':
			if (g_strcasecmp(channel->server->nick, arg) == 0)
				channel->chanop = type == '+';
			nick_mode_change(channel, arg, '@', type);
			break;
		case 'h':
			nick_mode_change(channel, arg, '%', type);
			break;
		case 'v':
			nick_mode_change(channel, arg, '+', type);
			break;

		case 'l':
			mode_set_arg(newmode, type, 'l', arg);
			channel->limit = type == '-' ? 0 : atoi(arg);
			break;
		case 'k':
			mode_set_arg(newmode, type, 'k', arg);
			g_free_and_null(channel->key);
			if (type == '+')
				channel->key = g_strdup(arg);
			break;

		default:
                        mode_set(newmode, type, *curmode);
			break;
		}

		curmode++;
	}
	g_free(dup);

	if (strchr(channel->mode, 'k') == NULL && channel->key != NULL) {
		/* join was used with key but there's no key set
		   in channel modes.. */
		g_free(channel->key);
		channel->key = NULL;
	}

	if (strcmp(newmode->str, channel->mode) != 0) {
		g_free(channel->mode);
		channel->mode = g_strdup(newmode->str);

		signal_emit("channel mode changed", 1, channel);
	}

	g_string_free(newmode, TRUE);
}

/* add `mode' to `old' - return newly allocated mode. */
char *modes_join(const char *old, const char *mode)
{
	GString *newmode;
	char *dup, *modestr, *curmode, type;

        g_return_val_if_fail(mode != NULL, NULL);

	type = '+';
	newmode = g_string_new(old);

	dup = modestr = g_strdup(mode);
	curmode = cmd_get_param(&modestr);
	while (*curmode != '\0' && *curmode != ' ') {
		if (*curmode == '+' || *curmode == '-') {
			type = *curmode;
			curmode++;
			continue;
		}

		if (!HAS_MODE_ARG(type, *curmode))
			mode_set(newmode, type, *curmode);
		else {
			mode_set_arg(newmode, type, *curmode,
				     cmd_get_param(&modestr));
		}

		curmode++;
	}
	g_free(dup);

	modestr = newmode->str;
	g_string_free(newmode, FALSE);
	return modestr;
}

/* Parse user mode string */
static void parse_user_mode(IRC_SERVER_REC *server, const char *modestr)
{
	char *newmode, *oldmode;

	g_return_if_fail(IS_IRC_SERVER(server));
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

static void event_mode(const char *data, IRC_SERVER_REC *server,
		       const char *nick)
{
	IRC_CHANNEL_REC *chanrec;
	char *params, *channel, *mode;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST,
				  &channel, &mode);

	if (!ischannel(*channel)) {
		/* user mode change */
		parse_user_mode(server, mode);
	} else {
		/* channel mode change */
		chanrec = irc_channel_find(server, channel);
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

void channel_set_singlemode(IRC_SERVER_REC *server, const char *channel,
			    const char *nicks, const char *mode)
{
	GString *str;
	int num, modepos;
	char **nick, **nicklist;

	g_return_if_fail(IS_IRC_SERVER(server));
	g_return_if_fail(channel != NULL && nicks != NULL && mode != NULL);
	if (*nicks == '\0') return;

	num = modepos = 0;
	str = g_string_new(NULL);

	nicklist = g_strsplit(nicks, " ", -1);
	for (nick = nicklist; *nick != NULL; nick++) {
		if (**nick == '\0')
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

		if (++num == server->max_modes_in_cmd) {
			/* max. modes / command reached, send to server */
			irc_send_cmd(server, str->str);
			num = 0;
		}
	}
	if (num > 0) irc_send_cmd(server, str->str);

	g_strfreev(nicklist);
	g_string_free(str, TRUE);
}

void channel_set_mode(IRC_SERVER_REC *server, const char *channel,
		      const char *mode)
{
	char *modestr, *curmode, *orig, type, prevtype;
	GString *tmode, *targs;
	int count;

	g_return_if_fail(IS_IRC_SERVER(server));
	g_return_if_fail(channel != NULL && mode != NULL);

	tmode = g_string_new(NULL);
	targs = g_string_new(NULL);
	count = 0;

	orig = modestr = g_strdup(mode);

        type = '+'; prevtype = '\0';
	curmode = cmd_get_param(&modestr);
	for (; *curmode != '\0'; curmode++) {
		if (*curmode == '+' || *curmode == '-') {
			type = *curmode;
			continue;
		}

		if (count == server->max_modes_in_cmd &&
		    HAS_MODE_ARG(type, *curmode)) {
			irc_send_cmdv(server, "MODE %s %s%s",
				      channel, tmode->str, targs->str);

			count = 0; prevtype = '\0';
			g_string_truncate(tmode, 0);
			g_string_truncate(targs, 0);
		}

		if (type != prevtype) {
			prevtype = type;
			g_string_append_c(tmode, type);
		}
		g_string_append_c(tmode, *curmode);

		if (HAS_MODE_ARG(type, *curmode)) {
			char *arg;

			count++;
			arg = cmd_get_param(&modestr);
			if (*arg != '\0') g_string_sprintfa(targs, " %s", arg);
		}
	}

	if (tmode->len > 0) {
		irc_send_cmdv(server, "MODE %s %s%s",
			      channel, tmode->str, targs->str);
	}

	g_string_free(tmode, TRUE);
	g_string_free(targs, TRUE);
	g_free(orig);
}

static char *get_nicks(IRC_CHANNEL_REC *channel,
		       const char *data, int op, int voice)
{
        GString *str;
	GSList *nicks, *tmp;
	char **matches, **match, *ret;

	g_return_val_if_fail(channel != NULL, NULL);
	g_return_val_if_fail(data != NULL, NULL);
	if (*data == '\0') return NULL;

	str = g_string_new(NULL);
	matches = g_strsplit(data, " ", -1);
	for (match = matches; *match != NULL; match++) {
		if (strchr(*match, '*') == NULL && strchr(*match, '?') == NULL) {
			/* no wildcards */
                        g_string_sprintfa(str, "%s ", *match);
			continue;
		}

		/* wildcards */
		nicks = nicklist_find_multiple(CHANNEL(channel), data);
		for (tmp = nicks; tmp != NULL; tmp = tmp->next) {
			NICK_REC *rec = tmp->data;

			if ((op == 1 && !rec->op) || (op == 0 && rec->op) ||
			    (voice == 1 && !rec->voice) || (voice == 0 && rec->voice))
				continue;

			if (g_strcasecmp(rec->nick, channel->server->nick) == 0)
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

/* SYNTAX: OP <nicks> */
static void cmd_op(const char *data, IRC_SERVER_REC *server,
		   IRC_CHANNEL_REC *channel)
{
	char *nicks;

	if (!IS_IRC_CHANNEL(channel))
		return;

	nicks = get_nicks(channel, data, 0, -1);
	if (nicks != NULL && *nicks != '\0')
		channel_set_singlemode(server, channel->name, nicks, "+o");
	g_free_not_null(nicks);
}

/* SYNTAX: DEOP <nicks> */
static void cmd_deop(const char *data, IRC_SERVER_REC *server,
		     IRC_CHANNEL_REC *channel)
{
	char *nicks;

	if (!IS_IRC_CHANNEL(channel))
		return;

	nicks = get_nicks(channel, data, 1, -1);
	if (nicks != NULL && *nicks != '\0')
		channel_set_singlemode(server, channel->name, nicks, "-o");
	g_free_not_null(nicks);
}

/* SYNTAX: VOICE <nicks> */
static void cmd_voice(const char *data, IRC_SERVER_REC *server,
		      IRC_CHANNEL_REC *channel)
{
	char *nicks;

	if (!IS_IRC_CHANNEL(channel))
		return;

	nicks = get_nicks(channel, data, 0, 0);
	if (nicks != NULL && *nicks != '\0')
		channel_set_singlemode(server, channel->name, nicks, "+v");
	g_free_not_null(nicks);
}

/* SYNTAX: DEVOICE <nicks> */
static void cmd_devoice(const char *data, IRC_SERVER_REC *server,
			IRC_CHANNEL_REC *channel)
{
	char *nicks;

	if (!IS_IRC_CHANNEL(channel))
		return;

	nicks = get_nicks(channel, data, 0, 1);
	if (nicks != NULL && *nicks != '\0')
		channel_set_singlemode(server, channel->name, nicks, "-v");
	g_free_not_null(nicks);
}

/* SYNTAX: MODE <your nick>|<channel> [<mode> [<mode parameters>]] */
static void cmd_mode(const char *data, IRC_SERVER_REC *server,
		     IRC_CHANNEL_REC *channel)
{
	char *target, *mode;
	void *free_arg;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !IS_IRC_SERVER(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);

	if (*data == '+' || *data == '-') {
		target = "*";
		if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_GETREST, &mode))
			return;
	} else {
		if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST, &target, &mode))
			return;
	}

	if (strcmp(target, "*") == 0) {
		if (!IS_IRC_CHANNEL(channel))
			cmd_param_error(CMDERR_NOT_JOINED);

		target = channel->name;
	}
	if (*target == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	if (*mode == '\0')
		irc_send_cmdv(server, "MODE %s", target);
	else if (ischannel(*target))
		channel_set_mode(server, target, mode);
	else
		irc_send_cmdv(server, "MODE %s %s", target, mode);

	cmd_params_free(free_arg);
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
