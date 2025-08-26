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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include <irssi/src/core/signals.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/core/misc.h>

#include <irssi/src/irc/core/irc-commands.h>
#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/irc/core/irc-channels.h>
#include <irssi/src/irc/core/servers-redirect.h>
#include <irssi/src/irc/core/modes.h>
#include <irssi/src/irc/core/mode-lists.h>
#include <irssi/src/core/nicklist.h>

/* Change nick's mode in channel */
static void nick_mode_change(IRC_CHANNEL_REC *channel, const char *nick,
			     char mode, int type, const char *setby)
{
	NICK_REC *nickrec;
	char modestr[2], typestr[2];

	g_return_if_fail(IS_IRC_CHANNEL(channel));
	g_return_if_fail(nick != NULL);

	nickrec = nicklist_find(CHANNEL(channel), nick);
	if (nickrec == NULL) return; /* No /names list got yet */

	if (mode == '@') nickrec->op = type == '+';
	else if (mode == '+') nickrec->voice = type == '+';
	else if (mode == '%') nickrec->halfop = type == '+';
	if (channel->server->prefix[(unsigned char) mode] != '\0') {
		if (type == '+')
			prefix_add(nickrec->prefixes, mode, (SERVER_REC *) channel->server);
		else
			prefix_del(nickrec->prefixes, mode);
	}

	modestr[0] = mode; modestr[1] = '\0';
	typestr[0] = type; typestr[1] = '\0';
	signal_emit("nick mode changed", 5,
		    channel, nickrec, setby, modestr, typestr);
}

void prefix_add(char prefixes[MAX_USER_PREFIXES+1], char newprefix, SERVER_REC *server)
{
	const char *prefixlst;
	char newprefixes[MAX_USER_PREFIXES+1]; /* to hold the new prefixes */
	unsigned int newpos = 0; /* to hold our position in the new prefixes */
	unsigned int oldpos = 0; /* to hold our position in the old prefixes */

	prefixlst = server->get_nick_flags(server);

	/* go through the possible prefixes, copy higher ones, and find this one's place
	 * always leave room for the current prefix to be added, though.
	 */
	while (*prefixlst != '\0' && prefixes[oldpos] != '\0' &&
			newpos < MAX_USER_PREFIXES - 1) {
		if (prefixes[oldpos] == newprefix)
			return; /* already inserted.  why are we here? */

		if (*prefixlst == newprefix)
			break; /* insert the new prefix here */

		if (*prefixlst == prefixes[oldpos]) {
			/* this prefix is present.
			 * the one we are inserting goes after it.
			 * copy it over, and continue searching.
			 */
			newprefixes[newpos++] = prefixes[oldpos++];
		}
		prefixlst++;
	}

	/* newpos is now the position in which we wish to insert the prefix */
	newprefixes[newpos++] = newprefix;

	/* finish copying the remaining prefixes */
	while (prefixes[oldpos] != '\0' && newpos < MAX_USER_PREFIXES)
		newprefixes[newpos++] = prefixes[oldpos++];

	newprefixes[newpos] = '\0';

	strcpy(prefixes, newprefixes);
}

void prefix_del(char prefixes[MAX_USER_PREFIXES+1], char oldprefix)
{
	char *todel;

	todel = strchr(prefixes, oldprefix);
	if (todel)
		memmove(todel, todel+1, strlen(todel));
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

	g_string_insert_c(str, pos, ' ');
	g_string_insert(str, pos+1, arg);
}

/* Add mode character to list sorted alphabetically */
static void mode_add_sorted(IRC_SERVER_REC *server, GString *str,
			    char mode, const char *arg, int user)
{
	char *p;
	int updating, argpos = 0;

	/* check that mode isn't already set */
	if ((!user && !HAS_MODE_ARG_SET(server, mode)) &&
	    mode_is_set(str->str, mode))
		return;

	updating = FALSE;
	for (p = str->str; *p != '\0' && *p != ' '; p++) {
		if (mode < *p)
			break;
		if (mode == *p) {
                        updating = TRUE;
			break;
		}
		if (!user && HAS_MODE_ARG_SET(server, *p))
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
static void mode_remove(IRC_SERVER_REC *server, GString *str, char mode, int user)
{
	char *p;
	int argpos = 0;

	for (p = str->str; *p != '\0' && *p != ' '; p++) {
		if (mode == *p) {
			g_string_erase(str, (int) (p-str->str), 1);
			if (!user && HAS_MODE_ARG_SET(server, mode))
                                node_remove_arg(str, argpos);
			break;
		}
		if (!user && HAS_MODE_ARG_SET(server, *p))
			argpos++;
	}
}

static void mode_set(IRC_SERVER_REC *server, GString *str,
		     char type, char mode, int user)
{
	g_return_if_fail(str != NULL);

	if (type == '-')
		mode_remove(server, str, mode, user);
        else
		mode_add_sorted(server, str, mode, NULL, user);
}

static void mode_set_arg(IRC_SERVER_REC *server, GString *str,
			 char type, char mode, const char *arg, int user)
{
	g_return_if_fail(str != NULL);
	g_return_if_fail(type == '-' || arg != NULL);

	if (type == '-')
		mode_remove(server, str, mode, user);
        else
		mode_add_sorted(server, str, mode, arg, user);
}

/* Mode that needs a parameter of a mask for both setting and removing
   (eg: bans) */
void modes_type_a(IRC_CHANNEL_REC *channel, const char *setby, char type,
		  char mode, char *arg, GString *newmode)
{
	if (mode == 'b') {
		if (type == '+')
			banlist_add(channel, arg, setby, time(NULL));
		else
			banlist_remove(channel, arg, setby);
	}
}

/* Mode that needs parameter for both setting and removing (eg: +k) */
void modes_type_b(IRC_CHANNEL_REC *channel, const char *setby, char type,
		  char mode, char *arg, GString *newmode)
{
	if (mode == 'k') {
		if (*arg == '\0' && type == '+')
			arg = channel->key != NULL ? channel->key : "???";

		if (arg != channel->key) {
			g_free_and_null(channel->key);
			if (type == '+')
				channel->key = g_strdup(arg);
		}
	}

	mode_set_arg(channel->server, newmode, type, mode, arg, FALSE);
}

/* Mode that needs parameter only for adding */
void modes_type_c(IRC_CHANNEL_REC *channel, const char *setby,
		  char type, char mode, char *arg, GString *newmode)
{
	if (mode == 'l') {
		channel->limit = type == '-' ? 0 : atoi(arg);
	}

	mode_set_arg(channel->server, newmode, type, mode, arg, FALSE);
}

/* Mode that takes no parameter */
void modes_type_d(IRC_CHANNEL_REC *channel, const char *setby,
		  char type, char mode, char *arg, GString *newmode)
{
	mode_set(channel->server, newmode, type, mode, FALSE);
}

void modes_type_prefix(IRC_CHANNEL_REC *channel, const char *setby,
		       char type, char mode, char *arg, GString *newmode)
{
	int umode = (unsigned char) mode;

	if (g_ascii_strcasecmp(channel->server->nick, arg) == 0) {
		/* see if we need to update channel->chanop */
		const char *prefix =
			g_hash_table_lookup(channel->server->isupport, "PREFIX");
		if (prefix != NULL && *prefix == '(') {
			prefix++;
			while (*prefix != ')' && *prefix != '\0') {
				if (*prefix == mode) {
					channel->chanop = type == '+';
					break;
				}
				if (*prefix == 'o')
					break;
				prefix++;
			}
		} else {
			if (mode == 'o' || mode == 'O')
				channel->chanop = type == '+';
		}
	}

	nick_mode_change(channel, arg, channel->server->modes[umode].prefix,
			 type, setby);
}

int channel_mode_is_set(IRC_CHANNEL_REC *channel, char mode)
{
	g_return_val_if_fail(IS_IRC_CHANNEL(channel), FALSE);

	return channel->mode == NULL ? FALSE :
		mode_is_set(channel->mode, mode);
}

/* Parse channel mode string */
void parse_channel_modes(IRC_CHANNEL_REC *channel, const char *setby,
			 const char *mode, int update_key)
{
	IRC_SERVER_REC *server = channel->server;
        GString *newmode;
	char *dup, *modestr, *arg, *curmode, type, *old_key;
	int umode;

	g_return_if_fail(IS_IRC_CHANNEL(channel));
	g_return_if_fail(mode != NULL);

	type = '+';
	newmode = g_string_new(channel->mode);
	old_key = update_key ? NULL : g_strdup(channel->key);

	dup = modestr = g_strdup(mode);
	curmode = cmd_get_param(&modestr);
	while (*curmode != '\0') {
		if (HAS_MODE_ARG(server, type, *curmode)) {
			/* get the argument for the mode. NOTE: We don't
			   get the +k's argument when joining to channel. */
			arg = cmd_get_param(&modestr);
		} else {
			arg = NULL;
		}

		switch (*curmode) {
		case '+':
		case '-':
			type = *curmode;
			break;
		default:
			umode = (unsigned char) *curmode;
			if (server->modes[umode].func != NULL) {
				server->modes[umode].func(channel, setby,
							  type, *curmode, arg,
							  newmode);
			} else {
				/* Treat unknown modes as ones without params */
				modes_type_d(channel, setby, type, *curmode,
					     arg, newmode);
			}
		}

		curmode++;
	}
	g_free(dup);

	if (channel->key != NULL &&
	    strchr(channel->mode, 'k') == NULL &&
	    strchr(newmode->str, 'k') == NULL) {
		/* join was used with key but there's no key set
		   in channel modes.. */
		g_free(channel->key);
		channel->key = NULL;
	} else if (!update_key && old_key != NULL) {
		/* get the old one back, just in case it was replaced */
		g_free(channel->key);
		channel->key = old_key;
		mode_set_arg(channel->server, newmode, '+', 'k', old_key, FALSE);
		old_key = NULL;
	}

	if (g_strcmp0(newmode->str, channel->mode) != 0) {
		g_free(channel->mode);
		channel->mode = g_strdup(newmode->str);

		signal_emit("channel mode changed", 2, channel, setby);
	}

	g_string_free(newmode, TRUE);
	g_free(old_key);
}

/* add `mode' to `old' - return newly allocated mode.
   `channel' specifies if we're parsing channel mode and we should try
   to join mode arguments too. */
char *modes_join(IRC_SERVER_REC *server, const char *old,
		 const char *mode, int channel)
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

		if (!channel || !HAS_MODE_ARG(server, type, *curmode))
			mode_set(server, newmode, type, *curmode, !channel);
		else {
			mode_set_arg(server, newmode, type, *curmode,
				     cmd_get_param(&modestr), !channel);
		}

		curmode++;
	}
	g_free(dup);

	modestr = g_string_free_and_steal(newmode);
	return modestr;
}

/* Parse user mode string */
static void parse_user_mode(IRC_SERVER_REC *server, const char *modestr)
{
	char *newmode, *oldmode;

	g_return_if_fail(IS_IRC_SERVER(server));
	g_return_if_fail(modestr != NULL);

	newmode = modes_join(NULL, server->usermode, modestr, FALSE);
	oldmode = server->usermode;
	server->usermode = newmode;
	server->server_operator = ((strchr(newmode, 'o') != NULL) || (strchr(newmode, 'O') != NULL));

	signal_emit("user mode changed", 2, server, oldmode);
	g_free_not_null(oldmode);
}

static void event_user_mode(IRC_SERVER_REC *server, const char *data)
{
	char *params, *nick, *mode;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &nick, &mode);
	parse_user_mode(server, mode);

	g_free(params);
}

static void event_mode(IRC_SERVER_REC *server, const char *data,
		       const char *nick)
{
	IRC_CHANNEL_REC *chanrec;
	char *params, *channel, *mode;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST,
				  &channel, &mode);

	if (!server_ischannel(SERVER(server), channel)) {
		/* user mode change */
		parse_user_mode(server, mode);
	} else {
		/* channel mode change */
		chanrec = irc_channel_find(server, channel);
		if (chanrec != NULL)
			parse_channel_modes(chanrec, nick, mode, TRUE);
	}

	g_free(params);
}

static void event_oper(IRC_SERVER_REC *server, const char *data)
{
	const char *opermode;

	opermode = settings_get_str("opermode");
        if (*opermode != '\0')
		irc_send_cmdv(server, "MODE %s %s", server->nick, opermode);
}

static void event_away(IRC_SERVER_REC *server, const char *data)
{
	g_return_if_fail(server != NULL);

	server->usermode_away = TRUE;
	signal_emit("away mode changed", 1, server);
}

static void event_unaway(IRC_SERVER_REC *server, const char *data)
{
	g_return_if_fail(server != NULL);

	server->usermode_away = FALSE;
	g_free_and_null(server->away_reason);
	signal_emit("away mode changed", 1, server);
}

static void sig_req_usermode_change(IRC_SERVER_REC *server, const char *data,
				    const char *nick, const char *addr)
{
	char *params, *target, *mode;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST,
				  &target, &mode);
	if (!server_ischannel(SERVER(server), target)) {
                /* we requested a user mode change, save this */
		mode = modes_join(NULL, server->wanted_usermode, mode, FALSE);
                g_free_not_null(server->wanted_usermode);
		server->wanted_usermode = mode;
	}

	g_free(params);

	signal_emit("event mode", 4, server, data, nick, addr);
}

void channel_set_singlemode(IRC_CHANNEL_REC *channel, const char *nicks,
			    const char *mode)
{
	GString *str;
	int num, modepos;
	char **nick, **nicklist;

	g_return_if_fail(IS_IRC_CHANNEL(channel));
	g_return_if_fail(nicks != NULL && mode != NULL);
	if (*nicks == '\0') return;

	num = modepos = 0;
	str = g_string_new(NULL);

	nicklist = g_strsplit(nicks, " ", -1);
	for (nick = nicklist; *nick != NULL; nick++) {
		if (**nick == '\0')
			continue;

		if (num == 0)
		{
			g_string_printf(str, "MODE %s %s",
					 channel->name, mode);
			modepos = str->len;
		} else {
			/* insert the mode string */
			g_string_insert(str, modepos, mode);
		}

		g_string_append_printf(str, " %s", *nick);

		if (++num == channel->server->max_modes_in_cmd) {
			/* max. modes / command reached, send to server */
			irc_send_cmd(channel->server, str->str);
			num = 0;
		}
	}
	if (num > 0) irc_send_cmd(channel->server, str->str);

	g_strfreev(nicklist);
	g_string_free(str, TRUE);
}

void channel_set_mode(IRC_SERVER_REC *server, const char *channel,
		      const char *mode)
{
	IRC_CHANNEL_REC *chanrec;
	GString *tmode, *targs;
	char *modestr, *curmode, *orig, type, prevtype;
	int count;

	g_return_if_fail(IS_IRC_SERVER(server));
	g_return_if_fail(channel != NULL && mode != NULL);

	tmode = g_string_new(NULL);
	targs = g_string_new(NULL);
	count = 0;

	chanrec = irc_channel_find(server, channel);
	if (chanrec != NULL)
		channel = chanrec->name;

	orig = modestr = g_strdup(mode);

        type = '+'; prevtype = '\0';
	curmode = cmd_get_param(&modestr);
	for (;; curmode++) {
		if (*curmode == '\0') {
			/* support for +o nick +o nick2 */
			curmode = cmd_get_param(&modestr);
			if (*curmode == '\0')
				break;
		}

		if (*curmode == '+' || *curmode == '-') {
			type = *curmode;
			continue;
		}

		if (count == server->max_modes_in_cmd &&
		    HAS_MODE_ARG(server, type, *curmode)) {
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

		if (HAS_MODE_ARG(server, type, *curmode)) {
			char *arg;

			count++;
			arg = cmd_get_param(&modestr);
			if (*arg == '\0' && type == '-' && *curmode == 'k') {
				/* "/mode #channel -k" - no reason why it
				   shouldn't work really, so append the key */
				IRC_CHANNEL_REC *chanrec;

				chanrec = irc_channel_find(server, channel);
				if (chanrec != NULL && chanrec->key != NULL)
                                        arg = chanrec->key;
			}

			if (*arg != '\0')
				g_string_append_printf(targs, " %s", arg);
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

static int get_wildcard_nicks(GString *output, const char *mask,
			      IRC_CHANNEL_REC *channel, int op, int voice)
{
	GSList *nicks, *tmp;
        int count;

	g_return_val_if_fail(output != NULL, 0);
	g_return_val_if_fail(mask != NULL, 0);
	g_return_val_if_fail(IS_IRC_CHANNEL(channel), 0);

        count = 0;
	nicks = nicklist_find_multiple(CHANNEL(channel), mask);
	for (tmp = nicks; tmp != NULL; tmp = tmp->next) {
		NICK_REC *rec = tmp->data;

		if ((op == 1 && !rec->op) || (op == 0 && rec->op) ||
		    (voice == 1 && !rec->voice) || (voice == 0 && rec->voice))
			continue;

		if (g_ascii_strcasecmp(rec->nick, channel->server->nick) == 0)
			continue;

		g_string_append_printf(output, "%s ", rec->nick);
                count++;
	}
	g_slist_free(nicks);

        return count;
}

static char *get_nicks(IRC_SERVER_REC *server, WI_ITEM_REC *item,
		       const char *data, int op, int voice,
		       IRC_CHANNEL_REC **ret_channel)
{
        IRC_CHANNEL_REC *channel;
        GString *str;
        GHashTable *optlist;
	char **matches, **match, *ret, *channame, *nicks;
	void *free_arg;
        int count, max_modes;

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST |
			    PARAM_FLAG_OPTIONS | PARAM_FLAG_OPTCHAN_NAME,
			    item, "op", &optlist, &channame, &nicks))
		return NULL;

	if (*nicks == '\0')
		return NULL;

	channel = irc_channel_find(server, channame);
	if (channel == NULL) {
		cmd_params_free(free_arg);
		return NULL;
	}

	str = g_string_new(NULL);
	matches = g_strsplit(nicks, " ", -1);
	for (match = matches; *match != NULL; match++) {
		if (strchr(*match, '*') == NULL &&
		    strchr(*match, '?') == NULL) {
			/* no wildcards */
                        g_string_append_printf(str, "%s ", *match);
		} else {
			count = get_wildcard_nicks(str, *match, channel,
						   op, voice);
                        max_modes = settings_get_int("max_wildcard_modes");
			if (max_modes > 0 && count > max_modes &&
			    g_hash_table_lookup(optlist, "yes") == NULL) {
                                /* too many matches */
				g_string_free(str, TRUE);
				g_strfreev(matches);
				cmd_params_free(free_arg);

				signal_emit("error command", 1,
					    GINT_TO_POINTER(CMDERR_NOT_GOOD_IDEA));
				signal_stop();
                                return NULL;
			}
		}
	}

        if (str->len > 0) g_string_truncate(str, str->len-1);
	ret = g_string_free_and_steal(str);
	g_strfreev(matches);
	cmd_params_free(free_arg);

	*ret_channel = channel;
	return ret;
}

/* SYNTAX: OP <nicks> */
static void cmd_op(const char *data, IRC_SERVER_REC *server,
		   WI_ITEM_REC *item)
{
        IRC_CHANNEL_REC *channel;
	char *nicks;

	CMD_IRC_SERVER(server);

	nicks = get_nicks(server, item, data, 0, -1, &channel);
	if (nicks != NULL && *nicks != '\0')
		channel_set_singlemode(channel, nicks, "+o");
	g_free_not_null(nicks);
}

/* SYNTAX: DEOP <nicks> */
static void cmd_deop(const char *data, IRC_SERVER_REC *server,
		     WI_ITEM_REC *item)
{
        IRC_CHANNEL_REC *channel;
	char *nicks;

        CMD_IRC_SERVER(server);

	nicks = get_nicks(server, item, data, 1, -1, &channel);
	if (nicks != NULL && *nicks != '\0')
		channel_set_singlemode(channel, nicks, "-o");
	g_free_not_null(nicks);
}

/* SYNTAX: VOICE <nicks> */
static void cmd_voice(const char *data, IRC_SERVER_REC *server,
		      WI_ITEM_REC *item)
{
        IRC_CHANNEL_REC *channel;
	char *nicks;

        CMD_IRC_SERVER(server);

	nicks = get_nicks(server, item, data, 0, 0, &channel);
	if (nicks != NULL && *nicks != '\0')
		channel_set_singlemode(channel, nicks, "+v");
	g_free_not_null(nicks);
}

/* SYNTAX: DEVOICE <nicks> */
static void cmd_devoice(const char *data, IRC_SERVER_REC *server,
			WI_ITEM_REC *item)
{
        IRC_CHANNEL_REC *channel;
	char *nicks;

        CMD_IRC_SERVER(server);

	nicks = get_nicks(server, item, data, -1, 1, &channel);
	if (nicks != NULL && *nicks != '\0')
		channel_set_singlemode(channel, nicks, "-v");
	g_free_not_null(nicks);
}

/* SYNTAX: MODE <your nick>|<channel> [<mode> [<mode parameters>]] */
static void cmd_mode(const char *data, IRC_SERVER_REC *server,
		     IRC_CHANNEL_REC *channel)
{
	IRC_CHANNEL_REC *chanrec;
	char *target, *mode;
	void *free_arg;

        CMD_IRC_SERVER(server);

	if (*data == '+' || *data == '-') {
		target = "*";
		if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_GETREST | PARAM_FLAG_STRIP_TRAILING_WS, &mode))
			return;
	} else {
		if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST | PARAM_FLAG_STRIP_TRAILING_WS, &target, &mode))
			return;
	}

	if (g_strcmp0(target, "*") == 0) {
		if (!IS_IRC_CHANNEL(channel))
			cmd_param_error(CMDERR_NOT_JOINED);

		target = channel->name;
	}
	if (*target == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	if (*mode == '\0') {
		chanrec = irc_channel_find(server, target);
		if (chanrec != NULL)
			target = chanrec->name;

		irc_send_cmdv(server, "MODE %s", target);
	} else if (server_ischannel(SERVER(server), target))
		channel_set_mode(server, target, mode);
	else {
		if (g_ascii_strcasecmp(target, server->nick) == 0) {
			server_redirect_event(server, "mode user", 1, target, -1, NULL,
					      "event mode", "requested usermode change", NULL);
		}

		irc_send_cmdv(server, "MODE %s %s", target, mode);
	}

	cmd_params_free(free_arg);
}

void modes_server_init(IRC_SERVER_REC *server)
{
	server->modes['b'].func = modes_type_a;
	server->modes['e'].func = modes_type_a;
	server->modes['I'].func = modes_type_a;

	server->modes['h'].func = modes_type_prefix;
	server->modes['h'].prefix = '%';
	server->modes['o'].func = modes_type_prefix;
	server->modes['o'].prefix = '@';
	server->modes['O'].func = modes_type_prefix;
	server->modes['O'].prefix = '@';
	server->modes['v'].func = modes_type_prefix;
	server->modes['v'].prefix = '+';

	server->prefix['%'] = 'h';
	server->prefix['@'] = 'o';
	server->prefix['+'] = 'v';

	server->modes['k'].func = modes_type_b;
	server->modes['l'].func = modes_type_c;
}

void modes_init(void)
{
	settings_add_str("misc", "opermode", "");
	settings_add_int("misc", "max_wildcard_modes", 6);

	signal_add("event 221", (SIGNAL_FUNC) event_user_mode);
	signal_add("event 305", (SIGNAL_FUNC) event_unaway);
	signal_add("event 306", (SIGNAL_FUNC) event_away);
	signal_add("event 381", (SIGNAL_FUNC) event_oper);
	signal_add("event mode", (SIGNAL_FUNC) event_mode);
        signal_add("requested usermode change", (SIGNAL_FUNC) sig_req_usermode_change);

	command_bind_irc("op", NULL, (SIGNAL_FUNC) cmd_op);
	command_bind_irc("deop", NULL, (SIGNAL_FUNC) cmd_deop);
	command_bind_irc("voice", NULL, (SIGNAL_FUNC) cmd_voice);
	command_bind_irc("devoice", NULL, (SIGNAL_FUNC) cmd_devoice);
	command_bind_irc("mode", NULL, (SIGNAL_FUNC) cmd_mode);

	command_set_options("op", "yes");
}

void modes_deinit(void)
{
	signal_remove("event 221", (SIGNAL_FUNC) event_user_mode);
	signal_remove("event 305", (SIGNAL_FUNC) event_unaway);
	signal_remove("event 306", (SIGNAL_FUNC) event_away);
	signal_remove("event 381", (SIGNAL_FUNC) event_oper);
	signal_remove("event mode", (SIGNAL_FUNC) event_mode);
        signal_remove("requested usermode change", (SIGNAL_FUNC) sig_req_usermode_change);

	command_unbind("op", (SIGNAL_FUNC) cmd_op);
	command_unbind("deop", (SIGNAL_FUNC) cmd_deop);
	command_unbind("voice", (SIGNAL_FUNC) cmd_voice);
	command_unbind("devoice", (SIGNAL_FUNC) cmd_devoice);
	command_unbind("mode", (SIGNAL_FUNC) cmd_mode);
}
