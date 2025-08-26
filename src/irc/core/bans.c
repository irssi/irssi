/*
 bans.c : irssi

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
#include <irssi/src/core/misc.h>
#include <irssi/src/core/settings.h>

#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/irc/core/irc-channels.h>
#include <irssi/src/irc/core/irc-masks.h>
#include <irssi/src/irc/core/irc-commands.h>
#include <irssi/src/irc/core/modes.h>
#include <irssi/src/irc/core/mode-lists.h>
#include <irssi/src/core/nicklist.h>

#define BAN_TYPE_NORMAL (IRC_MASK_USER | IRC_MASK_DOMAIN)
#define BAN_TYPE_USER (IRC_MASK_USER)
#define BAN_TYPE_HOST (IRC_MASK_HOST | IRC_MASK_DOMAIN)
#define BAN_TYPE_DOMAIN (IRC_MASK_DOMAIN)
#define BAN_FIRST "1"
#define BAN_LAST "-1"

static char *default_ban_type_str;
static int default_ban_type;

char *ban_get_mask(IRC_CHANNEL_REC *channel, const char *nick, int ban_type)
{
	NICK_REC *rec;
	char *str, *user, *host;
        int size;

	g_return_val_if_fail(IS_IRC_CHANNEL(channel), NULL);
	g_return_val_if_fail(nick != NULL, NULL);

	rec = nicklist_find(CHANNEL(channel), nick);
	if (rec == NULL) return NULL;
	if (rec->host == NULL) {
		g_warning("channel %s is not synced, using nick ban for %s", channel->name, nick);
		return g_strdup_printf("%s!*@*", nick);
	}

	if (ban_type <= 0)
		ban_type = default_ban_type;

	str = irc_get_mask(nick, rec->host, ban_type);

	/* there's a limit of 10 characters in user mask. so, banning
	   someone with user mask of 10 characters gives us "*1234567890",
	   which is one too much.. so, remove the first character after "*"
           so we'll get "*234567890" */
	user = strchr(str, '!');
	if (user == NULL) return str;

	host = strchr(++user, '@');
	if (host == NULL) return str;

        size = (int) (host-user);
	if (size >= 10) {
		/* too long user mask */
		memmove(user+1, user+(size-9), strlen(user+(size-9))+1);
	}
	return str;
}

char *ban_get_masks(IRC_CHANNEL_REC *channel, const char *nicks, int ban_type)
{
	GString *str;
	char **ban, **banlist, *realban, *ret;

	str = g_string_new(NULL);
	banlist = g_strsplit(nicks, " ", -1);
	for (ban = banlist; *ban != NULL; ban++) {
		if (**ban == '$' || strchr(*ban, '!') != NULL) {
			/* explicit ban */
			g_string_append_printf(str, "%s ", *ban);
			continue;
		}

		/* ban nick */
		realban = ban_get_mask(channel, *ban, ban_type);
		if (realban != NULL) {
			g_string_append_printf(str, "%s ", realban);
			g_free(realban);
		}
	}
	g_strfreev(banlist);

	if (str->len > 0)
		g_string_truncate(str, str->len-1);

	ret = g_string_free_and_steal(str);
	return ret;
}

void ban_set(IRC_CHANNEL_REC *channel, const char *bans, int ban_type)
{
	char *masks;

	g_return_if_fail(bans != NULL);

	if (ban_type <= 0)
		ban_type = default_ban_type;

	masks = ban_get_masks(channel, bans, ban_type);
	channel_set_singlemode(channel, masks, "+b");
        g_free(masks);
}

void ban_remove(IRC_CHANNEL_REC *channel, const char *bans)
{
	GString *str;
	GSList *tmp;
	BAN_REC *rec;
	char **ban, **banlist;
        int found;

	g_return_if_fail(bans != NULL);

	str = g_string_new(NULL);
	banlist = g_strsplit(bans, " ", -1);
	for (ban = banlist; *ban != NULL; ban++) {
                found = FALSE;
		for (tmp = channel->banlist; tmp != NULL; tmp = tmp->next) {
			rec = tmp->data;

			if (match_wildcards(*ban, rec->ban)) {
				g_string_append_printf(str, "%s ", rec->ban);
                                found = TRUE;
			}
		}

		if (!found) {
			rec = NULL;
			if (!g_ascii_strcasecmp(*ban, BAN_LAST)) {
				/* unnbanning last set ban */
				rec = g_slist_nth_data(channel->banlist,
							g_slist_length(channel->banlist) - 1);
			}
			else if (is_numeric(*ban, '\0')) {
				/* unbanning with ban# */
				rec = g_slist_nth_data(channel->banlist,
							atoi(*ban)-1);
			}
			if (rec != NULL)
				g_string_append_printf(str, "%s ", rec->ban);
			else if (!channel->synced)
				g_warning("channel %s is not synced", channel->name);
		}
	}
	g_strfreev(banlist);

	if (str->len > 0)
		channel_set_singlemode(channel, str->str, "-b");
	g_string_free(str, TRUE);
}

static void command_set_ban(const char *data, IRC_SERVER_REC *server,
			    WI_ITEM_REC *item, int set, int ban_type)
{
	IRC_CHANNEL_REC *chanrec;
	char *channel, *nicks;
	void *free_arg;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !IS_IRC_SERVER(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_OPTCHAN | PARAM_FLAG_GETREST |
			    PARAM_FLAG_STRIP_TRAILING_WS, item, &channel, &nicks)) return;
	if (!server_ischannel(SERVER(server), channel)) cmd_param_error(CMDERR_NOT_JOINED);
	if (*nicks == '\0') {
		if (g_strcmp0(data, "*") != 0)
			cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
                /* /BAN * or /UNBAN * - ban/unban everyone */
		nicks = (char *) data;
	}

	chanrec = irc_channel_find(server, channel);
	if (chanrec == NULL)
		cmd_param_error(CMDERR_CHAN_NOT_FOUND);

	if (set)
		ban_set(chanrec, nicks, ban_type);
	else
		ban_remove(chanrec, nicks);

	cmd_params_free(free_arg);
}

static int parse_custom_ban(const char *type)
{
	char **list;
	int n, ban_type;

        ban_type = 0;
	list = g_strsplit(type, " ", -1);
	for (n = 0; list[n] != NULL; n++) {
		if (i_toupper(list[n][0]) == 'N')
			ban_type |= IRC_MASK_NICK;
		else if (i_toupper(list[n][0]) == 'U')
			ban_type |= IRC_MASK_USER;
		else if (i_toupper(list[n][0]) == 'H')
			ban_type |= IRC_MASK_HOST | IRC_MASK_DOMAIN;
		else if (i_toupper(list[n][0]) == 'D')
			ban_type |= IRC_MASK_DOMAIN;
	}
	g_strfreev(list);

        return ban_type;
}

static int parse_ban_type(const char *type)
{
	const char *pos;

	g_return_val_if_fail(type != NULL, 0);

	if (i_toupper(type[0]) == 'N')
		return BAN_TYPE_NORMAL;
	if (i_toupper(type[0]) == 'U')
		return BAN_TYPE_USER;
	if (i_toupper(type[0]) == 'H')
		return BAN_TYPE_HOST;
	if (i_toupper(type[0]) == 'D')
		return BAN_TYPE_DOMAIN;
	if (i_toupper(type[0]) == 'C') {
		pos = strchr(type, ' ');
                if (pos != NULL)
			return parse_custom_ban(pos+1);
	}

        return 0;
}

/* SYNTAX: BAN [-normal | -user | -host | -domain | -custom <type>] <nicks/masks> */
static void cmd_ban(const char *data, IRC_SERVER_REC *server, void *item)
{
	GHashTable *optlist;
        const char *custom_type;
	char *ban;
        int ban_type;
	void *free_arg;

        CMD_IRC_SERVER(server);

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS | 
			    PARAM_FLAG_GETREST | PARAM_FLAG_STRIP_TRAILING_WS,
			    "ban", &optlist, &ban))
		return;

	if (g_hash_table_lookup(optlist, "normal") != NULL)
		ban_type = BAN_TYPE_NORMAL;
	else if (g_hash_table_lookup(optlist, "user") != NULL)
		ban_type = BAN_TYPE_USER;
	else if (g_hash_table_lookup(optlist, "host") != NULL)
		ban_type = BAN_TYPE_HOST;
	else if (g_hash_table_lookup(optlist, "domain") != NULL)
		ban_type = BAN_TYPE_DOMAIN;
	else {
		custom_type = g_hash_table_lookup(optlist, "custom");
                if (custom_type != NULL)
			ban_type = parse_custom_ban(custom_type);
                else
			ban_type = default_ban_type;
	}

	command_set_ban(ban, server, item, TRUE, ban_type);

	cmd_params_free(free_arg);
}

/* SYNTAX: UNBAN -first | -last | <id> | <masks> */
static void cmd_unban(const char *data, IRC_SERVER_REC *server, void *item)
{
	GHashTable *optlist;
	char *ban;
	void *free_arg;

        CMD_IRC_SERVER(server);

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS | 
			    PARAM_FLAG_GETREST | PARAM_FLAG_STRIP_TRAILING_WS,
			    "unban", &optlist, &ban))
		return;

	ban = NULL;
	if (g_hash_table_lookup(optlist, "first") != NULL)
		ban = g_strdup(BAN_FIRST);
	else if (g_hash_table_lookup(optlist, "last") != NULL)
		ban = g_strdup(BAN_LAST);

	command_set_ban(ban ? ban : data, server, item, FALSE, 0);

	g_free(ban);

	cmd_params_free(free_arg);
}

static void read_settings(void)
{
	if (default_ban_type_str != NULL &&
	    g_strcmp0(default_ban_type_str, settings_get_str("ban_type")) == 0)
		return;

	g_free_not_null(default_ban_type_str);
	default_ban_type = parse_ban_type(settings_get_str("ban_type"));
	if (default_ban_type <= 0 || default_ban_type_str != NULL) {
		signal_emit("ban type changed", 1,
			    GINT_TO_POINTER(default_ban_type));
	}

	if (default_ban_type <= 0)
                default_ban_type = IRC_MASK_USER|IRC_MASK_DOMAIN;

	default_ban_type_str = g_strdup(settings_get_str("ban_type"));
}

void bans_init(void)
{
        default_ban_type_str = NULL;
	settings_add_str("misc", "ban_type", "normal");

	command_bind_irc("ban", NULL, (SIGNAL_FUNC) cmd_ban);
	command_bind_irc("unban", NULL, (SIGNAL_FUNC) cmd_unban);
	command_set_options("ban", "normal user host domain +custom");
	command_set_options("unban", "first last");

        read_settings();
        signal_add("setup changed", (SIGNAL_FUNC) read_settings);
}

void bans_deinit(void)
{
	g_free_not_null(default_ban_type_str);

	command_unbind("ban", (SIGNAL_FUNC) cmd_ban);
	command_unbind("unban", (SIGNAL_FUNC) cmd_unban);

	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
}
