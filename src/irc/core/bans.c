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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "signals.h"
#include "commands.h"
#include "misc.h"
#include "settings.h"

#include "irc-masks.h"
#include "modes.h"
#include "mode-lists.h"
#include "irc.h"
#include "nicklist.h"

static char *default_ban_type_str;
static int default_ban_type;

char *ban_get_mask(IRC_CHANNEL_REC *channel, const char *nick, int ban_type)
{
	NICK_REC *rec;
	char *str, *user, *host;

	g_return_val_if_fail(IS_IRC_CHANNEL(channel), NULL);
	g_return_val_if_fail(nick != NULL, NULL);

	rec = nicklist_find(CHANNEL(channel), nick);
	if (rec == NULL || rec->host == NULL) return NULL;

	if (ban_type <= 0)
		ban_type = default_ban_type;

	str = irc_get_mask(nick, rec->host, ban_type);

	/* there's a limit of 10 characters in user mask. so, banning
	   someone with user mask of 10 characters gives us "*1234567890",
	   which is one too much.. so, replace the 10th character with '*' */
	user = strchr(str, '!');
	if (user == NULL) return str;

	host = strchr(++user, '@');
	if (host == NULL) return str;

	if ((int) (host-user) > 10) {
		/* too long user mask */
		user[9] = '*';
		g_memmove(user+10, host, strlen(host)+1);
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
		if (strchr(*ban, '!') != NULL) {
			/* explicit ban */
			g_string_sprintfa(str, "%s ", *ban);
			continue;
		}

		/* ban nick */
		realban = ban_get_mask(channel, *ban, ban_type);
		if (realban != NULL) {
			g_string_sprintfa(str, "%s ", realban);
			g_free(realban);
		}
	}
	g_strfreev(banlist);

	if (str->len > 0)
		g_string_truncate(str, str->len-1);

	ret = str->str;
	g_string_free(str, FALSE);
        return ret;
}

void ban_set(IRC_CHANNEL_REC *channel, const char *bans, int ban_type)
{
	char *masks;

	g_return_if_fail(bans != NULL);

	if (ban_type <= 0)
		ban_type = default_ban_type;

	masks = ban_get_masks(channel, bans, ban_type);
	channel_set_singlemode(channel->server, channel->name,
			       masks, "+b");
        g_free(masks);
}

void ban_remove(IRC_CHANNEL_REC *channel, const char *bans)
{
	GString *str;
	GSList *tmp;
	char **ban, **banlist;

	g_return_if_fail(bans != NULL);

	str = g_string_new(NULL);
	banlist = g_strsplit(bans, " ", -1);
	for (ban = banlist; *ban != NULL; ban++) {
		for (tmp = channel->banlist; tmp != NULL; tmp = tmp->next) {
			BAN_REC *rec = tmp->data;

			if (match_wildcards(*ban, rec->ban))
				g_string_sprintfa(str, "%s ", rec->ban);
		}
	}
	g_strfreev(banlist);

	if (str->len > 0)
		channel_set_singlemode(channel->server, channel->name,
				       str->str, "-b");
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

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_OPTCHAN | PARAM_FLAG_GETREST,
			    item, &channel, &nicks)) return;
	if (!ischannel(*channel)) cmd_param_error(CMDERR_NOT_JOINED);
	if (*nicks == '\0') {
		if (strcmp(data, "*") != 0)
			cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
                /* /BAN * or /UNBAN * - ban/unban everyone */
		nicks = (char *) data;
	}

	chanrec = irc_channel_find(server, channel);
	if (chanrec == NULL)
		cmd_param_error(CMDERR_CHAN_NOT_FOUND);
	if (!chanrec->wholist)
		cmd_param_error(CMDERR_CHAN_NOT_SYNCED);

	if (set)
		ban_set(chanrec, nicks, ban_type);
	else {
		if (is_numeric(nicks, '\0')) {
			/* unban with ban number */
			BAN_REC *ban = g_slist_nth_data(chanrec->banlist,
							atoi(nicks)-1);
			if (ban != NULL)
                                nicks = ban->ban;
		}

		ban_remove(chanrec, nicks);
	}

	cmd_params_free(free_arg);
}

static int ban_parse_type(const char *type)
{
	char **list;
	int n, ban_type;

	g_return_val_if_fail(type != NULL, 0);

        ban_type = 0;
	if (toupper(type[0]) == 'N')
		ban_type = IRC_MASK_USER | IRC_MASK_DOMAIN;
	else if (toupper(type[0]) == 'H')
		ban_type = IRC_MASK_HOST | IRC_MASK_DOMAIN;
	else if (toupper(type[0]) == 'D')
		ban_type = IRC_MASK_DOMAIN;
	else if (toupper(type[0]) == 'C') {
		list = g_strsplit(type, " ", -1);
                for (n = 1; list[n] != NULL; n++) {
			if (toupper(list[n][0]) == 'N')
				ban_type |= IRC_MASK_NICK;
			else if (toupper(list[n][0]) == 'U')
				ban_type |= IRC_MASK_USER;
			else if (toupper(list[n][0]) == 'H')
				ban_type |= IRC_MASK_HOST | IRC_MASK_DOMAIN;
			else if (toupper(list[n][0]) == 'D')
				ban_type |= IRC_MASK_DOMAIN;
		}
                g_strfreev(list);
	}

        return ban_type;
}

/* SYNTAX: BAN [-type <ban type>] <nicks/masks> */
static void cmd_ban(const char *data, IRC_SERVER_REC *server, void *item)
{
	GHashTable *optlist;
	char *ban, *ban_type_str;
        int ban_type;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 1 |
			    PARAM_FLAG_OPTIONS | PARAM_FLAG_GETREST,
			    "ban", &optlist, &ban))
		return;

	ban_type_str = g_hash_table_lookup(optlist, "type");
	ban_type = ban_type_str == NULL ? default_ban_type :
		ban_parse_type(ban_type_str);

	command_set_ban(ban, server, item, TRUE, ban_type);

	cmd_params_free(free_arg);
}

/* SYNTAX: UNBAN <masks> */
static void cmd_unban(const char *data, IRC_SERVER_REC *server, void *item)
{
	command_set_ban(data, server, item, FALSE, 0);
}

static void read_settings(void)
{
	if (default_ban_type_str != NULL &&
	    strcmp(default_ban_type_str, settings_get_str("ban_type")) == 0)
		return;

	g_free_not_null(default_ban_type_str);
	default_ban_type = ban_parse_type(settings_get_str("ban_type"));
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

	command_bind("ban", NULL, (SIGNAL_FUNC) cmd_ban);
	command_bind("unban", NULL, (SIGNAL_FUNC) cmd_unban);
	command_set_options("ban", "+type");

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
