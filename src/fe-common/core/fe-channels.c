/*
 fe-channels.c : irssi

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
#include <irssi/src/fe-common/core/module-formats.h>
#include <irssi/src/core/modules.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/core/special-vars.h>
#include <irssi/src/core/utf8.h>

#include <irssi/src/core/chat-protocols.h>
#include <irssi/src/core/chatnets.h>
#include <irssi/src/core/servers.h>
#include <irssi/src/core/channels.h>
#include <irssi/src/core/channels-setup.h>
#include <irssi/src/core/nicklist.h>

#include <irssi/src/fe-common/core/fe-windows.h>
#include <irssi/src/fe-common/core/fe-channels.h>
#include <irssi/src/fe-common/core/window-items.h>
#include <irssi/src/fe-common/core/printtext.h>

static void signal_channel_created(CHANNEL_REC *channel, void *automatic)
{
	if (window_item_window(channel) == NULL) {
		window_item_create((WI_ITEM_REC *) channel,
				   GPOINTER_TO_INT(automatic));
	}
}

static void signal_channel_created_curwin(CHANNEL_REC *channel)
{
	g_return_if_fail(channel != NULL);

	window_item_add(active_win, (WI_ITEM_REC *) channel, FALSE);
}

static void signal_channel_destroyed(CHANNEL_REC *channel)
{
	WINDOW_REC *window;

	g_return_if_fail(channel != NULL);

	window = window_item_window((WI_ITEM_REC *) channel);
	if (window == NULL)
		return;

	window_item_destroy((WI_ITEM_REC *) channel);

	if (channel->joined && !channel->left &&
	    !channel->server->disconnected) {
		/* kicked out from channel */
		window_bind_add(window, channel->server->tag,
				channel->visible_name);
	} else if (!channel->joined || channel->left)
		window_auto_destroy(window);
}

static void sig_disconnected(SERVER_REC *server)
{
	WINDOW_REC *window;
	GSList *tmp;

	g_return_if_fail(IS_SERVER(server));

	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *channel = tmp->data;

		window = window_item_window((WI_ITEM_REC *) channel);
		window_bind_add(window, server->tag, channel->name);
	}
}

static void signal_window_item_changed(WINDOW_REC *window, WI_ITEM_REC *item)
{
	g_return_if_fail(window != NULL);
	if (item == NULL) return;

	if (g_slist_length(window->items) > 1 && IS_CHANNEL(item)) {
		printformat(item->server, item->visible_name,
			    MSGLEVEL_CLIENTNOTICE,
			    TXT_TALKING_IN, item->visible_name);
                signal_stop();
	}
}

static void sig_channel_joined(CHANNEL_REC *channel)
{
	if (settings_get_bool("show_names_on_join") && !channel->session_rejoin) {
		int limit = settings_get_int("show_names_on_join_limit");
		int flags = CHANNEL_NICKLIST_FLAG_ALL;
		if (limit > 0 && g_hash_table_size(channel->nicks) > limit) {
			flags |= CHANNEL_NICKLIST_FLAG_COUNT;
		}
		fe_channels_nicklist(channel, flags);
	}
}

/* SYNTAX: JOIN [-window] [-invite] [-<server tag>] <channels> [<keys>] */
static void cmd_join(const char *data, SERVER_REC *server)
{
	WINDOW_REC *window;
        CHANNEL_REC *channel;
	GHashTable *optlist;
	char *pdata;
	int invite;
	int samewindow;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS |
			    PARAM_FLAG_UNKNOWN_OPTIONS | PARAM_FLAG_GETREST |
			    PARAM_FLAG_STRIP_TRAILING_WS,
			    "join", &optlist, &pdata))
		return;

	invite = g_hash_table_lookup(optlist, "invite") != NULL;
	samewindow = g_hash_table_lookup(optlist, "window") != NULL;
	if (!invite && *pdata == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	/* -<server tag> */
	server = cmd_options_get_server("join", optlist, server);

	channel = channel_find(server, pdata);
	if (channel != NULL) {
		/* already joined to channel, set it active */
		window = window_item_window(channel);
		if (window != active_win)
			window_set_active(window);

		window_item_set_active(active_win, (WI_ITEM_REC *) channel);
	}
	else {
		if (server == NULL || !server->connected)
			cmd_param_error(CMDERR_NOT_CONNECTED);
		if (invite) {
			if (server->last_invite == NULL) {
				printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_NOT_INVITED);
				signal_stop();
				cmd_params_free(free_arg);
				return;
			}
			pdata = server->last_invite;
		}
		if (samewindow)
			signal_add("channel created",
				   (SIGNAL_FUNC) signal_channel_created_curwin);
		server->channels_join(server, pdata, FALSE);
		if (samewindow)
			signal_remove("channel created",
				      (SIGNAL_FUNC) signal_channel_created_curwin);
	}
	cmd_params_free(free_arg);
}

static void cmd_channel_list_joined(void)
{
	CHANNEL_REC *channel;
	GString *nicks;
	GSList *nicklist, *tmp, *ntmp;

	if (channels == NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_NOT_IN_CHANNELS);
		return;
	}

	/* print active channel */
	channel = CHANNEL(active_win->active);
	if (channel != NULL)
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
			    TXT_CURRENT_CHANNEL, channel->visible_name);

	/* print list of all channels, their modes, server tags and nicks */
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_CHANLIST_HEADER);
	for (tmp = channels; tmp != NULL; tmp = tmp->next) {
		channel = tmp->data;

		nicklist = nicklist_getnicks(channel);
		nicks = g_string_new(NULL);
		for (ntmp = nicklist; ntmp != NULL; ntmp = ntmp->next) {
			NICK_REC *rec = ntmp->data;

			g_string_append_printf(nicks, "%s ", rec->nick);
		}

		if (nicks->len > 1) g_string_truncate(nicks, nicks->len-1);
		printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_CHANLIST_LINE,
			    channel->visible_name, channel->mode,
			    channel->server->tag, nicks->str);

		g_slist_free(nicklist);
		g_string_free(nicks, TRUE);
	}
}

/* SYNTAX: CHANNEL LIST */
static void cmd_channel_list(void)
{
	GString *str;
	GSList *tmp;

	str = g_string_new(NULL);
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_CHANSETUP_HEADER);
	for (tmp = setupchannels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_SETUP_REC *rec = tmp->data;

		g_string_truncate(str, 0);
		if (rec->autojoin)
			g_string_append(str, "autojoin, ");
		if (rec->botmasks != NULL && *rec->botmasks != '\0')
			g_string_append_printf(str, "bots: %s, ", rec->botmasks);
		if (rec->autosendcmd != NULL && *rec->autosendcmd != '\0')
			g_string_append_printf(str, "botcmd: %s, ", rec->autosendcmd);

		if (str->len > 2) g_string_truncate(str, str->len-2);
		printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_CHANSETUP_LINE,
			    rec->name, rec->chatnet == NULL ? "" : rec->chatnet,
			    rec->password == NULL ? "" : rec->password, str->str);
	}
	g_string_free(str, TRUE);
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_CHANSETUP_FOOTER);
}

static void cmd_channel(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	if (*data == '\0')
		cmd_channel_list_joined();
	else if (server != NULL && server_ischannel(server, data)) {
		signal_emit("command join", 3, data, server, item);
	} else {
		command_runsub("channel", data, server, item);
	}
}

static void cmd_channel_add_modify(const char *data, gboolean add)
{
	GHashTable *optlist;
        CHATNET_REC *chatnetrec;
	CHANNEL_SETUP_REC *rec;
	char *botarg, *botcmdarg, *chatnet, *channel, *password;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 3 | PARAM_FLAG_OPTIONS,
		"channel add", &optlist, &channel, &chatnet, &password))
		return;

	if (*chatnet == '\0' || *channel == '\0') {
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
	}

	chatnetrec = chatnet_find(chatnet);
	if (chatnetrec == NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
			TXT_UNKNOWN_CHATNET, chatnet);
		cmd_params_free(free_arg);
		return;
	}

	botarg = g_hash_table_lookup(optlist, "bots");
	botcmdarg = g_hash_table_lookup(optlist, "botcmd");

	rec = channel_setup_find(channel, chatnet);
	if (rec == NULL) {
		if (add == FALSE) {
			printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
				TXT_CHANSETUP_NOT_FOUND, channel, chatnet);
			cmd_params_free(free_arg);
			return;
		}

		rec = CHAT_PROTOCOL(chatnetrec)->create_channel_setup();
		rec->name = g_strdup(channel);
		rec->chatnet = g_strdup(chatnet);
	} else {
		if (g_hash_table_lookup(optlist, "bots")) g_free_and_null(rec->botmasks);
		if (g_hash_table_lookup(optlist, "botcmd")) g_free_and_null(rec->autosendcmd);
		if (*password != '\0') g_free_and_null(rec->password);
	}
	if (g_hash_table_lookup(optlist, "auto")) rec->autojoin = TRUE;
	if (g_hash_table_lookup(optlist, "noauto")) rec->autojoin = FALSE;
	if (botarg != NULL && *botarg != '\0') rec->botmasks = g_strdup(botarg);
	if (botcmdarg != NULL && *botcmdarg != '\0') rec->autosendcmd = g_strdup(botcmdarg);
	if (*password != '\0' && g_strcmp0(password, "-") != 0) rec->password = g_strdup(password);

	signal_emit("channel add fill", 2, rec, optlist);

	channel_setup_create(rec);
	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
		    TXT_CHANSETUP_ADDED, channel, chatnet);

	cmd_params_free(free_arg);
}

/* SYNTAX: CHANNEL ADD|MODIFY [-auto | -noauto] [-bots <masks>] [-botcmd <command>]
                              <channel> <network> [<password>] */
static void cmd_channel_add(const char *data)
{
	cmd_channel_add_modify(data, TRUE);
}

static void cmd_channel_modify(const char *data)
{
	cmd_channel_add_modify(data, FALSE);
}

/* SYNTAX: CHANNEL REMOVE <channel> <network> */
static void cmd_channel_remove(const char *data)
{
	CHANNEL_SETUP_REC *rec;
	char *chatnet, *channel;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 2, &channel, &chatnet))
		return;
	if (*chatnet == '\0' || *channel == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	rec = channel_setup_find(channel, chatnet);
	if (rec == NULL)
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_CHANSETUP_NOT_FOUND, channel, chatnet);
	else {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_CHANSETUP_REMOVED, channel, chatnet);
		channel_setup_remove(rec);
	}
	cmd_params_free(free_arg);
}

static int get_nick_length(void *data)
{
        return string_width(((NICK_REC *) data)->nick, -1);
}

static void display_sorted_nicks(CHANNEL_REC *channel, GSList *nicklist)
{
	WINDOW_REC *window;
	TEXT_DEST_REC dest;
	GString *str;
	GSList *tmp;
	char *format, *stripped, *prefix_format;
	char *aligned_nick, nickmode[2] = { 0, 0 };
	int *columns, cols, rows, last_col_rows, col, row, max_width;
	int item_extra, formatnum;

	window = window_find_closest(channel->server, channel->visible_name,
	                             MSGLEVEL_CLIENTCRAP);
	max_width = window->width;

	/* get the length of item extra stuff ("[ ] ") */
	format = format_get_text(MODULE_NAME, NULL,
	                         channel->server, channel->visible_name,
	                         TXT_NAMES_NICK, " ", "");
	stripped = strip_codes(format);
	item_extra = strlen(stripped);
	g_free(stripped);
	g_free(format);

	if (settings_get_int("names_max_width") > 0 &&
	    settings_get_int("names_max_width") < max_width)
		max_width = settings_get_int("names_max_width");

	/* remove width of the timestamp from max_width */
	format_create_dest(&dest, channel->server, channel->visible_name,
	                   MSGLEVEL_CLIENTCRAP, NULL);
	format = format_get_line_start(current_theme, &dest, time(NULL));
	if (format != NULL) {
		stripped = strip_codes(format);
		max_width -= strlen(stripped);
		g_free(stripped);
		g_free(format);
	}

	/* remove width of the prefix from max_width */
	prefix_format = format_get_text(MODULE_NAME, NULL,
	                                channel->server, channel->visible_name,
	                                TXT_NAMES_PREFIX,
	                                channel->visible_name);
	if (prefix_format != NULL) {
		stripped = strip_codes(prefix_format);
		max_width -= strlen(stripped);
		g_free(stripped);
	}

	if (max_width <= 0) {
		/* we should always have at least some space .. if we
		   really don't, it won't show properly anyway. */
		max_width = 10;
	}

	/* calculate columns */
	cols = get_max_column_count(nicklist, get_nick_length, max_width,
	                            settings_get_int("names_max_columns"),
	                            item_extra, 3, &columns, &rows);
	nicklist = columns_sort_list(nicklist, rows);

	/* rows in last column */
	last_col_rows = rows-(cols*rows-g_slist_length(nicklist));
	if (last_col_rows == 0)
		last_col_rows = rows;

	str = g_string_new(prefix_format);

	col = 0; row = 0;
	for (tmp = nicklist; tmp != NULL; tmp = tmp->next) {
		NICK_REC *rec = tmp->data;

		if (rec->prefixes[0])
			nickmode[0] = rec->prefixes[0];
		else
			nickmode[0] = ' ';

		aligned_nick = get_alignment(rec->nick,
		                             columns[col]-item_extra,
		                             ALIGN_PAD, ' ');

		formatnum = rec->op     ? TXT_NAMES_NICK_OP :
		            rec->halfop ? TXT_NAMES_NICK_HALFOP :
		            rec->voice  ? TXT_NAMES_NICK_VOICE :
		                          TXT_NAMES_NICK;
		format = format_get_text(MODULE_NAME, NULL,
		                         channel->server,
		                         channel->visible_name,
		                         formatnum, nickmode, aligned_nick);
		g_string_append(str, format);
		g_free(aligned_nick);
		g_free(format);

		if (++col == cols) {
			printtext(channel->server, channel->visible_name,
			          MSGLEVEL_CLIENTCRAP, "%s", str->str);
			g_string_truncate(str, 0);
			if (prefix_format != NULL)
				g_string_assign(str, prefix_format);
			col = 0; row++;

			if (row == last_col_rows)
				cols--;
		}
	}

	if (prefix_format != NULL && str->len > strlen(prefix_format)) {
		printtext(channel->server, channel->visible_name,
		          MSGLEVEL_CLIENTCRAP, "%s", str->str);
	}

	g_slist_free(nicklist);
	g_string_free(str, TRUE);
	g_free_not_null(columns);
	g_free_not_null(prefix_format);
}

void fe_channels_nicklist(CHANNEL_REC *channel, int flags)
{
	NICK_REC *nick;
	GSList *tmp, *nicklist, *sorted;
	int nicks, normal, voices, halfops, ops;
	const char *nick_flags;

	nicks = normal = voices = halfops = ops = 0;
	nicklist = nicklist_getnicks(channel);
	sorted = NULL;
	nick_flags = channel->server->get_nick_flags(channel->server);

	/* filter (for flags) and count ops, halfops, voices */
	for (tmp = nicklist; tmp != NULL; tmp = tmp->next) {
		nick = tmp->data;

		nicks++;
		if (nick->op) {
			ops++;
			if ((flags & CHANNEL_NICKLIST_FLAG_OPS) == 0)
                                continue;
		} else if (nick->halfop) {
			halfops++;
			if ((flags & CHANNEL_NICKLIST_FLAG_HALFOPS) == 0)
				continue;
		} else if (nick->voice) {
			voices++;
			if ((flags & CHANNEL_NICKLIST_FLAG_VOICES) == 0)
				continue;
		} else {
			normal++;
			if ((flags & CHANNEL_NICKLIST_FLAG_NORMAL) == 0)
				continue;
		}

		sorted = g_slist_prepend(sorted, nick);
	}
	g_slist_free(nicklist);

	/* sort the nicklist */
	sorted = g_slist_sort_with_data(sorted, (GCompareDataFunc) nicklist_compare, (void *)nick_flags);

	/* display the nicks */
        if ((flags & CHANNEL_NICKLIST_FLAG_COUNT) == 0) {
		printformat(channel->server, channel->visible_name,
			    MSGLEVEL_CLIENTCRAP, TXT_NAMES,
			    channel->visible_name,
			    nicks, ops, halfops, voices, normal);
		display_sorted_nicks(channel, sorted);
	}
	g_slist_free(sorted);

	printformat(channel->server, channel->visible_name,
		    MSGLEVEL_CLIENTNOTICE, TXT_ENDOFNAMES,
		    channel->visible_name, nicks, ops, halfops, voices, normal);
}

/* SYNTAX: NAMES [-count | -ops -halfops -voices -normal] [<channels> | **] */
static void cmd_names(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	CHANNEL_REC *chanrec;
	GHashTable *optlist;
        GString *unknowns;
	char *channel, **channels, **tmp;
        int flags;
	void *free_arg;

	g_return_if_fail(data != NULL);
	if (!IS_SERVER(server) || !server->connected)
		cmd_return_error(CMDERR_NOT_CONNECTED);

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS,
			    "names", &optlist, &channel))
		return;

	if (g_strcmp0(channel, "*") == 0 || *channel == '\0') {
		if (!IS_CHANNEL(item))
                        cmd_param_error(CMDERR_NOT_JOINED);

		channel = CHANNEL(item)->name;
	}

	flags = 0;
	if (g_hash_table_lookup(optlist, "ops") != NULL)
		flags |= CHANNEL_NICKLIST_FLAG_OPS;
	if (g_hash_table_lookup(optlist, "halfops") != NULL)
		flags |= CHANNEL_NICKLIST_FLAG_HALFOPS;
	if (g_hash_table_lookup(optlist, "voices") != NULL)
		flags |= CHANNEL_NICKLIST_FLAG_VOICES;
	if (g_hash_table_lookup(optlist, "normal") != NULL)
		flags |= CHANNEL_NICKLIST_FLAG_NORMAL;
	if (g_hash_table_lookup(optlist, "count") != NULL)
		flags |= CHANNEL_NICKLIST_FLAG_COUNT;

        if (flags == 0) flags = CHANNEL_NICKLIST_FLAG_ALL;

        unknowns = g_string_new(NULL);

	channels = g_strsplit(channel, ",", -1);
	for (tmp = channels; *tmp != NULL; tmp++) {
		chanrec = channel_find(server, *tmp);
		if (chanrec == NULL)
			g_string_append_printf(unknowns, "%s,", *tmp);
		else {
			fe_channels_nicklist(chanrec, flags);
			signal_stop();
		}
	}
	g_strfreev(channels);

	if (unknowns->len > 1)
                g_string_truncate(unknowns, unknowns->len-1);

	if (unknowns->len > 0 && g_strcmp0(channel, unknowns->str) != 0)
                signal_emit("command names", 3, unknowns->str, server, item);
        g_string_free(unknowns, TRUE);

	cmd_params_free(free_arg);
}

/* SYNTAX: CYCLE [<channel>] [<message>] */
static void cmd_cycle(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	CHANNEL_REC *chanrec;
	char *channame, *msg, *joindata;
	void *free_arg;

	g_return_if_fail(data != NULL);
	if (!IS_SERVER(server) || !server->connected)
		cmd_return_error(CMDERR_NOT_CONNECTED);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_OPTCHAN,
			    item, &channame, &msg))
		return;
	if (*channame == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	chanrec = channel_find(server, channame);
	if (chanrec == NULL) cmd_param_error(CMDERR_CHAN_NOT_FOUND);

	joindata = chanrec->get_join_data(chanrec);
	window_bind_add(window_item_window(chanrec),
			chanrec->server->tag, chanrec->name);

	/* FIXME: kludgy kludgy... */
	signal_emit("command part", 3, data, server, item);

	if (g_slist_find(channels, chanrec) != NULL) {
		chanrec->left = TRUE;
		channel_destroy(chanrec);
	}

	server->channels_join(server, joindata, FALSE);
	g_free(joindata);

	cmd_params_free(free_arg);
}

void fe_channels_init(void)
{
	settings_add_bool("lookandfeel", "autoclose_windows", TRUE);
	settings_add_bool("lookandfeel", "show_names_on_join", TRUE);
	settings_add_int("lookandfeel", "show_names_on_join_limit", 18);
	settings_add_int("lookandfeel", "names_max_columns", 6);
	settings_add_int("lookandfeel", "names_max_width", 0);

	signal_add("channel created", (SIGNAL_FUNC) signal_channel_created);
	signal_add("channel destroyed", (SIGNAL_FUNC) signal_channel_destroyed);
	signal_add_last("window item changed", (SIGNAL_FUNC) signal_window_item_changed);
	signal_add_last("server disconnected", (SIGNAL_FUNC) sig_disconnected);
	signal_add_last("channel joined", (SIGNAL_FUNC) sig_channel_joined);

	command_bind("join", NULL, (SIGNAL_FUNC) cmd_join);
	command_bind("channel", NULL, (SIGNAL_FUNC) cmd_channel);
	command_bind("channel add", NULL, (SIGNAL_FUNC) cmd_channel_add);
	command_bind("channel modify", NULL, (SIGNAL_FUNC) cmd_channel_modify);
	command_bind("channel remove", NULL, (SIGNAL_FUNC) cmd_channel_remove);
	command_bind("channel list", NULL, (SIGNAL_FUNC) cmd_channel_list);
	command_bind_first("names", NULL, (SIGNAL_FUNC) cmd_names);
	command_bind("cycle", NULL, (SIGNAL_FUNC) cmd_cycle);

	command_set_options("channel add", "auto noauto -bots -botcmd");
	command_set_options("channel modify", "auto noauto -bots -botcmd");
	command_set_options("names", "count ops halfops voices normal");
	command_set_options("join", "invite window");
}

void fe_channels_deinit(void)
{
	signal_remove("channel created", (SIGNAL_FUNC) signal_channel_created);
	signal_remove("channel destroyed", (SIGNAL_FUNC) signal_channel_destroyed);
	signal_remove("window item changed", (SIGNAL_FUNC) signal_window_item_changed);
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_disconnected);
	signal_remove("channel joined", (SIGNAL_FUNC) sig_channel_joined);

	command_unbind("join", (SIGNAL_FUNC) cmd_join);
	command_unbind("channel", (SIGNAL_FUNC) cmd_channel);
	command_unbind("channel add", (SIGNAL_FUNC) cmd_channel_add);
	command_unbind("channel modify", (SIGNAL_FUNC) cmd_channel_modify);
	command_unbind("channel remove", (SIGNAL_FUNC) cmd_channel_remove);
	command_unbind("channel list", (SIGNAL_FUNC) cmd_channel_list);
	command_unbind("names", (SIGNAL_FUNC) cmd_names);
	command_unbind("cycle", (SIGNAL_FUNC) cmd_cycle);
}
