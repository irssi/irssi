/*
 channel.c : irssi

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
#include <irssi/src/core/special-vars.h>

#include <irssi/src/core/servers.h>
#include <irssi/src/core/channels.h>
#include <irssi/src/core/channels-setup.h>
#include <irssi/src/core/nicklist.h>

GSList *channels; /* List of all channels */

static char *get_join_data(CHANNEL_REC *channel)
{
	return g_strdup(channel->name);
}

static const char *channel_get_target(WI_ITEM_REC *item)
{
	return ((CHANNEL_REC *) item)->name;
}

void channel_init(CHANNEL_REC *channel, SERVER_REC *server, const char *name,
		  const char *visible_name, int automatic)
{
	g_return_if_fail(channel != NULL);
	g_return_if_fail(name != NULL);
	g_return_if_fail(server != NULL);

	if (visible_name == NULL)
		visible_name = name;

        MODULE_DATA_INIT(channel);
	channel->type = module_get_uniq_id_str("WINDOW ITEM TYPE", "CHANNEL");
        channel->destroy = (void (*) (WI_ITEM_REC *)) channel_destroy;
	channel->get_target = channel_get_target;
        channel->get_join_data = get_join_data;

	channel->chat_type = server->chat_type;
	channel->server = server;
	channel->name = g_strdup(name);
	channel->visible_name = g_strdup(visible_name);
	channel->mode = g_strdup("");
	channel->createtime = time(NULL);

	channels = g_slist_append(channels, channel);
	server->channels = g_slist_append(server->channels, channel);

	signal_emit("channel created", 2, channel, GINT_TO_POINTER(automatic));
}

void channel_destroy(CHANNEL_REC *channel)
{
	g_return_if_fail(IS_CHANNEL(channel));

	if (channel->destroying) return;
	channel->destroying = TRUE;

	channels = g_slist_remove(channels, channel);
	channel->server->channels =
		g_slist_remove(channel->server->channels, channel);

	signal_emit("channel destroyed", 1, channel);

        MODULE_DATA_DEINIT(channel);
	g_free_not_null(channel->hilight_color);
	g_free_not_null(channel->topic);
	g_free_not_null(channel->topic_by);
	g_free_not_null(channel->key);
	g_free(channel->mode);
	g_free(channel->name);
	g_free(channel->visible_name);

        channel->type = 0;
	g_free(channel);
}

static CHANNEL_REC *channel_find_server(SERVER_REC *server,
					const char *name)
{
	GSList *tmp;

	g_return_val_if_fail(IS_SERVER(server), NULL);

	if (server->channel_find_func != NULL) {
		/* use the server specific channel find function */
		return server->channel_find_func(server, name);
	}

	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *rec = tmp->data;

		if (g_ascii_strcasecmp(name, rec->name) == 0)
			return rec;
	}

	return NULL;
}

CHANNEL_REC *channel_find(SERVER_REC *server, const char *name)
{
	g_return_val_if_fail(server == NULL || IS_SERVER(server), NULL);
	g_return_val_if_fail(name != NULL, NULL);

	if (server != NULL)
		return channel_find_server(server, name);

	/* find from any server */
	return i_slist_foreach_find(servers, (FOREACH_FIND_FUNC) channel_find_server,
	                            (void *) name);
}

void channel_change_name(CHANNEL_REC *channel, const char *name)
{
	g_return_if_fail(IS_CHANNEL(channel));

	g_free(channel->name);
	channel->name = g_strdup(name);

	signal_emit("channel name changed", 1, channel);
}

void channel_change_visible_name(CHANNEL_REC *channel, const char *name)
{
	g_return_if_fail(IS_CHANNEL(channel));

	g_free(channel->visible_name);
	channel->visible_name = g_strdup(name);

	signal_emit("window item name changed", 1, channel);
}

static CHANNEL_REC *channel_find_servers(GSList *servers, const char *name)
{
	return i_slist_foreach_find(servers, (FOREACH_FIND_FUNC) channel_find_server,
	                            (void *) name);
}

static GSList *servers_find_chatnet_except(SERVER_REC *server)
{
	GSList *tmp, *list;

        list = NULL;
	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		SERVER_REC *rec = tmp->data;

		if (server != rec && rec->connrec->chatnet != NULL &&
		    g_strcmp0(server->connrec->chatnet,
			   rec->connrec->chatnet) == 0) {
			/* chatnets match */
			list = g_slist_append(list, rec);
		}
	}

        return list;
}

/* connected to server, autojoin to channels. */
static void event_connected(SERVER_REC *server)
{
	GString *chans;
	GSList *tmp, *chatnet_servers;

	g_return_if_fail(SERVER(server));

	if (server->connrec->reconnection ||
	    server->connrec->no_autojoin_channels)
		return;

	/* get list of servers in same chat network */
	chatnet_servers = server->connrec->chatnet == NULL ? NULL:
		servers_find_chatnet_except(server);

	/* join to the channels marked with autojoin in setup */
	chans = g_string_new(NULL);
	for (tmp = setupchannels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_SETUP_REC *rec = tmp->data;

		if (!rec->autojoin ||
		    !channel_chatnet_match(rec->chatnet,
					   server->connrec->chatnet))
			continue;

		/* check that we haven't already joined this channel in
		   same chat network connection.. */
                if (channel_find_servers(chatnet_servers, rec->name) == NULL)
			g_string_append_printf(chans, "%s,", rec->name);
	}
        g_slist_free(chatnet_servers);

	if (chans->len > 0) {
		g_string_truncate(chans, chans->len-1);
		server->channels_join(server, chans->str, TRUE);
	}

	g_string_free(chans, TRUE);
}

static int match_nick_flags(SERVER_REC *server, NICK_REC *nick, char flag)
{
	const char *flags = server->get_nick_flags(server);

	return strchr(flags, flag) == NULL ||
		(flag == flags[0] && nick->op) ||
		(flag == flags[1] && (nick->voice || nick->halfop ||
				      nick->op)) ||
		(flag == flags[2] && (nick->halfop || nick->op));
}

/* Send the auto send command to channel */
void channel_send_autocommands(CHANNEL_REC *channel)
{
	CHANNEL_SETUP_REC *rec;

	g_return_if_fail(IS_CHANNEL(channel));

	if (channel->session_rejoin)
		return;

	rec = channel_setup_find(channel->name, channel->server->connrec->chatnet);
	if (rec == NULL || rec->autosendcmd == NULL || !*rec->autosendcmd)
		return;

	/* if the autosendcmd alone (with no -bots parameter) has been
	 * specified then send it right after joining the channel, when
	 * the WHO list hasn't been yet retrieved.
	 * Depending on the value of the 'channel_max_who_sync' option
	 * the WHO list might not be retrieved after the join event. */

	if (rec->botmasks == NULL || !*rec->botmasks) {
		/* just send the command. */
		eval_special_string(rec->autosendcmd, "", channel->server, channel);
	}
}

void channel_send_botcommands(CHANNEL_REC *channel)
{
	CHANNEL_SETUP_REC *rec;
	NICK_REC *nick;
	char **bots, **bot;

	g_return_if_fail(IS_CHANNEL(channel));

	if (channel->session_rejoin)
                return;

	rec = channel_setup_find(channel->name, channel->server->connrec->chatnet);
	if (rec == NULL || rec->autosendcmd == NULL || !*rec->autosendcmd)
		return;

	/* this case has already been handled by channel_send_autocommands */
	if (rec->botmasks == NULL || !*rec->botmasks)
		return;

	/* find first available bot.. */
	bots = g_strsplit(rec->botmasks, " ", -1);
	for (bot = bots; *bot != NULL; bot++) {
		const char *botnick = *bot;

		if (*botnick == '\0')
                        continue;

		nick = nicklist_find_mask(channel,
					  channel->server->isnickflag(channel->server, *botnick) ?
					  botnick+1 : botnick);
		if (nick != NULL &&
		    match_nick_flags(channel->server, nick, *botnick)) {
			eval_special_string(rec->autosendcmd, nick->nick,
					    channel->server, channel);
			break;
		}
	}
	g_strfreev(bots);
}

void channels_init(void)
{
	channels_setup_init();

	signal_add("event connected", (SIGNAL_FUNC) event_connected);
}

void channels_deinit(void)
{
	channels_setup_deinit();

	signal_remove("event connected", (SIGNAL_FUNC) event_connected);
}
