/*
 channels-setup.c : irssi

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

#include "channels.h"
#include "channels-setup.h"
#include "nicklist.h"
#include "irc-server.h"
#include "server-setup.h"
#include "special-vars.h"

#include "lib-config/iconfig.h"
#include "settings.h"

GSList *setupchannels;

#define ircnet_match(a, b) \
	((a) == NULL || (a[0]) == '\0' || (b != NULL && g_strcasecmp(a, b) == 0))

static void channel_config_add(SETUP_CHANNEL_REC *channel)
{
	CONFIG_NODE *node;

	node = iconfig_node_traverse("(channels", TRUE);
	node = config_node_section(node, NULL, NODE_TYPE_BLOCK);

	config_node_set_str(node, "name", channel->name);
	config_node_set_str(node, "ircnet", channel->ircnet);
	if (channel->autojoin)
		config_node_set_bool(node, "autojoin", TRUE);
	config_node_set_str(node, "password", channel->password);
	config_node_set_str(node, "botmasks", channel->botmasks);
	config_node_set_str(node, "autosendcmd", channel->autosendcmd);
	config_node_set_str(node, "background", channel->background);
	config_node_set_str(node, "font", channel->font);
}

static void channel_config_remove(SETUP_CHANNEL_REC *channel)
{
	CONFIG_NODE *node;

	node = iconfig_node_traverse("channels", FALSE);
	if (node != NULL) config_node_list_remove(node, g_slist_index(setupchannels, channel));
}

void channels_setup_create(SETUP_CHANNEL_REC *channel)
{
	if (g_slist_find(setupchannels, channel) != NULL) {
		channel_config_remove(channel);
		setupchannels = g_slist_remove(setupchannels, channel);
	}
	setupchannels = g_slist_append(setupchannels, channel);

        channel_config_add(channel);
}

void channels_setup_destroy(SETUP_CHANNEL_REC *channel)
{
	g_return_if_fail(channel != NULL);

        channel_config_remove(channel);
	setupchannels = g_slist_remove(setupchannels, channel);

	g_free(channel->name);
	g_free(channel->ircnet);
	g_free_not_null(channel->password);
	g_free_not_null(channel->botmasks);
	g_free_not_null(channel->autosendcmd);
	g_free_not_null(channel->background);
	g_free_not_null(channel->font);
	g_free(channel);
}

SETUP_CHANNEL_REC *channels_setup_find(const char *channel, const char *ircnet)
{
	GSList *tmp;

	g_return_val_if_fail(channel != NULL, NULL);

	for (tmp = setupchannels; tmp != NULL; tmp = tmp->next) {
		SETUP_CHANNEL_REC *rec = tmp->data;

		if (g_strcasecmp(rec->name, channel) == 0 &&
		    ircnet_match(rec->ircnet, ircnet))
			return rec;
	}

	return NULL;
}

/* connected to server, autojoin to channels. */
static void event_connected(IRC_SERVER_REC *server)
{
	GString *chans;
	GSList *tmp;

	g_return_if_fail(server != NULL);

	if (server->connrec->reconnection)
		return;

	/* join to the channels marked with autojoin in setup */
	chans = g_string_new(NULL);
	for (tmp = setupchannels; tmp != NULL; tmp = tmp->next) {
		SETUP_CHANNEL_REC *rec = tmp->data;

		if (!rec->autojoin || !ircnet_match(rec->ircnet, server->connrec->ircnet))
			continue;

		g_string_sprintfa(chans, "%s,", rec->name);
	}

	if (chans->len > 0) {
		g_string_truncate(chans, chans->len-1);
		channels_join(server, chans->str, TRUE);
	}

	g_string_free(chans, TRUE);
}

/* channel wholist received: send the auto send command */
static void channel_wholist(CHANNEL_REC *channel)
{
	SETUP_CHANNEL_REC *rec;
	NICK_REC *nick;
	char **bots, **bot;

	g_return_if_fail(channel != NULL);

	rec = channels_setup_find(channel->name, channel->server->connrec->ircnet);
	if (rec == NULL || rec->autosendcmd == NULL || !*rec->autosendcmd)
		return;

	if (rec->botmasks == NULL || !*rec->botmasks) {
		/* just send the command. */
		eval_special_string(rec->autosendcmd, "", channel->server, channel);
	}

	/* find first available bot.. */
	bots = g_strsplit(rec->botmasks, " ", -1);
	for (bot = bots; *bot != NULL; bot++) {
		nick = nicklist_find(channel, *bot);
		if (nick == NULL)
			continue;

		/* got one! */
		eval_special_string(rec->autosendcmd, nick->nick, channel->server, channel);
		break;
	}
	g_strfreev(bots);
}

static SETUP_CHANNEL_REC *setupchannel_add(CONFIG_NODE *node)
{
	SETUP_CHANNEL_REC *rec;
	char *channel, *ircnet, *password, *botmasks, *autosendcmd, *background, *font;

	g_return_val_if_fail(node != NULL, NULL);

	channel = config_node_get_str(node, "name", NULL);
	ircnet = config_node_get_str(node, "ircnet", NULL);
	if (channel == NULL || ircnet == NULL) {
		/* missing information.. */
		return NULL;
	}

	password = config_node_get_str(node, "password", NULL);
	botmasks = config_node_get_str(node, "botmasks", NULL);
	autosendcmd = config_node_get_str(node, "autosendcmd", NULL);
	background = config_node_get_str(node, "background", NULL);
	font = config_node_get_str(node, "font", NULL);

	rec = g_new(SETUP_CHANNEL_REC, 1);
	rec->autojoin = config_node_get_bool(node, "autojoin", FALSE);
	rec->name = g_strdup(channel);
	rec->ircnet = g_strdup(ircnet);
	rec->password = (password == NULL || *password == '\0') ? NULL : g_strdup(password);
	rec->botmasks = (botmasks == NULL || *botmasks == '\0') ? NULL : g_strdup(botmasks);
	rec->autosendcmd = (autosendcmd == NULL || *autosendcmd == '\0') ? NULL : g_strdup(autosendcmd);
	rec->background = (background == NULL || *background == '\0') ? NULL : g_strdup(background);
	rec->font = (font == NULL || *font == '\0') ? NULL : g_strdup(font);

	setupchannels = g_slist_append(setupchannels, rec);
	return rec;
}

static void channels_read_config(void)
{
	CONFIG_NODE *node;
	GSList *tmp;

	while (setupchannels != NULL)
		channels_setup_destroy(setupchannels->data);

	/* Read channels */
	node = iconfig_node_traverse("channels", FALSE);
	if (node != NULL) {
		for (tmp = node->value; tmp != NULL; tmp = tmp->next)
			setupchannel_add(tmp->data);
	}
}

void channels_setup_init(void)
{
	source_host_ok = FALSE;

	channels_read_config();
	signal_add("event connected", (SIGNAL_FUNC) event_connected);
	signal_add("channel wholist", (SIGNAL_FUNC) channel_wholist);
        signal_add("setup reread", (SIGNAL_FUNC) channels_read_config);
}

void channels_setup_deinit(void)
{
	while (setupchannels != NULL)
		channels_setup_destroy(setupchannels->data);

	signal_remove("event connected", (SIGNAL_FUNC) event_connected);
	signal_remove("channel wholist", (SIGNAL_FUNC) channel_wholist);
        signal_remove("setup reread", (SIGNAL_FUNC) channels_read_config);
}
