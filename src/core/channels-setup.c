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
#include "lib-config/iconfig.h"
#include "settings.h"

#include "channels.h"
#include "channels-setup.h"
#include "servers-setup.h"

GSList *setupchannels;

static CHANNEL_SETUP_REC *channel_setup_read(CONFIG_NODE *node)
{
	CHANNEL_SETUP_REC *rec;
	char *channel, *password, *botmasks, *autosendcmd;

	g_return_val_if_fail(node != NULL, NULL);

	channel = config_node_get_str(node, "name", NULL);
	if (channel == NULL) {
		/* missing information.. */
		return NULL;
	}

	password = config_node_get_str(node, "password", NULL);
	botmasks = config_node_get_str(node, "botmasks", NULL);
	autosendcmd = config_node_get_str(node, "autosendcmd", NULL);

	rec = g_new(CHANNEL_SETUP_REC, 1);
	rec->autojoin = config_node_get_bool(node, "autojoin", FALSE);
	rec->name = g_strdup(channel);
	rec->chatnet = g_strdup(config_node_get_str(node, "chatnet", NULL));
	if (rec->chatnet == NULL) /* FIXME: remove this in time... */
		rec->chatnet = g_strdup(config_node_get_str(node, "ircnet", NULL));
	rec->password = (password == NULL || *password == '\0') ? NULL : g_strdup(password);
	rec->botmasks = (botmasks == NULL || *botmasks == '\0') ? NULL : g_strdup(botmasks);
	rec->autosendcmd = (autosendcmd == NULL || *autosendcmd == '\0') ? NULL : g_strdup(autosendcmd);

	setupchannels = g_slist_append(setupchannels, rec);
	signal_emit("channel setup created", 2, rec, node);
	return rec;
}

static void channel_setup_save(CHANNEL_SETUP_REC *channel)
{
	CONFIG_NODE *parentnode, *node;
	int index;

	index = g_slist_index(setupchannels, channel);

	parentnode = iconfig_node_traverse("(channels", TRUE);
	node = config_node_index(parentnode, index);
	if (node == NULL)
		node = config_node_section(parentnode, NULL, NODE_TYPE_BLOCK);

        iconfig_node_clear(node);
	iconfig_node_set_str(node, "name", channel->name);
	iconfig_node_set_str(node, "chatnet", channel->chatnet);
	if (channel->autojoin)
		config_node_set_bool(node, "autojoin", TRUE);
	iconfig_node_set_str(node, "password", channel->password);
	iconfig_node_set_str(node, "botmasks", channel->botmasks);
	iconfig_node_set_str(node, "autosendcmd", channel->autosendcmd);
}

static void channel_config_remove(CHANNEL_SETUP_REC *channel)
{
	CONFIG_NODE *node;

	node = iconfig_node_traverse("channels", FALSE);
	if (node != NULL) iconfig_node_list_remove(node, g_slist_index(setupchannels, channel));
}

void channels_setup_create(CHANNEL_SETUP_REC *channel)
{
	if (g_slist_find(setupchannels, channel) == NULL)
		setupchannels = g_slist_append(setupchannels, channel);
	channel_setup_save(channel);

	signal_emit("channel setup created", 1, channel);
}

static void channels_setup_destroy_rec(CHANNEL_SETUP_REC *channel)
{
	g_return_if_fail(channel != NULL);

	setupchannels = g_slist_remove(setupchannels, channel);
	signal_emit("channel setup destroyed", 1, channel);

	g_free(channel->name);
	g_free_not_null(channel->chatnet);
	g_free_not_null(channel->password);
	g_free_not_null(channel->botmasks);
	g_free_not_null(channel->autosendcmd);
	g_free(channel);
}

void channels_setup_destroy(CHANNEL_SETUP_REC *channel)
{
        channel_config_remove(channel);
        channels_setup_destroy_rec(channel);
}

CHANNEL_SETUP_REC *channels_setup_find(const char *channel, const char *chatnet)
{
	GSList *tmp;

	g_return_val_if_fail(channel != NULL, NULL);

	for (tmp = setupchannels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_SETUP_REC *rec = tmp->data;

		if (g_strcasecmp(rec->name, channel) == 0 &&
		    channel_chatnet_match(rec->chatnet, chatnet))
			return rec;
	}

	return NULL;
}

static void channels_read_config(void)
{
	CONFIG_NODE *node;
	GSList *tmp;

	while (setupchannels != NULL)
		channels_setup_destroy_rec(setupchannels->data);

	/* Read channels */
	node = iconfig_node_traverse("channels", FALSE);
	if (node != NULL) {
		for (tmp = node->value; tmp != NULL; tmp = tmp->next)
			channel_setup_read(tmp->data);
	}
}

void channels_setup_init(void)
{
	source_host_ok = FALSE;

        signal_add("setup reread", (SIGNAL_FUNC) channels_read_config);
        signal_add("irssi init read settings", (SIGNAL_FUNC) channels_read_config);
}

void channels_setup_deinit(void)
{
	while (setupchannels != NULL)
		channels_setup_destroy(setupchannels->data);

        signal_remove("setup reread", (SIGNAL_FUNC) channels_read_config);
        signal_remove("irssi init read settings", (SIGNAL_FUNC) channels_read_config);
}
