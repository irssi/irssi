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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include <irssi/src/core/signals.h>
#include <irssi/src/lib-config/iconfig.h>
#include <irssi/src/core/settings.h>

#include <irssi/src/core/chat-protocols.h>
#include <irssi/src/core/chatnets.h>
#include <irssi/src/core/servers-setup.h>
#include <irssi/src/core/channels-setup.h>

GSList *setupchannels;

static int compare_channel_setup (CONFIG_NODE *node, CHANNEL_SETUP_REC *channel)
{
	char *name, *chatnet;

	/* skip comment nodes */
	if (node->type == NODE_TYPE_COMMENT)
		return -1;

	name = config_node_get_str(node, "name", NULL);
	chatnet = config_node_get_str(node, "chatnet", NULL);

	if (name == NULL || chatnet == NULL) {
		return 0;
	}

	if (g_ascii_strcasecmp(name, channel->name) != 0 ||
	    g_ascii_strcasecmp(chatnet, channel->chatnet) != 0) {
		return 1;
	}

	return 0;
}

static void channel_setup_save(CHANNEL_SETUP_REC *channel)
{
	CONFIG_NODE *parent_node, *node;
	GSList *config_node;

	parent_node = iconfig_node_traverse("(channels", TRUE);

	/* Try to find this channel in the configuration */
	config_node = g_slist_find_custom(parent_node->value, channel,
					  (GCompareFunc)compare_channel_setup);
	if (config_node != NULL)
		/* Let's update this channel record */
		node = config_node->data;
	else
		/* Create a brand-new channel record */
		node = iconfig_node_section(parent_node, NULL, NODE_TYPE_BLOCK);

        iconfig_node_clear(node);
	iconfig_node_set_str(node, "name", channel->name);
	iconfig_node_set_str(node, "chatnet", channel->chatnet);
	if (channel->autojoin)
		iconfig_node_set_bool(node, "autojoin", TRUE);
	iconfig_node_set_str(node, "password", channel->password);
	iconfig_node_set_str(node, "botmasks", channel->botmasks);
	iconfig_node_set_str(node, "autosendcmd", channel->autosendcmd);
}

void channel_setup_create(CHANNEL_SETUP_REC *channel)
{
	channel->type = module_get_uniq_id("CHANNEL SETUP", 0);

	if (g_slist_find(setupchannels, channel) == NULL)
		setupchannels = g_slist_append(setupchannels, channel);
	channel_setup_save(channel);

	signal_emit("channel setup created", 1, channel);
}

static void channel_config_remove(CHANNEL_SETUP_REC *channel)
{
	CONFIG_NODE *parent_node;
	GSList *config_node;

	parent_node = iconfig_node_traverse("channels", FALSE);

	if (parent_node == NULL)
		return;

	/* Try to find this channel in the configuration */
	config_node = g_slist_find_custom(parent_node->value, channel,
					  (GCompareFunc)compare_channel_setup);

	if (config_node != NULL)
		/* Delete the channel from the configuration */
		iconfig_node_remove(parent_node, config_node->data);
}

static void channel_setup_destroy(CHANNEL_SETUP_REC *channel)
{
	g_return_if_fail(channel != NULL);

	setupchannels = g_slist_remove(setupchannels, channel);
	signal_emit("channel setup destroyed", 1, channel);

	g_free_not_null(channel->chatnet);
	g_free_not_null(channel->password);
	g_free_not_null(channel->botmasks);
	g_free_not_null(channel->autosendcmd);
	g_free(channel->name);
	g_free(channel);
}

void channel_setup_remove_chatnet(const char *chatnet)
{
	GSList *tmp, *next;

	g_return_if_fail(chatnet != NULL);

	for (tmp = setupchannels; tmp != NULL; tmp = next) {
		CHANNEL_SETUP_REC *rec = tmp->data;

		next = tmp->next;
		if (g_ascii_strcasecmp(rec->chatnet, chatnet) == 0)
			channel_setup_remove(rec);
	}
}

void channel_setup_remove(CHANNEL_SETUP_REC *channel)
{
        channel_config_remove(channel);
        channel_setup_destroy(channel);
}

CHANNEL_SETUP_REC *channel_setup_find(const char *channel,
				      const char *chatnet)
{
	GSList *tmp;

	g_return_val_if_fail(channel != NULL, NULL);

	for (tmp = setupchannels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_SETUP_REC *rec = tmp->data;

		if (g_ascii_strcasecmp(rec->name, channel) == 0 &&
		    channel_chatnet_match(rec->chatnet, chatnet))
			return rec;
	}

	return NULL;
}

static CHANNEL_SETUP_REC *channel_setup_read(CONFIG_NODE *node)
{
	CHANNEL_SETUP_REC *rec;
        CHATNET_REC *chatnetrec;
	char *channel, *chatnet;

	g_return_val_if_fail(node != NULL, NULL);

	channel = config_node_get_str(node, "name", NULL);
        chatnet = config_node_get_str(node, "chatnet", NULL);

	chatnetrec = chatnet == NULL ? NULL : chatnet_find(chatnet);
	if (channel == NULL || chatnetrec == NULL) {
		/* missing information.. */
		return NULL;
	}

	rec = CHAT_PROTOCOL(chatnetrec)->create_channel_setup();
	rec->type = module_get_uniq_id("CHANNEL SETUP", 0);
	rec->chat_type = CHAT_PROTOCOL(chatnetrec)->id;
	rec->autojoin = config_node_get_bool(node, "autojoin", FALSE);
	rec->name = g_strdup(channel);
	rec->chatnet = g_strdup(chatnetrec != NULL ? chatnetrec->name : chatnet);
	rec->password = g_strdup(config_node_get_str(node, "password", NULL));
	rec->botmasks = g_strdup(config_node_get_str(node, "botmasks", NULL));
	rec->autosendcmd = g_strdup(config_node_get_str(node, "autosendcmd", NULL));

	setupchannels = g_slist_append(setupchannels, rec);
	signal_emit("channel setup created", 2, rec, node);
	return rec;
}

static void channels_read_config(void)
{
	CONFIG_NODE *node;
	GSList *tmp;

	while (setupchannels != NULL)
		channel_setup_destroy(setupchannels->data);

	/* Read channels */
	node = iconfig_node_traverse("channels", FALSE);
	if (node != NULL) {
		int i = 0;
		tmp = config_node_first(node->value);
		for (; tmp != NULL; tmp = config_node_next(tmp), i++) {
			node = tmp->data;
			if (node->type != NODE_TYPE_BLOCK) {
				g_critical("Expected block node at `channels[%d]' was of %s type. "
				           "Corrupt config?",
				           i, node->type == NODE_TYPE_LIST ? "list" : "scalar");
			} else {
				channel_setup_read(node);
			}
		}
	}
}

void channels_setup_init(void)
{
        setupchannels = NULL;
	source_host_ok = FALSE;

	signal_add("setup reread channels", (SIGNAL_FUNC) channels_read_config);
}

void channels_setup_deinit(void)
{
	while (setupchannels != NULL)
		channel_setup_destroy(setupchannels->data);

	signal_remove("setup reread channels", (SIGNAL_FUNC) channels_read_config);
}
