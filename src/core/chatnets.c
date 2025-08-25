/*
 chatnets.c : irssi

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
#include <irssi/src/core/network.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/special-vars.h>
#include <irssi/src/lib-config/iconfig.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/core/misc.h>

#include <irssi/src/core/chat-protocols.h>
#include <irssi/src/core/chatnets.h>
#include <irssi/src/core/servers.h>

GSList *chatnets, *chatnets_unavailable; /* list of available chat networks */

static void chatnet_config_save(CHATNET_REC *chatnet)
{
	CONFIG_NODE *node;

	node = iconfig_node_traverse("chatnets", TRUE);
	node = iconfig_node_section(node, chatnet->name, NODE_TYPE_BLOCK);
	iconfig_node_clear(node);

	iconfig_node_set_str(node, "type", chat_protocol_find_id(chatnet->chat_type)->name);
	iconfig_node_set_str(node, "nick", chatnet->nick);
	iconfig_node_set_str(node, "username", chatnet->username);
	iconfig_node_set_str(node, "realname", chatnet->realname);
	iconfig_node_set_str(node, "host", chatnet->own_host);
	iconfig_node_set_str(node, "autosendcmd", chatnet->autosendcmd);

        signal_emit("chatnet saved", 2, chatnet, node);
}

static void chatnet_config_remove(CHATNET_REC *chatnet)
{
	CONFIG_NODE *node;

	node = iconfig_node_traverse("chatnets", FALSE);
	if (node != NULL) iconfig_node_set_str(node, chatnet->name, NULL);
}

void chatnet_create(CHATNET_REC *chatnet)
{
	g_return_if_fail(chatnet != NULL);
	g_return_if_fail(!CHAT_PROTOCOL(chatnet)->not_initialized);

	chatnet->type = module_get_uniq_id("CHATNET", 0);
	if (g_slist_find(chatnets, chatnet) == NULL)
		chatnets = g_slist_append(chatnets, chatnet);

	chatnet_config_save(chatnet);
	signal_emit("chatnet created", 1, chatnet);
}

void chatnet_remove(CHATNET_REC *chatnet)
{
	g_return_if_fail(IS_CHATNET(chatnet));

	signal_emit("chatnet removed", 1, chatnet);

	chatnet_config_remove(chatnet);
	chatnet_destroy(chatnet);
}

void chatnet_destroy(CHATNET_REC *chatnet)
{
	g_return_if_fail(IS_CHATNET(chatnet));

	chatnets = g_slist_remove(chatnets, chatnet);
	signal_emit("chatnet destroyed", 1, chatnet);

	g_free_not_null(chatnet->nick);
	g_free_not_null(chatnet->username);
	g_free_not_null(chatnet->realname);
	g_free_not_null(chatnet->own_host);
	g_free_not_null(chatnet->autosendcmd);
	g_free(chatnet->name);
	g_free(chatnet);
}

/* Find the chat network by name */
CHATNET_REC *chatnet_find(const char *name)
{
	GSList *tmp;

	g_return_val_if_fail(name != NULL, NULL);

	for (tmp = chatnets; tmp != NULL; tmp = tmp->next) {
		CHATNET_REC *rec = tmp->data;

		if (g_ascii_strcasecmp(rec->name, name) == 0)
			return rec;
	}

	return NULL;
}

gboolean chatnet_find_unavailable(const char *name)
{
	CHAT_PROTOCOL_REC *proto;

	if (i_slist_find_icase_string(chatnets_unavailable, name) != NULL)
		return TRUE;

	proto = CHAT_PROTOCOL(chatnet_find(name));

	if (proto == NULL || proto->not_initialized)
		return TRUE;

	return FALSE;
}

static void sig_connected(SERVER_REC *server)
{
	CHATNET_REC *rec;

	g_return_if_fail(IS_SERVER(server));

	if (server->connrec->chatnet == NULL || server->session_reconnect)
		return;

	rec = chatnet_find(server->connrec->chatnet);
	if (!server->connrec->no_autosendcmd && rec != NULL && rec->autosendcmd)
		eval_special_string(rec->autosendcmd, "", server, NULL);
}

static void chatnet_read(CONFIG_NODE *node)
{
        CHAT_PROTOCOL_REC *proto;
	CHATNET_REC *rec;
        char *type;

	if (node == NULL || node->key == NULL || !is_node_list(node))
		return;

	type = config_node_get_str(node, "type", NULL);
	if (type == NULL) {
		proto = chat_protocol_get_default();
	} else {
		proto = chat_protocol_find(type);
	}

	if (proto == NULL) {
		/* protocol not loaded */
		if (i_slist_find_icase_string(chatnets_unavailable, node->key) == NULL)
			chatnets_unavailable =
			    g_slist_append(chatnets_unavailable, g_strdup(node->key));

		return;
	} else if (type == NULL) {
		iconfig_node_set_str(node, "type", proto->name);
	}

	rec = proto->create_chatnet();
	rec->type = module_get_uniq_id("CHATNET", 0);
	rec->chat_type = proto->id;
	rec->name = g_strdup(node->key);
	rec->nick = g_strdup(config_node_get_str(node, "nick", NULL));
	rec->username = g_strdup(config_node_get_str(node, "username", NULL));
	rec->realname = g_strdup(config_node_get_str(node, "realname", NULL));
	rec->own_host = g_strdup(config_node_get_str(node, "host", NULL));
	rec->autosendcmd = g_strdup(config_node_get_str(node, "autosendcmd", NULL));

	chatnets = g_slist_append(chatnets, rec);
        signal_emit("chatnet read", 2, rec, node);
}

static void read_chatnets(void)
{
	CONFIG_NODE *node;
        GSList *tmp;

	while (chatnets != NULL)
                chatnet_destroy(chatnets->data);

	while (chatnets_unavailable != NULL) {
		char *name = chatnets_unavailable->data;
		chatnets_unavailable = g_slist_remove(chatnets_unavailable, name);
		g_free(name);
	}

	node = iconfig_node_traverse("chatnets", FALSE);
	if (node != NULL) {
		tmp = config_node_first(node->value);
		for (; tmp != NULL; tmp = config_node_next(tmp))
                        chatnet_read(tmp->data);
	}
}

void chatnets_init(void)
{
	chatnets = NULL;

	signal_add_first("event connected", (SIGNAL_FUNC) sig_connected);
	signal_add("setup reread chatnets", (SIGNAL_FUNC) read_chatnets);
}

void chatnets_deinit(void)
{
	module_uniq_destroy("CHATNET");

	signal_remove("event connected", (SIGNAL_FUNC) sig_connected);
	signal_remove("setup reread chatnets", (SIGNAL_FUNC) read_chatnets);
}
