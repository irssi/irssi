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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "network.h"
#include "signals.h"
#include "special-vars.h"
#include "lib-config/iconfig.h"
#include "settings.h"

#include "chatnets.h"
#include "servers.h"

GSList *chatnets; /* list of available chat networks */

void chatnet_read(CHATNET_REC *chatnet, void *nodep)
{
	CONFIG_NODE *node = nodep;

	g_return_if_fail(chatnet != NULL);
	g_return_if_fail(node != NULL);
	g_return_if_fail(node->key != NULL);

	chatnet->type = module_get_uniq_id("CHATNET", 0);
	chatnet->name = g_strdup(node->key);
	chatnet->nick = g_strdup(config_node_get_str(node, "nick", NULL));
	chatnet->username = g_strdup(config_node_get_str(node, "username", NULL));
	chatnet->realname = g_strdup(config_node_get_str(node, "realname", NULL));
	chatnet->own_host = g_strdup(config_node_get_str(node, "host", NULL));
	chatnet->autosendcmd = g_strdup(config_node_get_str(node, "autosendcmd", NULL));

	chatnets = g_slist_append(chatnets, chatnet);
}

void *chatnet_save(CHATNET_REC *chatnet, void *parentnode)
{
	CONFIG_NODE *node = parentnode;

	g_return_val_if_fail(parentnode != NULL, NULL);
	g_return_val_if_fail(IS_CHATNET(chatnet), NULL);

	node = config_node_section(node, chatnet->name, NODE_TYPE_BLOCK);
	iconfig_node_clear(node);

	iconfig_node_set_str(node, "nick", chatnet->nick);
	iconfig_node_set_str(node, "username", chatnet->username);
	iconfig_node_set_str(node, "realname", chatnet->realname);
	iconfig_node_set_str(node, "host", chatnet->own_host);
	iconfig_node_set_str(node, "autosendcmd", chatnet->autosendcmd);
	return node;
}

void chatnet_create(CHATNET_REC *chatnet)
{
	g_return_if_fail(chatnet != NULL);

        chatnet->type = module_get_uniq_id("CHATNET", 0);
	if (g_slist_find(chatnets, chatnet) == NULL)
		chatnets = g_slist_append(chatnets, chatnet);

	signal_emit("chatnet created", 1, chatnet);
}

void chatnet_remove(CHATNET_REC *chatnet)
{
	g_return_if_fail(IS_CHATNET(chatnet));

	signal_emit("chatnet removed", 1, chatnet);
        chatnet_destroy(chatnet);
}

void chatnet_destroy(CHATNET_REC *chatnet)
{
	g_return_if_fail(IS_CHATNET(chatnet));

	chatnets = g_slist_remove(chatnets, chatnet);
	signal_emit("chatnet destroyed", 1, chatnet);

	g_free(chatnet->name);
	g_free_not_null(chatnet->nick);
	g_free_not_null(chatnet->username);
	g_free_not_null(chatnet->realname);
	g_free_not_null(chatnet->own_host);
	g_free_not_null(chatnet->autosendcmd);
	g_free(chatnet);
}

/* Find the irc network by name */
CHATNET_REC *chatnet_find(const char *name)
{
	GSList *tmp;

	g_return_val_if_fail(name != NULL, NULL);

	for (tmp = chatnets; tmp != NULL; tmp = tmp->next) {
		CHATNET_REC *rec = tmp->data;

		if (g_strcasecmp(rec->name, name) == 0)
			return rec;
	}

	return NULL;
}

static void sig_connected(SERVER_REC *server)
{
	CHATNET_REC *rec;

	g_return_if_fail(IS_SERVER(server));

	if (server->connrec->chatnet == NULL)
		return;

	rec = chatnet_find(server->connrec->chatnet);
	if (rec != NULL && rec->autosendcmd)
		eval_special_string(rec->autosendcmd, "", server, NULL);
}

void chatnets_init(void)
{
	signal_add("event connected", (SIGNAL_FUNC) sig_connected);
}

void chatnets_deinit(void)
{
	while (chatnets != NULL)
		chatnet_destroy(chatnets->data);

	signal_remove("event connected", (SIGNAL_FUNC) sig_connected);
	module_uniq_destroy("CHATNET");
}
