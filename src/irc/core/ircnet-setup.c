/*
 ircnet-setup.c : irssi

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
#include "lib-config/iconfig.h"
#include "settings.h"

#include "irc-server.h"
#include "ircnet-setup.h"
#include "special-vars.h"

GSList *ircnets; /* list of available ircnets */

static void ircnet_config_add(IRCNET_REC *ircnet)
{
	CONFIG_NODE *node;

	node = iconfig_node_traverse("ircnets", TRUE);
	iconfig_node_set_str(node, ircnet->name, NULL);
	node = config_node_section(node, ircnet->name, NODE_TYPE_BLOCK);

	iconfig_node_set_str(node, "nick", ircnet->nick);
	iconfig_node_set_str(node, "username", ircnet->username);
	iconfig_node_set_str(node, "realname", ircnet->realname);
	iconfig_node_set_str(node, "host", ircnet->own_host);
	iconfig_node_set_str(node, "autosendcmd", ircnet->autosendcmd);

	if (ircnet->max_cmds_at_once > 0)
		config_node_set_int(node, "cmdmax", ircnet->max_cmds_at_once);
	if (ircnet->cmd_queue_speed > 0)
		config_node_set_int(node, "cmdspeed", ircnet->cmd_queue_speed);

	if (ircnet->max_kicks > 0)
		config_node_set_int(node, "max_kicks", ircnet->max_kicks);
	if (ircnet->max_msgs > 0)
		config_node_set_int(node, "max_msgs", ircnet->max_msgs);
	if (ircnet->max_modes > 0)
		config_node_set_int(node, "max_modes", ircnet->max_modes);
	if (ircnet->max_whois > 0)
		config_node_set_int(node, "max_whois", ircnet->max_whois);

}

static void ircnet_config_remove(IRCNET_REC *ircnet)
{
	CONFIG_NODE *node;

	node = iconfig_node_traverse("ircnets", FALSE);
	if (node != NULL) iconfig_node_set_str(node, ircnet->name, NULL);
}

void ircnet_create(IRCNET_REC *ircnet)
{
	if (g_slist_find(ircnets, ircnet) == NULL)
		ircnets = g_slist_append(ircnets, ircnet);

        ircnet_config_add(ircnet);
}

void ircnet_destroy(IRCNET_REC *ircnet)
{
        ircnet_config_remove(ircnet);
	ircnets = g_slist_remove(ircnets, ircnet);

	g_free(ircnet->name);
	g_free_not_null(ircnet->nick);
	g_free_not_null(ircnet->username);
	g_free_not_null(ircnet->realname);
	g_free_not_null(ircnet->own_host);
	g_free_not_null(ircnet->autosendcmd);
	g_free(ircnet);
}

/* Find the irc network by name */
IRCNET_REC *ircnet_find(const char *name)
{
	GSList *tmp;

	g_return_val_if_fail(name != NULL, NULL);

	for (tmp = ircnets; tmp != NULL; tmp = tmp->next) {
		IRCNET_REC *rec = tmp->data;

		if (g_strcasecmp(rec->name, name) == 0)
			return rec;
	}

	return NULL;
}

static IRCNET_REC *ircnet_add(CONFIG_NODE *node)
{
	IRCNET_REC *rec;

	g_return_val_if_fail(node != NULL, NULL);
	if (node->key == NULL) return NULL;

	rec = g_new0(IRCNET_REC, 1);

	rec->name = g_strdup(node->key);
	rec->nick = g_strdup(config_node_get_str(node, "nick", NULL));
	rec->username = g_strdup(config_node_get_str(node, "username", NULL));
	rec->realname = g_strdup(config_node_get_str(node, "realname", NULL));
	rec->own_host = g_strdup(config_node_get_str(node, "host", NULL));
	rec->autosendcmd = g_strdup(config_node_get_str(node, "autosendcmd", NULL));

	rec->max_cmds_at_once = config_node_get_int(node, "cmdmax", 0);
	rec->cmd_queue_speed = config_node_get_int(node, "cmdspeed", 0);

	rec->max_kicks = config_node_get_int(node, "max_kicks", 0);
	rec->max_msgs = config_node_get_int(node, "max_msgs", 0);
	rec->max_modes = config_node_get_int(node, "max_modes", 0);
	rec->max_whois = config_node_get_int(node, "max_whois", 0);

	ircnets = g_slist_append(ircnets, rec);
	return rec;
}

static void read_ircnets(void)
{
	CONFIG_NODE *node;
	GSList *tmp;

	while (ircnets != NULL)
		ircnet_destroy(ircnets->data);

	/* read ircnets */
	node = iconfig_node_traverse("ircnets", FALSE);
	if (node != NULL) {
		for (tmp = node->value; tmp != NULL; tmp = tmp->next)
			ircnet_add(tmp->data);
	}
}

static void sig_connected(IRC_SERVER_REC *server)
{
	IRCNET_REC *ircnet;

	if (server->connrec->ircnet == NULL) return;

	ircnet = ircnet_find(server->connrec->ircnet);
	if (ircnet != NULL && ircnet->autosendcmd)
		eval_special_string(ircnet->autosendcmd, "", server, NULL);
}

void ircnets_setup_init(void)
{
	read_ircnets();
        signal_add("setup reread", (SIGNAL_FUNC) read_ircnets);
	signal_add("event connected", (SIGNAL_FUNC) sig_connected);
}

void ircnets_setup_deinit(void)
{
	while (ircnets != NULL)
		ircnet_destroy(ircnets->data);

	signal_remove("setup reread", (SIGNAL_FUNC) read_ircnets);
	signal_remove("event connected", (SIGNAL_FUNC) sig_connected);
}
