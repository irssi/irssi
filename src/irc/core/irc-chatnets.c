/*
 irc-chatnets.c : irssi

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
#include "servers.h"
#include "chatnets.h"
#include "special-vars.h"
#include "lib-config/iconfig.h"
#include "settings.h"

#include "irc-chatnets.h"

static void ircnet_read(CONFIG_NODE *node)
{
	IRC_CHATNET_REC *rec;

	if (node == NULL || node->key == NULL)
		return;

	rec = g_new0(IRC_CHATNET_REC, 1);
	rec->chat_type = IRC_PROTOCOL;

	rec->max_cmds_at_once = config_node_get_int(node, "cmdmax", 0);
	rec->cmd_queue_speed = config_node_get_int(node, "cmdspeed", 0);

	rec->max_kicks = config_node_get_int(node, "max_kicks", 0);
	rec->max_msgs = config_node_get_int(node, "max_msgs", 0);
	rec->max_modes = config_node_get_int(node, "max_modes", 0);
	rec->max_whois = config_node_get_int(node, "max_whois", 0);

	chatnet_read((CHATNET_REC *) rec, node);
}

static void ircnet_save(IRC_CHATNET_REC *rec)
{
	CONFIG_NODE *node;

	g_return_if_fail(IS_IRC_CHATNET(rec));

	node = iconfig_node_traverse("ircnets", TRUE);
	node = chatnet_save(CHATNET(rec), node);

	if (rec->max_cmds_at_once > 0)
		config_node_set_int(node, "cmdmax", rec->max_cmds_at_once);
	if (rec->cmd_queue_speed > 0)
		config_node_set_int(node, "cmdspeed", rec->cmd_queue_speed);

	if (rec->max_kicks > 0)
		config_node_set_int(node, "max_kicks", rec->max_kicks);
	if (rec->max_msgs > 0)
		config_node_set_int(node, "max_msgs", rec->max_msgs);
	if (rec->max_modes > 0)
		config_node_set_int(node, "max_modes", rec->max_modes);
	if (rec->max_whois > 0)
		config_node_set_int(node, "max_whois", rec->max_whois);
}

static void ircnet_remove(IRC_CHATNET_REC *rec)
{
	CONFIG_NODE *node;

	g_return_if_fail(IS_IRC_CHATNET(rec));

	node = iconfig_node_traverse("ircnets", FALSE);
	if (node != NULL) iconfig_node_set_str(node, rec->name, NULL);
}

void ircnet_create(IRC_CHATNET_REC *rec)
{
	g_return_if_fail(rec != NULL);

	rec->chat_type = IRC_PROTOCOL;

	ircnet_save(rec);
        chatnet_create(CHATNET(rec));
}

static void read_ircnets(void)
{
	CONFIG_NODE *node;
	GSList *tmp;

	while (chatnets != NULL)
		chatnet_destroy(chatnets->data);

	/* read ircnets */
	node = iconfig_node_traverse("ircnets", FALSE);
	if (node != NULL) {
		for (tmp = node->value; tmp != NULL; tmp = tmp->next)
			ircnet_read(tmp->data);
	}
}

static void sig_chatnet_removed(IRC_CHATNET_REC *rec)
{
	if (IS_IRC_CHATNET(rec))
		ircnet_remove(rec);
}

void irc_chatnets_init(void)
{
	read_ircnets();

	signal_add("chatnet removed", (SIGNAL_FUNC) sig_chatnet_removed);
        signal_add("setup reread", (SIGNAL_FUNC) read_ircnets);
}

void irc_chatnets_deinit(void)
{
	signal_remove("chatnet removed", (SIGNAL_FUNC) sig_chatnet_removed);
        signal_remove("setup reread", (SIGNAL_FUNC) read_ircnets);
}
