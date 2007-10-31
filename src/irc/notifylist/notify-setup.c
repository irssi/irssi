/*
 notify-setup.c : irssi

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
#include "lib-config/iconfig.h"
#include "settings.h"

#include "irc-servers.h"
#include "notifylist.h"

void notifylist_add_config(NOTIFYLIST_REC *rec)
{
	CONFIG_NODE *node;

	node = iconfig_node_traverse("notifies", TRUE);
	node = config_node_section(node, rec->mask, NODE_TYPE_BLOCK);

	if (rec->away_check)
		iconfig_node_set_bool(node, "away_check", TRUE);
	else
		iconfig_node_set_str(node, "away_check", NULL);

	iconfig_node_set_str(node, "ircnets", NULL);
	if (rec->ircnets != NULL && *rec->ircnets != NULL) {
		node = config_node_section(node, "ircnets", NODE_TYPE_LIST);
		iconfig_node_add_list(node, rec->ircnets);
	}
}

void notifylist_remove_config(NOTIFYLIST_REC *rec)
{
	iconfig_set_str("notifies", rec->mask, NULL);
}

void notifylist_read_config(void)
{
	CONFIG_NODE *node;
	NOTIFYLIST_REC *rec;
	GSList *tmp;

	notifylist_destroy_all();

	node = iconfig_node_traverse("notifies", FALSE);
	if (node == NULL) return;

	tmp = config_node_first(node->value);
	for (; tmp != NULL; tmp = config_node_next(tmp)) {
		node = tmp->data;

		if (node->type != NODE_TYPE_BLOCK)
			continue;

		rec = g_new0(NOTIFYLIST_REC, 1);
		notifies = g_slist_append(notifies, rec);

		rec->mask = g_strdup(node->key);
		rec->away_check = config_node_get_bool(node, "away_check", FALSE);

		node = config_node_section(node, "ircnets", -1);
		if (node != NULL) rec->ircnets = config_node_get_list(node);
	}
}
