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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include <irssi/src/core/signals.h>
#include <irssi/src/lib-config/iconfig.h>
#include <irssi/src/core/settings.h>

#include <irssi/src/irc/core/irc-chatnets.h>

void ircnet_create(IRC_CHATNET_REC *rec)
{
	g_return_if_fail(rec != NULL);

	rec->chat_type = IRC_PROTOCOL;
        chatnet_create((CHATNET_REC *) rec);
}

static void sig_chatnet_read(IRC_CHATNET_REC *rec, CONFIG_NODE *node)
{
	char *value;

	if (!IS_IRC_CHATNET(rec))
		return;

	value = config_node_get_str(node, "usermode", NULL);
	rec->usermode = (value != NULL && *value != '\0') ? g_strdup(value) : NULL;

	value = config_node_get_str(node, "alternate_nick", NULL);
	rec->alternate_nick = (value != NULL && *value != '\0') ? g_strdup(value) : NULL;

	rec->max_cmds_at_once = config_node_get_int(node, "cmdmax", 0);
	rec->cmd_queue_speed = config_node_get_int(node, "cmdspeed", 0);
	rec->max_query_chans = config_node_get_int(node, "max_query_chans", 0);

	rec->max_kicks = config_node_get_int(node, "max_kicks", 0);
	rec->max_msgs = config_node_get_int(node, "max_msgs", 0);
	rec->max_modes = config_node_get_int(node, "max_modes", 0);
	rec->max_whois = config_node_get_int(node, "max_whois", 0);

	rec->sasl_mechanism = g_strdup(config_node_get_str(node, "sasl_mechanism", NULL));
	rec->sasl_username = g_strdup(config_node_get_str(node, "sasl_username", NULL));
	rec->sasl_password = g_strdup(config_node_get_str(node, "sasl_password", NULL));
}

static void sig_chatnet_saved(IRC_CHATNET_REC *rec, CONFIG_NODE *node)
{
	if (!IS_IRC_CHATNET(rec))
		return;

	if (rec->usermode != NULL)
		iconfig_node_set_str(node, "usermode", rec->usermode);

	if (rec->alternate_nick != NULL)
		iconfig_node_set_str(node, "alternate_nick", rec->alternate_nick);

	if (rec->max_cmds_at_once > 0)
		iconfig_node_set_int(node, "cmdmax", rec->max_cmds_at_once);
	if (rec->cmd_queue_speed > 0)
		iconfig_node_set_int(node, "cmdspeed", rec->cmd_queue_speed);
	if (rec->max_query_chans > 0)
		iconfig_node_set_int(node, "max_query_chans", rec->max_query_chans);

	if (rec->max_kicks > 0)
		iconfig_node_set_int(node, "max_kicks", rec->max_kicks);
	if (rec->max_msgs > 0)
		iconfig_node_set_int(node, "max_msgs", rec->max_msgs);
	if (rec->max_modes > 0)
		iconfig_node_set_int(node, "max_modes", rec->max_modes);
	if (rec->max_whois > 0)
		iconfig_node_set_int(node, "max_whois", rec->max_whois);

	if (rec->sasl_mechanism != NULL)
		iconfig_node_set_str(node, "sasl_mechanism", rec->sasl_mechanism);
	if (rec->sasl_username != NULL)
		iconfig_node_set_str(node, "sasl_username", rec->sasl_username);
	if (rec->sasl_password != NULL)
		iconfig_node_set_str(node, "sasl_password", rec->sasl_password);
}

static void sig_chatnet_destroyed(IRC_CHATNET_REC *rec)
{
	if (IS_IRC_CHATNET(rec)) {
		g_free(rec->usermode);
		g_free(rec->alternate_nick);
		g_free(rec->sasl_mechanism);
		g_free(rec->sasl_username);
		g_free(rec->sasl_password);
	}
}


void irc_chatnets_init(void)
{
	signal_add("chatnet read", (SIGNAL_FUNC) sig_chatnet_read);
	signal_add("chatnet saved", (SIGNAL_FUNC) sig_chatnet_saved);
	signal_add("chatnet destroyed", (SIGNAL_FUNC) sig_chatnet_destroyed);
}

void irc_chatnets_deinit(void)
{
	GSList *tmp, *next;

	for (tmp = chatnets; tmp != NULL; tmp = next) {
		CHATNET_REC *rec = tmp->data;

		next = tmp->next;
		if (IS_IRC_CHATNET(rec))
                        chatnet_destroy(rec);
	}

	signal_remove("chatnet read", (SIGNAL_FUNC) sig_chatnet_read);
	signal_remove("chatnet saved", (SIGNAL_FUNC) sig_chatnet_saved);
	signal_remove("chatnet destroyed", (SIGNAL_FUNC) sig_chatnet_destroyed);
}
