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

GSList *ircnets; /* list of available ircnets */

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

static void ircnet_destroy(IRCNET_REC *rec)
{
	ircnets = g_slist_remove(ircnets, rec);

	g_free(rec->name);
	if (rec->nick != NULL) g_free(rec->nick);
	if (rec->username != NULL) g_free(rec->username);
	if (rec->realname != NULL) g_free(rec->realname);
	g_free(rec);
}

static IRCNET_REC *ircnet_add(CONFIG_NODE *node)
{
	IRCNET_REC *rec;
	char *name, *nick, *username, *realname;

	g_return_val_if_fail(node != NULL, NULL);

	name = config_node_get_str(node, "name", NULL);
	if (name == NULL) return NULL;

	nick = config_node_get_str(node, "nick", NULL);
	username = config_node_get_str(node, "username", NULL);
	realname = config_node_get_str(node, "realname", NULL);

	rec = g_new0(IRCNET_REC, 1);
	rec->max_kicks = config_node_get_int(node, "max_kicks", 0);
	rec->max_msgs = config_node_get_int(node, "max_msgs", 0);
	rec->max_modes = config_node_get_int(node, "max_modes", 0);
	rec->max_whois = config_node_get_int(node, "max_whois", 0);

	rec->name = g_strdup(name);
	rec->nick = (nick == NULL || *nick == '\0') ? NULL : g_strdup(nick);
	rec->username = (username == NULL || *username == '\0') ? NULL : g_strdup(username);
	rec->realname = (realname == NULL || *realname == '\0') ? NULL : g_strdup(realname);

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

void ircnets_setup_init(void)
{
        signal_add("setup reread", (SIGNAL_FUNC) read_ircnets);
}

void ircnets_setup_deinit(void)
{
	while (ircnets != NULL)
		ircnet_destroy(ircnets->data);

	signal_remove("setup reread", (SIGNAL_FUNC) read_ircnets);
}
