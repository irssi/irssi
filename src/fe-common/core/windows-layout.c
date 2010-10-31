/*
 windows-layout.c : irssi

    Copyright (C) 2000-2001 Timo Sirainen

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
#include "signals.h"
#include "misc.h"
#include "levels.h"
#include "lib-config/iconfig.h"
#include "settings.h"

#include "chat-protocols.h"
#include "servers.h"
#include "channels.h"
#include "queries.h"

#include "module-formats.h"
#include "printtext.h"
#include "themes.h"
#include "fe-windows.h"
#include "window-items.h"

static WINDOW_REC *restore_win;

static void signal_query_created_curwin(QUERY_REC *query)
{
	g_return_if_fail(IS_QUERY(query));

	window_item_add(restore_win, (WI_ITEM_REC *) query, TRUE);
}

static void sig_layout_restore_item(WINDOW_REC *window, const char *type,
				    CONFIG_NODE *node)
{
	char *name, *tag, *chat_type;

	chat_type = config_node_get_str(node, "chat_type", NULL);
	name = config_node_get_str(node, "name", NULL);
	tag = config_node_get_str(node, "tag", NULL);

	if (name == NULL || tag == NULL)
		return;

	if (g_ascii_strcasecmp(type, "CHANNEL") == 0) {
		/* bind channel to window */
		WINDOW_BIND_REC *rec = window_bind_add(window, tag, name);
                rec->sticky = TRUE;
	} else if (g_ascii_strcasecmp(type, "QUERY") == 0 && chat_type != NULL) {
		CHAT_PROTOCOL_REC *protocol;
		/* create query immediately */
		signal_add("query created",
			   (SIGNAL_FUNC) signal_query_created_curwin);

                restore_win = window;
		
		protocol = chat_protocol_find(chat_type);
		if (protocol->query_create != NULL)
			protocol->query_create(tag, name, TRUE);
		else {
			QUERY_REC *query;

			query = g_new0(QUERY_REC, 1);
			query->chat_type = chat_protocol_lookup(chat_type);
			query->name = g_strdup(name);
			query->server_tag = g_strdup(tag);
			query_init(query, TRUE);
		}

		signal_remove("query created",
			      (SIGNAL_FUNC) signal_query_created_curwin);
	}
}

static void window_add_items(WINDOW_REC *window, CONFIG_NODE *node)
{
	GSList *tmp;
	char *type;

	if (node == NULL)
		return;

	tmp = config_node_first(node->value);
	for (; tmp != NULL; tmp = config_node_next(tmp)) {
		CONFIG_NODE *node = tmp->data;

		type = config_node_get_str(node, "type", NULL);
		if (type != NULL) {
			signal_emit("layout restore item", 3,
				    window, type, node);
		}
	}
}

void windows_layout_restore(void)
{
	signal_emit("layout restore", 0);
}

static void sig_layout_restore(void)
{
	WINDOW_REC *window;
	CONFIG_NODE *node;
	GSList *tmp;

	node = iconfig_node_traverse("windows", FALSE);
	if (node == NULL) return;

	tmp = config_node_first(node->value);
	for (; tmp != NULL; tmp = config_node_next(tmp)) {
		CONFIG_NODE *node = tmp->data;

		window = window_find_refnum(atoi(node->key));
		if (window == NULL)
			window = window_create(NULL, TRUE);

		window_set_refnum(window, atoi(node->key));
                window->sticky_refnum = config_node_get_bool(node, "sticky_refnum", FALSE);
                window->immortal = config_node_get_bool(node, "immortal", FALSE);
		window_set_name(window, config_node_get_str(node, "name", NULL));
		window_set_history(window, config_node_get_str(node, "history_name", NULL));
		window_set_level(window, level2bits(config_node_get_str(node, "level", ""), NULL));

		window->servertag = g_strdup(config_node_get_str(node, "servertag", NULL));
		window->theme_name = g_strdup(config_node_get_str(node, "theme", NULL));
		if (window->theme_name != NULL)
			window->theme = theme_load(window->theme_name);

		window_add_items(window, config_node_section(node, "items", -1));
		signal_emit("layout restore window", 2, window, node);
	}
}

static void sig_layout_save_item(WINDOW_REC *window, WI_ITEM_REC *item,
				 CONFIG_NODE *node)
{
	CONFIG_NODE *subnode;
        CHAT_PROTOCOL_REC *proto;
	const char *type;
	WINDOW_BIND_REC *rec;

	type = module_find_id_str("WINDOW ITEM TYPE", item->type);
	if (type == NULL)
		return;

	subnode = config_node_section(node, NULL, NODE_TYPE_BLOCK);

	iconfig_node_set_str(subnode, "type", type);
	proto = item->chat_type == 0 ? NULL :
		chat_protocol_find_id(item->chat_type);
	if (proto != NULL)
		iconfig_node_set_str(subnode, "chat_type", proto->name);
	iconfig_node_set_str(subnode, "name", item->visible_name);

	if (item->server != NULL) {
		iconfig_node_set_str(subnode, "tag", item->server->tag);
		if (IS_CHANNEL(item)) {
			rec = window_bind_add(window, item->server->tag, item->visible_name);
			if (rec != NULL)
				rec->sticky = TRUE;
		}
	} else if (IS_QUERY(item)) {
		iconfig_node_set_str(subnode, "tag", QUERY(item)->server_tag);
	}
}

static void window_save_items(WINDOW_REC *window, CONFIG_NODE *node)
{
	GSList *tmp;

	node = config_node_section(node, "items", NODE_TYPE_LIST);
	for (tmp = window->items; tmp != NULL; tmp = tmp->next)
		signal_emit("layout save item", 3, window, tmp->data, node);
}

static void window_save(WINDOW_REC *window, CONFIG_NODE *node)
{
	char refnum[MAX_INT_STRLEN];

        ltoa(refnum, window->refnum);
	node = config_node_section(node, refnum, NODE_TYPE_BLOCK);

	if (window->sticky_refnum)
		iconfig_node_set_bool(node, "sticky_refnum", TRUE);

	if (window->immortal)
		iconfig_node_set_bool(node, "immortal", TRUE);

	if (window->name != NULL)
		iconfig_node_set_str(node, "name", window->name);

	if (window->history_name != NULL)
		iconfig_node_set_str(node, "history_name", window->history_name);

	if (window->servertag != NULL)
		iconfig_node_set_str(node, "servertag", window->servertag);
	if (window->level != 0) {
                char *level = bits2level(window->level);
		iconfig_node_set_str(node, "level", level);
		g_free(level);
	}
	if (window->theme_name != NULL)
		iconfig_node_set_str(node, "theme", window->theme_name);

	while (window->bound_items != NULL)
		window_bind_destroy(window, window->bound_items->data);
	if (window->items != NULL)
		window_save_items(window, node);

	signal_emit("layout save window", 2, window, node);
}

void windows_layout_save(void)
{
	CONFIG_NODE *node;
	GSList *sorted;

	iconfig_set_str(NULL, "windows", NULL);
	node = iconfig_node_traverse("windows", TRUE);

	sorted = windows_get_sorted();
	g_slist_foreach(sorted, (GFunc) window_save, node);
	g_slist_free(sorted);
	signal_emit("layout save", 0);

	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
		    TXT_WINDOWS_LAYOUT_SAVED);
}

void windows_layout_reset(void)
{
	GSList *tmp;

	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *window = tmp->data;
		while (window->bound_items != NULL)
			window_bind_destroy(window, window->bound_items->data);
	}

	iconfig_set_str(NULL, "windows", NULL);
	signal_emit("layout reset", 0);

	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
		    TXT_WINDOWS_LAYOUT_RESET);
}

void windows_layout_init(void)
{
	signal_add("layout restore item", (SIGNAL_FUNC) sig_layout_restore_item);
	signal_add("layout restore", (SIGNAL_FUNC) sig_layout_restore);
	signal_add("layout save item", (SIGNAL_FUNC) sig_layout_save_item);
}

void windows_layout_deinit(void)
{
	signal_remove("layout restore item", (SIGNAL_FUNC) sig_layout_restore_item);
	signal_remove("layout restore", (SIGNAL_FUNC) sig_layout_restore);
	signal_remove("layout save item", (SIGNAL_FUNC) sig_layout_save_item);
}
