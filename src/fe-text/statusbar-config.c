/*
 statusbar-config.c : irssi

    Copyright (C) 2001 Timo Sirainen

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
#include "settings.h"
#include "lib-config/iconfig.h"

#include "statusbar.h"

static void read_statusbar_config_from_node(CONFIG_NODE *node);

static STATUSBAR_CONFIG_REC *
statusbar_config_create(STATUSBAR_GROUP_REC *group, const char *name)
{
	STATUSBAR_CONFIG_REC *bar;

        g_return_val_if_fail(group != NULL, NULL);
        g_return_val_if_fail(name != NULL, NULL);

	bar = g_new0(STATUSBAR_CONFIG_REC, 1);
	group->config_bars = g_slist_append(group->config_bars, bar);

	bar->name = g_strdup(name);
	return bar;
}

static SBAR_ITEM_CONFIG_REC *
statusbar_item_config_create(STATUSBAR_CONFIG_REC *bar, const char *name,
			     int priority, int right_alignment)
{
	SBAR_ITEM_CONFIG_REC *rec;

	g_return_val_if_fail(bar != NULL, NULL);
	g_return_val_if_fail(name != NULL, NULL);

	rec = g_new0(SBAR_ITEM_CONFIG_REC, 1);
	bar->items = g_slist_append(bar->items, rec);

        rec->name = g_strdup(name);
	rec->priority = priority;
        rec->right_alignment = right_alignment;

	return rec;
}

static void statusbar_config_item_destroy(STATUSBAR_CONFIG_REC *barconfig,
					  SBAR_ITEM_CONFIG_REC *itemconfig)
{
	barconfig->items = g_slist_remove(barconfig->items, itemconfig);

	g_free(itemconfig->name);
        g_free(itemconfig);
}

void statusbar_config_destroy(STATUSBAR_GROUP_REC *group,
			      STATUSBAR_CONFIG_REC *config)
{
	group->config_bars = g_slist_remove(group->config_bars, config);

	while (config->items != NULL)
		statusbar_config_item_destroy(config, config->items->data);

	g_free(config->name);
        g_free(config);
}

static STATUSBAR_CONFIG_REC *
statusbar_config_find(STATUSBAR_GROUP_REC *group, const char *name)
{
	GSList *tmp;

	for (tmp = group->config_bars; tmp != NULL; tmp = tmp->next) {
		STATUSBAR_CONFIG_REC *config = tmp->data;

		if (strcmp(config->name, name) == 0)
                        return config;
	}

        return NULL;
}

static void statusbar_reset_defaults(void)
{
	CONFIG_REC *config;
        CONFIG_NODE *node;

	while (statusbar_groups != NULL)
		statusbar_group_destroy(statusbar_groups->data);
	active_statusbar_group = NULL;

        /* read the default statusbar settings from internal config */
	config = config_open(NULL, -1);
	config_parse_data(config, default_config, "internal");
	node = config_node_traverse(config, "statusbar", FALSE);
        if (node != NULL)
		read_statusbar_config_from_node(node);
        config_close(config);
}

static void statusbar_read_items(CONFIG_NODE *items)
{
	GSList *tmp;

	tmp = config_node_first(items->value);
	for (; tmp != NULL; tmp = config_node_next(tmp)) {
		CONFIG_NODE *node = tmp->data;

		statusbar_item_register(node->key, node->value, NULL);
	}
}

static void statusbar_read_item(STATUSBAR_CONFIG_REC *bar, CONFIG_NODE *node)
{
	int priority, right_alignment;

	priority = config_node_get_int(node, "priority", 0);
	right_alignment = strcmp(config_node_get_str(node, "alignment", ""), "right") == 0;
	statusbar_item_config_create(bar, node->key,
				     priority, right_alignment);
}

static void statusbar_read(STATUSBAR_GROUP_REC *group, CONFIG_NODE *node)
{
	STATUSBAR_CONFIG_REC *bar;
        GSList *tmp;
	int visible;
        const char *visible_str;

	bar = statusbar_config_find(group, node->key);
	visible = bar == NULL ? STATUSBAR_VISIBLE_ALWAYS : bar->visible;

        /* first make sure we want to see this statusbar */
        visible_str = config_node_get_str(node, "visible", "");
	if (strcmp(visible_str, "active") == 0)
                visible = STATUSBAR_VISIBLE_ACTIVE;
	else if (strcmp(visible_str, "inactive") == 0)
		visible = STATUSBAR_VISIBLE_INACTIVE;
	else if (strcmp(visible_str, "never") == 0) {
		/* we don't want this statusbar -
		   destroy it if it already exists */
		if (bar != NULL)
			statusbar_config_destroy(group, bar);
                return;
	}

	if (bar == NULL) {
		bar = statusbar_config_create(group, node->key);
		bar->type = STATUSBAR_TYPE_ROOT;
		bar->placement = STATUSBAR_BOTTOM;
		bar->position = 0;
	}
	bar->visible = visible;

	if (strcmp(config_node_get_str(node, "type", ""), "window") == 0)
                bar->type = STATUSBAR_TYPE_WINDOW;
	if (strcmp(config_node_get_str(node, "placement", ""), "top") == 0)
                bar->placement = STATUSBAR_TOP;
	bar->position = config_node_get_int(node, "position", 0);

	node = config_node_section(node, "items", -1);
	if (node != NULL) {
                /* we're overriding the items - destroy the old */
                while (bar->items != NULL)
			statusbar_config_item_destroy(bar, bar->items->data);

		tmp = config_node_first(node->value);
		for (; tmp != NULL; tmp = config_node_next(tmp))
			statusbar_read_item(bar, tmp->data);
	}
}

static void statusbar_read_group(CONFIG_NODE *node)
{
	STATUSBAR_GROUP_REC *group;
	GSList *tmp;

	group = statusbar_group_find(node->key);
	if (group == NULL) {
		group = statusbar_group_create(node->key);
		if (active_statusbar_group == NULL)
			active_statusbar_group = group;
	}

        tmp = config_node_first(node->value);
	for (; tmp != NULL; tmp = config_node_next(tmp))
		statusbar_read(group, tmp->data);
}

static void create_root_statusbars(void)
{
        STATUSBAR_REC *bar;
	GSList *tmp;

        tmp = active_statusbar_group->config_bars;
	for (; tmp != NULL; tmp = tmp->next) {
		STATUSBAR_CONFIG_REC *rec = tmp->data;

		if (rec->type == STATUSBAR_TYPE_ROOT) {
			bar = statusbar_create(active_statusbar_group, rec, NULL);
                        statusbar_redraw(bar, TRUE);
		}
	}
}

static void read_statusbar_config_from_node(CONFIG_NODE *node)
{
	CONFIG_NODE *items;
	GSList *tmp;

	items = config_node_section(node, "items", -1);
	if (items != NULL)
		statusbar_read_items(items);

        tmp = config_node_first(node->value);
	for (; tmp != NULL; tmp = config_node_next(tmp)) {
		if (tmp->data != items)
			statusbar_read_group(tmp->data);
	}
}

static void read_statusbar_config(void)
{
	CONFIG_NODE *node;

        statusbar_reset_defaults();

	node = iconfig_node_traverse("statusbar", FALSE);
	if (node != NULL)
		read_statusbar_config_from_node(node);

        create_root_statusbars();
}

void statusbar_config_init(void)
{
        read_statusbar_config();
	signal_add("setup reread", (SIGNAL_FUNC) read_statusbar_config);
}

void statusbar_config_deinit(void)
{
	signal_remove("setup reread", (SIGNAL_FUNC) read_statusbar_config);
}
