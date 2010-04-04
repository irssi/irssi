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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include "module-formats.h"
#include "signals.h"
#include "commands.h"
#include "settings.h"
#include "levels.h"
#include "lib-config/iconfig.h"
#include "misc.h"

#include "statusbar.h"
#include "printtext.h"

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
        const char *visible_str;

	bar = statusbar_config_find(group, node->key);
	if (config_node_get_bool(node, "disabled", FALSE)) {
		/* disabled, destroy it if it already exists */
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

        visible_str = config_node_get_str(node, "visible", "");
	if (g_ascii_strcasecmp(visible_str, "active") == 0)
                bar->visible = STATUSBAR_VISIBLE_ACTIVE;
	else if (g_ascii_strcasecmp(visible_str, "inactive") == 0)
		bar->visible = STATUSBAR_VISIBLE_INACTIVE;
	else
		bar->visible = STATUSBAR_VISIBLE_ALWAYS;

	if (g_ascii_strcasecmp(config_node_get_str(node, "type", ""), "window") == 0)
                bar->type = STATUSBAR_TYPE_WINDOW;
	if (g_ascii_strcasecmp(config_node_get_str(node, "placement", ""), "top") == 0)
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
        statusbars_create_window_bars();
}

static const char *sbar_get_type(STATUSBAR_CONFIG_REC *rec)
{
	return rec->type == STATUSBAR_TYPE_ROOT ? "root" :
		rec->type == STATUSBAR_TYPE_WINDOW ? "window" : "??";
}

static const char *sbar_get_placement(STATUSBAR_CONFIG_REC *rec)
{
	return rec->placement == STATUSBAR_TOP ? "top" :
		rec->placement == STATUSBAR_BOTTOM ? "bottom" : "??";
}

static const char *sbar_get_visibility(STATUSBAR_CONFIG_REC *rec)
{
	return rec->visible == STATUSBAR_VISIBLE_ALWAYS ? "always" :
		rec->visible == STATUSBAR_VISIBLE_ACTIVE ? "active" :
		rec->visible == STATUSBAR_VISIBLE_INACTIVE ? "inactive" : "??";
}

static void statusbar_list_items(STATUSBAR_CONFIG_REC *bar)
{
	GSList *tmp;

	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
		    TXT_STATUSBAR_INFO_ITEM_HEADER);

	for (tmp = bar->items; tmp != NULL; tmp = tmp->next) {
		SBAR_ITEM_CONFIG_REC *rec = tmp->data;

		printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
			    TXT_STATUSBAR_INFO_ITEM_NAME,
			    rec->name, rec->priority,
			    rec->right_alignment ? "right" : "left");
	}

	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
		    TXT_STATUSBAR_INFO_ITEM_FOOTER);
}

static void statusbar_print(STATUSBAR_CONFIG_REC *rec)
{
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
		    TXT_STATUSBAR_INFO_NAME, rec->name);

	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
		    TXT_STATUSBAR_INFO_TYPE, sbar_get_type(rec));
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
		    TXT_STATUSBAR_INFO_PLACEMENT,
		    sbar_get_placement(rec));
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
		    TXT_STATUSBAR_INFO_POSITION, rec->position);
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
		    TXT_STATUSBAR_INFO_VISIBLE,
		    sbar_get_visibility(rec));

	if (rec->items != NULL)
		statusbar_list_items(rec);
}

static void cmd_statusbar_list(void)
{
	GSList *tmp;

	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_STATUSBAR_LIST_HEADER);

        tmp = active_statusbar_group->config_bars;
	for (; tmp != NULL; tmp = tmp->next) {
		STATUSBAR_CONFIG_REC *rec = tmp->data;

		printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
			    TXT_STATUSBAR_LIST, rec->name, sbar_get_type(rec),
			    sbar_get_placement(rec), rec->position,
			    sbar_get_visibility(rec));
	}

	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_STATUSBAR_LIST_FOOTER);
}

static void cmd_statusbar_print_info(const char *name)
{
	GSList *tmp;

        tmp = active_statusbar_group->config_bars;
	for (; tmp != NULL; tmp = tmp->next) {
		STATUSBAR_CONFIG_REC *rec = tmp->data;

		if (g_strcasecmp(rec->name, name) == 0) {
                        statusbar_print(rec);
			return;
		}
	}

	printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
		    TXT_STATUSBAR_NOT_FOUND, name);
}

/* SYNTAX: STATUSBAR <name> ENABLE */
static void cmd_statusbar_enable(const char *data, void *server,
				 void *item, CONFIG_NODE *node)
{
        iconfig_node_set_str(node, "disabled", NULL);
}

/* SYNTAX: STATUSBAR <name> DISABLE */
static void cmd_statusbar_disable(const char *data, void *server,
				  void *item, CONFIG_NODE *node)
{
        iconfig_node_set_bool(node, "disabled", TRUE);
}

/* SYNTAX: STATUSBAR <name> RESET */
static void cmd_statusbar_reset(const char *data, void *server,
				void *item, CONFIG_NODE *node)
{
	CONFIG_NODE *parent;

	parent = iconfig_node_traverse("statusbar", TRUE);
	parent = config_node_section(parent, active_statusbar_group->name,
				     NODE_TYPE_BLOCK);

        iconfig_node_set_str(parent, node->key, NULL);
}

/* SYNTAX: STATUSBAR <name> TYPE window|root */
static void cmd_statusbar_type(const char *data, void *server,
			       void *item, CONFIG_NODE *node)
{
	if (g_ascii_strcasecmp(data, "window") == 0)
		iconfig_node_set_str(node, "type", "window");
        else if (g_ascii_strcasecmp(data, "root") == 0)
		iconfig_node_set_str(node, "type", "root");
	else {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			    TXT_STATUSBAR_UNKNOWN_TYPE, data);
	}
}

/* SYNTAX: STATUSBAR <name> PLACEMENT top|bottom */
static void cmd_statusbar_placement(const char *data, void *server,
				    void *item, CONFIG_NODE *node)
{
	if (g_ascii_strcasecmp(data, "top") == 0)
		iconfig_node_set_str(node, "placement", "top");
        else if (g_ascii_strcasecmp(data, "bottom") == 0)
		iconfig_node_set_str(node, "placement", "bottom");
	else {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			    TXT_STATUSBAR_UNKNOWN_PLACEMENT, data);
	}
}

/* SYNTAX: STATUSBAR <name> POSITION <num> */
static void cmd_statusbar_position(const char *data, void *server,
                                   void *item, CONFIG_NODE *node)
{
	iconfig_node_set_int(node, "position", atoi(data));
}

/* SYNTAX: STATUSBAR <name> VISIBLE always|active|inactive */
static void cmd_statusbar_visible(const char *data, void *server,
				  void *item, CONFIG_NODE *node)
{
	if (g_ascii_strcasecmp(data, "always") == 0)
		iconfig_node_set_str(node, "visible", "always");
        else if (g_ascii_strcasecmp(data, "active") == 0)
		iconfig_node_set_str(node, "visible", "active");
        else if (g_ascii_strcasecmp(data, "inactive") == 0)
		iconfig_node_set_str(node, "visible", "inactive");
	else {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			    TXT_STATUSBAR_UNKNOWN_VISIBILITY, data);
	}
}

static CONFIG_NODE *statusbar_items_section(CONFIG_NODE *parent)
{
	STATUSBAR_CONFIG_REC *bar;
        CONFIG_NODE *node;
        GSList *tmp;

	node = config_node_section(parent, "items", -1);
	if (node != NULL)
		return node;

        /* find the statusbar configuration from memory */
	bar = statusbar_config_find(active_statusbar_group, parent->key);
	if (bar == NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			    TXT_STATUSBAR_NOT_FOUND, parent->key);
                return NULL;
	}

	/* since items list in config file overrides defaults,
	   we'll need to copy the whole list. */
	parent = config_node_section(parent, "items", NODE_TYPE_BLOCK);
	for (tmp = bar->items; tmp != NULL; tmp = tmp->next) {
		SBAR_ITEM_CONFIG_REC *rec = tmp->data;

		node = config_node_section(parent, rec->name,
					   NODE_TYPE_BLOCK);
		if (rec->priority != 0)
                        iconfig_node_set_int(node, "priority", rec->priority);
		if (rec->right_alignment)
                        iconfig_node_set_str(node, "alignment", "right");
	}

        return parent;
}

/* SYNTAX: STATUSBAR <name> ADD [-before | -after <item>]
           [-priority #] [-alignment left|right] <item> */
static void cmd_statusbar_add(const char *data, void *server,
			      void *item, CONFIG_NODE *node)
{
        GHashTable *optlist;
        char *name, *value;
	void *free_arg;
        int index;

	node = statusbar_items_section(node);
	if (node == NULL)
                return;

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS,
			    "statusbar add", &optlist, &name))
		return;

        /* get the index */
	index = -1;
	value = g_hash_table_lookup(optlist, "before");
	if (value != NULL) index = config_node_index(node, value);
	value = g_hash_table_lookup(optlist, "after");
	if (value != NULL) index = config_node_index(node, value)+1;

        /* create/move item */
	node = config_node_section_index(node, name, index, NODE_TYPE_BLOCK);

        /* set the options */
        value = g_hash_table_lookup(optlist, "priority");
        if (value != NULL) iconfig_node_set_int(node, "priority", atoi(value));

	value = g_hash_table_lookup(optlist, "alignment");
	if (value != NULL) {
		iconfig_node_set_str(node, "alignment",
				     g_ascii_strcasecmp(value, "right") == 0 ?
				     "right" : NULL);
	}

	cmd_params_free(free_arg);
}

/* SYNTAX: STATUSBAR <name> REMOVE <item> */
static void cmd_statusbar_remove(const char *data, void *server,
				 void *item, CONFIG_NODE *node)
{
        node = statusbar_items_section(node);
	if (node == NULL)
                return;

	if (config_node_section(node, data, -1) != NULL)
		iconfig_node_set_str(node, data, NULL);
	else {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			    TXT_STATUSBAR_ITEM_NOT_FOUND, data);
	}
}

static void cmd_statusbar(const char *data)
{
        CONFIG_NODE *node;
	char *name, *cmd, *params, *signal;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 3 | PARAM_FLAG_GETREST,
			    &name, &cmd, &params))
		return;

	if (*name == '\0') {
		/* list all statusbars */
                cmd_statusbar_list();
		cmd_params_free(free_arg);
                return;
	}

	if (*cmd == '\0') {
		/* print statusbar info */
                cmd_statusbar_print_info(name);
		cmd_params_free(free_arg);
                return;
	}

        /* lookup/create the statusbar node */
	node = iconfig_node_traverse("statusbar", TRUE);
	node = config_node_section(node, active_statusbar_group->name,
				   NODE_TYPE_BLOCK);
	node = config_node_section(node, name, NODE_TYPE_BLOCK);

	/* call the subcommand */
	signal = g_strconcat("command statusbar ", cmd, NULL);
	ascii_strdown(signal);
	if (!signal_emit(signal, 4, params, NULL, NULL, node)) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			    TXT_STATUSBAR_UNKNOWN_COMMAND, cmd);
	} else {
                read_statusbar_config();
	}
	g_free(signal);

	cmd_params_free(free_arg);
}

void statusbar_config_init(void)
{
        read_statusbar_config();
	signal_add_last("setup reread", (SIGNAL_FUNC) read_statusbar_config);
	signal_add("theme changed", (SIGNAL_FUNC) read_statusbar_config);

        command_bind("statusbar", NULL, (SIGNAL_FUNC) cmd_statusbar);
        command_bind("statusbar enable", NULL, (SIGNAL_FUNC) cmd_statusbar_enable);
        command_bind("statusbar disable", NULL, (SIGNAL_FUNC) cmd_statusbar_disable);
        command_bind("statusbar reset", NULL, (SIGNAL_FUNC) cmd_statusbar_reset);
        command_bind("statusbar add", NULL, (SIGNAL_FUNC) cmd_statusbar_add);
        command_bind("statusbar remove", NULL, (SIGNAL_FUNC) cmd_statusbar_remove);
        command_bind("statusbar type", NULL, (SIGNAL_FUNC) cmd_statusbar_type);
        command_bind("statusbar placement", NULL, (SIGNAL_FUNC) cmd_statusbar_placement);
        command_bind("statusbar position", NULL, (SIGNAL_FUNC) cmd_statusbar_position);
        command_bind("statusbar visible", NULL, (SIGNAL_FUNC) cmd_statusbar_visible);

	command_set_options("statusbar add", "+before +after +priority +alignment");
}

void statusbar_config_deinit(void)
{
	signal_remove("setup reread", (SIGNAL_FUNC) read_statusbar_config);
	signal_remove("theme changed", (SIGNAL_FUNC) read_statusbar_config);

        command_unbind("statusbar", (SIGNAL_FUNC) cmd_statusbar);
        command_unbind("statusbar enable", (SIGNAL_FUNC) cmd_statusbar_enable);
        command_unbind("statusbar disable", (SIGNAL_FUNC) cmd_statusbar_disable);
        command_unbind("statusbar reset", (SIGNAL_FUNC) cmd_statusbar_reset);
        command_unbind("statusbar add", (SIGNAL_FUNC) cmd_statusbar_add);
        command_unbind("statusbar remove", (SIGNAL_FUNC) cmd_statusbar_remove);
        command_unbind("statusbar type", (SIGNAL_FUNC) cmd_statusbar_type);
        command_unbind("statusbar placement", (SIGNAL_FUNC) cmd_statusbar_placement);
        command_unbind("statusbar position", (SIGNAL_FUNC) cmd_statusbar_position);
        command_unbind("statusbar visible", (SIGNAL_FUNC) cmd_statusbar_visible);
}
