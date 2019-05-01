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
#include <irssi/src/fe-text/module-formats.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/lib-config/iconfig.h>
#include <irssi/src/core/misc.h>

#include <irssi/src/fe-text/statusbar.h>
#include <irssi/src/fe-common/core/printtext.h>

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

		if ((config->name == NULL || name == NULL) ?
		        config->name == name :
		        g_ascii_strcasecmp(config->name, name) == 0)
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
	right_alignment = g_strcmp0(config_node_get_str(node, "alignment", ""), "right") == 0;
	statusbar_item_config_create(bar, node->key,
				     priority, right_alignment);
}

static void statusbar_read(STATUSBAR_GROUP_REC *group, CONFIG_NODE *node)
{
	STATUSBAR_CONFIG_REC *bar;
        GSList *tmp;
        const char *visible_str;

	g_return_if_fail(is_node_list(node));
	g_return_if_fail(node->key != NULL);

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

	node = iconfig_node_section(node, "items", -1);
	if (node != NULL) {
                /* we're overriding the items - destroy the old */
                while (bar->items != NULL)
			statusbar_config_item_destroy(bar, bar->items->data);

		tmp = config_node_first(node->value);
		for (; tmp != NULL; tmp = config_node_next(tmp))
			statusbar_read_item(bar, tmp->data);
	}
}

#define skip_corrupt_config(parent, node, index, format, ...)	\
	if ((node)->type != NODE_TYPE_BLOCK) {			\
		if ((node)->key == NULL) {				\
			g_critical("Expected %s node at `.." format "/%s[%d]' was of %s type. Corrupt config?", \
				   "block", ##__VA_ARGS__, (parent)->key, (index), \
				   (node)->type == NODE_TYPE_LIST ? "list" : "scalar"); \
		} else {						\
			g_critical("Expected %s node at `.." format "/%s/%s' was of %s type. Corrupt config?", \
				   "block", ##__VA_ARGS__, (parent)->key, (node)->key, \
				   (node)->type == NODE_TYPE_LIST ? "list" : "scalar"); \
		}							\
		continue;						\
	}								\


static void statusbar_read_group(CONFIG_NODE *node)
{
	STATUSBAR_GROUP_REC *group;
	GSList *tmp;
	int i;

	g_return_if_fail(is_node_list(node));

	group = statusbar_group_find(node->key);
	if (group == NULL) {
		group = statusbar_group_create(node->key);
		if (active_statusbar_group == NULL)
			active_statusbar_group = group;
	}

	for (tmp = config_node_first(node->value), i = 0; tmp != NULL; tmp = config_node_next(tmp), i++) {
		CONFIG_NODE *value = tmp->data;
		skip_corrupt_config(node, value, i, "statusbar");
		statusbar_read(group, value);
	}
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
	CONFIG_NODE *items, *group;
	GSList *tmp;
	int i;

	items = iconfig_node_section(node, "items", -1);
	if (items != NULL)
		statusbar_read_items(items);

	for (tmp = config_node_first(node->value), i = 0; tmp != NULL; tmp = config_node_next(tmp), i++) {
		group = tmp->data;
		if (group != items) {
			skip_corrupt_config(node, group, i, "");
			statusbar_read_group(group);
		}
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

#define iconfig_sbar_node(a, b) config_sbar_node(mainconfig, a, b)
static CONFIG_NODE *config_sbar_node(CONFIG_REC *config, const char *name, gboolean create)
{
	CONFIG_NODE *node;

	node = config_node_traverse(config, "statusbar", create);
	if (node != NULL) {
		node = config_node_section(config, node, active_statusbar_group->name,
		                           create ? NODE_TYPE_BLOCK : -1);
	}

	if (node != NULL) {
		node = config_node_section(config, node, name, create ? NODE_TYPE_BLOCK : -1);
	}

	return node;
}

static CONFIG_NODE *sbar_node(const char *name, gboolean create)
{
	STATUSBAR_CONFIG_REC *rec = statusbar_config_find(active_statusbar_group, name);
	if (rec != NULL) {
		name = rec->name;
	}

	/* lookup/create the statusbar node */
	return iconfig_sbar_node(name, create);
}

static gboolean sbar_node_isdefault(const char *name)
{
	CONFIG_REC *config;
	CONFIG_NODE *node;

	/* read the default statusbar settings from internal config */
	config = config_open(NULL, -1);
	config_parse_data(config, default_config, "internal");

	node = config_sbar_node(config, name, FALSE);

	config_close(config);

	return node != NULL ? TRUE : FALSE;
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
	STATUSBAR_CONFIG_REC *rec = statusbar_config_find(active_statusbar_group, name);

	if (rec != NULL) {
		statusbar_print(rec);
		return;
	}

	if (sbar_node(name, FALSE) != NULL || sbar_node_isdefault(name))
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			    TXT_STATUSBAR_NOT_ENABLED, name);
	else
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			    TXT_STATUSBAR_NOT_FOUND, name);
}

/* SYNTAX: STATUSBAR ADD|MODIFY [-disable | -nodisable] [-type window|root]
           [-placement top|bottom] [-position #] [-visible always|active|inactive] <statusbar> */
static void cmd_statusbar_add_modify(const char *data, void *server, void *witem)
{
	GHashTable *optlist;
	CONFIG_NODE *node;
	char *name, *type, *placement, *visible;
	void *free_arg;
	int error;
	int add = GPOINTER_TO_INT(signal_get_user_data());

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS | PARAM_FLAG_STRIP_TRAILING_WS,
	                    "statusbar add", &optlist, &name))
		return;

	if (*name == '\0') {
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
	}

	error = 0;

	type = NULL;
	data = g_hash_table_lookup(optlist, "type");
	if (data != NULL) {
		if (g_ascii_strcasecmp(data, "window") == 0)
			type = "window";
		else if (g_ascii_strcasecmp(data, "root") == 0)
			type = "root";
		else {
			printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, TXT_STATUSBAR_UNKNOWN_TYPE,
			            data);
			error++;
		}
	}

	placement = NULL;
	data = g_hash_table_lookup(optlist, "placement");
	if (data != NULL) {
		if (g_ascii_strcasecmp(data, "top") == 0)
			placement = "top";
		else if (g_ascii_strcasecmp(data, "bottom") == 0)
			placement = "bottom";
		else {
			printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			            TXT_STATUSBAR_UNKNOWN_PLACEMENT, data);
			error++;
		}
	}

	visible = NULL;
	data = g_hash_table_lookup(optlist, "visible");
	if (data != NULL) {
		if (g_ascii_strcasecmp(data, "always") == 0)
			visible = "always";
		else if (g_ascii_strcasecmp(data, "active") == 0)
			visible = "active";
		else if (g_ascii_strcasecmp(data, "inactive") == 0)
			visible = "inactive";
		else {
			printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			            TXT_STATUSBAR_UNKNOWN_VISIBILITY, data);
			error++;
		}
	}

	if (!error) {
		node = sbar_node(name, add);
		if (node == NULL && !add && sbar_node_isdefault(name)) {
			/* If this node is a default status bar, we need to create it in the config
			 * to configure it */
			node = sbar_node(name, TRUE);
		}

		if (node == NULL) {
			printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, TXT_STATUSBAR_NOT_FOUND, name);
			error++;
		}
	}

	if (error) {
		cmd_params_free(free_arg);
		return;
	}

	if (g_hash_table_lookup(optlist, "nodisable"))
		iconfig_node_set_str(node, "disabled", NULL);
	if (g_hash_table_lookup(optlist, "disable"))
		iconfig_node_set_bool(node, "disabled", TRUE);
	if (type != NULL)
		iconfig_node_set_str(node, "type", type);
	if (placement != NULL)
		iconfig_node_set_str(node, "placement", placement);
	data = g_hash_table_lookup(optlist, "position");
	if (data != NULL)
		iconfig_node_set_int(node, "position", atoi(data));
	if (visible != NULL)
		iconfig_node_set_str(node, "visible", visible);

	read_statusbar_config();
	cmd_params_free(free_arg);
}

/* SYNTAX: STATUSBAR RESET <statusbar> */
static void cmd_statusbar_reset(const char *data, void *server, void *witem)
{
	CONFIG_NODE *node, *parent;
	char *name;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_STRIP_TRAILING_WS, &name))
		return;

	if (*name == '\0') {
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
	}

	node = sbar_node(name, FALSE);
	if (node == NULL && !sbar_node_isdefault(name)) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, TXT_STATUSBAR_NOT_FOUND, name);
		cmd_params_free(free_arg);
		return;
	}

	parent = iconfig_node_traverse("statusbar", FALSE);
	if (parent != NULL) {
		parent = iconfig_node_section(parent, active_statusbar_group->name, -1);
	}

	if (parent != NULL && node != NULL) {
		iconfig_node_set_str(parent, node->key, NULL);
	}

	read_statusbar_config();
	cmd_params_free(free_arg);
}

#define iconfig_sbar_items_section(a, b) config_sbar_items_section(mainconfig, a, b)
static CONFIG_NODE *config_sbar_items_section(CONFIG_REC *config, CONFIG_NODE *parent,
                                              gboolean create)
{
	return config_node_section(config, parent, "items", create ? NODE_TYPE_BLOCK : -1);
}

static CONFIG_NODE *statusbar_copy_config(CONFIG_REC *config, CONFIG_NODE *source,
                                          CONFIG_NODE *parent)
{
	GSList *tmp;

	g_return_val_if_fail(parent != NULL, NULL);

	parent = iconfig_sbar_items_section(parent, TRUE);

	/* since items list in config file overrides defaults,
	   we'll need to copy the whole list. */
	for (tmp = config_node_first(source->value); tmp != NULL; tmp = config_node_next(tmp)) {
		int priority, right_alignment;
		CONFIG_NODE *node, *snode;

		snode = tmp->data;

		priority = config_node_get_int(snode, "priority", 0);
		right_alignment =
		    g_strcmp0(config_node_get_str(snode, "alignment", ""), "right") == 0;

		/* create new item */
		node = iconfig_node_section(parent, snode->key, NODE_TYPE_BLOCK);

		if (priority != 0)
			iconfig_node_set_int(node, "priority", priority);
		if (right_alignment)
			iconfig_node_set_str(node, "alignment", "right");
	}

	return parent;
}

static CONFIG_NODE *sbar_find_item_with_defaults(const char *statusbar, const char *item,
                                                 gboolean create)
{
	CONFIG_REC *config, *close_config;
	CONFIG_NODE *node;

	close_config = NULL;
	config = mainconfig;
	node = sbar_node(statusbar, FALSE);

	if (node == NULL) {
		/* we are looking up defaults from the internal config */
		close_config = config = config_open(NULL, -1);
		config_parse_data(config, default_config, "internal");
		node = config_sbar_node(config, statusbar, FALSE);
	}

	if (node == NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, TXT_STATUSBAR_NOT_FOUND, statusbar);
		if (close_config != NULL)
			config_close(close_config);
		return NULL;
	}

	node = config_sbar_items_section(config, node, create);

	if (node == NULL || (!create && config_node_section(config, node, item, -1) == NULL)) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, TXT_STATUSBAR_ITEM_NOT_FOUND, item);
		if (close_config != NULL)
			config_close(close_config);
		return NULL;
	}

	if (config != mainconfig) {
		/* we need to copy default to user config */
		node = statusbar_copy_config(config, node, sbar_node(statusbar, TRUE));
	}

	if (close_config != NULL)
		config_close(close_config);

	return node;
}

/* SYNTAX: STATUSBAR ADDITEM|MODIFYITEM [-before | -after <item>]
           [-priority #] [-alignment left|right] <item> <statusbar> */
static void cmd_statusbar_additem_modifyitem(const char *data, void *server, void *witem)
{
	CONFIG_NODE *node;
	GHashTable *optlist;
	char *item, *statusbar, *value;
	void *free_arg;
	int index;
	int additem = GPOINTER_TO_INT(signal_get_user_data());

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_OPTIONS | PARAM_FLAG_STRIP_TRAILING_WS,
	                    "statusbar additem", &optlist, &item, &statusbar))
		return;

	if (*statusbar == '\0') {
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
	}

	node = sbar_find_item_with_defaults(statusbar, item, additem);
	if (node == NULL) {
		cmd_params_free(free_arg);
		return;
	}

	/* get the index */
	index = -1;
	value = g_hash_table_lookup(optlist, "before");
	if (value != NULL)
		index = config_node_index(node, value);
	value = g_hash_table_lookup(optlist, "after");
	if (value != NULL)
		index = config_node_index(node, value) + 1;

	/* create/move item */
	node = iconfig_node_section_index(node, item, index, NODE_TYPE_BLOCK);

	/* set the options */
	value = g_hash_table_lookup(optlist, "priority");
	if (value != NULL) iconfig_node_set_int(node, "priority", atoi(value));

	value = g_hash_table_lookup(optlist, "alignment");
	if (value != NULL) {
		iconfig_node_set_str(node, "alignment",
				     g_ascii_strcasecmp(value, "right") == 0 ?
				     "right" : NULL);
	}

	read_statusbar_config();
	cmd_params_free(free_arg);
}

/* SYNTAX: STATUSBAR REMOVEITEM <item> <statusbar> */
static void cmd_statusbar_removeitem(const char *data, void *server, void *witem)
{
	CONFIG_NODE *node;
	char *item, *statusbar;
	void *free_arg;
	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_STRIP_TRAILING_WS, &item, &statusbar))
		return;

	if (*statusbar == '\0') {
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
	}

	node = sbar_find_item_with_defaults(statusbar, item, FALSE);

	if (node != NULL)
		iconfig_node_set_str(node, item, NULL);

	read_statusbar_config();
	cmd_params_free(free_arg);
}

/* SYNTAX: STATUSBAR INFO <statusbar> */
static void cmd_statusbar_info(const char *data)
{
	void *free_arg;
	char *name;
	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_STRIP_TRAILING_WS, &name))
		return;

	if (*name == '\0') {
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
	}

	/* print statusbar info */
	cmd_statusbar_print_info(name);
	cmd_params_free(free_arg);
	return;
}

static void cmd_statusbar(const char *data)
{
	char *arg1, *arg2, *params, *oldcmd;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 3 | PARAM_FLAG_GETREST | PARAM_FLAG_STRIP_TRAILING_WS,
	                    &arg1, &arg2, &params))
		return;

	/* backward compatibility layer */
	oldcmd = NULL;
	if (*arg1 == '\0') {
		oldcmd = g_strdup("list");
	} else if (g_ascii_strcasecmp(arg2, "enable") == 0) {
		oldcmd = g_strdup_printf("add -nodisable %s %s", arg1, params);
	} else if (g_ascii_strcasecmp(arg2, "disable") == 0) {
		oldcmd = g_strdup_printf("add -disable %s %s", arg1, params);
	} else if (g_ascii_strcasecmp(arg2, "reset") == 0) {
		oldcmd = g_strdup_printf("reset %s", arg1);
	} else if (g_ascii_strcasecmp(arg2, "type") == 0) {
		oldcmd = g_strdup_printf("add -type %s %s", params, arg1);
	} else if (g_ascii_strcasecmp(arg2, "placement") == 0) {
		oldcmd = g_strdup_printf("add -placement %s %s", params, arg1);
	} else if (g_ascii_strcasecmp(arg2, "position") == 0) {
		oldcmd = g_strdup_printf("add -position %s %s", params, arg1);
	} else if (g_ascii_strcasecmp(arg2, "visible") == 0) {
		oldcmd = g_strdup_printf("add -visible %s %s", params, arg1);
	} else if (g_ascii_strcasecmp(arg2, "add") == 0) {
		oldcmd = g_strdup_printf("additem %s %s", params, arg1);
	} else if (g_ascii_strcasecmp(arg2, "remove") == 0) {
		oldcmd = g_strdup_printf("removeitem %s %s", params, arg1);
	} else if (*arg2 == '\0') {
		oldcmd = g_strdup_printf("statusbar %s", arg1);
		if (command_find(oldcmd) == NULL) {
			g_free(oldcmd);
			oldcmd = g_strdup_printf("info %s", arg1);
		} else {
			g_free(oldcmd);
			oldcmd = NULL;
		}
	}

	cmd_params_free(free_arg);
	if (oldcmd) {
		command_runsub("statusbar", oldcmd, NULL, NULL);
		g_free(oldcmd);
	} else {
		command_runsub("statusbar", data, NULL, NULL);
	}

	return;
}

void statusbar_config_init(void)
{
        read_statusbar_config();
	signal_add_last("setup reread", (SIGNAL_FUNC) read_statusbar_config);
	signal_add("theme changed", (SIGNAL_FUNC) read_statusbar_config);

	command_bind("statusbar", NULL, (SIGNAL_FUNC) cmd_statusbar);
	command_bind("statusbar list", NULL, (SIGNAL_FUNC) cmd_statusbar_list);
	command_bind_data("statusbar add", NULL, (SIGNAL_FUNC) cmd_statusbar_add_modify, GINT_TO_POINTER(TRUE));
	command_bind_data("statusbar modify", NULL, (SIGNAL_FUNC) cmd_statusbar_add_modify, GINT_TO_POINTER(FALSE));
	command_bind("statusbar reset", NULL, (SIGNAL_FUNC) cmd_statusbar_reset);
	command_bind("statusbar info", NULL, (SIGNAL_FUNC) cmd_statusbar_info);
	command_bind_data("statusbar additem", NULL, (SIGNAL_FUNC) cmd_statusbar_additem_modifyitem, GINT_TO_POINTER(TRUE));
	command_bind_data("statusbar modifyitem", NULL, (SIGNAL_FUNC) cmd_statusbar_additem_modifyitem, GINT_TO_POINTER(FALSE));
	command_bind("statusbar removeitem", NULL, (SIGNAL_FUNC) cmd_statusbar_removeitem);

	command_set_options("statusbar additem", "+before +after +priority +alignment");
	command_set_options("statusbar modifyitem", "+before +after +priority +alignment");
	command_set_options("statusbar add",
	                    "disable nodisable +type +placement +position +visible");
	command_set_options("statusbar modify",
	                    "disable nodisable +type +placement +position +visible");
}

void statusbar_config_deinit(void)
{
	signal_remove("setup reread", (SIGNAL_FUNC) read_statusbar_config);
	signal_remove("theme changed", (SIGNAL_FUNC) read_statusbar_config);

	command_unbind("statusbar", (SIGNAL_FUNC) cmd_statusbar);
	command_unbind("statusbar list", (SIGNAL_FUNC) cmd_statusbar_list);
	command_unbind_full("statusbar add", (SIGNAL_FUNC) cmd_statusbar_add_modify, GINT_TO_POINTER(TRUE));
	command_unbind_full("statusbar modify", (SIGNAL_FUNC) cmd_statusbar_add_modify, GINT_TO_POINTER(FALSE));
	command_unbind("statusbar reset", (SIGNAL_FUNC) cmd_statusbar_reset);
	command_unbind("statusbar info", (SIGNAL_FUNC) cmd_statusbar_info);
	command_unbind_full("statusbar additem", (SIGNAL_FUNC) cmd_statusbar_additem_modifyitem, GINT_TO_POINTER(TRUE));
	command_unbind_full("statusbar modifyitem", (SIGNAL_FUNC) cmd_statusbar_additem_modifyitem, GINT_TO_POINTER(FALSE));
	command_unbind("statusbar removeitem", (SIGNAL_FUNC) cmd_statusbar_removeitem);
}
