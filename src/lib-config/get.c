/*
 get.c : irssi configuration - get settings from memory

    Copyright (C) 1999 Timo Sirainen

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

CONFIG_NODE *config_node_find(CONFIG_NODE *node, const char *key)
{
	GSList *tmp;

	g_return_val_if_fail(node != NULL, NULL);
	g_return_val_if_fail(key != NULL, NULL);
	g_return_val_if_fail(is_node_list(node), NULL);

	for (tmp = node->value; tmp != NULL; tmp = tmp->next) {
		CONFIG_NODE *node = tmp->data;

		if (node->key != NULL && g_strcasecmp(node->key, key) == 0)
			return node;
	}

	return NULL;
}

CONFIG_NODE *config_node_section(CONFIG_NODE *parent, const char *key, int new_type)
{
        return config_node_section_index(parent, key, -1, new_type);
}

CONFIG_NODE *config_node_section_index(CONFIG_NODE *parent, const char *key,
				       int index, int new_type)
{
	CONFIG_NODE *node;
        int nindex;

	g_return_val_if_fail(parent != NULL, NULL);
	g_return_val_if_fail(is_node_list(parent), NULL);

	node = key == NULL ? NULL : config_node_find(parent, key);
	if (node != NULL) {
		g_return_val_if_fail(new_type == -1 || new_type == node->type, NULL);
		nindex = g_slist_index(parent->value, node);
		if (index >= 0 && nindex != index &&
		    nindex <= g_slist_length(parent->value)) {
			/* move it to wanted position */
			parent->value = g_slist_remove(parent->value, node);
			parent->value = g_slist_insert(parent->value, node, index);
		}
		return node;
	}

	if (new_type == -1)
		return NULL;

	node = g_new0(CONFIG_NODE, 1);
	parent->value = index < 0 ? g_slist_append(parent->value, node) :
		g_slist_insert(parent->value, node, index);

	node->type = new_type;
	node->key = key == NULL ? NULL : g_strdup(key);

	return node;
}

CONFIG_NODE *config_node_traverse(CONFIG_REC *rec, const char *section, int create)
{
	CONFIG_NODE *node;
	char **list, **tmp, *str;
	int is_list, new_type;

	g_return_val_if_fail(rec != NULL, NULL);

	if (section == NULL || *section == '\0')
		return rec->mainnode;

	/* check if it already exists in cache */
	node = g_hash_table_lookup(rec->cache, section);
	if (node != NULL) return node;

        new_type = -1;

	node = rec->mainnode;
	list = g_strsplit(section, "/", -1);
	for (tmp = list; *tmp != NULL; tmp++) {
		is_list = **tmp == '(';
		if (create) new_type = is_list ? NODE_TYPE_LIST : NODE_TYPE_BLOCK;

		node = config_node_section(node, *tmp + is_list, new_type);
		if (node == NULL) {
			g_strfreev(list);
			return NULL;
		}
	}
	g_strfreev(list);

	/* save to cache */
        str = g_strdup(section);
	g_hash_table_insert(rec->cache, str, node);
	g_hash_table_insert(rec->cache_nodes, node, str);
	return node;
}

char *config_get_str(CONFIG_REC *rec, const char *section, const char *key, const char *def)
{
	CONFIG_NODE *parent, *node;
	char *path;

	g_return_val_if_fail(rec != NULL, (char *) def);
	g_return_val_if_fail(key != NULL, (char *) def);

	/* check if it already exists in cache */
	path = g_strconcat(section == NULL ? "" : section, "/", key, NULL);
	node = g_hash_table_lookup(rec->cache, path);

	if (node != NULL)
		g_free(path);
	else {
		parent = config_node_traverse(rec, section, FALSE);
		node = parent == NULL ? NULL :
			config_node_find(parent, key);

		/* save to cache */
		if (node == NULL)
			g_free(path);
		else {
			g_hash_table_insert(rec->cache, path, node);
			g_hash_table_insert(rec->cache_nodes, node, path);
		}
	}

	return (node == NULL || !has_node_value(node)) ? (char *) def : node->value;
}

int config_get_int(CONFIG_REC *rec, const char *section, const char *key, int def)
{
	char *str;

	str = config_get_str(rec, section, key, NULL);
	if (str == NULL) return def;

        return atoi(str);
}

int config_get_bool(CONFIG_REC *rec, const char *section, const char *key, int def)
{
	char *str;

	str = config_get_str(rec, section, key, NULL);
	if (str == NULL) return def;

        return i_toupper(*str) == 'T' || i_toupper(*str) == 'Y';
}

char *config_node_get_str(CONFIG_NODE *parent, const char *key, const char *def)
{
	CONFIG_NODE *node;

        if (parent == NULL) return (char *) def;

	node = config_node_find(parent, key);
	return (char *) ((node != NULL && has_node_value(node)) ?
			 node->value : def);
}

int config_node_get_int(CONFIG_NODE *parent, const char *key, int def)
{
	char *str;

	str = config_node_get_str(parent, key, NULL);
	if (str == NULL) return def;

	return atoi(str);
}

int config_node_get_bool(CONFIG_NODE *parent, const char *key, int def)
{
	char *str;

	str = config_node_get_str(parent, key, NULL);
	if (str == NULL) return def;

	return i_toupper(*str) == 'T' || i_toupper(*str) == 'Y' ||
		(i_toupper(*str) == 'O' && i_toupper(str[1]) == 'N');
}

char **config_node_get_list(CONFIG_NODE *node)
{
	GString *values;
	GSList *tmp;
	char **ret;

	g_return_val_if_fail(node != NULL, NULL);
	g_return_val_if_fail(is_node_list(node), NULL);

	/* put values to string */
	values = g_string_new(NULL);
	for (tmp = node->value; tmp != NULL; tmp = tmp->next) {
		node = tmp->data;

		if (node->type == NODE_TYPE_VALUE)
			g_string_append_printf(values, "%s ", (char *) node->value);
	}

	/* split the values to **str array */
	if (values->len == 0)
		ret = NULL;
	else {
		g_string_truncate(values, values->len-1);
                ret = g_strsplit(values->str, " ", -1);
	}

	g_string_free(values, TRUE);
        return ret;
}

CONFIG_NODE *config_node_nth(CONFIG_NODE *node, int index)
{
	GSList *tmp;

	g_return_val_if_fail(node != NULL, NULL);
	g_return_val_if_fail(is_node_list(node), NULL);

	for (tmp = node->value; tmp != NULL; tmp = tmp->next) {
		CONFIG_NODE *node = tmp->data;

		if (node->type != NODE_TYPE_COMMENT) {
			if (index == 0)
				return node;
			index--;
		}
	}

	return NULL;
}

int config_node_index(CONFIG_NODE *parent, const char *key)
{
	CONFIG_NODE *node;
	GSList *tmp;
	int index;

	g_return_val_if_fail(parent != NULL, -1);
	g_return_val_if_fail(key != NULL, -1);

	node = config_node_find(parent, key);
	if (node == NULL)
		return -1;

	index = 0;
	for (tmp = parent->value; tmp != NULL; tmp = tmp->next) {
		CONFIG_NODE *tmpnode = tmp->data;

		if (tmpnode == node)
			return index;

		if (tmpnode->type != NODE_TYPE_COMMENT)
			index++;
	}

        return -1;
}

GSList *config_node_first(GSList *list)
{
	while (list != NULL) {
		CONFIG_NODE *node = list->data;

		if (node->type != NODE_TYPE_COMMENT)
                        break;
		list = list->next;
	}
	return list;
}

GSList *config_node_next(GSList *list)
{
	list = list->next;
        return config_node_first(list);
}
