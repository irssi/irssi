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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

/* find the section from node - if not found create it unless new_type is -1.
   you can also specify in new_type if it's NODE_TYPE_LIST or NODE_TYPE_BLOCK */
CONFIG_NODE *config_node_section(CONFIG_NODE *parent, const char *key, int new_type)
{
	CONFIG_NODE *node;

	g_return_val_if_fail(parent != NULL, NULL);
	g_return_val_if_fail(is_node_list(parent), NULL);

	node = key == NULL ? NULL : config_node_find(parent, key);
	if (node != NULL) {
		g_return_val_if_fail(new_type == -1 || new_type == node->type, NULL);
                return node;
	}

	if (new_type == -1)
		return NULL;

	node = g_new0(CONFIG_NODE, 1);
	parent->value = g_slist_append(parent->value, node);

	node->type = new_type;
	node->key = key == NULL ? NULL : g_strdup(key);

	return node;
}

/* find the section with the whole path.
   create the path if necessary `create' is TRUE. */
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

/* Return value of key `value_key' from list item where `key' is `value' */
const char *config_list_find(CONFIG_REC *rec, const char *section, const char *key, const char *value, const char *value_key)
{
	CONFIG_NODE *node;

	node = config_list_find_node(rec, section, key, value, value_key);
	return node != NULL && node->type == NODE_TYPE_KEY ?
		node->value : NULL;
}

/* Like config_list_find(), but return node instead of it's value */
CONFIG_NODE *config_list_find_node(CONFIG_REC *rec, const char *section, const char *key, const char *value, const char *value_key)
{
	CONFIG_NODE *node, *keynode;
	GSList *tmp;

	g_return_val_if_fail(rec != NULL, NULL);
	g_return_val_if_fail(key != NULL, NULL);
	g_return_val_if_fail(value_key != NULL, NULL);

	node = config_node_traverse(rec, section, FALSE);
	if (node == NULL || !is_node_list(node)) return NULL;

	for (tmp = node->value; tmp != NULL; tmp = tmp->next) {
		node = tmp->data;

		if (node->type != NODE_TYPE_BLOCK)
			continue;

		/* key matches value? */
		keynode = config_node_find(node, key);
		if (keynode == NULL || keynode->type != NODE_TYPE_KEY ||
		    g_strcasecmp(keynode->value, value) != 0) continue;

		return config_node_find(node, value_key);
	}

	return NULL;
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

/* Get the value of keys `key' and `key_value' and put them to
   `ret_key' and `ret_value'. Returns -1 if not found. */
int config_node_get_keyvalue(CONFIG_NODE *node, const char *key, const char *value_key, char **ret_key, char **ret_value)
{
	CONFIG_NODE *keynode, *valuenode;
	GSList *tmp;

	g_return_val_if_fail(node != NULL, -1);
	g_return_val_if_fail(key != NULL, -1);
	g_return_val_if_fail(value_key != NULL, -1);
	g_return_val_if_fail(ret_key != NULL, -1);
	g_return_val_if_fail(ret_value != NULL, -1);

	for (tmp = node->value; tmp != NULL; tmp = tmp->next) {
		node = tmp->data;

		if (node->type != NODE_TYPE_BLOCK)
			continue;

		keynode = config_node_find(node, key);
		if (keynode == NULL || keynode->type != NODE_TYPE_KEY)
			continue;

		valuenode = config_node_find(node, value_key);

		*ret_key = keynode->key;
		*ret_value = valuenode != NULL && valuenode->type == NODE_TYPE_KEY ?
			valuenode->value : NULL;
		return 0;
	}

	return -1;
}

/* Return all values from from the list `node' in a g_strsplit() array */
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
			g_string_sprintfa(values, "%s ", (char *) node->value);
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

/* Returns n'th node from list. */
CONFIG_NODE *config_node_index(CONFIG_NODE *node, int index)
{
	GSList *tmp;

	g_return_val_if_fail(node != NULL, NULL);
	g_return_val_if_fail(is_node_list(node), NULL);

	for (tmp = node->value; tmp != NULL; tmp = tmp->next, index--) {
		if (index == 0)
                        return tmp->data;
	}

	return NULL;
}

/* Returns the first non-comment node in list */
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

/* Returns the next non-comment node in list */
GSList *config_node_next(GSList *list)
{
	list = list->next;
        return config_node_first(list);
}
