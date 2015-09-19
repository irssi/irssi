/*
 set.c : irssi configuration - change settings in memory

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

static void config_rec_increase_modifycounter(CONFIG_REC *rec)
{
	g_return_if_fail(rec != NULL);

	/* handle CONFIG_RECs which are includes of other configs */
	if (rec->root_rec)
		rec->root_rec->modifycounter++;
}

static void cache_remove(CONFIG_REC *rec, CONFIG_NODE *node)
{
	char *path;

	path = g_hash_table_lookup(rec->cache_nodes, node);
	if (path != NULL) {
		g_hash_table_remove(rec->cache, path);
		g_hash_table_remove(rec->cache_nodes, node);
                g_free(path);
	}
}

void config_node_remove(CONFIG_REC *rec, CONFIG_NODE *parent, CONFIG_NODE *node)
{
	g_return_if_fail(node != NULL);

	if (parent == NULL)
                parent = rec->mainnode;

	config_rec_increase_modifycounter(rec);
	cache_remove(rec, node);
	parent->value = g_slist_remove(parent->value, node);

	switch (node->type) {
	case NODE_TYPE_KEY:
	case NODE_TYPE_VALUE:
	case NODE_TYPE_COMMENT:
		g_free_not_null(node->value);
		break;
	case NODE_TYPE_INCLUDE: {
		CONFIG_INCLUDE *inc = node->value;
		if (inc) {
			g_hash_table_remove(inc->rec->root_rec->includes, inc->original_path);
			config_close(inc->rec);
			g_free_not_null(inc->original_path);
			g_free(inc);
		}
		break;
	}
	case NODE_TYPE_BLOCK:
	case NODE_TYPE_LIST:
		while (node->value != NULL)
			config_node_remove(rec, node, ((GSList *) node->value)->data);
		break;
	}
	g_free_not_null(node->key);
        g_free(node);
}

void config_node_list_remove(CONFIG_REC *rec, CONFIG_NODE *node, int index)
{
	CONFIG_NODE *child;

	g_return_if_fail(node != NULL);
	g_return_if_fail(is_node_list(node));

	child = config_node_nth(node, index);
	if (child != NULL) config_node_remove(rec, node, child);
}

void config_node_clear(CONFIG_REC *rec, CONFIG_NODE *node)
{
	g_return_if_fail(node != NULL);
	g_return_if_fail(is_node_list(node));

	while (node->value != NULL)
                config_node_remove(rec, node, ((GSList *) node->value)->data);
}

void config_nodes_remove_all(CONFIG_REC *rec)
{
	g_return_if_fail(rec != NULL);

	while (rec->mainnode->value != NULL)
		config_node_remove(rec, rec->mainnode, ((GSList *) rec->mainnode->value)->data);
}

void config_node_set_include(CONFIG_REC *rec, CONFIG_NODE *parent, const char *fname)
{
	CONFIG_NODE *node;
	CONFIG_INCLUDE *inc;
	CONFIG_REC *root_rec;
	char *full_path = NULL;

	g_return_if_fail(rec != NULL);
	g_return_if_fail(parent != NULL);

	if (!fname || !*fname) {
		config_error(rec, "Included filename is empty.\n");
		return;
	}

	/* if the parent rec has no root_rec, it is the root */
	root_rec = rec->root_rec ? rec->root_rec : rec;
	if (!root_rec->includes) {
		root_rec->includes = g_hash_table_new_full(g_str_hash, g_str_equal,
		                                           g_free, NULL);
		if (!root_rec->includes)
			return;
	}

	if (g_hash_table_contains(root_rec->includes, fname)) {
		config_error(rec, "'%s' has already been included.\n", fname);
		return;
	}

	if (!g_path_is_absolute(fname)) {
		gchar *dirname = g_path_get_dirname(rec->fname);
		if (!dirname) {
			config_error(rec, "g_path_get_dirname failed.\n");
			return;
		}
		full_path = g_build_filename(dirname, fname, NULL);
		g_free(dirname);
	}

	node = g_new0(CONFIG_NODE, 1);
	if (!node) {
		return;
	}
	node->type = NODE_TYPE_INCLUDE;

	inc = g_new0(CONFIG_INCLUDE, 1);
	if (!inc) {
		config_node_remove(rec, parent, node);
		return;
	}
	node->value = inc;
	inc->original_path = g_strdup(fname);

	inc->rec = config_open(full_path ? full_path : fname, 0660);
	if (!inc->rec) {
		config_error(rec, "Unable to open '%s': %s.\n", fname,
		             strerror(errno));
		config_node_remove(rec, parent, node);
		return;
	}
	g_free_not_null(full_path);
	inc->rec->root_rec = root_rec;
	g_hash_table_add(root_rec->includes, g_strdup(fname));

	if (config_parse(inc->rec) != 0) {
		config_node_remove(rec, parent, node);
		return;
	}

	parent->value = g_slist_append(parent->value, node);
	config_rec_increase_modifycounter(rec);
}

void config_node_set_str(CONFIG_REC *rec, CONFIG_NODE *parent, const char *key, const char *value)
{
	CONFIG_NODE *node;
	int no_key;

	g_return_if_fail(rec != NULL);
	g_return_if_fail(parent != NULL);

	no_key = key == NULL;
	node = no_key ? NULL : config_node_find(parent, key);

	if (value == NULL) {
                /* remove the key */
		if (node != NULL) config_node_remove(rec, parent, node);
		return;
	}

	if (node != NULL && !has_node_value(node)) {
		g_critical("Expected scalar node at `..%s/%s' was of complex type. Corrupt config?",
				   parent->key, key);
		config_node_remove(rec, parent, node);
		node = NULL;
	}
	if (node != NULL) {
		if (g_strcmp0(node->value, value) == 0)
			return;
                g_free(node->value);
	} else {
		node = g_new0(CONFIG_NODE, 1);
		parent->value = g_slist_append(parent->value, node);

		node->type = no_key ? NODE_TYPE_VALUE : NODE_TYPE_KEY;
		node->key = no_key ? NULL : g_strdup(key);
	}

	node->value = g_strdup(value);
	config_rec_increase_modifycounter(rec);
}

void config_node_set_int(CONFIG_REC *rec, CONFIG_NODE *parent, const char *key, int value)
{
	char str[MAX_INT_STRLEN];

	g_snprintf(str, sizeof(str), "%d", value);
	config_node_set_str(rec, parent, key, str);
}

void config_node_set_bool(CONFIG_REC *rec, CONFIG_NODE *parent, const char *key, int value)
{
	config_node_set_str(rec, parent, key, value ? "yes" : "no");
}

int config_set_str(CONFIG_REC *rec, const char *section, const char *key, const char *value)
{
	CONFIG_NODE *parent;

	g_return_val_if_fail(rec != NULL, -1);

	parent = config_node_traverse(rec, section, TRUE);
	if (parent == NULL) return -1;

	config_node_set_str(rec, parent, key, value);
	return 0;
}

int config_set_int(CONFIG_REC *rec, const char *section, const char *key, int value)
{
	char str[MAX_INT_STRLEN];

	g_snprintf(str, sizeof(str), "%d", value);
	return config_set_str(rec, section, key, str);
}

int config_set_bool(CONFIG_REC *rec, const char *section, const char *key, int value)
{
	return config_set_str(rec, section, key, value ? "yes" : "no");
}

void config_node_add_list(CONFIG_REC *rec, CONFIG_NODE *node, char **array)
{
	char **tmp;

	for (tmp = array; *tmp != NULL; tmp++)
                config_node_set_str(rec, node, NULL, *tmp);
}
