/*
 keyboard.c : irssi

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
#include "signals.h"
#include "lib-config/iconfig.h"
#include "settings.h"

#include "keyboard.h"
#include "windows.h"

GSList *keyinfos;
static GHashTable *keys;

KEYINFO_REC *key_info_find(gchar *id)
{
    GSList *tmp;

    for (tmp = keyinfos; tmp != NULL; tmp = tmp->next)
    {
	KEYINFO_REC *rec = tmp->data;

	if (g_strcasecmp(rec->id, id) == 0)
	    return rec;
    }

    return NULL;
}

/* Bind a key for function */
void key_bind(gchar *id, gchar *data, gchar *description, gchar *key_default, SIGNAL_FUNC func)
{
    KEYINFO_REC *info;
    KEY_REC *rec;

    g_return_if_fail(id != NULL);
    g_return_if_fail(func != NULL);

    /* create key info record */
    info = key_info_find(id);
    if (info == NULL)
    {
	g_return_if_fail(description != NULL);
	info = g_new0(KEYINFO_REC, 1);
	info->id = g_strdup(id);
	info->description = g_strdup(description);
	keyinfos = g_slist_append(keyinfos, info);

	/* add the signal */
	id = g_strconcat("key ", id, NULL);
	signal_add(id, func);
	g_free(id);

	signal_emit("keyinfo created", 1, info);
    }

    if (key_default == NULL || *key_default == '\0')
    {
	/* just create a possible key command, don't bind it to any key yet */
	return;
    }

    /* create/replace key record */
    rec = g_hash_table_lookup(keys, key_default);
    if (rec != NULL)
    {
	if (rec->data != NULL)
	    g_free(rec->data);
    }
    else
    {
	rec = g_new0(KEY_REC, 1);
	info->keys = g_slist_append(info->keys, rec);
	rec->key = g_strdup(key_default);
	g_hash_table_insert(keys, rec->key, rec);
    }
    rec->info = info;
    rec->data = data == NULL ? NULL : g_strdup(data);
}

static void keyinfo_remove(KEYINFO_REC *info)
{
    GSList *tmp;

    g_return_if_fail(info != NULL);

    keyinfos = g_slist_remove(keyinfos, info);
    signal_emit("keyinfo destroyed", 1, info);

    /* destroy all keys */
    for (tmp = info->keys; tmp != NULL; tmp = tmp->next)
    {
	KEY_REC *rec = tmp->data;

	g_hash_table_remove(keys, rec->key);
        if (rec->data != NULL) g_free(rec->data);
        g_free(rec->key);
        g_free(rec);
    }

    /* destroy key info */
    g_slist_free(info->keys);
    g_free(info->description);
    g_free(info->id);
    g_free(info);
}

/* Unbind key */
void key_unbind(gchar *id, SIGNAL_FUNC func)
{
    KEYINFO_REC *info;

    g_return_if_fail(id != NULL);
    g_return_if_fail(func != NULL);

    /* remove keys */
    info = key_info_find(id);
    if (info != NULL)
	keyinfo_remove(info);

    /* remove signal */
    id = g_strconcat("key ", id, NULL);
    signal_remove(id, func);
    g_free(id);
}

/* Configure new key */
void key_configure_add(gchar *id, gchar *data, gchar *key)
{
    KEYINFO_REC *info;
    KEY_REC *rec;

    g_return_if_fail(id != NULL);
    g_return_if_fail(key != NULL && *key != '\0');

    info = key_info_find(id);
    if (info == NULL)
	return;

    rec = g_new0(KEY_REC, 1);
    info->keys = g_slist_append(info->keys, rec);

    rec->info = info;
    rec->data = data == NULL ? NULL : g_strdup(data);
    rec->key = g_strdup(key);
    g_hash_table_insert(keys, rec->key, rec);
}

/* Remove key */
void key_configure_remove(gchar *key)
{
    KEY_REC *rec;

    g_return_if_fail(key != NULL);

    rec = g_hash_table_lookup(keys, key);
    if (rec == NULL) return;

    rec->info->keys = g_slist_remove(rec->info->keys, rec);
    g_hash_table_remove(keys, key);

    if (rec->data != NULL) g_free(rec->data);
    g_free(rec->key);
    g_free(rec);
}

gboolean key_pressed(gchar *key, gpointer data)
{
    KEY_REC *rec;
    gboolean ret;
    gchar *str;

    g_return_val_if_fail(key != NULL, FALSE);

    rec = g_hash_table_lookup(keys, key);
    if (rec == NULL) return FALSE;

    str = g_strconcat("key ", rec->info->id, NULL);
    ret = signal_emit(str, 3, rec->data, data, rec->info);
    g_free(str);

    return ret;
}

void keyboard_save(void)
{
	CONFIG_NODE *keyboard, *node, *listnode;
	GSList *tmp, *tmp2;

	/* remove old keyboard settings */
	iconfig_node_set_str(NULL, "(keyboard", NULL);
	keyboard = iconfig_node_traverse("(keyboard", TRUE);

	for (tmp = keyinfos; tmp != NULL; tmp = tmp->next) {
		KEYINFO_REC *info = tmp->data;

                node = config_node_section(keyboard, info->id, TRUE);
		for (tmp2 = info->keys; tmp2 != NULL; tmp2 = tmp2->next) {
			KEY_REC *key = tmp2->data;

                        listnode = config_node_section(node, NULL, NODE_TYPE_BLOCK);
			if (key->data != NULL)
				iconfig_node_set_str(listnode, "data", key->data);
			iconfig_node_set_str(listnode, "key", key->key);
		}
	}
}

static void sig_command(gchar *data)
{
	signal_emit("send command", 3, data, active_win->active_server, active_win->active);
}

void read_keyinfo(KEYINFO_REC *info, CONFIG_NODE *node)
{
	GSList *tmp;
	char *data, *key;

	g_return_if_fail(info != NULL);
	g_return_if_fail(node != NULL);
	g_return_if_fail(is_node_list(node));

	/* remove all old keys */
	while (info->keys != NULL)
		key_configure_remove(((KEY_REC *) info->keys->data)->key);

	/* add the new keys */
	for (tmp = node->value; tmp != NULL; tmp = tmp->next) {
		node = tmp->data;

		data = config_node_get_str(node->value, "data", NULL);
		key = config_node_get_str(node->value, "key", NULL);

		if (key != NULL) key_configure_add(info->id, data, key);
	}
}

static void read_keyboard_config(void)
{
	KEYINFO_REC *info;
	CONFIG_NODE *node;
	GSList *tmp;

	node = iconfig_node_traverse("keyboard", FALSE);
	if (node == NULL) return;

	for (tmp = node->value; tmp != NULL; tmp = tmp->next) {
		node = tmp->data;

		if (node->key == NULL || node->value == NULL)
			continue;

		info = key_info_find(node->key);
		if (info != NULL) read_keyinfo(info, node->value);
	}
}

void keyboard_init(void)
{
	keys = g_hash_table_new((GHashFunc) g_str_hash, (GCompareFunc) g_str_equal);
	keyinfos = NULL;

	key_bind("command", NULL, "Run any IRC command", NULL, (SIGNAL_FUNC) sig_command);

	read_keyboard_config();
        signal_add("setup reread", (SIGNAL_FUNC) read_keyboard_config);
}

void keyboard_deinit(void)
{
	while (keyinfos != NULL)
		keyinfo_remove(keyinfos->data);
	g_hash_table_destroy(keys);

        signal_remove("setup reread", (SIGNAL_FUNC) read_keyboard_config);
}
