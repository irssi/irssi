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
#include "module-formats.h"
#include "signals.h"
#include "commands.h"
#include "levels.h"
#include "misc.h"
#include "lib-config/iconfig.h"
#include "settings.h"

#include "keyboard.h"
#include "fe-windows.h"
#include "printtext.h"

GSList *keyinfos;
static GHashTable *keys;

static void keyconfig_save(const char *id, const char *key, const char *data)
{
	CONFIG_NODE *node;

	g_return_if_fail(id != NULL);
	g_return_if_fail(key != NULL);

	/* remove old keyboard settings */
	node = iconfig_node_traverse("keyboard", TRUE);
	node = config_node_section(node, id, NODE_TYPE_BLOCK);

	iconfig_node_set_str(node, key, data == NULL ? "" : data);
}

static void keyconfig_clear(const char *id, const char *key)
{
	CONFIG_NODE *node;

	g_return_if_fail(id != NULL);

	/* remove old keyboard settings */
	node = iconfig_node_traverse("keyboard", TRUE);
	if (key == NULL)
		iconfig_node_set_str(node, id, NULL);
	else {
		node = config_node_section(node, id, -1);
		if (node != NULL) iconfig_node_set_str(node, key, NULL);
	}
}

KEYINFO_REC *key_info_find(const char *id)
{
	GSList *tmp;

	for (tmp = keyinfos; tmp != NULL; tmp = tmp->next) {
		KEYINFO_REC *rec = tmp->data;

		if (g_strcasecmp(rec->id, id) == 0)
			return rec;
	}

	return NULL;
}

/* Bind a key for function */
void key_bind(const char *id, const char *description,
	      const char *key_default, const char *data, SIGNAL_FUNC func)
{
	KEYINFO_REC *info;
	char *key;

	g_return_if_fail(id != NULL);
	g_return_if_fail(func != NULL);

	/* create key info record */
	info = key_info_find(id);
	if (info == NULL) {
		if (description == NULL)
			g_warning("key_bind(%s) should have description!", id);
		info = g_new0(KEYINFO_REC, 1);
		info->id = g_strdup(id);
		info->description = g_strdup(description);
		keyinfos = g_slist_append(keyinfos, info);

		/* add the signal */
		key = g_strconcat("key ", id, NULL);
		signal_add(key, func);
		g_free(key);

		signal_emit("keyinfo created", 1, info);
	}

	if (key_default != NULL && *key_default != '\0')
		key_configure_add(id, key_default, data);
}

static void keyinfo_remove(KEYINFO_REC *info)
{
	GSList *tmp;

	g_return_if_fail(info != NULL);

	keyinfos = g_slist_remove(keyinfos, info);
	signal_emit("keyinfo destroyed", 1, info);

	/* destroy all keys */
	for (tmp = info->keys; tmp != NULL; tmp = tmp->next) {
		KEY_REC *rec = tmp->data;

		g_hash_table_remove(keys, rec->key);
		g_free_not_null(rec->data);
		g_free(rec->key);
		g_free(rec);
	}

	/* destroy key info */
	g_slist_free(info->keys);
	g_free_not_null(info->description);
	g_free(info->id);
	g_free(info);
}

/* Unbind key */
void key_unbind(const char *id, SIGNAL_FUNC func)
{
	KEYINFO_REC *info;
	char *key;

	g_return_if_fail(id != NULL);
	g_return_if_fail(func != NULL);

	/* remove keys */
	info = key_info_find(id);
	if (info != NULL)
		keyinfo_remove(info);

	/* remove signal */
	key = g_strconcat("key ", id, NULL);
	signal_remove(key, func);
	g_free(key);
}

/* Configure new key */
static void key_configure_create(const char *id, const char *key,
				 const char *data)
{
	KEYINFO_REC *info;
	KEY_REC *rec;

	g_return_if_fail(id != NULL);
	g_return_if_fail(key != NULL && *key != '\0');

	info = key_info_find(id);
	if (info == NULL)
		return;

	key_configure_remove(key);

	rec = g_new0(KEY_REC, 1);
	rec->key = g_strdup(key);
	rec->info = info;
	rec->data = g_strdup(data);
	info->keys = g_slist_append(info->keys, rec);
	g_hash_table_insert(keys, rec->key, rec);
}

/* Configure new key */
void key_configure_add(const char *id, const char *key, const char *data)
{
	g_return_if_fail(id != NULL);
	g_return_if_fail(key != NULL && *key != '\0');

	key_configure_create(id, key, data);
	keyconfig_save(id, key, data);
}

static void key_configure_destroy(KEY_REC *rec)
{
	g_return_if_fail(rec != NULL);

	rec->info->keys = g_slist_remove(rec->info->keys, rec);
	g_hash_table_remove(keys, rec->key);

	g_free_not_null(rec->data);
	g_free(rec->key);
	g_free(rec);
}

/* Remove key */
void key_configure_remove(const char *key)
{
	KEY_REC *rec;

	g_return_if_fail(key != NULL);

	rec = g_hash_table_lookup(keys, key);
	if (rec == NULL) return;

        keyconfig_clear(rec->info->id, key);
	key_configure_destroy(rec);
}

int key_pressed(const char *key, void *data)
{
	KEY_REC *rec;
	char *str;
	int ret;

	g_return_val_if_fail(key != NULL, FALSE);

	rec = g_hash_table_lookup(keys, key);
	if (rec == NULL) return FALSE;

	str = g_strconcat("key ", rec->info->id, NULL);
	ret = signal_emit(str, 3, rec->data, data, rec->info);
	g_free(str);

	return ret;
}

static void sig_command(const char *data)
{
	const char *cmdchars;
	char *str;

	cmdchars = settings_get_str("cmdchars");
	str = strchr(cmdchars, *data) != NULL ? g_strdup(data) :
		g_strdup_printf("%c%s", *cmdchars, data);

	signal_emit("send command", 3, str, active_win->active_server, active_win->active);

	g_free(str);
}

void read_keyinfo(KEYINFO_REC *info, CONFIG_NODE *node)
{
	GSList *tmp;

	g_return_if_fail(info != NULL);
	g_return_if_fail(node != NULL);
	g_return_if_fail(is_node_list(node));

	/* remove all old keys */
	while (info->keys != NULL)
		key_configure_destroy(info->keys->data);

	/* add the new keys */
	for (tmp = node->value; tmp != NULL; tmp = tmp->next) {
		node = tmp->data;

		if (node->key != NULL)
			key_configure_create(info->id, node->key, node->value);
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
		if (info != NULL) read_keyinfo(info, node);
	}
}

static void cmd_show_keys(const char *searchkey, int full)
{
	GSList *info, *key;
        int len;

	len = searchkey == NULL ? 0 : strlen(searchkey);
	for (info = keyinfos; info != NULL; info = info->next) {
		KEYINFO_REC *rec = info->data;

		for (key = rec->keys; key != NULL; key = key->next) {
			KEY_REC *rec = key->data;

			if ((len == 0 || g_strncasecmp(rec->key, searchkey, len) == 0) &&
			    (!full || rec->key[len] == '\0')) {
				printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_BIND_KEY,
					    rec->key, rec->info->id, rec->data == NULL ? "" : rec->data);
			}
		}
	}
}

/* SYNTAX: BIND [<key> [<command> [<data>]]] */
static void cmd_bind(const char *data)
{
	GHashTable *optlist;
	char *key, *id, *keydata;
	void *free_arg;
	int command_id;

	if (!cmd_get_params(data, &free_arg, 3 | PARAM_FLAG_GETREST | PARAM_FLAG_OPTIONS,
			    "bind", &optlist, &key, &id, &keydata))
		return;

	if (*key != '\0' && g_hash_table_lookup(optlist, "delete")) {
                /* delete key */
		key_configure_remove(key);
		cmd_params_free(free_arg);
		return;
	}

	if (*id == '\0') {
		/* show some/all keys */
		cmd_show_keys(key, FALSE);
		cmd_params_free(free_arg);
		return;
	}

	command_id = strchr(settings_get_str("cmdchars"), *id) != NULL;
	if (command_id) {
		/* using shortcut to command id */
		keydata = g_strconcat(id, " ", keydata, NULL);
		id = "command";
	}

	if (key_info_find(id) == NULL)
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, IRCTXT_BIND_UNKNOWN_ID, id);
	else {
		key_configure_add(id, key, keydata);
		cmd_show_keys(key, TRUE);
	}

	if (command_id) g_free(keydata);
        cmd_params_free(free_arg);
}

static GList *completion_get_keyinfos(const char *info)
{
	GList *list;
	GSList *tmp;
	int len;

	list = NULL; len = strlen(info);
	for (tmp = keyinfos; tmp != NULL; tmp = tmp->next) {
		KEYINFO_REC *rec = tmp->data;

		if (g_strncasecmp(rec->id, info, len) == 0)
                        list = g_list_append(list, g_strdup(rec->id));
	}

	return list;
}

static void sig_complete_bind(GList **list, WINDOW_REC *window,
			      const char *word, const char *line,
			      int *want_space)
{
	g_return_if_fail(list != NULL);
	g_return_if_fail(word != NULL);
	g_return_if_fail(line != NULL);

	if (*line == '\0' || strchr(line, ' ') != NULL)
		return;

	*list = completion_get_keyinfos(word);
	if (*list != NULL) signal_stop();
}

void keyboard_init(void)
{
	keys = g_hash_table_new((GHashFunc) g_istr_hash, (GCompareFunc) g_istr_equal);
	keyinfos = NULL;

	key_bind("command", "Run any IRC command", NULL, NULL, (SIGNAL_FUNC) sig_command);

	/* read the keyboard config when all key binds are known */
	signal_add("irssi init read settings", (SIGNAL_FUNC) read_keyboard_config);
	signal_add("setup reread", (SIGNAL_FUNC) read_keyboard_config);
	signal_add("complete command bind", (SIGNAL_FUNC) sig_complete_bind);

	command_bind("bind", NULL, (SIGNAL_FUNC) cmd_bind);
	command_set_options("bind", "delete");
}

void keyboard_deinit(void)
{
	while (keyinfos != NULL)
		keyinfo_remove(keyinfos->data);
	g_hash_table_destroy(keys);

	signal_remove("irssi init read settings", (SIGNAL_FUNC) read_keyboard_config);
        signal_remove("setup reread", (SIGNAL_FUNC) read_keyboard_config);
	signal_remove("complete command bind", (SIGNAL_FUNC) sig_complete_bind);
	command_unbind("bind", (SIGNAL_FUNC) cmd_bind);
}
