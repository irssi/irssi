/*
 keyboard.c : irssi

    Copyright (C) 1999-2001 Timo Sirainen

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
static GHashTable *keys, *default_keys;

/* A cache of some sort for key presses that generate a single char only.
   If the key isn't used, used_keys[key] is zero. */
static char used_keys[256];

/* contains list of all key bindings of which command is "key" -
   this can be used to check fast if some command queue exists or not.
   Format is _always_ in key1-key2-key3 format (like ^W-^N,
   not ^W^N) */
static GTree *key_states;
/* List of all key combo names */
static GSList *key_combos;
static int key_config_frozen;

struct KEYBOARD_REC {
	/* example:
	   /BIND ^[ key meta
	   /BIND meta-O key meta2
	   /BIND meta-[ key meta2

	   /BIND meta2-C key right
	   /BIND ^W-meta-right /echo ^W Meta-right key pressed

	   When ^W Meta-Right is pressed, the full char combination
	   is "^W^[^[[C".

	   We'll get there with key states:
	     ^W - key_prev_state = NULL, key_state = NULL -> ^W
	     ^[ - key_prev_state = NULL, key_state = ^W -> meta
	     ^[ - key_prev_state = ^W, key_state = meta -> meta
	     [ - key_prev_state = ^W-meta, key_state = meta -> meta2
	     C - key_prev_state = ^W-meta, key_state = meta2 -> right
	     key_prev_state = ^W-meta, key_state = right -> ^W-meta-right

	   key_state is moved to key_prev_state if there's nothing else in
	   /BINDs matching for key_state-newkey.

	   ^X^Y equals to ^X-^Y, ABC equals to A-B-C unless there's ABC
	   named key. ^ can be used with ^^ and - with -- */
	char *key_state, *key_prev_state;

        /* GUI specific data sent in "key pressed" signal */
        void *gui_data;
};

/* Creates a new "keyboard" - this is used only for keeping track of
   key combo states and sending the gui_data parameter in "key pressed"
   signal */
KEYBOARD_REC *keyboard_create(void *data)
{
	KEYBOARD_REC *rec;

	rec = g_new0(KEYBOARD_REC, 1);
	rec->gui_data = data;

	signal_emit("keyboard created", 1, rec);
        return rec;
}

/* Destroys a keyboard */
void keyboard_destroy(KEYBOARD_REC *keyboard)
{
	signal_emit("keyboard destroyed", 1, keyboard);

        g_free_not_null(keyboard->key_state);
        g_free_not_null(keyboard->key_prev_state);
        g_free(keyboard);
}

static void key_destroy(KEY_REC *rec, GHashTable *hash)
{
	g_hash_table_remove(hash, rec->key);

	g_free_not_null(rec->data);
	g_free(rec->key);
	g_free(rec);
}

static void key_default_add(const char *id, const char *key, const char *data)
{
        KEYINFO_REC *info;
	KEY_REC *rec;

	info = key_info_find(id);
	if (info == NULL)
		return;

	rec = g_hash_table_lookup(default_keys, key);
	if (rec != NULL) {
		/* key already exists, replace */
		rec->info->default_keys =
			g_slist_remove(rec->info->default_keys, rec);
		key_destroy(rec, default_keys);
	}

	rec = g_new0(KEY_REC, 1);
	rec->key = g_strdup(key);
	rec->info = info;
	rec->data = g_strdup(data);
        info->default_keys = g_slist_append(info->default_keys, rec);
	g_hash_table_insert(default_keys, rec->key, rec);
}

static CONFIG_NODE *key_config_find(const char *key)
{
	CONFIG_NODE *node;
        GSList *tmp;

	/* remove old keyboard settings */
	node = iconfig_node_traverse("(keyboard", TRUE);

	for (tmp = node->value; tmp != NULL; tmp = tmp->next) {
		node = tmp->data;

		if (strcmp(config_node_get_str(node, "key", ""), key) == 0)
                        return node;
	}

        return NULL;
}

static void keyconfig_save(const char *id, const char *key, const char *data)
{
	CONFIG_NODE *node;

	g_return_if_fail(id != NULL);
	g_return_if_fail(key != NULL);

	node = key_config_find(key);
	if (node == NULL) {
		node = iconfig_node_traverse("(keyboard", TRUE);
		node = config_node_section(node, NULL, NODE_TYPE_BLOCK);
	}

	iconfig_node_set_str(node, "key", key);
	iconfig_node_set_str(node, "id", id);
	iconfig_node_set_str(node, "data", data);
}

static void keyconfig_clear(const char *key)
{
	CONFIG_NODE *node;

	g_return_if_fail(key != NULL);

	/* remove old keyboard settings */
	node = key_config_find(key);
        if (node != NULL)
		iconfig_node_clear(node);
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

static KEY_REC *key_combo_find(const char *key)
{
	KEYINFO_REC *info;
        GSList *tmp;

	info = key_info_find("key");
	if (info == NULL)
		return NULL;

	for (tmp = info->keys; tmp != NULL; tmp = tmp->next) {
		KEY_REC *rec = tmp->data;

		if (strcmp(rec->data, key) == 0)
                        return rec;
	}

        return NULL;
}

static void key_states_scan_key(const char *key, KEY_REC *rec, GString *temp)
{
	char **keys, **tmp, *p;

	g_string_truncate(temp, 0);

	/* meta-^W^Gfoo -> meta-^W-^G-f-o-o */
	keys = g_strsplit(key, "-", -1);
	for (tmp = keys; *tmp != NULL; tmp++) {
		if (key_combo_find(*tmp)) {
                        /* key combo */
			g_string_append(temp, *tmp);
                        g_string_append_c(temp, '-');
                        continue;
		}

		if (**tmp == '\0') {
                        /* '-' */
			g_string_append(temp, "--");
                        continue;
		}

		for (p = *tmp; *p != '\0'; p++) {
			g_string_append_c(temp, *p);

			if (*p == '^') {
                                /* ctrl-code */
				if (p[1] != '\0')
					p++;
				g_string_append_c(temp, *p);
			}

			g_string_append_c(temp, '-');
		}
	}
	g_strfreev(keys);

	if (temp->len > 0) {
		g_string_truncate(temp, temp->len-1);

		if (temp->str[1] == '-' || temp->str[1] == '\0')
                        used_keys[(int) (unsigned char) temp->str[0]] = 1;
		g_tree_insert(key_states, g_strdup(temp->str), rec);
	}
}

static int key_state_destroy(char *key)
{
	g_free(key);
        return FALSE;
}

/* Rescan all the key combos and figure out which characters are supposed
   to be treated as characters and which as key combos.
   Yes, this is pretty slow function... */
static void key_states_rescan(void)
{
	GString *temp;

	memset(used_keys, 0, sizeof(used_keys));

	g_tree_traverse(key_states, (GTraverseFunc) key_state_destroy,
			G_IN_ORDER, NULL);
	g_tree_destroy(key_states);
	key_states = g_tree_new((GCompareFunc) strcmp);

        temp = g_string_new(NULL);
	g_hash_table_foreach(keys, (GHFunc) key_states_scan_key, temp);
        g_string_free(temp, TRUE);
}

void key_configure_freeze(void)
{
        key_config_frozen++;
}

void key_configure_thaw(void)
{
        g_return_if_fail(key_config_frozen > 0);

	if (--key_config_frozen == 0)
		key_states_rescan();
}

static void key_configure_destroy(KEY_REC *rec)
{
	g_return_if_fail(rec != NULL);

	rec->info->keys = g_slist_remove(rec->info->keys, rec);
	g_hash_table_remove(keys, rec->key);

	if (!key_config_frozen)
                key_states_rescan();

	g_free_not_null(rec->data);
	g_free(rec->key);
	g_free(rec);
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

	rec = g_hash_table_lookup(keys, key);
	if (rec != NULL)
		key_configure_destroy(rec);

	rec = g_new0(KEY_REC, 1);
	rec->key = g_strdup(key);
	rec->info = info;
	rec->data = g_strdup(data);
	info->keys = g_slist_append(info->keys, rec);
	g_hash_table_insert(keys, rec->key, rec);

	if (!key_config_frozen)
                key_states_rescan();
}

/* Bind a key for function */
void key_bind(const char *id, const char *description,
	      const char *key_default, const char *data, SIGNAL_FUNC func)
{
	KEYINFO_REC *info;
	char *key;

	g_return_if_fail(id != NULL);

	/* create key info record */
	info = key_info_find(id);
	if (info == NULL) {
		g_return_if_fail(func != NULL);

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

	if (key_default != NULL && *key_default != '\0') {
                key_default_add(id, key_default, data);
		key_configure_create(id, key_default, data);
	}
}

static void keyinfo_remove(KEYINFO_REC *info)
{
	g_return_if_fail(info != NULL);

	keyinfos = g_slist_remove(keyinfos, info);
	signal_emit("keyinfo destroyed", 1, info);

	/* destroy all keys */
        g_slist_foreach(info->keys, (GFunc) key_destroy, keys);
        g_slist_foreach(info->default_keys, (GFunc) key_destroy, default_keys);

	/* destroy key info */
	g_slist_free(info->keys);
	g_slist_free(info->default_keys);
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
void key_configure_add(const char *id, const char *key, const char *data)
{
	g_return_if_fail(id != NULL);
	g_return_if_fail(key != NULL && *key != '\0');

	key_configure_create(id, key, data);
	keyconfig_save(id, key, data);
}

/* Remove key */
void key_configure_remove(const char *key)
{
	KEY_REC *rec;

	g_return_if_fail(key != NULL);

	rec = g_hash_table_lookup(keys, key);
	if (rec == NULL) return;

        keyconfig_clear(key);
	key_configure_destroy(rec);
}

static int key_emit_signal(KEYBOARD_REC *keyboard, KEY_REC *key)
{
	int consumed;
        char *str;

	str = g_strconcat("key ", key->info->id, NULL);
	consumed = signal_emit(str, 3, key->data, keyboard->gui_data, key->info);
	g_free(str);

        return consumed;
}

int key_states_search(const char *combo, const char *search)
{
	while (*search != '\0') {
		if (*combo != *search)
			return *search - *combo;
                search++; combo++;
	}

	return *combo == '\0' || *combo == '-' ? 0 : -1;
}

/* Returns TRUE if key press was consumed. Control characters should be sent
   as "^@" .. "^_" instead of #0..#31 chars, #127 should be sent as ^? */
int key_pressed(KEYBOARD_REC *keyboard, const char *key)
{
	KEY_REC *rec;
	char *str;
        int consumed;

	g_return_val_if_fail(keyboard != NULL, FALSE);
	g_return_val_if_fail(key != NULL && *key != '\0', FALSE);

	if (keyboard->key_state == NULL) {
		if (key[1] == '\0' &&
		    !used_keys[(int) (unsigned char) key[0]]) {
                        /* fast check - key not used */
			return FALSE;
		}

		rec = g_tree_search(key_states,
				    (GSearchFunc) key_states_search,
				    (void *) key);
		if (rec == NULL ||
		    (g_tree_lookup(key_states, (void *) key) != NULL &&
		     strcmp(rec->info->id, "key") != 0)) {
			/* a single non-combo key was pressed */
			rec = g_hash_table_lookup(keys, key);
			if (rec == NULL)
				return FALSE;
			consumed = key_emit_signal(keyboard, rec);

			/* never consume non-control characters */
			return consumed && key[1] != '\0';
		}
	}

	if (keyboard->key_state == NULL) {
                /* first key in combo */
		rec = g_tree_lookup(key_states, (void *) key);
	} else {
		/* continuing key combination */
		str = g_strconcat(keyboard->key_state, "-", key, NULL);
		rec = g_tree_lookup(key_states, str);
		g_free(str);
	}

	if (rec != NULL && strcmp(rec->info->id, "key") == 0) {
		/* combo has a specified name, use it */
		g_free_not_null(keyboard->key_state);
		keyboard->key_state = g_strdup(rec->data);
	} else {
		/* some unnamed key - move key_state after key_prev_state
		   and replace key_state with this new key */
		if (keyboard->key_prev_state == NULL)
			keyboard->key_prev_state = keyboard->key_state;
		else {
			str = g_strconcat(keyboard->key_prev_state, "-",
					  keyboard->key_state, NULL);
			g_free(keyboard->key_prev_state);
			g_free(keyboard->key_state);
			keyboard->key_prev_state = str;
		}

		keyboard->key_state = g_strdup(key);
	}

        /* what to do with the key combo? */
	str = keyboard->key_prev_state == NULL ?
		g_strdup(keyboard->key_state) :
		g_strconcat(keyboard->key_prev_state, "-",
			    keyboard->key_state, NULL);

	rec = g_tree_lookup(key_states, str);
	if (rec != NULL) {
		if (strcmp(rec->info->id, "key") == 0)
			rec = g_tree_lookup(key_states, rec->data);

		if (rec != NULL) {
			/* full key combo */
			key_emit_signal(keyboard, rec);
			rec = NULL;
		}
	} else {
                /* check that combo is possible */
		rec = g_tree_search(key_states,
				    (GSearchFunc) key_states_search, str);
	}

	if (rec == NULL) {
		/* a) key combo finished, b) unknown key combo, abort */
		g_free_and_null(keyboard->key_prev_state);
		g_free_and_null(keyboard->key_state);
	}

	g_free(str);
        return TRUE;
}

void keyboard_entry_redirect(SIGNAL_FUNC func, const char *entry,
			     int flags, void *data)
{
	signal_emit("gui entry redirect", 4, func, entry,
		    GINT_TO_POINTER(flags), data);
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

static void sig_key(const char *data)
{
        /* we should never get here */
}

static void sig_multi(const char *data, void *gui_data)
{
        KEYINFO_REC *info;
	char **list, **tmp, *p, *str;

	list = g_strsplit(data, ";", -1);
	for (tmp = list; *tmp != NULL; tmp++) {
		p = strchr(*tmp, ' ');
		if (p != NULL) *p++ = '\0'; else p = "";

		info = key_info_find(*tmp);
		if (info != NULL) {
			str = g_strconcat("key ", info->id, NULL);
			signal_emit(str, 3, p, gui_data, info);
			g_free(str);
		}
	}
        g_strfreev(list);
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
				printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_BIND_KEY,
					    rec->key, rec->info->id, rec->data == NULL ? "" : rec->data);
			}
		}
	}
}

/* SYNTAX: BIND [-delete] [<key> [<command> [<data>]]] */
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
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, TXT_BIND_UNKNOWN_ID, id);
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

static int key_destroy_hash(const char *key, KEY_REC *rec)
{
	rec->info->keys = g_slist_remove(rec->info->keys, rec);

	g_free_not_null(rec->data);
	g_free(rec->key);
	g_free(rec);
        return TRUE;
}

static void key_copy_default(const char *key, KEY_REC *orig)
{
	KEY_REC *rec;

        rec = g_new0(KEY_REC, 1);
	rec->key = g_strdup(orig->key);
	rec->info = orig->info;
	rec->data = g_strdup(orig->data);

	rec->info->keys = g_slist_append(rec->info->keys, rec);
	g_hash_table_insert(keys, rec->key, rec);
}

static void keyboard_reset_defaults(void)
{
	g_hash_table_foreach_remove(keys, (GHRFunc) key_destroy_hash, NULL);
        g_hash_table_foreach(default_keys, (GHFunc) key_copy_default, NULL);
}

static void key_config_read(CONFIG_NODE *node)
{
	char *key, *id, *data;

	g_return_if_fail(node != NULL);

	key = config_node_get_str(node, "key", NULL);
	id = config_node_get_str(node, "id", NULL);
	data = config_node_get_str(node, "data", NULL);

	if (key != NULL && id != NULL)
		key_configure_create(id, key, data);
}

static void read_keyboard_config(void)
{
	CONFIG_NODE *node;
	GSList *tmp;

        key_configure_freeze();

	keyboard_reset_defaults();

	node = iconfig_node_traverse("keyboard", FALSE);
	if (node == NULL) {
		key_configure_thaw();
		return;
	}

	/* FIXME: backward "compatibility" - remove after irssi .99 */
	if (node->type != NODE_TYPE_LIST) {
                iconfig_node_remove(NULL, node);
		key_configure_thaw();
		return;
	}

	for (tmp = node->value; tmp != NULL; tmp = tmp->next)
		key_config_read(tmp->data);

        key_configure_thaw();
}

void keyboard_init(void)
{
	keys = g_hash_table_new((GHashFunc) g_str_hash,
				(GCompareFunc) g_str_equal);
	default_keys = g_hash_table_new((GHashFunc) g_str_hash,
					(GCompareFunc) g_str_equal);
	keyinfos = NULL;
	key_states = g_tree_new((GCompareFunc) strcmp);
	key_combos = NULL;
        key_config_frozen = 0;
	memset(used_keys, 0, sizeof(used_keys));

	key_bind("command", "Run any IRC command", NULL, NULL, (SIGNAL_FUNC) sig_command);
	key_bind("key", "Specify name for key binding", NULL, NULL, (SIGNAL_FUNC) sig_key);
	key_bind("multi", "Run multiple commands", NULL, NULL, (SIGNAL_FUNC) sig_multi);

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
	g_hash_table_destroy(default_keys);

	g_tree_traverse(key_states, (GTraverseFunc) key_state_destroy,
			G_IN_ORDER, NULL);
	g_tree_destroy(key_states);

	signal_remove("irssi init read settings", (SIGNAL_FUNC) read_keyboard_config);
        signal_remove("setup reread", (SIGNAL_FUNC) read_keyboard_config);
	signal_remove("complete command bind", (SIGNAL_FUNC) sig_complete_bind);
	command_unbind("bind", (SIGNAL_FUNC) cmd_bind);
}
