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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

/* Contains a list of all possible executable key bindings (not "key" keys).
   Format is _always_ in key1-key2-key3 format and fully extracted, like
   ^[-[-A, not meta-A */
static GTree *key_states;
static int key_config_frozen;

struct _KEYBOARD_REC {
	char *key_state; /* the ongoing key combo */
        void *gui_data; /* GUI specific data sent in "key pressed" signal */
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

	tmp = config_node_first(node->value);
	for (; tmp != NULL; tmp = config_node_next(tmp)) {
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
	if (node != NULL) {
		iconfig_node_remove(iconfig_node_traverse("(keyboard", FALSE),
				    node);
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

static int expand_key(const char *key, GSList **out);

#define expand_out_char(out, c) \
	{ \
	  GSList *tmp; \
	  for (tmp = out; tmp != NULL; tmp = tmp->next) \
            g_string_append_c(tmp->data, c); \
	}

#define expand_out_free(out) \
	{ \
	  GSList *tmp; \
	  for (tmp = out; tmp != NULL; tmp = tmp->next) \
            g_string_free(tmp->data, TRUE); \
	  g_slist_free(out); out = NULL; \
	}

static int expand_combo(const char *start, const char *end, GSList **out)
{
        KEY_REC *rec;
	KEYINFO_REC *info;
        GSList *tmp, *tmp2, *list, *copy, *newout;
	char *str, *p;

	if (start == end) {
		/* single key */
		expand_out_char(*out, *start);
                return TRUE;
	}

	info = key_info_find("key");
	if (info == NULL)
		return FALSE;

        /* get list of all key combos that generate the named combo.. */
        list = NULL;
	str = g_strndup(start, (int) (end-start)+1);
	for (tmp = info->keys; tmp != NULL; tmp = tmp->next) {
		KEY_REC *rec = tmp->data;

		if (strcmp(rec->data, str) == 0)
                        list = g_slist_append(list, rec);
	}

	if (list == NULL) {
		/* unknown keycombo - add it as-is, maybe the GUI will
		   feed it to us as such */
		for (p = str; *p != '\0'; p++)
			expand_out_char(*out, *p);
		g_free(str);
		return TRUE;
	}
	g_free(str);

	if (list->next == NULL) {
                /* only one way to generate the combo, good */
                rec = list->data;
		g_slist_free(list);
		return expand_key(rec->key, out);
	}

	/* multiple ways to generate the combo -
	   we'll need to include all of them in output */
        newout = NULL;
	for (tmp = list->next; tmp != NULL; tmp = tmp->next) {
		KEY_REC *rec = tmp->data;

		copy = NULL;
		for (tmp2 = *out; tmp2 != NULL; tmp2 = tmp2->next) {
			GString *str = tmp2->data;
                        copy = g_slist_append(copy, g_string_new(str->str));
		}

		if (!expand_key(rec->key, &copy)) {
			/* illegal key combo, remove from list */
                        expand_out_free(copy);
		} else {
                        newout = g_slist_concat(newout, copy);
		}
	}

        rec = list->data;
	g_slist_free(list);
	if (!expand_key(rec->key, out)) {
		/* illegal key combo, remove from list */
		expand_out_free(*out);
	}

	*out = g_slist_concat(*out, newout);
        return *out != NULL;
}

/* Expand key code - returns TRUE if successful. */
static int expand_key(const char *key, GSList **out)
{
	GSList *tmp;
	const char *start;
	int last_hyphen;

	/* meta-^W^Gf -> ^[-^W-^G-f */
        start = NULL; last_hyphen = TRUE;
	for (; *key != '\0'; key++) {
		if (start != NULL) {
			if (i_isalnum(*key) || *key == '_') {
                                /* key combo continues */
				continue;
			}

			if (!expand_combo(start, key-1, out))
                                return FALSE;
			expand_out_char(*out, '-');
                        start = NULL;
		}

		if (*key == '-') {
			if (last_hyphen) {
                                expand_out_char(*out, '-');
                                expand_out_char(*out, '-');
			}
			last_hyphen = !last_hyphen;
		} else if (*key == '^') {
                        /* ctrl-code */
			if (key[1] != '\0')
				key++;

			expand_out_char(*out, '^');
			expand_out_char(*out, *key);
			expand_out_char(*out, '-');
                        last_hyphen = FALSE; /* optional */
		} else if (last_hyphen && i_isalpha(*key)) {
                        /* possibly beginning of keycombo */
			start = key;
                        last_hyphen = FALSE;
		} else {
			expand_out_char(*out, *key);
			expand_out_char(*out, '-');
                        last_hyphen = FALSE; /* optional */
		}
	}

	if (start != NULL)
		return expand_combo(start, key-1, out);

	for (tmp = *out; tmp != NULL; tmp = tmp->next) {
		GString *str = tmp->data;

		g_string_truncate(str, str->len-1);
	}

        return TRUE;
}

static void key_states_scan_key(const char *key, KEY_REC *rec)
{
	GSList *tmp, *out;

	if (strcmp(rec->info->id, "key") == 0)
		return;

        out = g_slist_append(NULL, g_string_new(NULL));
	if (expand_key(key, &out)) {
		for (tmp = out; tmp != NULL; tmp = tmp->next) {
			GString *str = tmp->data;

			if (str->str[1] == '-' || str->str[1] == '\0')
				used_keys[(int)(unsigned char)str->str[0]] = 1;

			g_tree_insert(key_states, g_strdup(str->str), rec);
		}
	}

	expand_out_free(out);
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

	signal_emit("key destroyed", 1, rec);

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

	signal_emit("key created", 1, rec);

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

static int key_states_search(const unsigned char *combo,
			     const unsigned char *search)
{
	while (*search != '\0') {
		if (*combo != *search)
			return *search - *combo;
                search++; combo++;
	}

        return 0;
}

int key_pressed(KEYBOARD_REC *keyboard, const char *key)
{
	KEY_REC *rec;
        char *combo;
        int first_key, consumed;

	g_return_val_if_fail(keyboard != NULL, FALSE);
	g_return_val_if_fail(key != NULL && *key != '\0', FALSE);

	if (keyboard->key_state == NULL && key[1] == '\0' &&
	    !used_keys[(int) (unsigned char) key[0]]) {
		/* fast check - key not used */
		return -1;
	}

        first_key = keyboard->key_state == NULL;
	combo = keyboard->key_state == NULL ? g_strdup(key) :
                g_strconcat(keyboard->key_state, "-", key, NULL);
	g_free_and_null(keyboard->key_state);

	rec = g_tree_search(key_states,
			    (GCompareFunc) key_states_search,
			    combo);
	if (rec == NULL) {
		/* unknown key combo, eat the invalid key
		   unless it was the first key pressed */
                g_free(combo);
		return first_key ? -1 : 1;
	}

	if (g_tree_lookup(key_states, combo) != rec) {
		/* key combo continues.. */
		keyboard->key_state = combo;
                return 0;
	}

        /* finished key combo, execute */
        g_free(combo);
	consumed = key_emit_signal(keyboard, rec);

	/* never consume non-control characters */
	return consumed ? 1 : -1;
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

static void sig_nothing(const char *data)
{
}

static void cmd_show_keys(const char *searchkey, int full)
{
	GSList *info, *key;
        int len;

	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_BIND_HEADER);

	len = searchkey == NULL ? 0 : strlen(searchkey);
	for (info = keyinfos; info != NULL; info = info->next) {
		KEYINFO_REC *rec = info->data;

		for (key = rec->keys; key != NULL; key = key->next) {
			KEY_REC *rec = key->data;

			if ((len == 0 || g_strncasecmp(rec->key, searchkey, len) == 0) &&
			    (!full || rec->key[len] == '\0')) {
				printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_BIND_LIST,
					    rec->key, rec->info->id, rec->data == NULL ? "" : rec->data);
			}
		}
	}

	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_BIND_FOOTER);
}

/* SYNTAX: BIND [-list] [-delete] [<key> [<command> [<data>]]] */
static void cmd_bind(const char *data)
{
	GHashTable *optlist;
	char *key, *id, *keydata;
	void *free_arg;
	int command_id;

	if (!cmd_get_params(data, &free_arg, 3 | PARAM_FLAG_GETREST | PARAM_FLAG_OPTIONS,
			    "bind", &optlist, &key, &id, &keydata))
		return;

	if (g_hash_table_lookup(optlist, "list")) {
		GSList *tmp;

		for (tmp = keyinfos; tmp != NULL; tmp = tmp->next) {
			KEYINFO_REC *rec = tmp->data;

			printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_BIND_COMMAND_LIST,
				    rec->id, rec->description ? rec->description : "");
		}
		cmd_params_free(free_arg);
		return;
	}

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
		keydata = g_strconcat(id+1, " ", keydata, NULL);
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

	tmp = config_node_first(node->value);
	for (; tmp != NULL; tmp = config_node_next(tmp))
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
        key_config_frozen = 0;
	memset(used_keys, 0, sizeof(used_keys));

	key_bind("command", "Run any command", NULL, NULL, (SIGNAL_FUNC) sig_command);
	key_bind("key", "Specify name for key binding", NULL, NULL, (SIGNAL_FUNC) sig_key);
	key_bind("multi", "Run multiple commands", NULL, NULL, (SIGNAL_FUNC) sig_multi);
	key_bind("nothing", "Do nothing", NULL, NULL, (SIGNAL_FUNC) sig_nothing);

	/* read the keyboard config when all key binds are known */
	signal_add("irssi init read settings", (SIGNAL_FUNC) read_keyboard_config);
	signal_add("setup reread", (SIGNAL_FUNC) read_keyboard_config);
	signal_add("complete command bind", (SIGNAL_FUNC) sig_complete_bind);

	command_bind("bind", NULL, (SIGNAL_FUNC) cmd_bind);
	command_set_options("bind", "delete list");
}

void keyboard_deinit(void)
{
	key_unbind("command", (SIGNAL_FUNC) sig_command);
	key_unbind("key", (SIGNAL_FUNC) sig_key);
	key_unbind("multi", (SIGNAL_FUNC) sig_multi);
	key_unbind("nothing", (SIGNAL_FUNC) sig_nothing);

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
