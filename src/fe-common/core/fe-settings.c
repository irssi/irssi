/*
 fe-settings.c : irssi

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
#include <irssi/src/fe-common/core/module-formats.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/core/servers.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/lib-config/iconfig.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/fe-common/core/fe-settings.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/fe-common/core/printtext.h>
#include <irssi/src/fe-common/core/keyboard.h>

static void set_print(SETTINGS_REC *rec)
{
	char *value;

	value = settings_get_print(rec);
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_SET_ITEM,
		    rec->key, value);
	g_free(value);
}

void fe_settings_set_print(const char *key)
{
	set_print(settings_get_record(key));
}

static void set_print_pattern(const char *pattern)
{
	GSList *sets, *tmp;
	const char *last_section;

	last_section = "";
	sets = settings_get_sorted();
	for (tmp = sets; tmp != NULL; tmp = tmp->next) {
		SETTINGS_REC *rec = tmp->data;

		if (stristr(rec->key, pattern) == NULL)
			continue;
		if (g_strcmp0(last_section, rec->section) != 0) {
			/* print section */
			printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
				    TXT_SET_TITLE, rec->section);
			last_section = rec->section;
		}
		set_print(rec);
	}
	g_slist_free(sets);
}

static void set_print_section(const char *pattern)
{
	GSList *sets, *tmp;
	const char *last_section;

	last_section = "";
	sets = settings_get_sorted();
	for (tmp = sets; tmp != NULL; tmp = tmp->next) {
		SETTINGS_REC *rec = tmp->data;

		if (stristr(rec->section, pattern) != NULL) {
			if (g_strcmp0(last_section, rec->section) != 0) {
				/* print section */
				printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
						TXT_SET_TITLE, rec->section);
				last_section = rec->section;
			}
			set_print(rec);
		}
	}
	g_slist_free(sets);
}

static void set_boolean(const char *key, const char *value)
{
	char *stripped_value;

	stripped_value = g_strdup(value);
	g_strstrip(stripped_value);

	if (g_ascii_strcasecmp(stripped_value, "ON") == 0)
		settings_set_bool(key, TRUE);
	else if (g_ascii_strcasecmp(stripped_value, "OFF") == 0)
		settings_set_bool(key, FALSE);
	else if (g_ascii_strcasecmp(stripped_value, "TOGGLE") == 0)
		settings_set_bool(key, !settings_get_bool(key));
	else
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, TXT_NOT_TOGGLE);

	g_free(stripped_value);
}

static void set_int(const char *key, const char *value)
{
	char *endp;
	long longval;
	int error;

	errno = 0;
	longval = strtol(value, &endp, 10);
	error = errno;
	while (i_isspace(*endp))
		endp++;
	if (error != 0 || *endp != '\0' || longval < INT_MIN || longval > INT_MAX)
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, TXT_INVALID_NUMBER);
	else
		settings_set_int(key, (int)longval);
}

static void set_choice(const char *key, const char *value)
{
	char *stripped_value;

	stripped_value = g_strdup(value);
	g_strstrip(stripped_value);

	if (settings_set_choice(key, stripped_value) == FALSE) {
		SETTINGS_REC *rec = settings_get_record(key);
		char *msg = g_strjoinv(", ", rec->choices);

		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, TXT_INVALID_CHOICE, msg);
		g_free(msg);
	}

	g_free(stripped_value);
}

/* SYNTAX: SET [-clear | -default | -section] [<key> [<value>]] */
static void cmd_set(char *data)
{
        GHashTable *optlist;
	char *key, *value;
	void *free_arg;
	int clear, set_default, list_section;
	SETTINGS_REC *rec;

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST |
			    PARAM_FLAG_OPTIONS,
			    "set", &optlist, &key, &value))
		return;

	clear = g_hash_table_lookup(optlist, "clear") != NULL;
	set_default = g_hash_table_lookup(optlist, "default") != NULL;
	list_section = g_hash_table_lookup(optlist, "section") != NULL;

	if (*key == '\0')
		clear = set_default = list_section = FALSE;

	if (list_section)
		set_print_section(key);
	else if (!(clear || set_default || *value != '\0'))
		set_print_pattern(key);
	else {
		rec = settings_get_record(key);
		if (rec != NULL) {
			/* change the setting */
			switch (rec->type) {
			case SETTING_TYPE_BOOLEAN:
				if (clear)
					settings_set_bool(key, FALSE);
				else if (set_default)
					settings_set_bool(key, rec->default_value.v_bool);
				else
					set_boolean(key, value);
				break;
			case SETTING_TYPE_INT:
				if (clear)
					settings_set_int(key, 0);
				else if (set_default)
					settings_set_int(key, rec->default_value.v_int);
				else
					set_int(key, value);
				break;
			case SETTING_TYPE_CHOICE:
				if (clear || set_default)
					settings_set_choice(key, rec->choices[rec->default_value.v_int]);
				else
					set_choice(key, value);
				break;
			case SETTING_TYPE_STRING:
				settings_set_str(key, clear ? "" :
						 set_default ? rec->default_value.v_string :
						 value);
				break;
			case SETTING_TYPE_TIME:
				if (!settings_set_time(key, clear ? "0" :
						       set_default ? rec->default_value.v_string : value))
					printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, TXT_INVALID_TIME);
				break;
			case SETTING_TYPE_LEVEL:
				if (!settings_set_level(key, clear ? "" :
							set_default ? rec->default_value.v_string : value))
					printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, TXT_INVALID_LEVEL);
				break;
			case SETTING_TYPE_SIZE:
				if (!settings_set_size(key, clear ? "0" :
						       set_default ? rec->default_value.v_string : value))
					printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, TXT_INVALID_SIZE);
				break;
			case SETTING_TYPE_ANY:
				/* Unpossible! */
				break;
			}
			signal_emit("setup changed", 0);
			printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_SET_TITLE, rec->section);
			set_print(rec);
		} else
			printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, TXT_SET_UNKNOWN, key);
	}

	cmd_params_free(free_arg);
}

/* SYNTAX: TOGGLE <key> [on|off|toggle] */
static void cmd_toggle(const char *data)
{
	char *key, *value;
	void *free_arg;
	int type;

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST | PARAM_FLAG_STRIP_TRAILING_WS, &key, &value))
		return;

	if (*key == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	type = settings_get_type(key);
	if (type == SETTING_TYPE_ANY)
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, TXT_SET_UNKNOWN, key);
	else if (type != SETTING_TYPE_BOOLEAN)
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, TXT_SET_NOT_BOOLEAN, key);
	else {
		set_boolean(key, *value != '\0' ? value : "TOGGLE");
		set_print(settings_get_record(key));
		signal_emit("setup changed", 0);
	}

	cmd_params_free(free_arg);
}

static int config_key_compare(CONFIG_NODE *node1, CONFIG_NODE *node2)
{
	return g_ascii_strcasecmp(node1->key, node2->key);
}

static void show_aliases(const char *alias)
{
	CONFIG_NODE *node;
	GSList *tmp, *list;
	int aliaslen;

	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_ALIASLIST_HEADER);

	node = iconfig_node_traverse("aliases", FALSE);
	tmp = node == NULL ? NULL : config_node_first(node->value);

	/* first get the list of aliases sorted */
	list = NULL;
	aliaslen = strlen(alias);
	for (; tmp != NULL; tmp = config_node_next(tmp)) {
		CONFIG_NODE *node = tmp->data;

		if (node->type != NODE_TYPE_KEY)
			continue;

		if (aliaslen != 0 && g_ascii_strncasecmp(node->key, alias, aliaslen) != 0)
			continue;

		list = g_slist_insert_sorted(list, node, (GCompareFunc) config_key_compare);
	}

	/* print the aliases */
	for (tmp = list; tmp != NULL; tmp = tmp->next) {
		CONFIG_NODE *node = tmp->data;

		printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_ALIASLIST_LINE,
			    node->key, node->value);
	}
	g_slist_free(list);

	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_ALIASLIST_FOOTER);
}

static void alias_remove(const char *alias)
{
	if (iconfig_get_str("aliases", alias, NULL) == NULL)
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_ALIAS_NOT_FOUND, alias);
	else {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_ALIAS_REMOVED, alias);
		iconfig_set_str("aliases", alias, NULL);

		signal_emit("alias removed", 1, alias);
	}
}

/* SYNTAX: ALIAS [[-]<alias> [<command>]] */
static void cmd_alias(const char *data)
{
	char *alias, *value;
	void *free_arg;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST, &alias, &value))
		return;

	if (*alias == '-') {
		if (alias[1] != '\0') alias_remove(alias+1);
	} else if (*alias == '\0' || *value == '\0')
		show_aliases(alias);
	else {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_ALIAS_ADDED, alias);
		iconfig_set_str("aliases", alias, value);
		signal_emit("alias added", 2, alias, value);
	}
        cmd_params_free(free_arg);
}

/* SYNTAX: UNALIAS <alias> */
static void cmd_unalias(const char *data)
{
	char *alias;
	void *free_arg;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 1, &alias))
		return;
	if (*alias == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	alias_remove(alias);
        cmd_params_free(free_arg);
}

/* SYNTAX: RELOAD [<file>] */
static void cmd_reload(const char *data)
{
	const char *fname;

	fname = *data == '\0' ? get_irssi_config() : data;

	if (settings_reread(fname)) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
			    TXT_CONFIG_RELOADED, fname);
	}
}

static void settings_save_fe(const char *fname)
{
	if (settings_save(fname, FALSE /* not autosaved */)) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
			    TXT_CONFIG_SAVED, fname);
	}
}

static void settings_save_confirm(const char *line, char *fname)
{
	if (i_toupper(line[0]) == 'Y')
		settings_save_fe(fname);
	g_free(fname);
}

/* SYNTAX: SAVE [<file>] */
static void cmd_save(const char *data)
{
        GHashTable *optlist;
	char *format, *fname;
        void *free_arg;

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS,
			    "save", &optlist, &fname))
		return;

	if (*fname == '\0')
		fname = mainconfig->fname;

	if (!irssi_config_is_changed(fname))
		settings_save_fe(fname);
	else {
                /* config file modified outside irssi */
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
			    TXT_CONFIG_MODIFIED, fname);

		format = format_get_text(MODULE_NAME, NULL, NULL, NULL,
					 TXT_OVERWRITE_CONFIG);
		keyboard_entry_redirect((SIGNAL_FUNC) settings_save_confirm,
					format, 0, g_strdup(fname));
		g_free(format);
	}

	cmd_params_free(free_arg);
}

static void settings_clean_confirm(const char *line)
{
	if (i_toupper(line[0]) == 'Y')
                settings_clean_invalid();
}

static void sig_settings_errors(const char *msg)
{
        printtext(NULL, NULL, MSGLEVEL_CLIENTERROR, "%s", msg);
	keyboard_entry_redirect((SIGNAL_FUNC) settings_clean_confirm,
				"Remove unknown settings from config file (Y/n)?",
				0, NULL);
}

void fe_settings_init(void)
{
	command_bind("set", NULL, (SIGNAL_FUNC) cmd_set);
	command_bind("toggle", NULL, (SIGNAL_FUNC) cmd_toggle);
	command_bind("alias", NULL, (SIGNAL_FUNC) cmd_alias);
	command_bind("unalias", NULL, (SIGNAL_FUNC) cmd_unalias);
	command_bind("reload", NULL, (SIGNAL_FUNC) cmd_reload);
	command_bind("save", NULL, (SIGNAL_FUNC) cmd_save);
	command_set_options("set", "clear default section");

        signal_add("settings errors", (SIGNAL_FUNC) sig_settings_errors);
}

void fe_settings_deinit(void)
{
	command_unbind("set", (SIGNAL_FUNC) cmd_set);
	command_unbind("toggle", (SIGNAL_FUNC) cmd_toggle);
	command_unbind("alias", (SIGNAL_FUNC) cmd_alias);
	command_unbind("unalias", (SIGNAL_FUNC) cmd_unalias);
	command_unbind("reload", (SIGNAL_FUNC) cmd_reload);
	command_unbind("save", (SIGNAL_FUNC) cmd_save);

	signal_remove("settings errors", (SIGNAL_FUNC) sig_settings_errors);
}
