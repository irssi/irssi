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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "module-formats.h"
#include "signals.h"
#include "commands.h"
#include "server.h"
#include "lib-config/iconfig.h"
#include "settings.h"

#include "levels.h"

static void set_print(SETTINGS_REC *rec)
{
	const char *value;
	char value_int[MAX_INT_STRLEN];

	switch (rec->type) {
	case SETTING_TYPE_BOOLEAN:
		value = settings_get_bool(rec->key) ? "ON" : "OFF";
		break;
	case SETTING_TYPE_INT:
                g_snprintf(value_int, sizeof(value_int), "%d", settings_get_int(rec->key));
		value = value_int;
		break;
	case SETTING_TYPE_STRING:
		value = settings_get_str(rec->key);
		break;
	default:
		value = "";
	}
	printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "%s = %s", rec->key, value);
}

static void set_boolean(const char *key, const char *value)
{
	if (g_strcasecmp(value, "ON") == 0)
		iconfig_set_bool("settings", key, TRUE);
	else if (g_strcasecmp(value, "OFF") == 0)
		iconfig_set_bool("settings", key, FALSE);
	else if (g_strcasecmp(value, "TOGGLE") == 0)
		iconfig_set_bool("settings", key, !settings_get_bool(key));
	else
		printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_NOT_TOGGLE);
}

static void cmd_set(char *data)
{
	GSList *sets, *tmp;
	char *params, *key, *value, *last_section;
	int keylen, found;

	params = cmd_get_params(data, 2 | PARAM_FLAG_GETREST, &key, &value);

	keylen = strlen(key);
	last_section = ""; found = 0;

	sets = settings_get_sorted();
	for (tmp = sets; tmp != NULL; tmp = tmp->next) {
		SETTINGS_REC *rec = tmp->data;

		if ((*value != '\0' && g_strcasecmp(rec->key, key) != 0) ||
		    (*value == '\0' && keylen != 0 && g_strncasecmp(rec->key, key, keylen) != 0))
			continue;

		if (strcmp(last_section, rec->section) != 0) {
			/* print section */
			printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "%_[ %s ]", rec->section);
			last_section = rec->section;
		}

		if (*value != '\0') {
			/* change the setting */
			switch (rec->type) {
			case SETTING_TYPE_BOOLEAN:
                                set_boolean(key, value);
				break;
			case SETTING_TYPE_INT:
				iconfig_set_int("settings", key, atoi(value));
				break;
			case SETTING_TYPE_STRING:
                                iconfig_set_str("settings", key, value);
				break;
			}
			signal_emit("setup changed", 0);
		}

                set_print(rec);
		found = TRUE;
	}
	g_slist_free(sets);

        if (!found)
		printtext(NULL, NULL, MSGLEVEL_CLIENTERROR, "Unknown setting %s", key);

	g_free(params);
}

static void cmd_toggle(const char *data)
{
	char *params, *key, *value;
	int type;

	params = cmd_get_params(data, 2 | PARAM_FLAG_GETREST, &key, &value);

	type = settings_get_type(key);
        if (type == -1)
		printtext(NULL, NULL, MSGLEVEL_CLIENTERROR, "Unknown setting %_%s", key);
	else if (type != SETTING_TYPE_BOOLEAN)
		printtext(NULL, NULL, MSGLEVEL_CLIENTERROR, "Setting %_%s%_ isn't boolean, use /SET", key);
	else {
		set_boolean(key, *value != '\0' ? value : "TOGGLE");
                set_print(settings_get_record(key));
	}

	g_free(params);
}

static void show_aliases(const char *alias)
{
	CONFIG_NODE *node;
	GSList *tmp;
	int aliaslen;

	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_ALIASLIST_HEADER);

	node = iconfig_node_traverse("aliases", FALSE);
	tmp = node == NULL ? NULL : node->value;

	aliaslen = strlen(alias);
	for (; tmp != NULL; tmp = tmp->next) {
		CONFIG_NODE *node = tmp->data;

		if (node->type != NODE_TYPE_KEY)
			continue;

		if (aliaslen != 0 && g_strncasecmp(node->key, alias, aliaslen) != 0)
			continue;

		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_ALIASLIST_LINE,
			    node->key, node->value);
	}

	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_ALIASLIST_FOOTER);
}

static void alias_remove(const char *alias)
{
	if (iconfig_get_str("aliases", alias, NULL) == NULL)
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_ALIAS_NOT_FOUND, alias);
	else {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_ALIAS_REMOVED, alias);
		iconfig_set_str("aliases", alias, NULL);
	}
}

static void cmd_alias(const char *data)
{
	char *params, *alias, *value;

	g_return_if_fail(data != NULL);

	params = cmd_get_params(data, 2 | PARAM_FLAG_GETREST, &alias, &value);
	if (*alias == '-') {
		if (alias[1] != '\0') alias_remove(alias+1);
	} else if (*alias == '\0' || *value == '\0')
		show_aliases(alias);
	else {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_ALIAS_ADDED, alias);
		iconfig_set_str("aliases", alias, value);
	}
	g_free(params);
}

static void cmd_unalias(const char *data)
{
	g_return_if_fail(data != NULL);
	if (*data == '\0') cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

	alias_remove(data);
}

void fe_settings_init(void)
{
	command_bind("set", NULL, (SIGNAL_FUNC) cmd_set);
	command_bind("toggle", NULL, (SIGNAL_FUNC) cmd_toggle);
	command_bind("alias", NULL, (SIGNAL_FUNC) cmd_alias);
	command_bind("unalias", NULL, (SIGNAL_FUNC) cmd_unalias);
}

void fe_settings_deinit(void)
{
	command_unbind("set", (SIGNAL_FUNC) cmd_set);
	command_unbind("toggle", (SIGNAL_FUNC) cmd_toggle);
	command_unbind("alias", (SIGNAL_FUNC) cmd_alias);
	command_unbind("unalias", (SIGNAL_FUNC) cmd_unalias);
}
