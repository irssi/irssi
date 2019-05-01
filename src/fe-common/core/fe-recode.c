/*
 fe-recode.c : irssi

    Copyright (C) 1999-2000 Timo Sirainen

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
#include <irssi/src/core/modules.h>
#include <irssi/src/fe-common/core/module-formats.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/lib-config/iconfig.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/fe-common/core/printtext.h>
#include <irssi/src/fe-common/core/formats.h>
#include <irssi/src/core/recode.h>

static char *recode_fallback = NULL;
static char *recode_out_default = NULL;
static char *term_charset = NULL;

static const char *fe_recode_get_target (WI_ITEM_REC *witem)
{
	if (witem && (witem->type == module_get_uniq_id_str("WINDOW ITEM TYPE", "QUERY")
	    || witem->type == module_get_uniq_id_str("WINDOW ITEM TYPE", "CHANNEL")))
		return window_item_get_target(witem);

	printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, TXT_NOT_CHANNEL_OR_QUERY);
	return NULL;
}

static int fe_recode_compare_func (CONFIG_NODE *node1, CONFIG_NODE *node2)
{
	return g_strcmp0(node1->key, node2->key);
}

/* SYNTAX: RECODE */
static void fe_recode_cmd (const char *data, SERVER_REC *server, WI_ITEM_REC *witem)
{
	if (*data)
		command_runsub("recode", data, server, witem);
	else {
		CONFIG_NODE *conversions;
		GSList *tmp;
		GSList *sorted = NULL;

		conversions = iconfig_node_traverse("conversions", FALSE);

		for (tmp = conversions ? config_node_first(conversions->value) : NULL;
		     tmp != NULL;
		     tmp = config_node_next(tmp)) {
			CONFIG_NODE *node = tmp->data;

			if (node->type == NODE_TYPE_KEY)
				sorted = g_slist_insert_sorted(sorted, node, (GCompareFunc) fe_recode_compare_func);
		}

	 	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_RECODE_HEADER);
		for (tmp = sorted; tmp != NULL; tmp = tmp->next) {
			CONFIG_NODE *node = tmp->data;
			printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_RECODE_LINE, node->key, node->value);
		}

		g_slist_free(sorted);
	}
}

/* SYNTAX: RECODE ADD [[<tag>/]<target>] <charset> */
static void fe_recode_add_cmd (const char *data, SERVER_REC *server, WI_ITEM_REC *witem)
{
	const char *first;
	const char *second;
	const char *target;
	const char *charset;
	void *free_arg;

	if (! cmd_get_params(data, &free_arg, 2, &first, &second))
		return;

	if (! *first)
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	if (*second) {
		target = first;
		charset = second;
	} else {
		target = fe_recode_get_target(witem);
		charset = first;
		if (! target)
			goto end;
	}
	if (is_valid_charset(charset)) {
		iconfig_set_str("conversions", target, charset);
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_CONVERSION_ADDED, target, charset);
	} else
		signal_emit("error command", 2, GINT_TO_POINTER(CMDERR_INVALID_CHARSET), charset);
 end:
	cmd_params_free(free_arg);
}

/* SYNTAX: RECODE REMOVE [<target>] */
static void fe_recode_remove_cmd (const char *data, SERVER_REC *server, WI_ITEM_REC *witem)
{
	const char *target;
	void *free_arg;

	if (! cmd_get_params(data, &free_arg, 1, &target))
		return;

	if (! *target) {
		target = fe_recode_get_target(witem);
		if (! target)
			goto end;
	}

	if (iconfig_get_str("conversions", target, NULL) == NULL)
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_CONVERSION_NOT_FOUND, target);
	else {
		iconfig_set_str("conversions", target, NULL);
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_CONVERSION_REMOVED, target);
	}

 end:
	cmd_params_free(free_arg);
}

static void read_settings(void)
{
	/* preserve the valid values */
	char *old_term_charset = g_strdup(term_charset);
	char *old_recode_fallback = g_strdup(recode_fallback);
	char *old_recode_out_default = g_strdup(recode_out_default);

	if (settings_get_bool("recode_transliterate")) {
		/* check if transliterations are supported in this system */
		if (!is_valid_charset("ASCII")) {
			printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
				    TXT_CONVERSION_NO_TRANSLITS);
			settings_set_bool("recode_transliterate", FALSE);
		}
	}

	if (recode_fallback)
		g_free(recode_fallback);
	recode_fallback = g_strdup(settings_get_str("recode_fallback"));
	if (!is_valid_charset(recode_fallback)) {
		signal_emit("error command", 2, GINT_TO_POINTER(CMDERR_INVALID_CHARSET), recode_fallback);
		g_free(recode_fallback);
		recode_fallback = is_valid_charset(old_recode_fallback) ? g_strdup(old_recode_fallback) : NULL;
		settings_set_str("recode_fallback", recode_fallback);
	}

	if (term_charset)
		g_free(term_charset);
	term_charset = g_strdup(settings_get_str("term_charset"));
	if (!is_valid_charset(term_charset)) {
		g_free(term_charset);
		term_charset = is_valid_charset(old_term_charset) ? g_strdup(old_term_charset) : NULL;
		settings_set_str("term_charset", term_charset);
	}
	recode_update_charset();

	if (recode_out_default)
		g_free(recode_out_default);
	recode_out_default = g_strdup(settings_get_str("recode_out_default_charset"));
	if (recode_out_default != NULL && *recode_out_default != '\0' &&
	    !is_valid_charset(recode_out_default)) {
		signal_emit("error command", 2, GINT_TO_POINTER(CMDERR_INVALID_CHARSET), recode_out_default);
		g_free(recode_out_default);
		recode_out_default = is_valid_charset(old_recode_out_default) ? g_strdup(old_recode_out_default) : NULL;
		settings_set_str("recode_out_default_charset", recode_out_default);
	}

	g_free(old_term_charset);
	g_free(old_recode_fallback);
	g_free(old_recode_out_default);
}

void fe_recode_init (void)
{
	command_bind("recode", NULL, (SIGNAL_FUNC) fe_recode_cmd);
	command_bind("recode add", NULL, (SIGNAL_FUNC) fe_recode_add_cmd);
	command_bind("recode remove", NULL, (SIGNAL_FUNC) fe_recode_remove_cmd);
	signal_add_first("setup changed", (SIGNAL_FUNC) read_settings);
	read_settings();
}

void fe_recode_deinit (void)
{
	command_unbind("recode", (SIGNAL_FUNC) fe_recode_cmd);
	command_unbind("recode add", (SIGNAL_FUNC) fe_recode_add_cmd);
	command_unbind("recode remove", (SIGNAL_FUNC) fe_recode_remove_cmd);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
}
