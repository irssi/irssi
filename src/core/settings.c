/*
 settings.c : Irssi settings

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
#include "commands.h"
#include "misc.h"

#include "lib-config/iconfig.h"
#include "settings.h"
#include "default-config.h"

#include <signal.h>

CONFIG_REC *mainconfig;

static GString *last_errors;
static char *last_config_error_msg;
static GSList *last_invalid_modules;
static int fe_initialized;
static int config_changed; /* FIXME: remove after .98 (unless needed again) */

static GHashTable *settings;
static int timeout_tag;

static int config_last_modifycounter;
static time_t config_last_mtime;
static long config_last_size;
static unsigned int config_last_checksum;

static SETTINGS_REC *settings_find(const char *key)
{
	SETTINGS_REC *rec;

	g_return_val_if_fail(key != NULL, NULL);

	rec = g_hash_table_lookup(settings, key);
	if (rec == NULL) {
		g_warning("settings_get_default_str(%s) : "
			  "unknown setting", key);
		return NULL;
	}

	return rec;
}

const char *settings_get_str(const char *key)
{
	SETTINGS_REC *rec;
	CONFIG_NODE *setnode, *node;

	rec = settings_find(key);
        g_return_val_if_fail(rec != NULL, NULL);

	setnode = iconfig_node_traverse("settings", FALSE);
	if (setnode == NULL)
		return rec->def;

	node = config_node_section(setnode, rec->module, -1);
	return node == NULL ? rec->def :
		config_node_get_str(node, key, rec->def);
}

int settings_get_int(const char *key)
{
	SETTINGS_REC *rec;
	CONFIG_NODE *setnode, *node;
        int def;

	rec = settings_find(key);
        g_return_val_if_fail(rec != NULL, 0);
        def = GPOINTER_TO_INT(rec->def);

	setnode = iconfig_node_traverse("settings", FALSE);
	if (setnode == NULL)
		return def;

	node = config_node_section(setnode, rec->module, -1);
	return node == NULL ? def :
		config_node_get_int(node, key, def);
}

int settings_get_bool(const char *key)
{
	SETTINGS_REC *rec;
	CONFIG_NODE *setnode, *node;
        int def;

	rec = settings_find(key);
        g_return_val_if_fail(rec != NULL, 0);
        def = GPOINTER_TO_INT(rec->def);

	setnode = iconfig_node_traverse("settings", FALSE);
	if (setnode == NULL)
		return def;

	node = config_node_section(setnode, rec->module, -1);
	return node == NULL ? def :
		config_node_get_bool(node, key, def);
}

void settings_add_str_module(const char *module, const char *section,
			     const char *key, const char *def)
{
	SETTINGS_REC *rec;

	g_return_if_fail(key != NULL);
	g_return_if_fail(section != NULL);

	rec = g_hash_table_lookup(settings, key);
	g_return_if_fail(rec == NULL);

	rec = g_new0(SETTINGS_REC, 1);
        rec->module = g_strdup(module);
	rec->key = g_strdup(key);
	rec->section = g_strdup(section);
	rec->def = def == NULL ? NULL : g_strdup(def);

	g_hash_table_insert(settings, rec->key, rec);
}

void settings_add_int_module(const char *module, const char *section,
			     const char *key, int def)
{
	SETTINGS_REC *rec;

	g_return_if_fail(key != NULL);
	g_return_if_fail(section != NULL);

	rec = g_hash_table_lookup(settings, key);
	g_return_if_fail(rec == NULL);

	rec = g_new0(SETTINGS_REC, 1);
        rec->module = g_strdup(module);
	rec->type = SETTING_TYPE_INT;
	rec->key = g_strdup(key);
	rec->section = g_strdup(section);
	rec->def = GINT_TO_POINTER(def);

	g_hash_table_insert(settings, rec->key, rec);
}

void settings_add_bool_module(const char *module, const char *section,
			      const char *key, int def)
{
	SETTINGS_REC *rec;

	g_return_if_fail(key != NULL);
	g_return_if_fail(section != NULL);

	rec = g_hash_table_lookup(settings, key);
	g_return_if_fail(rec == NULL);

	rec = g_new0(SETTINGS_REC, 1);
        rec->module = g_strdup(module);
	rec->type = SETTING_TYPE_BOOLEAN;
	rec->key = g_strdup(key);
	rec->section = g_strdup(section);
	rec->def = GINT_TO_POINTER(def);

	g_hash_table_insert(settings, rec->key, rec);
}

static void settings_destroy(SETTINGS_REC *rec)
{
	if (rec->type == SETTING_TYPE_STRING)
		g_free_not_null(rec->def);
        g_free(rec->module);
        g_free(rec->section);
        g_free(rec->key);
	g_free(rec);
}

void settings_remove(const char *key)
{
	SETTINGS_REC *rec;

	g_return_if_fail(key != NULL);

	rec = g_hash_table_lookup(settings, key);
	if (rec == NULL) return;

	g_hash_table_remove(settings, key);
	settings_destroy(rec);
}

static int settings_remove_hash(const char *key, SETTINGS_REC *rec,
				const char *module)
{
	if (strcmp(rec->module, module) == 0) {
		settings_destroy(rec);
                return TRUE;
	}

        return FALSE;
}

void settings_remove_module(const char *module)
{
	g_hash_table_foreach_remove(settings,
				    (GHRFunc) settings_remove_hash,
				    (void *) module);
}

static CONFIG_NODE *settings_get_node(const char *key)
{
	SETTINGS_REC *rec;
        CONFIG_NODE *node;

	g_return_val_if_fail(key != NULL, NULL);

	rec = g_hash_table_lookup(settings, key);
	g_return_val_if_fail(rec != NULL, NULL);

	node = iconfig_node_traverse("settings", TRUE);
	return config_node_section(node, rec->module, NODE_TYPE_BLOCK);
}

void settings_set_str(const char *key, const char *value)
{
        iconfig_node_set_str(settings_get_node(key), key, value);
}

void settings_set_int(const char *key, int value)
{
        iconfig_node_set_int(settings_get_node(key), key, value);
}

void settings_set_bool(const char *key, int value)
{
        iconfig_node_set_bool(settings_get_node(key), key, value);
}

int settings_get_type(const char *key)
{
	SETTINGS_REC *rec;

	g_return_val_if_fail(key != NULL, -1);

	rec = g_hash_table_lookup(settings, key);
	return rec == NULL ? -1 : rec->type;
}

/* Get the record of the setting */
SETTINGS_REC *settings_get_record(const char *key)
{
	g_return_val_if_fail(key != NULL, NULL);

	return g_hash_table_lookup(settings, key);
}

static void sig_init_finished(void)
{
	fe_initialized = TRUE;
	if (last_errors != NULL) {
		signal_emit("settings errors", 1, last_errors->str);
		g_string_free(last_errors, TRUE);
	}

	if (last_config_error_msg != NULL) {
		signal_emit("gui dialog", 2, "error", last_config_error_msg);
		g_free_and_null(last_config_error_msg);
	}

	if (config_changed) {
		/* some backwards compatibility changes were made to
		   config file, reload it */
		signal_emit("setup changed", 0);
	}
}

/* FIXME: remove after 0.7.98 - only for backward compatibility */
static void settings_move(SETTINGS_REC *rec, char *value)
{
	CONFIG_NODE *setnode, *node;

	setnode = iconfig_node_traverse("settings", TRUE);
	node = config_node_section(setnode, rec->module, NODE_TYPE_BLOCK);

	iconfig_node_set_str(node, rec->key, value);
	iconfig_node_set_str(setnode, rec->key, NULL);

        config_changed = TRUE;
}

static void settings_clean_invalid_module(const char *module)
{
        CONFIG_NODE *node;
        SETTINGS_REC *set;
	GSList *tmp, *next;

	node = iconfig_node_traverse("settings", FALSE);
	if (node == NULL) return;

	node = config_node_section(node, module, -1);
	if (node == NULL) return;

	for (tmp = node->value; tmp != NULL; tmp = next) {
		CONFIG_NODE *subnode = tmp->data;
                next = tmp->next;

		set = g_hash_table_lookup(settings, subnode->key);
		if (set == NULL || strcmp(set->module, module) != 0)
                        iconfig_node_remove(node, subnode);
	}
}

/* remove all invalid settings from config file. works only with the
   modules that have already called settings_check() */
void settings_clean_invalid(void)
{
	while (last_invalid_modules != NULL) {
		char *module = last_invalid_modules->data;

                settings_clean_invalid_module(module);

                g_free(module);
		last_invalid_modules =
			g_slist_remove(last_invalid_modules, module);
	}
}

/* verify that all settings in config file for `module' are actually found
   from /SET list */
void settings_check_module(const char *module)
{
        SETTINGS_REC *set;
	CONFIG_NODE *node;
        GString *errors;
	GSList *tmp, *next;
        int count;

        g_return_if_fail(module != NULL);

	node = iconfig_node_traverse("settings", FALSE);
	if (node != NULL) {
		/* FIXME: remove after 0.7.98 */
		for (tmp = node->value; tmp != NULL; tmp = next) {
			CONFIG_NODE *node = tmp->data;

                        next = tmp->next;
			if (node->type != NODE_TYPE_KEY)
				continue;
			set = g_hash_table_lookup(settings, node->key);
                        if (set != NULL)
				settings_move(set, node->value);
		}
	}
	node = node == NULL ? NULL : config_node_section(node, module, -1);
	if (node == NULL) return;

        errors = g_string_new(NULL);
	g_string_sprintf(errors, "Unknown settings in configuration "
			 "file for module %s:", module);

        count = 0;
	for (tmp = node->value; tmp != NULL; tmp = tmp->next) {
		node = tmp->data;

		set = g_hash_table_lookup(settings, node->key);
		if (set == NULL || strcmp(set->module, module) != 0) {
			g_string_sprintfa(errors, " %s", node->key);
                        count++;
		}
	}
	if (count > 0) {
		if (gslist_find_icase_string(last_invalid_modules,
					     module) == NULL) {
                        /* mark this module having invalid settings */
			last_invalid_modules =
				g_slist_append(last_invalid_modules,
					       g_strdup(module));
		}
		if (fe_initialized)
                        signal_emit("settings errors", 1, errors->str);
		else {
			if (last_errors == NULL)
				last_errors = g_string_new(NULL);
			else
				g_string_append_c(last_errors, '\n');
                        g_string_append(last_errors, errors->str);
		}
	}
        g_string_free(errors, TRUE);
}

static int settings_compare(SETTINGS_REC *v1, SETTINGS_REC *v2)
{
	return strcmp(v1->section, v2->section);
}

static void settings_hash_get(const char *key, SETTINGS_REC *rec,
			      GSList **list)
{
	*list = g_slist_insert_sorted(*list, rec,
				      (GCompareFunc) settings_compare);
}

GSList *settings_get_sorted(void)
{
	GSList *list;

	list = NULL;
	g_hash_table_foreach(settings, (GHFunc) settings_hash_get, &list);
	return list;
}

void sig_term(int n)
{
	/* if we get SIGTERM after this, just die instead of coming back here. */
	signal(SIGTERM, SIG_DFL);

	/* quit from all servers too.. */
	signal_emit("command quit", 1, "");

	/* and die */
	raise(SIGTERM);
}

/* Yes, this is my own stupid checksum generator, some "real" algorithm
   would be nice but would just take more space without much real benefit */
static unsigned int file_checksum(const char *fname)
{
        char buf[512];
        int f, ret, n;
	unsigned int checksum = 0;

	f = open(fname, O_RDONLY);
	if (f == -1) return 0;

        n = 0;
	while ((ret = read(f, buf, sizeof(buf))) > 0) {
		while (ret-- > 0)
			checksum += buf[ret] << ((n++ & 3)*8);
	}
	close(f);
	return checksum;
}

static void irssi_config_save_state(const char *fname)
{
	struct stat statbuf;

	g_return_if_fail(fname != NULL);

	if (stat(fname, &statbuf) != 0)
		return;

	/* save modify time, file size and checksum */
	config_last_mtime = statbuf.st_mtime;
	config_last_size = statbuf.st_size;
	config_last_checksum = file_checksum(fname);
}

int irssi_config_is_changed(const char *fname)
{
	struct stat statbuf;

	if (fname == NULL)
		fname = mainconfig->fname;

	if (stat(fname, &statbuf) != 0)
		return FALSE;

	return config_last_mtime != statbuf.st_mtime &&
		(config_last_size != statbuf.st_size ||
		 config_last_checksum != file_checksum(fname));
}

static CONFIG_REC *parse_configfile(const char *fname)
{
	CONFIG_REC *config;
	struct stat statbuf;
        const char *path;
	char *real_fname;

	real_fname = fname != NULL ? g_strdup(fname) :
		g_strdup_printf("%s"G_DIR_SEPARATOR_S".irssi"
				G_DIR_SEPARATOR_S"config", g_get_home_dir());

	if (stat(real_fname, &statbuf) == 0)
		path = real_fname;
	else {
		/* user configuration file not found, use the default one
		   from sysconfdir */
                path = SYSCONFDIR"/irssi/config";
		if (stat(path, &statbuf) != 0) {
			/* no configuration file in sysconfdir ..
			   use the build-in configuration */
                        path = NULL;
		}
	}

	config = config_open(path, -1);
	if (config == NULL) {
		last_config_error_msg =
			g_strdup_printf("Error opening configuration file %s: %s",
					path, g_strerror(errno));
		config = config_open(NULL, -1);
	}

        if (path != NULL)
		config_parse(config);
        else
		config_parse_data(config, default_config, "internal");

	config_change_file_name(config, real_fname, 0660);
        irssi_config_save_state(real_fname);
	g_free(real_fname);
	return config;
}

static void init_configfile(void)
{
	struct stat statbuf;
	char *str;

	str = g_strdup_printf("%s"G_DIR_SEPARATOR_S".irssi", g_get_home_dir());
	if (stat(str, &statbuf) != 0) {
		/* ~/.irssi not found, create it. */
		if (mkpath(str, 0700) != 0) {
			g_error("Couldn't create %s directory", str);
		}
	} else if (!S_ISDIR(statbuf.st_mode)) {
		g_error("%s is not a directory.\n"
			"You should remove it with command: rm ~/.irssi", str);
	}
	g_free(str);

	mainconfig = parse_configfile(NULL);
	config_last_modifycounter = mainconfig->modifycounter;

	/* any errors? */
	if (config_last_error(mainconfig) != NULL) {
		last_config_error_msg =
			g_strdup_printf("Ignored errors in configuration "
					"file:\n%s",
					config_last_error(mainconfig));
	}

	signal(SIGTERM, sig_term);
}

int settings_reread(const char *fname)
{
	CONFIG_REC *tempconfig;
	char *str;

	if (fname == NULL) fname = "~/.irssi/config";

	str = convert_home(fname);
	tempconfig = parse_configfile(str);
	g_free(str);

	if (tempconfig == NULL) {
		signal_emit("gui dialog", 2, "error", g_strerror(errno));
		return FALSE;
	}

	if (config_last_error(tempconfig) != NULL) {
		str = g_strdup_printf("Errors in configuration file:\n%s",
				      config_last_error(tempconfig));
		signal_emit("gui dialog", 2, "error", str);
		g_free(str);

		config_close(tempconfig);
                return FALSE;
	}

	config_close(mainconfig);
	mainconfig = tempconfig;
	config_last_modifycounter = mainconfig->modifycounter;

	signal_emit("setup changed", 0);
	signal_emit("setup reread", 0);
        return TRUE;
}

int settings_save(const char *fname)
{
	char *str;
	int error;

	if (fname == NULL)
		fname = mainconfig->fname;

	error = config_write(mainconfig, fname, 0660) != 0;
	irssi_config_save_state(fname);
	config_last_modifycounter = mainconfig->modifycounter;
	if (error) {
		str = g_strdup_printf("Couldn't save configuration file: %s",
				      config_last_error(mainconfig));
		signal_emit("gui dialog", 2, "error", str);
		g_free(str);
	}
        return !error;
}

static void sig_autosave(void)
{
	char *fname, *str;

	if (!settings_get_bool("settings_autosave") ||
	    config_last_modifycounter == mainconfig->modifycounter)
		return;

	if (!irssi_config_is_changed(NULL))
		settings_save(NULL);
	else {
		fname = g_strconcat(mainconfig->fname, ".autosave", NULL);
		str = g_strdup_printf("Configuration file was modified "
				      "while irssi was running. Saving "
				      "configuration to file '%s' instead. "
				      "Use /SAVE or /RELOAD to get rid of "
				      "this message.", fname);
		signal_emit("gui dialog", 2, "warning", str);
		g_free(str);

                settings_save(fname);
		g_free(fname);
	}
}

void settings_init(void)
{
	settings = g_hash_table_new((GHashFunc) g_str_hash,
				    (GCompareFunc) g_str_equal);

	last_errors = NULL;
	last_config_error_msg = NULL;
        last_invalid_modules = NULL;
	fe_initialized = FALSE;
        config_changed = FALSE;

	config_last_mtime = 0;
	config_last_modifycounter = 0;
	init_configfile();

	settings_add_bool("misc", "settings_autosave", TRUE);
	timeout_tag = g_timeout_add(1000*60*60, (GSourceFunc) sig_autosave, NULL);
	signal_add("irssi init finished", (SIGNAL_FUNC) sig_init_finished);
	signal_add("gui exit", (SIGNAL_FUNC) sig_autosave);
}

static void settings_hash_free(const char *key, SETTINGS_REC *rec)
{
	settings_destroy(rec);
}

void settings_deinit(void)
{
        g_source_remove(timeout_tag);
	signal_remove("irssi init finished", (SIGNAL_FUNC) sig_init_finished);
	signal_remove("gui exit", (SIGNAL_FUNC) sig_autosave);

	g_slist_foreach(last_invalid_modules, (GFunc) g_free, NULL);
	g_slist_free(last_invalid_modules);

	g_hash_table_foreach(settings, (GHFunc) settings_hash_free, NULL);
	g_hash_table_destroy(settings);

	if (mainconfig != NULL) config_close(mainconfig);
}
