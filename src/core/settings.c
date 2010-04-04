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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include "signals.h"
#include "commands.h"
#include "levels.h"
#include "misc.h"

#include "lib-config/iconfig.h"
#include "recode.h"
#include "settings.h"
#include "default-config.h"

#include <signal.h>

#define SETTINGS_AUTOSAVE_TIMEOUT (1000*60*60) /* 1 hour */

CONFIG_REC *mainconfig;

static GString *last_errors;
static GSList *last_invalid_modules;
static int fe_initialized;
static int config_changed; /* FIXME: remove after .98 (unless needed again) */

static GHashTable *settings;
static int timeout_tag;

static int config_last_modifycounter;
static time_t config_last_mtime;
static long config_last_size;
static unsigned int config_last_checksum;

static SETTINGS_REC *settings_get(const char *key, SettingType type)
{
	SETTINGS_REC *rec;

	g_return_val_if_fail(key != NULL, NULL);

	rec = g_hash_table_lookup(settings, key);
	if (rec == NULL) {
		g_warning("settings_get(%s) : not found", key);
		return NULL;
	}
	if (type != -1 && rec->type != type) {
		g_warning("settings_get(%s) : invalid type", key);
		return NULL;
	}

	return rec;
}

static const char *
settings_get_str_type(const char *key, SettingType type)
{
	SETTINGS_REC *rec;
	CONFIG_NODE *node;

	rec = settings_get(key, type);
	if (rec == NULL) return NULL;

	node = iconfig_node_traverse("settings", FALSE);
	node = node == NULL ? NULL : config_node_section(node, rec->module, -1);

	return node == NULL ? rec->default_value.v_string :
		config_node_get_str(node, key, rec->default_value.v_string);
}

const char *settings_get_str(const char *key)
{
	return settings_get_str_type(key, -1);
}

int settings_get_int(const char *key)
{
	SETTINGS_REC *rec;
	CONFIG_NODE *node;

	rec = settings_get(key, SETTING_TYPE_INT);
	if (rec == NULL) return 0;

	node = iconfig_node_traverse("settings", FALSE);
	node = node == NULL ? NULL : config_node_section(node, rec->module, -1);

	return node == NULL ? rec->default_value.v_int :
		config_node_get_int(node, key, rec->default_value.v_int);
}

int settings_get_bool(const char *key)
{
	SETTINGS_REC *rec;
	CONFIG_NODE *node;

	rec = settings_get(key, SETTING_TYPE_BOOLEAN);
	if (rec == NULL) return FALSE;

	node = iconfig_node_traverse("settings", FALSE);
	node = node == NULL ? NULL : config_node_section(node, rec->module, -1);

	return node == NULL ? rec->default_value.v_bool :
		config_node_get_bool(node, key, rec->default_value.v_bool);
}

int settings_get_time(const char *key)
{
	const char *str;
	int msecs;

	str = settings_get_str_type(key, SETTING_TYPE_TIME);
	if (str != NULL && !parse_time_interval(str, &msecs))
		g_warning("settings_get_time(%s) : Invalid time '%s'", key, str);
	return str == NULL ? 0 : msecs;
}

int settings_get_level(const char *key)
{
	const char *str;

	str = settings_get_str_type(key, SETTING_TYPE_LEVEL);
	return str == NULL ? 0 : level2bits(str, NULL);
}

int settings_get_size(const char *key)
{
	const char *str;
	int bytes;

	str = settings_get_str_type(key, SETTING_TYPE_SIZE);
	if (str != NULL && !parse_size(str, &bytes))
		g_warning("settings_get_size(%s) : Invalid size '%s'", key, str);
	return str == NULL ? 0 : bytes;
}

char *settings_get_print(SETTINGS_REC *rec)
{
	char *value = NULL;

	switch(rec->type) {
	case SETTING_TYPE_BOOLEAN:
		value = g_strdup(settings_get_bool(rec->key) ? "ON" : "OFF");
		break;
	case SETTING_TYPE_INT:
		value = g_strdup_printf("%d", settings_get_int(rec->key));
		break;
	case SETTING_TYPE_STRING:
	case SETTING_TYPE_TIME:
	case SETTING_TYPE_LEVEL:
	case SETTING_TYPE_SIZE:
		value = g_strdup(settings_get_str(rec->key));
		break;
	}
	return value;
}

static void settings_add(const char *module, const char *section,
			 const char *key, SettingType type,
			 const SettingValue *default_value)
{
	SETTINGS_REC *rec;

	g_return_if_fail(key != NULL);
	g_return_if_fail(section != NULL);

	rec = g_hash_table_lookup(settings, key);
	if (rec != NULL) {
		/* Already exists, make sure it's correct type */
		if (rec->type != type) {
			g_warning("Trying to add already existing "
				  "setting '%s' with different type.", key);
			return;
		}
		rec->refcount++;
	} else {
		rec = g_new(SETTINGS_REC, 1);
		rec->refcount = 1;
		rec->module = g_strdup(module);
		rec->key = g_strdup(key);
		rec->section = g_strdup(section);
                rec->type = type;

		rec->default_value = *default_value;
		g_hash_table_insert(settings, rec->key, rec);
	}
}

void settings_add_str_module(const char *module, const char *section,
			     const char *key, const char *def)
{
	SettingValue default_value;

	memset(&default_value, 0, sizeof(default_value));
	default_value.v_string = g_strdup(def);
	settings_add(module, section, key, SETTING_TYPE_STRING, &default_value);
}

void settings_add_int_module(const char *module, const char *section,
			     const char *key, int def)
{
	SettingValue default_value;

	memset(&default_value, 0, sizeof(default_value));
        default_value.v_int = def;
	settings_add(module, section, key, SETTING_TYPE_INT, &default_value);
}

void settings_add_bool_module(const char *module, const char *section,
			      const char *key, int def)
{
	SettingValue default_value;

	memset(&default_value, 0, sizeof(default_value));
        default_value.v_bool = def;
	settings_add(module, section, key, SETTING_TYPE_BOOLEAN,
		     &default_value);
}

void settings_add_time_module(const char *module, const char *section,
			      const char *key, const char *def)
{
	SettingValue default_value;

	memset(&default_value, 0, sizeof(default_value));
	default_value.v_string = g_strdup(def);
	settings_add(module, section, key, SETTING_TYPE_TIME, &default_value);
}

void settings_add_level_module(const char *module, const char *section,
			       const char *key, const char *def)
{
	SettingValue default_value;

	memset(&default_value, 0, sizeof(default_value));
	default_value.v_string = g_strdup(def);
	settings_add(module, section, key, SETTING_TYPE_LEVEL, &default_value);
}

void settings_add_size_module(const char *module, const char *section,
			      const char *key, const char *def)
{
	SettingValue default_value;

	memset(&default_value, 0, sizeof(default_value));
	default_value.v_string = g_strdup(def);
	settings_add(module, section, key, SETTING_TYPE_SIZE, &default_value);
}

static void settings_destroy(SETTINGS_REC *rec)
{
	if (rec->type != SETTING_TYPE_INT &&
	    rec->type != SETTING_TYPE_BOOLEAN)
		g_free(rec->default_value.v_string);
        g_free(rec->module);
        g_free(rec->section);
        g_free(rec->key);
	g_free(rec);
}

static void settings_unref(SETTINGS_REC *rec, int remove_hash)
{
	if (--rec->refcount == 0) {
		if (remove_hash)
			g_hash_table_remove(settings, rec->key);
		settings_destroy(rec);
	}
}

void settings_remove(const char *key)
{
	SETTINGS_REC *rec;

	g_return_if_fail(key != NULL);

	rec = g_hash_table_lookup(settings, key);
	if (rec != NULL)
		settings_unref(rec, TRUE);
}

static int settings_remove_hash(const char *key, SETTINGS_REC *rec,
				const char *module)
{
	if (strcmp(rec->module, module) == 0) {
		settings_unref(rec, FALSE);
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
	if (rec == NULL) {
		g_warning("Changing unknown setting '%s'", key);
		return NULL;
	}

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

int settings_set_time(const char *key, const char *value)
{
	int msecs;

	if (!parse_time_interval(value, &msecs))
		return FALSE;

	iconfig_node_set_str(settings_get_node(key), key, value);
	return TRUE;
}

int settings_set_level(const char *key, const char *value)
{
	int iserror;

	(void)level2bits(value, &iserror);
	if (iserror)
		return FALSE;

        iconfig_node_set_str(settings_get_node(key), key, value);
	return TRUE;
}

int settings_set_size(const char *key, const char *value)
{
	int size;

	if (!parse_size(value, &size))
		return FALSE;

        iconfig_node_set_str(settings_get_node(key), key, value);
	return TRUE;
}

SettingType settings_get_type(const char *key)
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

	if (config_changed) {
		/* some backwards compatibility changes were made to
		   config file, reload it */
		g_warning("Some settings were automatically "
			  "updated, please /SAVE");
		signal_emit("setup changed", 0);
	}
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

	for (tmp = config_node_first(node->value); tmp != NULL; tmp = next) {
		CONFIG_NODE *subnode = tmp->data;
                next = config_node_next(tmp);

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

		last_invalid_modules =
			g_slist_remove(last_invalid_modules, module);
                g_free(module);
	}
}

static int backwards_compatibility(const char *module, CONFIG_NODE *node,
				   CONFIG_NODE *parent)
{
	const char *new_key, *new_module;
	CONFIG_NODE *new_node;
	char *new_value;

	new_value = NULL; new_key = NULL; new_module = NULL;

	/* fe-text term_type -> fe-common/core term_charset - for 0.8.10-> */
	if (strcmp(module, "fe-text") == 0) {
		if (g_ascii_strcasecmp(node->key, "term_type") == 0 ||
		    /* kludge for cvs-version where term_charset was in fe-text */
		    g_ascii_strcasecmp(node->key, "term_charset") == 0) {
			new_module = "fe-common/core";
			new_key = "term_charset";
			new_value = !is_valid_charset(node->value) ? NULL :
				g_strdup(node->value);
			new_node = iconfig_node_traverse("settings", FALSE);
			new_node = new_node == NULL ? NULL :
				config_node_section(new_node, new_module, -1);

			config_node_set_str(mainconfig, new_node,
					    new_key, new_value);
			/* remove old */
			config_node_set_str(mainconfig, parent,
					    node->key, NULL);
			g_free(new_value);
			config_changed = TRUE;
			return new_key != NULL;
		} else if (g_ascii_strcasecmp(node->key, "actlist_moves") == 0 &&
			   node->value != NULL && g_ascii_strcasecmp(node->value, "yes") == 0) {
			config_node_set_str(mainconfig, parent, "actlist_sort", "recent");
			config_node_set_str(mainconfig, parent, node->key, NULL);
			config_changed = TRUE;
			return TRUE;
		}
	}
	return new_key != NULL;
}

/* verify that all settings in config file for `module' are actually found
   from /SET list */
void settings_check_module(const char *module)
{
        SETTINGS_REC *set;
	CONFIG_NODE *node, *parent;
        GString *errors;
	GSList *tmp, *next;
        int count;

        g_return_if_fail(module != NULL);

	node = iconfig_node_traverse("settings", FALSE);
	node = node == NULL ? NULL : config_node_section(node, module, -1);
	if (node == NULL) return;

        errors = g_string_new(NULL);
	g_string_printf(errors, "Unknown settings in configuration "
			 "file for module %s:", module);

        count = 0;
	parent = node;
	tmp = config_node_first(node->value);
	for (; tmp != NULL; tmp = next) {
		node = tmp->data;
		next = config_node_next(tmp);

		set = g_hash_table_lookup(settings, node->key);
		if (backwards_compatibility(module, node, parent))
			continue;

		if (set == NULL || strcmp(set->module, module) != 0) {
			g_string_append_printf(errors, " %s", node->key);
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
	int cmp = strcmp(v1->section, v2->section);
	if (!cmp)
		cmp = strcmp(v1->key, v2->key);
	return cmp;
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
	char *str;

	if (fname == NULL)
		fname = get_irssi_config();

	if (stat(fname, &statbuf) == 0)
		path = fname;
	else {
		/* user configuration file not found, use the default one
		   from sysconfdir */
                path = SYSCONFDIR"/"IRSSI_GLOBAL_CONFIG;
		if (stat(path, &statbuf) != 0) {
			/* no configuration file in sysconfdir ..
			   use the build-in configuration */
                        path = NULL;
		}
	}

	config = config_open(path, -1);
	if (config == NULL) {
		str = g_strdup_printf("Error opening configuration file %s: %s",
				      path, g_strerror(errno));
		signal_emit("gui dialog", 2, "error", str);
                g_free(str);

		config = config_open(NULL, -1);
	}

        if (config->fname != NULL)
		config_parse(config);
        else
		config_parse_data(config, default_config, "internal");

	config_change_file_name(config, fname, 0660);
        irssi_config_save_state(fname);
	return config;
}

static void init_configfile(void)
{
	struct stat statbuf;
	char *str;

	if (stat(get_irssi_dir(), &statbuf) != 0) {
		/* ~/.irssi not found, create it. */
		if (mkpath(get_irssi_dir(), 0700) != 0) {
			g_error("Couldn't create %s directory", get_irssi_dir());
		}
	} else if (!S_ISDIR(statbuf.st_mode)) {
		g_error("%s is not a directory.\n"
			"You should remove it with command: rm %s",
			get_irssi_dir(), get_irssi_dir());
	}

	mainconfig = parse_configfile(NULL);
	config_last_modifycounter = mainconfig->modifycounter;

	/* any errors? */
	if (config_last_error(mainconfig) != NULL) {
		str = g_strdup_printf("Ignored errors in configuration file:\n%s",
				      config_last_error(mainconfig));
		signal_emit("gui dialog", 2, "error", str);
                g_free(str);
	}

	signal(SIGTERM, sig_term);
}

int settings_reread(const char *fname)
{
	CONFIG_REC *tempconfig;
	char *str;

	str = fname == NULL ? NULL : convert_home(fname);
	tempconfig = parse_configfile(str);
        g_free_not_null(str);

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
	signal_emit("setup reread", 1, mainconfig->fname);
        return TRUE;
}

int settings_save(const char *fname, int autosave)
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
	signal_emit("setup saved", 2, fname, GINT_TO_POINTER(autosave));
        return !error;
}

static int sig_autosave(void)
{
	char *fname, *str;

	if (!settings_get_bool("settings_autosave") ||
	    config_last_modifycounter == mainconfig->modifycounter)
		return 1;

	if (!irssi_config_is_changed(NULL))
		settings_save(NULL, TRUE);
	else {
		fname = g_strconcat(mainconfig->fname, ".autosave", NULL);
		str = g_strdup_printf("Configuration file was modified "
				      "while irssi was running. Saving "
				      "configuration to file '%s' instead. "
				      "Use /SAVE or /RELOAD to get rid of "
				      "this message.", fname);
		signal_emit("gui dialog", 2, "warning", str);
		g_free(str);

                settings_save(fname, TRUE);
		g_free(fname);
	}

        return 1;
}

void settings_init(void)
{
	settings = g_hash_table_new((GHashFunc) g_istr_hash,
				    (GCompareFunc) g_istr_equal);

	last_errors = NULL;
        last_invalid_modules = NULL;
	fe_initialized = FALSE;
        config_changed = FALSE;

	config_last_mtime = 0;
	config_last_modifycounter = 0;
	init_configfile();

	settings_add_bool("misc", "settings_autosave", TRUE);
	timeout_tag = g_timeout_add(SETTINGS_AUTOSAVE_TIMEOUT,
				    (GSourceFunc) sig_autosave, NULL);
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
