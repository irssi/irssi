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

static GHashTable *settings;
static char *last_error_msg;
static int timeout_tag;

static time_t config_last_mtime;
static long config_last_size;
static unsigned int config_last_checksum;

static const char *settings_get_default_str(const char *key)
{
	SETTINGS_REC *rec;

	g_return_val_if_fail(key != NULL, NULL);

	rec = g_hash_table_lookup(settings, key);
	if (rec == NULL) {
		g_warning("settings_get_default_str(%s) : "
			  "unknown setting", key);
		return NULL;
	}

	return rec->def;
}

static int settings_get_default_int(const char *key)
{
	SETTINGS_REC *rec;

	g_return_val_if_fail(key != NULL, -1);

	rec = g_hash_table_lookup(settings, key);
	if (rec == NULL) {
		g_warning("settings_get_default_int(%s) : "
			  "unknown setting", key);
		return -1;
	}

	return GPOINTER_TO_INT(rec->def);
}

const char *settings_get_str(const char *key)
{
	return iconfig_get_str("settings", key, settings_get_default_str(key));
}

int settings_get_int(const char *key)
{
	return iconfig_get_int("settings", key, settings_get_default_int(key));
}

int settings_get_bool(const char *key)
{
	return iconfig_get_bool("settings", key,
				settings_get_default_int(key));
}

void settings_add_str(const char *section, const char *key, const char *def)
{
	SETTINGS_REC *rec;

	g_return_if_fail(key != NULL);
	g_return_if_fail(section != NULL);

	rec = g_hash_table_lookup(settings, key);
	g_return_if_fail(rec == NULL);

	rec = g_new0(SETTINGS_REC, 1);
	rec->key = g_strdup(key);
	rec->section = g_strdup(section);
	rec->def = def == NULL ? NULL : g_strdup(def);

	g_hash_table_insert(settings, rec->key, rec);
}

void settings_add_int(const char *section, const char *key, int def)
{
	SETTINGS_REC *rec;

	g_return_if_fail(key != NULL);
	g_return_if_fail(section != NULL);

	rec = g_hash_table_lookup(settings, key);
	g_return_if_fail(rec == NULL);

	rec = g_new0(SETTINGS_REC, 1);
	rec->type = SETTING_TYPE_INT;
	rec->key = g_strdup(key);
	rec->section = g_strdup(section);
	rec->def = GINT_TO_POINTER(def);

	g_hash_table_insert(settings, rec->key, rec);
}

void settings_add_bool(const char *section, const char *key, int def)
{
	SETTINGS_REC *rec;

	g_return_if_fail(key != NULL);
	g_return_if_fail(section != NULL);

	rec = g_hash_table_lookup(settings, key);
	g_return_if_fail(rec == NULL);

	rec = g_new0(SETTINGS_REC, 1);
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
	FILE *f;
	int n = 0;
	unsigned int checksum = 0;

	f = fopen(fname, "rb");
	while (!feof(f))
		checksum += fgetc(f) << ((n++ & 3)*8);
	fclose(f);
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
	char *real_fname;

	real_fname = fname != NULL ? g_strdup(fname) :
		g_strdup_printf("%s/.irssi/config", g_get_home_dir());
	config = config_open(real_fname, -1);

	if (config != NULL)
		config_parse(config);
	else if (fname == NULL) {
		/* user configuration file not found, use the default one
		   from sysconfdir */
		config = config_open(SYSCONFDIR"/irssi/config", -1);
		if (config != NULL)
			config_parse(config);
		else {
			/* no configuration file in sysconfdir ..
			   use the build-in configuration */
			config = config_open(NULL, -1);
			config_parse_data(config, default_config, "internal");
		}

                config_change_file_name(config, real_fname, 0660);
	}

        irssi_config_save_state(real_fname);
	g_free(real_fname);
	return config;
}

static void sig_print_config_error(void)
{
	signal_emit("gui dialog", 2, "error", last_error_msg);
	signal_remove("irssi init finished",
		      (SIGNAL_FUNC) sig_print_config_error);

	g_free_and_null(last_error_msg);
}

static void init_configfile(void)
{
	struct stat statbuf;
	char *str;

	str = g_strdup_printf("%s/.irssi", g_get_home_dir());
	if (stat(str, &statbuf) != 0) {
		/* ~/.irssi not found, create it. */
		if (mkpath(str, 0700) != 0) {
			g_error(_("Couldn't create %s/.irssi directory"),
				g_get_home_dir());
		}
	} else if (!S_ISDIR(statbuf.st_mode)) {
		g_error(_("%s/.irssi is not a directory.\n"
			  "You should remove it with command: rm ~/.irssi"),
			g_get_home_dir());
	}
	g_free(str);

	mainconfig = parse_configfile(NULL);

	/* any errors? */
	if (config_last_error(mainconfig) != NULL) {
		last_error_msg =
			g_strdup_printf(_("Ignored errors in configuration "
					  "file:\n%s"),
					config_last_error(mainconfig));
		signal_add("irssi init finished",
			   (SIGNAL_FUNC) sig_print_config_error);
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
		str = g_strdup_printf(_("Errors in configuration file:\n%s"),
				      config_last_error(tempconfig));
		signal_emit("gui dialog", 2, "error", str);
		g_free(str);

		config_close(tempconfig);
                return FALSE;
	}

	config_close(mainconfig);
	mainconfig = tempconfig;

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
	if (error) {
		str = g_strdup_printf(_("Couldn't save "
					"configuration file: %s"),
				      config_last_error(mainconfig));
		signal_emit("gui dialog", 2, "error", str);
		g_free(str);
	}
        return !error;
}

static void sig_autosave(void)
{
	char *fname, *str;

	if (!settings_get_bool("settings_autosave"))
		return;

	if (!irssi_config_is_changed(NULL))
		settings_save(NULL);
	else {
		fname = g_strconcat(mainconfig->fname, ".autosave", NULL);
		str = g_strdup_printf(_("Configuration file was modified "
					"while irssi was running. Saving "
					"configuration to file '%s' instead"),
					fname);
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

	config_last_mtime = 0;
	init_configfile();

	settings_add_bool("misc", "settings_autosave", TRUE);
	timeout_tag = g_timeout_add(1000*60*60, (GSourceFunc) sig_autosave, NULL);
	signal_add("gui exit", (SIGNAL_FUNC) sig_autosave);
}

static void settings_hash_free(const char *key, SETTINGS_REC *rec)
{
	settings_destroy(rec);
}

void settings_deinit(void)
{
        g_source_remove(timeout_tag);
	signal_remove("gui exit", (SIGNAL_FUNC) sig_autosave);

        g_free_not_null(last_error_msg);
	g_hash_table_foreach(settings, (GHFunc) settings_hash_free, NULL);
	g_hash_table_destroy(settings);

	if (mainconfig != NULL) config_close(mainconfig);
}
