/*
 themes.c : irssi

    Copyright (C) 1999-2000 Timo Sirainen

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
#include "misc.h"
#include "lib-config/iconfig.h"
#include "settings.h"

#include "printtext.h"
#include "themes.h"

GSList *themes;
THEME_REC *current_theme;

THEME_REC *theme_create(const char *path, const char *name)
{
	THEME_REC *rec;

	g_return_val_if_fail(path != NULL, NULL);
	g_return_val_if_fail(name != NULL, NULL);

	rec = g_new0(THEME_REC, 1);
	rec->path = g_strdup(path);
	rec->name = g_strdup(name);
	rec->modules = g_hash_table_new((GHashFunc) g_istr_hash, (GCompareFunc) g_istr_equal);
	signal_emit("theme created", 1, rec);

	return rec;
}

static void theme_destroy_hash(const char *key, MODULE_THEME_REC *rec)
{
	int n, max;

	max = strarray_length(rec->formatlist);
	for (n = 0; n < max; n++)
		if (rec->format[n] != NULL)
			g_free(rec->format[n]);
	g_free(rec->format);

	g_strfreev(rec->formatlist);
	g_free(rec->name);
	g_free(rec);
}

void theme_destroy(THEME_REC *rec)
{
	signal_emit("theme destroyed", 1, rec);
	g_hash_table_foreach(rec->modules, (GHFunc) theme_destroy_hash, NULL);
	g_hash_table_destroy(rec->modules);

	if (rec->bg_pixmap != NULL) g_free(rec->bg_pixmap);
	if (rec->font != NULL) g_free(rec->font);
	g_free(rec->path);
	g_free(rec->name);
	g_free(rec);
}

static THEME_REC *theme_find(const char *name)
{
	GSList *tmp;

	for (tmp = themes; tmp != NULL; tmp = tmp->next) {
		THEME_REC *rec = tmp->data;

		if (g_strcasecmp(rec->name, name) == 0)
			return rec;
	}

	return NULL;
}

/* Add all *.theme files from directory to themes */
static void find_themes(gchar *path)
{
	DIR *dirp;
	struct dirent *dp;
	char *fname, *name;
	int len;

	dirp = opendir(path);
	if (dirp == NULL) return;

	while ((dp = readdir(dirp)) != NULL) {
		len = strlen(dp->d_name);
		if (len <= 6 || strcmp(dp->d_name+len-6, ".theme") != 0)
			continue;

		name = g_strndup(dp->d_name, strlen(dp->d_name)-6);
		if (!theme_find(name)) {
			fname = g_strdup_printf("%s/%s", path, dp->d_name);
			themes = g_slist_append(themes, theme_create(fname, name));
			g_free(fname);
		}
		g_free(name);
	}
	closedir(dirp);
}

/* Read module texts into theme */
static void theme_read_module_texts(const char *hashkey, MODULE_THEME_REC *rec, CONFIG_REC *config)
{
	CONFIG_NODE *formats;
	GSList *tmp;
	char **flist;
	int n;

	formats = config_node_traverse(config, "moduleformats", FALSE);
	if (formats == NULL) return;

	for (tmp = formats->value; tmp != NULL; tmp = tmp->next) {
		CONFIG_NODE *node = tmp->data;

		if (node->key == NULL || node->value == NULL)
                        continue;

		for (n = 0, flist = rec->formatlist; *flist != NULL; flist++, n++) {
			if (g_strcasecmp(*flist, node->key) == 0) {
				rec->format[n] = g_strdup(node->value);
				break;
			}
		}
	}
}

static int theme_read(THEME_REC *theme, const char *path)
{
	MODULE_THEME_REC *mrec;
        CONFIG_REC *config;
	CONFIG_NODE *formats;
	GSList *tmp;
	char *value;
	int errors;

	config = config_open(path, -1);
	if (config == NULL) {
		/* didn't exist or no access? */
		theme->default_color = 15;
		return FALSE;
	}

        errors = config_parse(config) == -1;

	/* default color */
	theme->default_color = config_get_int(config, NULL, "default_color", 15);
	/* get font */
	value = config_get_str(config, NULL, "font", NULL);
	theme->font = (value == NULL || *value == '\0') ? NULL : g_strdup(value);

	/* get background pixmap */
	value = config_get_str(config, NULL, "bg_pixmap", NULL);
	theme->bg_pixmap = (value == NULL || *value == '\0') ? NULL : g_strdup(value);
	/* get background pixmap properties */
	if (config_get_bool(config, NULL, "bg_scrollable", FALSE))
		theme->flags |= THEME_FLAG_BG_SCROLLABLE;
	if (config_get_bool(config, NULL, "bg_scaled", TRUE))
		theme->flags |= THEME_FLAG_BG_SCALED;
	if (config_get_bool(config, NULL, "bg_shaded", FALSE))
		theme->flags |= THEME_FLAG_BG_SHADED;

	/* Read modules that are defined in this theme. */
	formats = config_node_traverse(config, "modules", FALSE);
	if (formats != NULL) {
		for (tmp = formats->value; tmp != NULL; tmp = tmp->next) {
			CONFIG_NODE *node = tmp->data;

			if (node->key == NULL || node->value == NULL)
				continue;

			mrec = g_new0(MODULE_THEME_REC, 1);
			mrec->name = g_strdup(node->key);
			mrec->formatlist = g_strsplit(node->value, " ", -1);
			mrec->format = g_new0(char*, strarray_length(mrec->formatlist));
			g_hash_table_insert(theme->modules, mrec->name, mrec);
		}
	}

	/* Read the texts inside the plugin */
	g_hash_table_foreach(theme->modules, (GHFunc) theme_read_module_texts, config);

	if (errors) {
		/* errors fixed - save the theme */
		if (config_write(config, NULL, 0660) == -1) {
			/* we probably tried to save to global directory
			   where we didn't have access.. try saving it to
			   home dir instead. */
			char *str;

			/* check that we really didn't try to save
			   it to home dir.. */
			str = g_strdup_printf("%s/.irssi/", g_get_home_dir());
			if (strncmp(path, str, strlen(str)) != 0) {
				g_free(str);
				str = g_strdup_printf("%s/.irssi/%s", g_get_home_dir(), g_basename(path));

				config_write(config, str, 0660);
			}
			g_free(str);
		}
	}
	config_close(config);

	return errors;
}

static void sig_formats_error(void)
{
	signal_emit("gui dialog", 2, "warning",
		    "Your theme(s) had some old format strings, "
		    "these have been changed back to their default values.");
	signal_remove("irssi init finished", (SIGNAL_FUNC) sig_formats_error);
}

void themes_init(void)
{
	THEME_REC *rec;
	GSList *tmp;
	const char *value;
	char *str;
	int errors;

	/* first there's default theme.. */
	str = g_strdup_printf("%s/.irssi/default.theme", g_get_home_dir());
	current_theme = theme_create(str, "default");
	current_theme->default_color = 15;
	themes = g_slist_append(NULL, current_theme);
	g_free(str);

	/* read list of themes */
	str = g_strdup_printf("%s/.irssi", g_get_home_dir());
	find_themes(str);
	g_free(str);
	find_themes(SYSCONFDIR"/irssi");

	/* read formats for all themes */
	errors = FALSE;
	for (tmp = themes; tmp != NULL; tmp = tmp->next) {
		rec = tmp->data;

		if (theme_read(rec, rec->path))
			errors = TRUE;
	}

	if (errors)
		signal_add("irssi init finished", (SIGNAL_FUNC) sig_formats_error);

	/* find the current theme to use */
	value = settings_get_str("current_theme");

	rec = theme_find(value);
	if (rec != NULL) current_theme = rec;
}

void themes_deinit(void)
{
	/* free memory used by themes */
	g_slist_foreach(themes, (GFunc) theme_destroy, NULL);
	g_slist_free(themes);
	themes = NULL;
}
