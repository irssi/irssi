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
#include "commands.h"
#include "levels.h"
#include "misc.h"
#include "lib-config/iconfig.h"
#include "settings.h"

#include "printtext.h"
#include "themes.h"

GSList *themes;
THEME_REC *current_theme;
GHashTable *default_formats;

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

static void theme_module_destroy(const char *key, MODULE_THEME_REC *rec)
{
	int n;

	for (n = 0; n < rec->count; n++)
		if (rec->formats[n] != NULL)
			g_free(rec->formats[n]);
	g_free(rec->formats);

	g_free(rec->name);
	g_free(rec);
}

void theme_destroy(THEME_REC *rec)
{
	signal_emit("theme destroyed", 1, rec);
	g_hash_table_foreach(rec->modules, (GHFunc) theme_module_destroy, NULL);
	g_hash_table_destroy(rec->modules);

	if (rec->bg_pixmap != NULL) g_free(rec->bg_pixmap);
	if (rec->font != NULL) g_free(rec->font);
	g_free(rec->path);
	g_free(rec->name);
	g_free(rec);
}

static MODULE_THEME_REC *theme_module_create(THEME_REC *theme, const char *module)
{
	MODULE_THEME_REC *rec;
	FORMAT_REC *formats;

	rec = g_hash_table_lookup(theme->modules, module);
	if (rec != NULL) return rec;

	formats = g_hash_table_lookup(default_formats, module);
        g_return_val_if_fail(formats != NULL, NULL);

	rec = g_new0(MODULE_THEME_REC, 1);
	rec->name = g_strdup(module);

	for (rec->count = 0; formats[rec->count].def != NULL; rec->count++) ;
	rec->formats = g_new0(char *, rec->count);

	g_hash_table_insert(theme->modules, rec->name, rec);
	return rec;
}

static void theme_read_formats(CONFIG_REC *config, THEME_REC *theme, const char *module)
{
	MODULE_THEME_REC *rec;
	FORMAT_REC *formats;
	CONFIG_NODE *node;
	GSList *tmp;
	int n;

	formats = g_hash_table_lookup(default_formats, module);
	if (formats == NULL) return;

	node = config_node_traverse(config, "formats", FALSE);
	if (node == NULL) return;
	node = config_node_section(node, module, -1);
	if (node == NULL) return;

	rec = theme_module_create(theme, module);

	for (tmp = node->value; tmp != NULL; tmp = tmp->next) {
		node = tmp->data;

		if (node->key == NULL || node->value == NULL)
                        continue;

		for (n = 0; formats[n].def != NULL; n++) {
			if (formats[n].tag != NULL &&
			    g_strcasecmp(formats[n].tag, node->key) == 0) {
				rec->formats[n] = g_strdup(node->value);
				break;
			}
		}
	}
}

static void theme_read_module(THEME_REC *theme, const char *module)
{
	CONFIG_REC *config;
	char *msg;

	config = config_open(theme->path, -1);
	if (config == NULL) return;

	config_parse(config);

	if (config_last_error(mainconfig) != NULL) {
		msg = g_strdup_printf(_("Ignored errors in theme:\n%s"),
				      config_last_error(mainconfig));
		signal_emit("gui dialog", 2, "error", msg);
		g_free(msg);
	}

	theme_read_formats(config, theme, module);

	config_close(config);
}

static void theme_remove_module(THEME_REC *theme, const char *module)
{
	MODULE_THEME_REC *rec;

	rec = g_hash_table_lookup(theme->modules, module);
	if (rec == NULL) return;

	g_hash_table_remove(theme->modules, module);
	theme_module_destroy(module, rec);
}

void theme_register_module(const char *module, FORMAT_REC *formats)
{
	if (g_hash_table_lookup(default_formats, module) != NULL)
		return;

        g_hash_table_insert(default_formats, g_strdup(module), formats);

	if (current_theme != NULL)
                theme_read_module(current_theme, module);
}

void theme_unregister_module(const char *module)
{
        gpointer key, value;

	if (!g_hash_table_lookup_extended(default_formats, module, &key, &value))
		return;

	g_hash_table_remove(default_formats, key);
	g_free(key);

	if (current_theme != NULL)
		theme_remove_module(current_theme, module);
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

static void theme_read(THEME_REC *theme, const char *path)
{
        CONFIG_REC *config;
	char *value;

	config = config_open(path, -1);
	if (config == NULL) {
		/* didn't exist or no access? */
		theme->default_color = 15;
		return;
	}

        config_parse(config);

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
	config_close(config);
}

typedef struct {
	char *name;
	char *short_name;
} THEME_SEARCH_REC;

static int theme_search_equal(THEME_SEARCH_REC *r1, THEME_SEARCH_REC *r2)
{
	return g_strcasecmp(r1->short_name, r2->short_name);
}

static void theme_get_modules(char *module, FORMAT_REC *formats, GSList **list)
{
	THEME_SEARCH_REC *rec;

	rec = g_new(THEME_SEARCH_REC, 1);
	rec->name = module;
	rec->short_name = strrchr(module, '/');
	if (rec->short_name != NULL)
		rec->short_name++; else rec->short_name = module;
	*list = g_slist_insert_sorted(*list, rec, (GCompareFunc) theme_search_equal);
}

static GSList *get_sorted_modules(void)
{
	GSList *list;

	list = NULL;
	g_hash_table_foreach(default_formats, (GHFunc) theme_get_modules, &list);
	return list;
}

static THEME_SEARCH_REC *theme_search(GSList *list, const char *module)
{
	THEME_SEARCH_REC *rec;

	while (list != NULL) {
		rec = list->data;

		if (g_strcasecmp(rec->short_name, module) == 0)
			return rec;
		list = list->next;
	}

	return NULL;
}

static void theme_show(THEME_SEARCH_REC *rec, const char *key, const char *value)
{
	MODULE_THEME_REC *theme;
	FORMAT_REC *formats;
	const char *text, *last_title;
	int n, first;

	formats = g_hash_table_lookup(default_formats, rec->name);
	theme = g_hash_table_lookup(current_theme->modules, rec->name);

	last_title = NULL; first = TRUE;
	for (n = 1; formats[n].def != NULL; n++) {
		text = theme != NULL && theme->formats[n] != NULL ?
			theme->formats[n] : formats[n].def;

		if (formats[n].tag == NULL)
			last_title = text;
		else if ((value != NULL && key != NULL && g_strcasecmp(formats[n].tag, key) == 0) ||
			 (value == NULL && (key == NULL || stristr(formats[n].tag, key) != NULL))) {
			if (first) {
				printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "");
				printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "%K[%W%s%K] - [%W%s%K]", rec->short_name, formats[0].def);
				printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "");
				first = FALSE;
			}
			if (last_title != NULL)
				printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "%K[%W%s%K]", last_title);
			if (value != NULL) {
				theme = theme_module_create(current_theme, rec->name);
                                theme->formats[n] = g_strdup(value);
				text = value;
			}
			printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "%s %K=%n %s", formats[n].tag, text);
			last_title = NULL;
		}
	}
}

static void cmd_format(const char *data)
{
	char *params, *module, *key, *value;
	GSList *tmp, *modules;

	/* /FORMAT [<module>] [<key> [<value>]] */
	params = cmd_get_params(data, 3 | PARAM_FLAG_GETREST, &module, &key, &value);

        modules = get_sorted_modules();
	if (*module != '\0' && theme_search(modules, module) == NULL) {
		/* first argument isn't module.. */
		g_free(params);
		params = cmd_get_params(data, 2 | PARAM_FLAG_GETREST, &key, &value);
		module = "";
	}

	if (*key == '\0') key = NULL;
	if (*value == '\0') value = NULL;

	for (tmp = modules; tmp != NULL; tmp = tmp->next) {
		THEME_SEARCH_REC *rec = tmp->data;

		if (*module == '\0' || g_strcasecmp(rec->short_name, module) == 0)
			theme_show(rec, key, value);
	}
	g_slist_foreach(modules, (GFunc) g_free, NULL);
	g_slist_free(modules);

	g_free(params);
}

static void module_save(const char *module, MODULE_THEME_REC *rec, CONFIG_NODE *fnode)
{
	CONFIG_NODE *node;
	FORMAT_REC *formats;
	int n;

	formats = g_hash_table_lookup(default_formats, rec->name);
	if (formats == NULL) return;

	node = config_node_section(fnode, rec->name, NODE_TYPE_BLOCK);
	for (n = 0; formats[n].def != NULL; n++) {
                if (rec->formats[n] != NULL)
			iconfig_node_set_str(node, formats[n].tag, rec->formats[n]);
	}
}

/* save changed formats */
static void cmd_save(void)
{
	CONFIG_REC *config;
	CONFIG_NODE *fnode;

	config = config_open(current_theme->path, 0660);
	if (config == NULL) return;

	config_parse(config);

	fnode = config_node_traverse(config, "formats", TRUE);
	g_hash_table_foreach(current_theme->modules, (GHFunc) module_save, fnode);

	if (config_write(config, NULL, 0660) == -1) {
		/* we probably tried to save to global directory
		   where we didn't have access.. try saving it to
		   home dir instead. */
		char *str;

		/* check that we really didn't try to save
		   it to home dir.. */
		str = g_strdup_printf("%s/.irssi/", g_get_home_dir());
		if (strncmp(current_theme->path, str, strlen(str)) != 0) {
			g_free(str);
			str = g_strdup_printf("%s/.irssi/%s", g_get_home_dir(), g_basename(current_theme->path));

			config_write(config, str, 0660);
		}
		g_free(str);
	}
	config_close(config);
}

void themes_init(void)
{
	THEME_REC *rec;
	GSList *tmp;
	const char *value;
	char *str;

        default_formats = g_hash_table_new((GHashFunc) g_str_hash, (GCompareFunc) g_str_equal);

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
	for (tmp = themes; tmp != NULL; tmp = tmp->next) {
		rec = tmp->data;

		theme_read(rec, rec->path);
	}

	/* find the current theme to use */
	value = settings_get_str("current_theme");

	rec = theme_find(value);
	if (rec != NULL) current_theme = rec;

	command_bind("format", NULL, (SIGNAL_FUNC) cmd_format);
	command_bind("save", NULL, (SIGNAL_FUNC) cmd_save);
}

void themes_deinit(void)
{
	/* free memory used by themes */
	g_slist_foreach(themes, (GFunc) theme_destroy, NULL);
	g_slist_free(themes);
	themes = NULL;

	g_hash_table_destroy(default_formats);

	command_unbind("format", (SIGNAL_FUNC) cmd_format);
	command_unbind("save", (SIGNAL_FUNC) cmd_save);
}
