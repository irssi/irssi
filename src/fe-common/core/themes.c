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
#include "module-formats.h"
#include "signals.h"
#include "commands.h"
#include "levels.h"
#include "misc.h"
#include "special-vars.h"
#include "lib-config/iconfig.h"
#include "settings.h"

#include "themes.h"

GSList *themes;
THEME_REC *current_theme;
GHashTable *default_formats;

static void theme_read(THEME_REC *theme, const char *path);

THEME_REC *theme_create(const char *path, const char *name)
{
	THEME_REC *rec;

	g_return_val_if_fail(path != NULL, NULL);
	g_return_val_if_fail(name != NULL, NULL);

	rec = g_new0(THEME_REC, 1);
	rec->path = g_strdup(path);
	rec->name = g_strdup(name);
	rec->abstracts = g_hash_table_new((GHashFunc) g_str_hash,
					  (GCompareFunc) g_str_equal);
	rec->modules = g_hash_table_new((GHashFunc) g_istr_hash,
					(GCompareFunc) g_istr_equal);
	themes = g_slist_append(themes, rec);
	signal_emit("theme created", 1, rec);

	return rec;
}

static void theme_abstract_destroy(char *key, char *value)
{
	g_free(key);
        g_free(value);
}

static void theme_module_destroy(const char *key, MODULE_THEME_REC *rec)
{
	int n;

	for (n = 0; n < rec->count; n++) {
		g_free_not_null(rec->formats[n]);
		g_free_not_null(rec->expanded_formats[n]);
	}
	g_free(rec->formats);
	g_free(rec->expanded_formats);

	g_free(rec->name);
	g_free(rec);
}

void theme_destroy(THEME_REC *rec)
{
	themes = g_slist_remove(themes, rec);

	signal_emit("theme destroyed", 1, rec);

	g_hash_table_foreach(rec->abstracts, (GHFunc) theme_abstract_destroy, NULL);
	g_hash_table_destroy(rec->abstracts);
	g_hash_table_foreach(rec->modules, (GHFunc) theme_module_destroy, NULL);
	g_hash_table_destroy(rec->modules);

	g_slist_foreach(rec->replace_keys, (GFunc) g_free, NULL);
	g_slist_free(rec->replace_keys);
	g_slist_foreach(rec->replace_values, (GFunc) g_free, NULL);
	g_slist_free(rec->replace_values);

	g_free(rec->path);
	g_free(rec->name);
	g_free(rec);
}

static char *theme_format_expand_data(THEME_REC *theme,
				      const char **format,
				      char default_color,
				      char *before_arg_color, int root);

static int theme_replace_find(THEME_REC *theme, char chr)
{
	GSList *tmp;
	int index = 0;

	for (tmp = theme->replace_keys; tmp != NULL; tmp = tmp->next) {
		if (strchr(tmp->data, chr) != NULL)
			return index;
		index++;
	}

	return -1;
}

static char *theme_replace_expand(THEME_REC *theme, int index,
				  char default_color, char chr)
{
	GSList *rec;
	char *ret, *abstract, data[2];

	rec = g_slist_nth(theme->replace_values, index);
	g_return_val_if_fail(rec != NULL, NULL);

	data[0] = chr; data[1] = '\0';

	abstract = rec->data;
	abstract = theme_format_expand_data(theme, (const char **) &abstract,
					    default_color, NULL, FALSE);
	ret = parse_special_string(abstract, NULL, NULL, data, NULL);
	g_free(abstract);
	return ret;
}

static const char *colorformats = "n01234567krgybmpcwKRGYBMPCW";

#define IS_COLOR_FORMAT(c) \
        (strchr(colorformats, c) != NULL)

/* append next "item", either a character, $variable or %format */
static void theme_format_append_next(THEME_REC *theme, GString *str,
				     const char **format,
				     char default_color, char *last_color)
{
	int index;
	char *value, chr;

	chr = **format;
	if ((chr == '$' || chr == '%') &&
	    (*format)[1] == '\0') {
		/* last char, always append */
		g_string_append_c(str, chr);
		(*format)++;
                return;
	}

	if (chr == '$') {
		/* $variable .. we'll always need to skip this, since it
		   may contain characters that are in replace chars. */
                const char *orig;
		char *args[1] = { NULL };
		int free_ret;

                orig = *format;
		(*format)++;

		value = parse_special((char **) format, NULL, NULL,
				      args, &free_ret, NULL );
		if (free_ret) g_free(value);
		(*format)++;

		/* append the variable name */
		value = g_strndup(orig, (int) (*format-orig));
                g_string_append(str, value);
                g_free(value);
		return;
	}

	if (**format == '%') {
		/* format */
		(*format)++;
		if (**format != '{' && **format != '}') {
                        chr = **format;
			if (**format == 'n')
                                chr = default_color;

			if (IS_COLOR_FORMAT(chr))
				*last_color = chr;
			g_string_append_c(str, '%');
			g_string_append_c(str, chr);
			(*format)++;
			return;
		}

		/* %{ or %} gives us { or } char */
		chr = **format;
	}

	index = theme_replace_find(theme, chr);
	if (index == -1)
		g_string_append_c(str, chr);
	else {
		value = theme_replace_expand(theme, index, default_color, chr);
		g_string_append(str, value);
		g_free(value);
	}

        (*format)++;
}

/* expand a single {abstract ...data... } */
static char *theme_format_expand_abstract(THEME_REC *theme,
					  const char **formatp,
					  char default_color)
{
	const char *p, *format;
	char *abstract, *data, *ret;
	int len;

	format = *formatp;

	/* get abstract name first */
	p = format;
	while (*p != '\0' && *p != ' ' &&
	       *p != '{' && *p != '}') p++;
	if (*p == '\0' || p == format)
		return NULL; /* error */

	len = (int) (p-format);
	abstract = g_strndup(format, len);

	/* skip the following space */
	if (*p == ' ') len++;
	*formatp = format + len;

	/* get the abstract data */
	data = g_hash_table_lookup(theme->abstracts, abstract);
	g_free(abstract);
	if (data == NULL) {
		/* unknown abstract */
		return NULL;
	}
	abstract = g_strdup(data);

	/* abstract may itself contain abstracts or replaces :) */
	p = data = abstract;
	abstract = theme_format_expand_data(theme, &p, default_color,
					    &default_color, FALSE);
	g_free(data);

	/* now we'll need to get the data part. it may contain
	   more abstracts, they are automatically expanded. */
	data = theme_format_expand_data(theme, formatp, default_color,
					NULL, FALSE);

	ret = parse_special_string(abstract, NULL, NULL, data, NULL);
	g_free(abstract);
	g_free(data);
	return ret;
}

/* expand the data part in {abstract data}. If root is TRUE, we're actually
   expanding the original format string so we ignore all extra } chars. */
static char *theme_format_expand_data(THEME_REC *theme,
				      const char **format,
				      char default_color,
				      char *before_arg_color, int root)
{
	GString *str;
	char *ret, *abstract;
	char last_color = default_color;

	str = g_string_new(NULL);

	while (**format != '\0') {
		if (!root && **format == '}') {
			(*format)++;
			break;
		}

		if (**format != '{') {
			if (before_arg_color != NULL &&
			    **format == '$' && (*format)[1] == '0') {
				/* save the color before $0 ..
				   this is for the %n replacing */
				*before_arg_color = last_color;
				before_arg_color = NULL;
			}

			theme_format_append_next(theme, str, format,
						 default_color, &last_color);
			continue;
		}

		(*format)++;
		if (**format == '\0' || **format == '}')
			break; /* error */

		/* get a single {...} */
		abstract = theme_format_expand_abstract(theme, format,
							last_color);
		if (abstract != NULL) {
			g_string_append(str, abstract);
			g_free(abstract);
		}
	}

	ret = str->str;
        g_string_free(str, FALSE);
        return ret;
}

static char *theme_format_expand(THEME_REC *theme, const char *format)
{
	g_return_val_if_fail(theme != NULL, NULL);
	g_return_val_if_fail(format != NULL, NULL);

	return theme_format_expand_data(theme, &format, 'n', NULL, TRUE);
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
	rec->expanded_formats = g_new0(char *, rec->count);

	g_hash_table_insert(theme->modules, rec->name, rec);
	return rec;
}

static void theme_read_replaces(CONFIG_REC *config, THEME_REC *theme)
{
	GSList *tmp;
	CONFIG_NODE *node;

	node = config_node_traverse(config, "replaces", FALSE);
	if (node == NULL || node->type !=  NODE_TYPE_BLOCK) return;

	for (tmp = node->value; tmp != NULL; tmp = tmp->next) {
		node = tmp->data;

		if (node->key != NULL && node->value != NULL) {
			theme->replace_keys =
				g_slist_append(theme->replace_keys,
					       g_strdup(node->key));
			theme->replace_values =
				g_slist_append(theme->replace_values,
					       g_strdup(node->value));
		}
	}
}

static void theme_read_abstracts(CONFIG_REC *config, THEME_REC *theme)
{
	GSList *tmp;
	CONFIG_NODE *node;

	node = config_node_traverse(config, "abstracts", FALSE);
	if (node == NULL || node->type !=  NODE_TYPE_BLOCK) return;

	for (tmp = node->value; tmp != NULL; tmp = tmp->next) {
		node = tmp->data;

		if (node->key != NULL && node->value != NULL &&
		    g_hash_table_lookup(theme->abstracts, node->key) == NULL) {
			g_hash_table_insert(theme->abstracts,
					    g_strdup(node->key),
					    g_strdup(node->value));
		}
	}
}

static void theme_set_format(THEME_REC *theme, MODULE_THEME_REC *rec,
			     FORMAT_REC *formats,
			     const char *key, const char *value)
{
	int n;

	for (n = 0; formats[n].def != NULL; n++) {
		if (formats[n].tag != NULL &&
		    g_strcasecmp(formats[n].tag, key) == 0) {
			rec->formats[n] = g_strdup(value);
			rec->expanded_formats[n] =
				theme_format_expand(theme, value);
			break;
		}
	}
}

static void theme_read_formats(CONFIG_REC *config, THEME_REC *theme,
			       const char *module)
{
	MODULE_THEME_REC *rec;
	FORMAT_REC *formats;
	CONFIG_NODE *node;
	GSList *tmp;

	formats = g_hash_table_lookup(default_formats, module);
	if (formats == NULL) return;

	node = config_node_traverse(config, "formats", FALSE);
	if (node == NULL) return;
	node = config_node_section(node, module, -1);
	if (node == NULL) return;

	rec = theme_module_create(theme, module);

	for (tmp = node->value; tmp != NULL; tmp = tmp->next) {
		node = tmp->data;

		if (node->key != NULL && node->value != NULL) {
			theme_set_format(theme, rec, formats,
					 node->key, node->value);
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

static void themes_read_module(const char *module)
{
        g_slist_foreach(themes, (GFunc) theme_read_module, (void *) module);
}

static void theme_remove_module(THEME_REC *theme, const char *module)
{
	MODULE_THEME_REC *rec;

	rec = g_hash_table_lookup(theme->modules, module);
	if (rec == NULL) return;

	g_hash_table_remove(theme->modules, module);
	theme_module_destroy(module, rec);
}

static void themes_remove_module(const char *module)
{
        g_slist_foreach(themes, (GFunc) theme_remove_module, (void *) module);
}

void theme_register_module(const char *module, FORMAT_REC *formats)
{
	if (g_hash_table_lookup(default_formats, module) != NULL)
		return;

        g_hash_table_insert(default_formats, g_strdup(module), formats);
	themes_read_module(module);
}

void theme_unregister_module(const char *module)
{
        gpointer key, value;

	if (!g_hash_table_lookup_extended(default_formats, module, &key, &value))
		return;

	g_hash_table_remove(default_formats, key);
	g_free(key);

	themes_remove_module(module);
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

THEME_REC *theme_load(const char *name)
{
	THEME_REC *theme;
	struct stat statbuf;
	char *fname;

	theme = theme_find(name);
	if (theme != NULL) return theme;

	/* check home dir */
	fname = g_strdup_printf("%s/.irssi/%s.theme", g_get_home_dir(), name);
	if (stat(fname, &statbuf) != 0) {
		/* check global config dir */
		g_free(fname);
		fname = g_strdup_printf(SYSCONFDIR"/irssi/%s.theme", name);
		if (stat(fname, &statbuf) != 0) {
			/* theme not found */
			g_free(fname);
			return NULL;
		}
	}

	theme = theme_create(fname, name);
	theme_read(theme, theme->path);

	g_free(fname);
	return theme;
}

typedef struct {
        THEME_REC *theme;
	CONFIG_REC *config;
} THEME_READ_REC;

static void theme_read_modules(const char *module, void *value,
			       THEME_READ_REC *rec)
{
	theme_read_formats(rec->config, rec->theme, module);
}

static void theme_read(THEME_REC *theme, const char *path)
{
	CONFIG_REC *config;
	THEME_READ_REC rec;

	config = config_open(path, -1);
	if (config == NULL) {
		/* didn't exist or no access? */
		theme->default_color = 15;
		return;
	}

        config_parse(config);
	theme->default_color = config_get_int(config, NULL, "default_color", 15);
        theme_read_replaces(config, theme);
	theme_read_abstracts(config, theme);

	rec.theme = theme;
	rec.config = config;
	g_hash_table_foreach(default_formats,
			     (GHFunc) theme_read_modules, &rec);
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

static void theme_show(THEME_SEARCH_REC *rec, const char *key, const char *value, int reset)
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
				printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_FORMAT_TITLE, rec->short_name, formats[0].def);
				first = FALSE;
			}
			if (last_title != NULL)
				printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_FORMAT_SUBTITLE, last_title);
			if (reset || value != NULL) {
				theme = theme_module_create(current_theme, rec->name);
                                g_free_not_null(theme->formats[n]);
                                g_free_not_null(theme->expanded_formats[n]);

				theme->formats[n] = reset ? NULL : g_strdup(value);
				theme->expanded_formats[n] = reset ? NULL : theme_format_expand(current_theme, value);
				text = reset ? formats[n].def : value;
			}
			printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_FORMAT_ITEM, formats[n].tag, text);
			last_title = NULL;
		}
	}
}

/* SYNTAX: FORMAT [-delete | -reset] [<module>] [<key> [<value>]] */
static void cmd_format(const char *data)
{
        GHashTable *optlist;
	GSList *tmp, *modules;
	char *module, *key, *value;
	void *free_arg;
	int reset;

	if (!cmd_get_params(data, &free_arg, 3 | PARAM_FLAG_GETREST | PARAM_FLAG_OPTIONS,
			    "format", &optlist, &module, &key, &value))
		return;

	modules = get_sorted_modules();
	if (*module == '\0')
		module = NULL;
	else if (theme_search(modules, module) == NULL) {
		/* first argument isn't module.. */
		cmd_params_free(free_arg);
		if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST | PARAM_FLAG_OPTIONS,
				    "format", &optlist, &key, &value))
			return;
		module = NULL;
	}

	reset = FALSE;
	if (*key == '\0') key = NULL;
	if (g_hash_table_lookup(optlist, "reset"))
		reset = TRUE;
	else if (g_hash_table_lookup(optlist, "delete"))
		value = "";
	else if (*value == '\0')
		value = NULL;

	for (tmp = modules; tmp != NULL; tmp = tmp->next) {
		THEME_SEARCH_REC *rec = tmp->data;

		if (module == NULL || g_strcasecmp(rec->short_name, module) == 0)
			theme_show(rec, key, value, reset);
	}
	g_slist_foreach(modules, (GFunc) g_free, NULL);
	g_slist_free(modules);

        cmd_params_free(free_arg);
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

static void theme_save(THEME_REC *theme)
{
	CONFIG_REC *config;
	CONFIG_NODE *fnode;
	char *path;
	int ok;

	config = config_open(theme->path, 0660);
	if (config == NULL) return;

	config_parse(config);

	fnode = config_node_traverse(config, "formats", TRUE);
	g_hash_table_foreach(theme->modules, (GHFunc) module_save, fnode);

        ok = TRUE;
	path = g_strdup(theme->path);
	if (config_write(config, NULL, 0660) == -1) {
		/* we probably tried to save to global directory
		   where we didn't have access.. try saving it to
		   home dir instead. */
		char *str;

		/* check that we really didn't try to save
		   it to home dir.. */
		g_free(path);
		path = g_strdup_printf("%s/.irssi/%s", g_get_home_dir(),
				       g_basename(theme->path));
		str = strrchr(path, '/');
		if (strncmp(theme->path, path, (int) (path-str)) == 0 ||
		    config_write(config, str, 0660) == -1)
			ok = FALSE;
	}
	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
		    ok ? IRCTXT_THEME_SAVED : IRCTXT_THEME_SAVE_FAILED,
		    path, config_last_error(config));
	g_free(path);
	config_close(config);
}

/* save changed formats */
static void cmd_save(void)
{
	GSList *tmp;

	for (tmp = themes; tmp != NULL; tmp = tmp->next) {
		THEME_REC *theme = tmp->data;

		theme_save(theme);
	}
}

static void complete_format_list(THEME_SEARCH_REC *rec, const char *key, GList **list)
{
	MODULE_THEME_REC *theme;
	FORMAT_REC *formats;
	int n, len;

	formats = g_hash_table_lookup(default_formats, rec->name);
	theme = g_hash_table_lookup(current_theme->modules, rec->name);

	len = strlen(key);
	for (n = 1; formats[n].def != NULL; n++) {
		const char *item = formats[n].tag;

		if (item != NULL && g_strncasecmp(item, key, len) == 0)
                        *list = g_list_append(*list, g_strdup(item));
	}
}

static GList *completion_get_formats(const char *module, const char *key)
{
	GSList *modules, *tmp;
	GList *list;

	g_return_val_if_fail(key != NULL, NULL);

	list = NULL;

	modules = get_sorted_modules();
	if (*module == '\0' || theme_search(modules, module) != NULL) {
		for (tmp = modules; tmp != NULL; tmp = tmp->next) {
			THEME_SEARCH_REC *rec = tmp->data;

			if (*module == '\0' || g_strcasecmp(rec->short_name, module) == 0)
				complete_format_list(rec, key, &list);
		}
	}
	g_slist_foreach(modules, (GFunc) g_free, NULL);
	g_slist_free(modules);

	return list;
}

static void sig_complete_format(GList **list, WINDOW_REC *window,
				const char *word, const char *line, int *want_space)
{
	const char *ptr;
	int words;

	g_return_if_fail(list != NULL);
	g_return_if_fail(word != NULL);
	g_return_if_fail(line != NULL);

        ptr = line;

	words = 0;
	do {
		words++;
                ptr = strchr(ptr, ' ');
	} while (ptr != NULL);

	if (words > 2)
		return;

	*list = completion_get_formats(line, word);
	if (*list != NULL) signal_stop();
}

static void read_settings(void)
{
	THEME_REC *rec;
	const char *theme;

	theme = settings_get_str("theme");
	if (strcmp(current_theme->name, theme) != 0) {
		rec = theme_load(theme);
		if (rec != NULL) current_theme = rec;
	}
}

static void themes_read(void)
{
	GSList *tmp;
	char *fname;

	while (themes != NULL)
		theme_destroy(themes->data);

	/* first there's default theme.. */
	current_theme = theme_load("default");
	if (current_theme == NULL) {
		fname = g_strdup_printf("%s/.irssi/default.theme",
					g_get_home_dir());
		current_theme = theme_create(fname, "default");
		current_theme->default_color = 15;
		g_free(fname);
	}

	/* update window theme structures */
	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		if (rec->theme_name != NULL)
                        rec->theme = theme_load(rec->theme_name);
	}

	read_settings();
}

void themes_init(void)
{
	settings_add_str("lookandfeel", "theme", "default");

	default_formats = g_hash_table_new((GHashFunc) g_str_hash,
					   (GCompareFunc) g_str_equal);

	themes = NULL;
	themes_read();

	command_bind("format", NULL, (SIGNAL_FUNC) cmd_format);
	command_bind("save", NULL, (SIGNAL_FUNC) cmd_save);
	signal_add("complete command format", (SIGNAL_FUNC) sig_complete_format);
        signal_add("setup changed", (SIGNAL_FUNC) read_settings);
        signal_add("setup reread", (SIGNAL_FUNC) themes_read);

	command_set_options("format", "delete reset");
}

void themes_deinit(void)
{
	while (themes != NULL)
		theme_destroy(themes->data);

	g_hash_table_destroy(default_formats);

	command_unbind("format", (SIGNAL_FUNC) cmd_format);
	command_unbind("save", (SIGNAL_FUNC) cmd_save);
	signal_remove("complete command format", (SIGNAL_FUNC) sig_complete_format);
        signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
        signal_remove("setup reread", (SIGNAL_FUNC) themes_read);
}
