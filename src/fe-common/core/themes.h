#ifndef __THEMES_H
#define __THEMES_H

typedef struct {
	char *name;

	int count;
	char **formats; /* in same order as in module's default formats */
	char **expanded_formats; /* this contains the formats after
				    expanding {templates} */
} MODULE_THEME_REC;

typedef struct {
	int refcount;

	char *path;
	char *name;
        time_t last_modify;

	int default_color; /* default color to use with text with default
			      background. default is -1 which means the
			      default color set by terminal */
	unsigned int info_eol:1; /* show the timestamp/servertag at the
	                            end of the line, not at beginning */

	GHashTable *modules;

        int replace_keys[256]; /* index to replace_values for each char */
	GSList *replace_values;
	GHashTable *abstracts;

	void *gui_data;
} THEME_REC;

typedef struct _FORMAT_REC FORMAT_REC;

extern GSList *themes;
extern THEME_REC *current_theme;
extern GHashTable *default_formats;

THEME_REC *theme_create(const char *path, const char *name);
void theme_destroy(THEME_REC *rec);

THEME_REC *theme_load(const char *name);

#define theme_register(formats) theme_register_module(MODULE_NAME, formats)
#define theme_unregister() theme_unregister_module(MODULE_NAME)
void theme_register_module(const char *module, FORMAT_REC *formats);
void theme_unregister_module(const char *module);

void theme_set_default_abstract(const char *key, const char *value);

#define EXPAND_FLAG_IGNORE_REPLACES     0x01 /* don't use the character replaces when expanding */
#define EXPAND_FLAG_IGNORE_EMPTY        0x02 /* if abstract's argument is empty, or the argument is a $variable that is empty, don't try to expand it (ie. {xx }, but not {xx}) */
#define EXPAND_FLAG_RECURSIVE_MASK      0x0f
/* private */
#define EXPAND_FLAG_ROOT		0x10
#define EXPAND_FLAG_LASTCOLOR_ARG	0x20

char *theme_format_expand(THEME_REC *theme, const char *format);
char *theme_format_expand_data(THEME_REC *theme, const char **format,
			       char default_fg, char default_bg,
			       char *save_last_fg, char *save_last_bg,
			       int flags);

void themes_reload(void);

void themes_init(void);
void themes_deinit(void);

#endif
