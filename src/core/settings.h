#ifndef __SETTINGS_H
#define __SETTINGS_H

enum {
	SETTING_TYPE_STRING,
	SETTING_TYPE_INT,
	SETTING_TYPE_BOOLEAN
};

typedef struct {
        char *module;
	int type;
	char *key;
	char *section;
	void *def;
} SETTINGS_REC;

/* macros for handling the default Irssi configuration */
#define iconfig_get_str(a, b, c) config_get_str(mainconfig, a, b, c)
#define iconfig_get_int(a, b, c) config_get_int(mainconfig, a, b, c)
#define iconfig_get_bool(a, b, c) config_get_bool(mainconfig, a, b, c)
#define iconfig_list_find(a, b, c, d) config_list_find(mainconfig, a, b, c, d)

#define iconfig_set_str(a, b, c) config_set_str(mainconfig, a, b, c)
#define iconfig_set_int(a, b, c) config_set_int(mainconfig, a, b, c)
#define iconfig_set_bool(a, b, c) config_set_bool(mainconfig, a, b, c)

#define iconfig_node_traverse(a, b) config_node_traverse(mainconfig, a, b)
#define iconfig_node_set_str(a, b, c) config_node_set_str(mainconfig, a, b, c)
#define iconfig_node_set_int(a, b, c) config_node_set_int(mainconfig, a, b, c)
#define iconfig_node_set_bool(a, b, c) config_node_set_bool(mainconfig, a, b, c)
#define iconfig_node_list_remove(a, b) config_node_list_remove(mainconfig, a, b)
#define iconfig_node_remove(a, b) config_node_remove(mainconfig, a, b)
#define iconfig_node_clear(a) config_node_clear(mainconfig, a)
#define iconfig_node_add_list(a, b) config_node_add_list(mainconfig, a, b)

extern CONFIG_REC *mainconfig;
extern const char *default_config;

/* Functions for handling the "settings" node of Irssi configuration */
const char *settings_get_str(const char *key);
int settings_get_int(const char *key);
int settings_get_bool(const char *key);

/* Functions to add/remove settings */
void settings_add_str_module(const char *module, const char *section,
			     const char *key, const char *def);
void settings_add_int_module(const char *module, const char *section,
			     const char *key, int def);
void settings_add_bool_module(const char *module, const char *section,
			      const char *key, int def);
void settings_remove(const char *key);
void settings_remove_module(const char *module);

#define settings_add_str(section, key, def) \
	settings_add_str_module(MODULE_NAME, section, key, def)
#define settings_add_int(section, key, def) \
	settings_add_int_module(MODULE_NAME, section, key, def)
#define settings_add_bool(section, key, def) \
	settings_add_bool_module(MODULE_NAME, section, key, def)

void settings_set_str(const char *key, const char *value);
void settings_set_int(const char *key, int value);
void settings_set_bool(const char *key, int value);

/* Get the type (SETTING_TYPE_xxx) of `key' */
int settings_get_type(const char *key);
/* Get all settings sorted by section. Free the result with g_slist_free() */
GSList *settings_get_sorted(void);
/* Get the record of the setting */
SETTINGS_REC *settings_get_record(const char *key);

/* verify that all settings in config file for `module' are actually found
   from /SET list */
void settings_check_module(const char *module);
#define settings_check() settings_check_module(MODULE_NAME)

/* remove all invalid settings from config file. works only with the
   modules that have already called settings_check() */
void settings_clean_invalid(void);

/* if `fname' is NULL, the default is used */
int settings_reread(const char *fname);
int settings_save(const char *fname, int autosave);
int irssi_config_is_changed(const char *fname);

void settings_init(void);
void settings_deinit(void);

#endif
