#ifndef __SETTINGS_H
#define __SETTINGS_H

#ifndef __ICONFIG_H
typedef struct _config_rec CONFIG_REC;
#endif

enum {
	SETTING_TYPE_STRING,
	SETTING_TYPE_INT,
	SETTING_TYPE_BOOLEAN
};

typedef struct {
	int type;
	char *key;
	char *section;
	void *def;
} SETTINGS_REC;

/* macros for handling the default Irssi configuration */
#define iconfig_get_str(a, b, c) config_get_str(mainconfig, a, b,c)
#define iconfig_get_int(a, b, c) config_get_int(mainconfig, a, b,c)
#define iconfig_get_bool(a, b, c) config_get_bool(mainconfig, a, b,c)
#define iconfig_list_find(a, b, c, d) config_list_find(mainconfig, a, b, c, d)

#define iconfig_set_str(a, b, c) config_set_str(mainconfig, a, b,c)
#define iconfig_set_int(a, b, c) config_set_int(mainconfig, a, b,c)
#define iconfig_set_bool(a, b, c) config_set_bool(mainconfig, a, b,c)

#define iconfig_node_traverse(a, b) config_node_traverse(mainconfig, a, b)

extern CONFIG_REC *mainconfig;

/* Functions for handling the "settings" node of Irssi configuration */
const char *settings_get_str(const char *key);
const int settings_get_int(const char *key);
const int settings_get_bool(const char *key);

/* Functions to add/remove settings */
void settings_add_str(const char *section, const char *key, const char *def);
void settings_add_int(const char *section, const char *key, int def);
void settings_add_bool(const char *section, const char *key, int def);
void settings_remove(const char *key);

/* Get the type (SETTING_TYPE_xxx) of `key' */
int settings_get_type(const char *key);
/* Get all settings sorted by section. Free the result with g_slist_free() */
GSList *settings_get_sorted(void);
/* Get the record of the setting */
SETTINGS_REC *settings_get_record(const char *key);

void settings_init(void);
void settings_deinit(void);

#endif
