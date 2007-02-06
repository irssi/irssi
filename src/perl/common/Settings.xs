#include "module.h"
#include "misc.h"

static GHashTable *perl_settings;

static void perl_settings_add(const char *key)
{
	PERL_SCRIPT_REC *script;
        GSList *list;

	script = perl_script_find_package(perl_get_package());
	g_return_if_fail(script != NULL);

	list = g_hash_table_lookup(perl_settings, script);
        list = g_slist_append(list, g_strdup(key));
	g_hash_table_insert(perl_settings, script, list);
}

static void perl_settings_remove(const char *key)
{
	PERL_SCRIPT_REC *script;
        GSList *list, *pos;

	script = perl_script_find_package(perl_get_package());
	g_return_if_fail(script != NULL);

	list = g_hash_table_lookup(perl_settings, script);
	pos = gslist_find_icase_string(list, key);
	if (pos != NULL) {
		list = g_slist_remove(list, pos->data);
		g_hash_table_insert(perl_settings, script, list);
	}
}

static void perl_settings_free(PERL_SCRIPT_REC *script, GSList *list)
{
	g_slist_foreach(list, (GFunc) g_free, NULL);
        g_slist_free(list);
}

static void sig_script_destroyed(PERL_SCRIPT_REC *script)
{
	GSList *list;

	list = g_hash_table_lookup(perl_settings, script);
	if (list != NULL) {
                g_slist_foreach(list, (GFunc) settings_remove, NULL);
		perl_settings_free(script, list);
		g_hash_table_remove(perl_settings, script);
	}
}

void perl_settings_init(void)
{
	perl_settings = g_hash_table_new((GHashFunc) g_direct_hash,
					 (GCompareFunc) g_direct_equal);
        signal_add("script destroyed", (SIGNAL_FUNC) sig_script_destroyed);
}

void perl_settings_deinit(void)
{
        signal_remove("script destroyed", (SIGNAL_FUNC) sig_script_destroyed);

	g_hash_table_foreach(perl_settings, (GHFunc) perl_settings_free, NULL);
	g_hash_table_destroy(perl_settings);
}

MODULE = Irssi::Settings  PACKAGE = Irssi
PROTOTYPES: ENABLE

SV *
settings_get_str(key)
	char *key
PREINIT:
	const char *str;
CODE:
	str = settings_get_str(key);
	RETVAL = new_pv(str);
OUTPUT:
	RETVAL

int
settings_get_int(key)
	char *key

int
settings_get_bool(key)
	char *key

int
settings_get_time(key)
       char *key

int
settings_get_level(key)
       char *key

int
settings_get_size(key)
       char *key

void
settings_set_str(key, value)
	char *key
	char *value

void
settings_set_int(key, value)
	char *key
	int value

void
settings_set_bool(key, value)
	char *key
	int value

int
settings_set_time(key, value)
	char *key
	char *value

int
settings_set_level(key, value)
	char *key
	char *value

int
settings_set_size(key, value)
	char *key
	char *value

void
settings_add_str(section, key, def)
	char *section
	char *key
	char *def
CODE:
        perl_settings_add(key);
	settings_add_str_module(MODULE_NAME"/scripts", section, key, def);

void
settings_add_int(section, key, def)
	char *section
	char *key
	int def
CODE:
        perl_settings_add(key);
	settings_add_int_module(MODULE_NAME"/scripts", section, key, def);

void
settings_add_bool(section, key, def)
	char *section
	char *key
	int def
CODE:
        perl_settings_add(key);
	settings_add_bool_module(MODULE_NAME"/scripts", section, key, def);

void
settings_add_time(section, key, def)
	char *section
	char *key
	char *def
CODE:
        perl_settings_add(key);
	settings_add_time_module(MODULE_NAME"/scripts", section, key, def);

void
settings_add_level(section, key, def)
	char *section
	char *key
	char *def
CODE:
        perl_settings_add(key);
	settings_add_level_module(MODULE_NAME"/scripts", section, key, def);

void
settings_add_size(section, key, def)
	char *section
	char *key
	char *def
CODE:
        perl_settings_add(key);
	settings_add_size_module(MODULE_NAME"/scripts", section, key, def);

void
settings_remove(key)
	char *key
CODE:
        perl_settings_remove(key);
	settings_remove(key);
