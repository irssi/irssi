#include "module.h"

MODULE = Irssi::Settings  PACKAGE = Irssi
PROTOTYPES: ENABLE

char *
settings_get_str(key)
	char *key
CODE:
	RETVAL = (char *) settings_get_str(key);
OUTPUT:
	RETVAL

int
settings_get_int(key)
	char *key

int
settings_get_bool(key)
	char *key

void
settings_add_str(section, key, def)
	char *section
	char *key
	char *def

void
settings_add_int(section, key, def)
	char *section
	char *key
	int def

void
settings_add_bool(section, key, def)
	char *section
	char *key
	int def

void
settings_remove(key)
	char *key
