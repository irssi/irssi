#ifndef __KEYBOARD_H
#define __KEYBOARD_H

#include "signals.h"

typedef struct
{
	char *id;
	char *description;

	GSList *keys;
}
KEYINFO_REC;

typedef struct
{
	KEYINFO_REC *info;

	char *key;
	void *data;
}
KEY_REC;

extern GSList *keyinfos;

void key_bind(gchar *id, gchar *data, gchar *description, gchar *key_default, SIGNAL_FUNC func);
void key_unbind(gchar *id, SIGNAL_FUNC func);

void key_configure_add(gchar *id, gchar *data, gchar *key);
void key_configure_remove(gchar *key);

KEYINFO_REC *key_info_find(gchar *id);
gboolean key_pressed(gchar *key, gpointer data);

void keyboard_save(void);

void keyboard_init(void);
void keyboard_deinit(void);

#endif
