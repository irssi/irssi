#ifndef __KEYBOARD_H
#define __KEYBOARD_H

#include "signals.h"

typedef struct {
	char *id;
	char *description;

	GSList *keys;
} KEYINFO_REC;

typedef struct {
	KEYINFO_REC *info;

	char *key;
	char *data;
} KEY_REC;

extern GSList *keyinfos;

void key_bind(const char *id, const char *description,
	      const char *key_default, const char *data, SIGNAL_FUNC func);
void key_unbind(const char *id, SIGNAL_FUNC func);

void key_configure_add(const char *id, const char *key, const char *data);
void key_configure_remove(const char *key);

KEYINFO_REC *key_info_find(const char *id);
int key_pressed(const char *key, void *data);

#define ENTRY_REDIRECT_FLAG_HOTKEY	0x01
#define ENTRY_REDIRECT_FLAG_HIDDEN	0x02

void keyboard_entry_redirect(SIGNAL_FUNC func, const char *entry,
			     int flags, void *data);

void keyboard_init(void);
void keyboard_deinit(void);

#endif
