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
	void *data;
} KEY_REC;

extern GSList *keyinfos;

void key_bind(const char *id, const char *description,
	      const char *key_default, const char *data, SIGNAL_FUNC func);
void key_unbind(const char *id, SIGNAL_FUNC func);

void key_configure_add(const char *id, const char *key, const char *data);
void key_configure_remove(const char *key);

KEYINFO_REC *key_info_find(const char *id);
int key_pressed(const char *key, void *data);

void keyboard_init(void);
void keyboard_deinit(void);

#endif
