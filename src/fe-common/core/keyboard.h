#ifndef __KEYBOARD_H
#define __KEYBOARD_H

#include "signals.h"

typedef struct _KEYBOARD_REC KEYBOARD_REC;
typedef struct _KEYINFO_REC KEYINFO_REC;
typedef struct _KEY_REC KEY_REC;

struct _KEYINFO_REC {
	char *id;
	char *description;

	GSList *keys, *default_keys;
};

struct _KEY_REC {
	KEYINFO_REC *info;

	char *key;
	char *data;
};

extern GSList *keyinfos;

/* Creates a new "keyboard" - this is used only for keeping track of
   key combo states and sending the gui_data parameter in "key pressed"
   signal */
KEYBOARD_REC *keyboard_create(void *gui_data);
/* Destroys a keyboard */
void keyboard_destroy(KEYBOARD_REC *keyboard);
/* Returns 1 if key press was consumed, -1 if not, 0 if it's beginning of a
   key combo. Control characters should be sent as "^@" .. "^_" instead of
   #0..#31 chars, #127 should be sent as ^? */
int key_pressed(KEYBOARD_REC *keyboard, const char *key);

void key_bind(const char *id, const char *description,
	      const char *key_default, const char *data, SIGNAL_FUNC func);
void key_unbind(const char *id, SIGNAL_FUNC func);

void key_configure_freeze(void);
void key_configure_thaw(void);

void key_configure_add(const char *id, const char *key, const char *data);
void key_configure_remove(const char *key);

KEYINFO_REC *key_info_find(const char *id);

#define ENTRY_REDIRECT_FLAG_HOTKEY	0x01
#define ENTRY_REDIRECT_FLAG_HIDDEN	0x02

void keyboard_entry_redirect(SIGNAL_FUNC func, const char *entry,
			     int flags, void *data);

void keyboard_init(void);
void keyboard_deinit(void);

#endif
