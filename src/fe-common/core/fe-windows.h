#ifndef __WINDOWS_H
#define __WINDOWS_H

#include "servers.h"

#define STRUCT_SERVER_REC SERVER_REC
#include "window-item-def.h"

enum {
        DATA_LEVEL_NONE = 0,
	DATA_LEVEL_TEXT,
	DATA_LEVEL_MSG,
        DATA_LEVEL_HILIGHT
};

typedef struct {
	char *servertag;
        char *name;
	unsigned int sticky:1;
} WINDOW_BIND_REC;

typedef struct {
	int refnum;
	char *name;

        int width, height;

	GSList *items;
	WI_ITEM_REC *active;
	SERVER_REC *active_server;
        char *servertag; /* active_server must be either NULL or have this tag (unless there's items in this window) */

	int level; /* message level */
	GSList *bound_items; /* list of WINDOW_BIND_RECs */

	unsigned int sticky_refnum:1;
	unsigned int destroying:1;

	/* window-specific command line history */
	GList *history, *history_pos;
	int history_lines, history_over_counter;

	int data_level; /* current data level */
	char *hilight_color; /* current hilight color in %format */

	time_t last_timestamp; /* When was last timestamp printed */
	time_t last_line; /* When was last line printed */

        char *theme_name; /* active theme in window, NULL = default */
	void *theme; /* THEME_REC */

	void *gui_data;
} WINDOW_REC;

extern GSList *windows;
extern WINDOW_REC *active_win;

WINDOW_REC *window_create(WI_ITEM_REC *item, int automatic);
void window_destroy(WINDOW_REC *window);

void window_auto_destroy(WINDOW_REC *window);

void window_set_active(WINDOW_REC *window);
void window_change_server(WINDOW_REC *window, void *server);

void window_set_refnum(WINDOW_REC *window, int refnum);
void window_set_name(WINDOW_REC *window, const char *name);
void window_set_level(WINDOW_REC *window, int level);

/* return active item's name, or if none is active, window's name */
char *window_get_active_name(WINDOW_REC *window);

WINDOW_REC *window_find_level(void *server, int level);
WINDOW_REC *window_find_closest(void *server, const char *name, int level);
WINDOW_REC *window_find_refnum(int refnum);
WINDOW_REC *window_find_name(const char *name);
WINDOW_REC *window_find_item(SERVER_REC *server, const char *name);

int window_refnum_prev(int refnum, int wrap);
int window_refnum_next(int refnum, int wrap);
int windows_refnum_last(void);

GSList *windows_get_sorted(void);

WINDOW_BIND_REC *window_bind_add(WINDOW_REC *window, const char *servertag,
				 const char *name);
void window_bind_destroy(WINDOW_REC *window, WINDOW_BIND_REC *rec);

WINDOW_BIND_REC *window_bind_find(WINDOW_REC *window, const char *servertag,
				  const char *name);
void window_bind_remove_unsticky(WINDOW_REC *window);

void windows_init(void);
void windows_deinit(void);

#endif
