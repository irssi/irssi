#ifndef IRSSI_FE_COMMON_CORE_FE_WINDOWS_H
#define IRSSI_FE_COMMON_CORE_FE_WINDOWS_H

#include <irssi/src/core/window-item-def.h>
#include <irssi/src/fe-common/core/command-history.h>

enum {
        DATA_LEVEL_NONE = 0,
	DATA_LEVEL_TEXT,
	DATA_LEVEL_MSG,
        DATA_LEVEL_HILIGHT
};

enum {
	MAIN_WINDOW_TYPE_NONE = -1,
	MAIN_WINDOW_TYPE_DEFAULT = 0,
	MAIN_WINDOW_TYPE_HIDDEN = 1,
	MAIN_WINDOW_TYPE_SPLIT = 2,
	MAIN_WINDOW_TYPE_RSPLIT = 3
};

typedef struct {
	char *servertag;
        char *name;
	int type;
	unsigned int sticky:1;
} WINDOW_BIND_REC;

struct _WINDOW_REC {
	int refnum;
	char *name;

        int width, height;

	GSList *items;
	WI_ITEM_REC *active;
	SERVER_REC *active_server;
	SERVER_REC *connect_server;
        char *servertag; /* active_server must be either NULL or have this tag (unless there's items in this window) */

	int level; /* message level */
	GSList *bound_items; /* list of WINDOW_BIND_RECs */

	unsigned int immortal:1;
	unsigned int sticky_refnum:1;
	unsigned int destroying:1;

	/* window-specific command line history */
	HISTORY_REC *history;
	char *history_name;

	int data_level; /* current data level */
	char *hilight_color; /* current hilight color in %format */

	time_t last_timestamp; /* When was last timestamp printed */
	time_t last_line; /* When was last line printed */

        char *theme_name; /* active theme in window, NULL = default */
	void *theme; /* THEME_REC */

	void *gui_data;
};

extern GSList *windows;
extern WINDOW_REC *active_win;

WINDOW_REC *window_create(WI_ITEM_REC *item, int automatic);
void window_destroy(WINDOW_REC *window);

void window_auto_destroy(WINDOW_REC *window);

void window_set_active(WINDOW_REC *window);
void window_change_server(WINDOW_REC *window, void *server);

void window_set_refnum(WINDOW_REC *window, int refnum);
void window_set_name(WINDOW_REC *window, const char *name);
void window_set_history(WINDOW_REC *window, const char *name);
void window_clear_history(WINDOW_REC *window, const char *name);
void window_set_level(WINDOW_REC *window, int level);
void window_set_immortal(WINDOW_REC *window, int immortal);

/* return active item's name, or if none is active, window's name */
const char *window_get_active_name(WINDOW_REC *window);

WINDOW_REC *window_find_level(void *server, int level);
WINDOW_REC *window_find_closest(void *server, const char *name, int level);
WINDOW_REC *window_find_refnum(int refnum);
WINDOW_REC *window_find_name(const char *name);
WINDOW_REC *window_find_item(SERVER_REC *server, const char *name);

int window_refnum_prev(int refnum, int wrap);
int window_refnum_next(int refnum, int wrap);
int windows_refnum_last(void);

int window_refnum_cmp(WINDOW_REC *w1, WINDOW_REC *w2);
GSList *windows_get_sorted(void);

/* Add a new bind to window - if duplicate is found it's returned */
WINDOW_BIND_REC *window_bind_add(WINDOW_REC *window, const char *servertag,
				 const char *name);
void window_bind_destroy(WINDOW_REC *window, WINDOW_BIND_REC *rec);

WINDOW_BIND_REC *window_bind_find(WINDOW_REC *window, const char *servertag,
				  const char *name);
void window_bind_remove_unsticky(WINDOW_REC *window);

void windows_init(void);
void windows_deinit(void);

short color_24bit_256(const unsigned char rgb[]);

#endif
