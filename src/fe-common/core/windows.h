#ifndef __WINDOWS_H
#define __WINDOWS_H

enum {
	NEWDATA_TEXT = 1,
	NEWDATA_MSG,
	NEWDATA_MSG_FORYOU,
	NEWDATA_CUSTOM
};

/* All window items *MUST* have these variables in same order
   at the start of the structure - the server's type can of course be
   replaced with the preferred record type. */
typedef struct {
	int type;
        GHashTable *module_data;

	void *server;
	char *name;

	int new_data;
} WI_ITEM_REC;

typedef struct {
	int refnum;
	char *name;

	GSList *items;
	WI_ITEM_REC *active;
	void *active_server;

	GSList *waiting_channels; /* list of "<server tag> <channel>" */

	int lines;
	int destroying:1;

	/* window-specific command line history */
	GList *cmdhist, *histpos;
	int histlines;

	int level;
	int new_data;
	time_t last_timestamp; /* When was last timestamp printed */
	time_t last_line; /* When was last line printed */

	gpointer gui_data;
} WINDOW_REC;

extern GSList *windows;
extern WINDOW_REC *active_win;

WINDOW_REC *window_create(WI_ITEM_REC *item, int automatic);
void window_destroy(WINDOW_REC *window);

void window_set_active_num(int number);
void window_set_active(WINDOW_REC *window);
void window_change_server(WINDOW_REC *window, void *server);

void window_set_refnum(WINDOW_REC *window, int refnum);
void window_set_name(WINDOW_REC *window, const char *name);

void window_set_level(WINDOW_REC *window, int level);
WINDOW_REC *window_find_level(void *server, int level);
WINDOW_REC *window_find_closest(void *server, const char *name, int level);
WINDOW_REC *window_find_refnum(int refnum);
WINDOW_REC *window_find_name(const char *name);
WINDOW_REC *window_find_item(WINDOW_REC *window, const char *name);

void windows_init(void);
void windows_deinit(void);

#endif
