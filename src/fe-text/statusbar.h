#ifndef __STATUSBAR_H
#define __STATUSBAR_H

#include "mainwindows.h"
#include "statusbar-item.h"

#define STATUSBAR_PRIORITY_HIGH		100
#define STATUSBAR_PRIORITY_NORMAL	0
#define STATUSBAR_PRIORITY_LOW		-100

typedef struct SBAR_ITEM_REC SBAR_ITEM_REC;

/* type */
#define STATUSBAR_TYPE_ROOT	1
#define STATUSBAR_TYPE_WINDOW	2

/* placement */
#define STATUSBAR_TOP		1
#define STATUSBAR_BOTTOM	2

/* visible */
#define STATUSBAR_VISIBLE_ALWAYS        1
#define STATUSBAR_VISIBLE_ACTIVE        2
#define STATUSBAR_VISIBLE_INACTIVE      3

typedef struct {
	char *name;
        GSList *config_bars;
	GSList *bars;
} STATUSBAR_GROUP_REC;

typedef struct {
	char *name;

	int type; /* root/window */
	int placement; /* top/bottom */
	int position; /* the higher the number, the lower it is in screen */
	int visible; /* active/inactive/always */

	GSList *items;
} STATUSBAR_CONFIG_REC;

typedef struct {
	STATUSBAR_GROUP_REC *group;
	STATUSBAR_CONFIG_REC *config;

	MAIN_WINDOW_REC *parent_window; /* if config->type == STATUSBAR_TYPE_WINDOW */
        GSList *items;

	char *color; /* background color */
	int real_ypos; /* real Y-position in screen at the moment */

	unsigned int dirty:1;
        int dirty_xpos; /* -1 = only redraw some items, >= 0 = redraw all items after from xpos */
} STATUSBAR_REC;

typedef struct {
	char *name;
	char *value; /* if non-NULL, overrides the default */

	int priority;
	unsigned int right_alignment:1;
} SBAR_ITEM_CONFIG_REC;

struct SBAR_ITEM_REC {
	STATUSBAR_REC *bar;
	SBAR_ITEM_CONFIG_REC *config;
        STATUSBAR_FUNC func;

	/* what item wants */
	int min_size, max_size;

	/* what item gets */
	int xpos, size;

        int current_size; /* item size currently in screen */
	unsigned int dirty:1;
};

extern GSList *statusbar_groups;
extern STATUSBAR_GROUP_REC *active_statusbar_group;

STATUSBAR_GROUP_REC *statusbar_group_create(const char *name);
void statusbar_group_destroy(STATUSBAR_GROUP_REC *rec);
STATUSBAR_GROUP_REC *statusbar_group_find(const char *name);

STATUSBAR_REC *statusbar_create(STATUSBAR_GROUP_REC *group,
                                STATUSBAR_CONFIG_REC *config,
                                MAIN_WINDOW_REC *parent_window);
void statusbar_destroy(STATUSBAR_REC *bar);
STATUSBAR_REC *statusbar_find(STATUSBAR_GROUP_REC *group, const char *name,
			      MAIN_WINDOW_REC *window);

SBAR_ITEM_REC *statusbar_item_create(STATUSBAR_REC *bar,
				     SBAR_ITEM_CONFIG_REC *config);
void statusbar_item_destroy(SBAR_ITEM_REC *item);

/* redraw statusbar, NULL = all */
void statusbar_redraw(STATUSBAR_REC *bar, int force);
void statusbar_item_redraw(SBAR_ITEM_REC *item);

void statusbar_recreate_items(STATUSBAR_REC *bar);
void statusbars_recreate_items(void);
void statusbars_create_window_bars(void);

void statusbar_redraw_dirty(void);

void statusbar_init(void);
void statusbar_deinit(void);

#endif
