#ifndef __STATUSBAR_H
#define __STATUSBAR_H

#include "mainwindows.h"

#define SBAR_PRIORITY_HIGH	100
#define SBAR_PRIORITY_NORMAL	0
#define SBAR_PRIORITY_LOW	-100

enum {
	STATUSBAR_POS_UP,
	STATUSBAR_POS_MIDDLE,
	STATUSBAR_POS_DOWN
};

typedef struct SBAR_ITEM_REC SBAR_ITEM_REC;
typedef void (*STATUSBAR_FUNC) (SBAR_ITEM_REC *item, int get_size_only);

typedef struct {
	MAIN_WINDOW_REC *window;

	int pos;
	int line;

        char *color_string;
        int color;

	int ypos; /* real position in screen at the moment */
	GSList *items;
} STATUSBAR_REC;

struct SBAR_ITEM_REC {
	STATUSBAR_REC *bar;
	STATUSBAR_FUNC func;

	/* what item wants */
        int priority;
	int min_size, max_size;
	unsigned int right_justify:1;

	/* what item gets */
        int xpos, size;
};

/* ypos is used only when pos == STATUSBAR_POS_MIDDLE */
STATUSBAR_REC *statusbar_create(int pos, int ypos);
void statusbar_destroy(STATUSBAR_REC *bar);

STATUSBAR_REC *statusbar_find(int pos, int line);

SBAR_ITEM_REC *statusbar_item_create(STATUSBAR_REC *bar,
				     int priority, int right_justify,
				     STATUSBAR_FUNC func);
void statusbar_item_remove(SBAR_ITEM_REC *item);

/* redraw statusbar, NULL = all */
void statusbar_redraw(STATUSBAR_REC *bar);
void statusbar_item_redraw(SBAR_ITEM_REC *item);

void statusbar_init(void);
void statusbar_deinit(void);

#endif
