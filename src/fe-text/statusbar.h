#ifndef __STATUSBAR_H
#define __STATUSBAR_H

enum {
	STATUSBAR_POS_UP,
	STATUSBAR_POS_MIDDLE,
	STATUSBAR_POS_DOWN
};

typedef struct {
	int pos;
	int line;

	int ypos; /* real position in screen at the moment */
	GSList *items;
} STATUSBAR_REC;

typedef struct {
        STATUSBAR_REC *bar;

	int xpos, size;
	int right_justify;
	void *func;
} SBAR_ITEM_REC;

typedef void (*STATUSBAR_FUNC) (SBAR_ITEM_REC *item, int ypos);

/* ypos is used only when pos == STATUSBAR_POS_MIDDLE */
STATUSBAR_REC *statusbar_create(int pos, int ypos);
void statusbar_destroy(STATUSBAR_REC *bar);

STATUSBAR_REC *statusbar_find(int pos, int line);

SBAR_ITEM_REC *statusbar_item_create(STATUSBAR_REC *bar, int size, gboolean right_justify, STATUSBAR_FUNC func);
void statusbar_item_resize(SBAR_ITEM_REC *item, int size);
void statusbar_item_remove(SBAR_ITEM_REC *item);

/* redraw statusbar, NULL = all */
void statusbar_redraw(STATUSBAR_REC *bar);
void statusbar_item_redraw(SBAR_ITEM_REC *item);

void statusbar_init(void);
void statusbar_deinit(void);

#endif
