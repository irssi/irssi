#ifndef __WINDOW_ITEMS_H
#define __WINDOW_ITEMS_H

#include "fe-windows.h"

/* Add/remove/destroy window item from `window' */
void window_item_add(WINDOW_REC *window, WI_ITEM_REC *item, int automatic);
void window_item_remove(WI_ITEM_REC *item);
void window_item_destroy(WI_ITEM_REC *item);

/* Find a window for `item' and call window_item_add(). */
void window_item_create(WI_ITEM_REC *item, int automatic);

#define window_item_window(item) \
	((WINDOW_REC *) ((WI_ITEM_REC *) (item))->window)
void window_item_change_server(WI_ITEM_REC *item, void *server);

void window_item_set_active(WINDOW_REC *window, WI_ITEM_REC *item);
/* Return TRUE if `item' is the active window item in the window.
   `item' can be NULL. */
int window_item_is_active(WI_ITEM_REC *item);

void window_item_prev(WINDOW_REC *window);
void window_item_next(WINDOW_REC *window);

/* Find wanted window item by name. `server' can be NULL. */
WI_ITEM_REC *window_item_find(void *server, const char *name);
WI_ITEM_REC *window_item_find_window(WINDOW_REC *window,
                                     void *server, const char *name);

void window_items_init(void);
void window_items_deinit(void);

#endif
