#ifndef __WINDOW_ITEMS_H
#define __WINDOW_ITEMS_H

#include "windows.h"

/* Add/remove window item from `window' */
void window_add_item(WINDOW_REC *window, WI_ITEM_REC *item, int automatic);
void window_remove_item(WINDOW_REC *window, WI_ITEM_REC *item);
/* Find a window for `item' and call window_add_item(). */
void window_item_create(WI_ITEM_REC *item, int automatic);

WINDOW_REC *window_item_window(WI_ITEM_REC *item);
void window_item_change_server(WI_ITEM_REC *item, void *server);

void window_item_set_active(WINDOW_REC *window, WI_ITEM_REC *item);
void window_item_prev(WINDOW_REC *window);
void window_item_next(WINDOW_REC *window);

/* Find wanted window item by name. `server' can be NULL. */
WI_ITEM_REC *window_item_find(void *server, const char *name);

void window_items_init(void);
void window_items_deinit(void);

#endif
