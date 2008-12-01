#ifndef IRSSI_STATUSBAR_ITEM_H
#define IRSSI_STATUSBAR_ITEM_H

struct SBAR_ITEM_REC;

typedef void (*STATUSBAR_FUNC) (struct SBAR_ITEM_REC *item, int get_size_only);

void statusbar_item_register(const char *name, const char *value,
			     STATUSBAR_FUNC func);
void statusbar_item_unregister(const char *name);
void statusbar_item_set_size(struct SBAR_ITEM_REC *item, int min_size, int max_size);
void statusbar_item_default_handler(struct SBAR_ITEM_REC *item, int get_size_only,
				    const char *str, const char *data,
				    int escape_vars);
void statusbar_items_redraw(const char *name);

#endif
