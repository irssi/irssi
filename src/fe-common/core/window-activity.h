#ifndef __WINDOW_ACTIVITY_H
#define __WINDOW_ACTIVITY_H

void window_activity(WINDOW_REC *window, int data_level,
		     const char *hilight_color);

void window_item_activity(WI_ITEM_REC *item, int data_level,
			  const char *hilight_color);

void window_activity_init(void);
void window_activity_deinit(void);

#endif
