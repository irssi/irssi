#ifndef __GUI_STATUSBAR_H
#define __GUI_STATUSBAR_H

typedef void (*STATUSBAR_FUNC) (gint xpos, gint ypos, gint size);

/* create new statusbar, return position */
gint gui_statusbar_create(gboolean up);
void gui_statusbar_delete(gboolean up, gint ypos);

/* allocate area in statusbar, returns tag or -1 if failed */
gint gui_statusbar_allocate(gint size, gboolean right_justify, gboolean up, gint ypos, STATUSBAR_FUNC func);
void gui_statusbar_resize(gint tag, gint size);
void gui_statusbar_remove(gint tag);

/* redraw item, -1 = all */
void gui_statusbar_redraw(gint tag);

void gui_statusbar_init(void);
void gui_statusbar_deinit(void);

#endif
