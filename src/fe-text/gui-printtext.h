#ifndef __GUI_PRINTTEXT_H
#define __GUI_PRINTTEXT_H

#include "gui-windows.h"

extern int mirc_colors[];

void gui_printtext_init(void);
void gui_printtext_deinit(void);

void gui_window_line_append(GUI_WINDOW_REC *gui, const char *str, int len);
void gui_window_line_remove(WINDOW_REC *window, LINE_REC *line, int redraw);
void gui_window_line_text_free(GUI_WINDOW_REC *gui, LINE_REC *line);

void gui_printtext(int xpos, int ypos, const char *str);

#endif
