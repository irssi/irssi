#ifndef __GUI_PRINTTEXT_H
#define __GUI_PRINTTEXT_H

#include "gui-windows.h"

extern int mirc_colors[];

void gui_printtext_init(void);
void gui_printtext_deinit(void);

void gui_printtext(int xpos, int ypos, const char *str);

#endif
