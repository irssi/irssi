#ifndef __GUI_PRINTTEXT_H
#define __GUI_PRINTTEXT_H

enum
{
    BLACK = 0,
    BLUE,
    GREEN,
    CYAN,
    RED,
    MAGENTA,
    YELLOW,
    WHITE,
    BBLACK,
    BBLUE,
    BGREEN,
    BCYAN,
    BRED,
    BMAGENTA,
    BYELLOW,
    BWHITE,
    NUM_COLORS
};

void gui_printtext_init(void);
void gui_printtext_deinit(void);

#endif
