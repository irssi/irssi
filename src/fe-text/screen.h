#ifndef __SCREEN_H
#define __SCREEN_H

#if defined(USE_NCURSES) && !defined(RENAMED_NCURSES)
#include <ncurses.h>
#else
#include <curses.h>
#endif

#define ATTR_UNDERLINE 0x100
#define ATTR_COLOR8    0x200
#define ATTR_REVERSE   0x400

extern gboolean use_colors;

gint init_screen(void); /* Initialize screen, detect screen length */
void deinit_screen(void); /* Deinitialize screen */

void set_color(gint col);
void set_bg(gint col);

void scroll_up(gint y1, gint y2); /* Scroll area up */
void scroll_down(gint y1, gint y2); /* Scroll area down */

void move_cursor(gint y, gint x);

void screen_refresh_freeze(void);
void screen_refresh_thaw(void);
void screen_refresh(void);

#endif
