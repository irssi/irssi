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

int init_screen(void); /* Initialize screen, detect screen length */
void deinit_screen(void); /* Deinitialize screen */

void set_color(int col);
void set_bg(int col);

void scroll_up(int y1, int y2); /* Scroll area up */
void scroll_down(int y1, int y2); /* Scroll area down */

void move_cursor(int y, int x);

void screen_refresh_freeze(void);
void screen_refresh_thaw(void);
void screen_refresh(void);

#endif
