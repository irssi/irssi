#ifndef __SCREEN_H
#define __SCREEN_H

#if defined(USE_NCURSES) && !defined(RENAMED_NCURSES)
#  include <ncurses.h>
#else
#  include <curses.h>
#endif

/* Some curseses include term.h, which #defines some things breaking irssi */
#undef lines
#undef key_backspace
#undef tab

#define ATTR_UNDERLINE 0x100
#define ATTR_COLOR8    0x200
#define ATTR_REVERSE   0x400

/* XXX I hope this could be integrated into BX.
 * XXX Well, this should be done via libc,
 *     but FreeBSD libc support is quite LAME.
 *     Macro below are copied from lynx.
 *
 *				clive@FreeBSD.org
 */
#ifdef WANT_BIG5
/* XXX I didn't check the encoding range of big5+. This is standard big5. */
#define is_big5_los(lo) (((char)0x40<=lo)&&(lo<=(char)0x7E))	/* standard */
#define is_big5_lox(lo) (((char)0x80<=lo)&&(lo<=(char)0xFE))	/* extended */
#define is_big5_hi(hi)  (((char)0x81<=hi)&&(hi<=(char)0xFE))
#define is_big5(hi,lo) is_big5_hi(hi) && (is_big5_los(lo) || is_big5_lox(lo))
#endif WANT_BIG5

int init_screen(void); /* Initialize screen, detect screen length */
void deinit_screen(void); /* Deinitialize screen */

void set_color(WINDOW *window, int col);
void set_bg(WINDOW *window, int col);

void move_cursor(int y, int x);

void screen_refresh_freeze(void);
void screen_refresh_thaw(void);
void screen_refresh(WINDOW *window);

#endif
